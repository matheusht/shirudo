// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo-build image`: `build` hands an ext4 image to
//! shirudo-gen-verity, which builds its verity tree and has this tool
//! sign the root; `sign-root` signs a root hash; `verify` checks an
//! image offline, its signature against a certificate and its tree with
//! veritysetup, on the very files it authenticated.

use core::ffi::{CStr, c_char, c_int};
use std::ffi::OsStr;
use std::io::{ErrorKind, Read, Write};
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Command;

use super::{KeyFiles, error, hex, print, strerr};
use crate::errno::{EINVAL, EIO, EKEYREJECTED, ENOENT};
use crate::sys::libc::{F_SETFD, O_NOFOLLOW, O_NONBLOCK, access, fcntl};
use crate::util::config_image::{self, ConfigImageOpen};
use crate::util::crypto_openssl::{
    Cert, cert_free, cert_key_algorithm, cert_read_file, cms_signed_by, verify_detached,
};
use crate::util::help::{Help, HelpSection, is_help, print_help};
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};

const SIG_MAX: usize = config_image::SIG_MAX as usize;
const X_OK: c_int = 1;

fn errno_of(e: &std::io::Error) -> c_int {
    -e.raw_os_error().unwrap_or(EIO)
}

/// `image build`: runs shirudo-gen-verity, beside this tool when
/// installed or in the tree, with this tool as its signer; returns only
/// when it cannot.
fn build(args: &[&CStr]) -> c_int {
    let Ok(exe) = std::fs::read_link("/proc/self/exe") else {
        return 1;
    };
    let exe = exe.as_os_str().as_bytes().to_vec();
    if exe.len() >= super::PATH_MAX - 1 {
        return 1;
    }
    let Some(slash) = exe.iter().rposition(|&c| c == b'/') else {
        return 1;
    };
    let dir = &exe[..slash];
    let installed = [dir, b"/../gen-image/shirudo-gen-verity"].concat();
    let in_tree = [dir, b"/gen-image/shirudo-gen-verity"].concat();
    let fits = |p: &[u8]| p.len() < super::PATH_MAX;
    if !fits(&installed) {
        return 1;
    }
    let installed_c = std::ffi::CString::new(installed.clone()).unwrap_or_default();
    // SAFETY: a C string.
    let script = if unsafe { access(installed_c.as_ptr(), X_OK) } == 0 {
        installed
    } else if fits(&in_tree) {
        in_tree
    } else {
        return 1;
    };
    let err = Command::new(OsStr::from_bytes(&script))
        .arg("--builder")
        .arg(OsStr::from_bytes(&exe))
        .args(args[2..].iter().map(|a| OsStr::from_bytes(a.to_bytes())))
        .exec();
    error(
        &[
            b"image build: cannot run ",
            &script[..],
            b": ",
            strerr(-errno_of(&err)),
        ]
        .concat(),
    );
    1
}

/// Runs `veritysetup verify` on the data and hash trees open at
/// `data_fd` and `hash_fd`, which it inherits, against `root`.
fn verify_verity(data_fd: c_int, hash_fd: c_int, root: &[u8]) -> c_int {
    let (data, hash) = (
        format!("/proc/self/fd/{data_fd}"),
        format!("/proc/self/fd/{hash_fd}"),
    );
    let mut cmd = Command::new("veritysetup");

    cmd.args(["verify", "--hash-offset=0", &data, &hash])
        .arg(OsStr::from_bytes(root));
    // SAFETY: between fork and exec only fcntl(), which is
    // async-signal-safe, on two descriptors this process owns.
    unsafe {
        cmd.pre_exec(move || {
            if fcntl(data_fd, F_SETFD, 0) != 0 || fcntl(hash_fd, F_SETFD, 0) != 0 {
                return Err(std::io::Error::from_raw_os_error(EIO));
            }
            Ok(())
        });
    }
    match cmd.status() {
        Err(e) => {
            error(
                &[
                    b"veritysetup: ",
                    strerr(-errno_of(&e)),
                    b"; install the operator veritysetup tool",
                ]
                .concat(),
            );
            -ENOENT
        }
        Ok(s) => match (s.code(), s.signal()) {
            (Some(0), _) => 0,
            (Some(127), _) => -ENOENT,
            (Some(_), _) | (None, _) => -EIO,
        },
    }
}

/// Whether `signature` signs `root`, the 64 hex digits of a root hash,
/// by the ML-DSA-87 key of the certificate at `cert_path`.
fn verify_root_signature(root: &[u8], signature: &[u8], cert_path: &CStr) -> c_int {
    let mut cert = Cert::new();
    let mut alg = [0u8; 32];

    // SAFETY: a C string, the cert to fill and room for its algorithm;
    // the signature and root with their lengths; the cert freed last.
    unsafe {
        let mut ret = cert_read_file(cert_path.as_ptr(), &mut cert);
        if ret == 0 {
            ret = cert_key_algorithm(&cert, alg.as_mut_ptr().cast(), alg.len());
        }
        if ret == 0 && crate::text::cstr(&alg) != b"ML-DSA-87" {
            ret = -EKEYREJECTED;
        }
        if ret == 0 && cms_signed_by(signature.as_ptr(), signature.len(), &cert) != 1 {
            ret = -EKEYREJECTED;
        }
        if ret == 0 {
            ret = verify_detached(
                root.as_ptr(),
                64,
                signature.as_ptr(),
                signature.len(),
                &cert,
            );
        }
        cert_free(&mut cert);
        ret
    }
}

/// The open parts of an image, closed when it goes.
struct Opened(ConfigImageOpen);

impl Drop for Opened {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// `image verify`: the signature, the verity tree, then the root hash
/// on stdout.
fn verify(prefix: &CStr, cert: &CStr) -> c_int {
    let img = match ConfigImageOpen::open(prefix, None) {
        Ok(img) => Opened(img),
        Err(err) => return err,
    };
    // SAFETY: the signature's descriptor, which the image keeps open.
    let file = ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(img.0.signature_fd) });
    let mut signature = vec![0u8; SIG_MAX + 1];
    let mut size = 0;
    while size < signature.len() {
        match file.read_at(&mut signature[size..], size as u64) {
            Ok(0) => break,
            Ok(n) => size += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return errno_of(&e),
        }
    }
    if size == 0 || size > SIG_MAX {
        return -EINVAL;
    }
    let root = hex(&img.0.image.root_hash);
    let mut ret = verify_root_signature(&root, &signature[..size], cert);
    if ret == 0 {
        ret = verify_verity(img.0.data_fd, img.0.hash_fd, &root);
    }
    if ret == 0 {
        print(true, &[&root[..], b"\n"].concat());
    }
    ret
}

/// `image sign-root`: signs the root hash, 64 lowercase hex digits, of
/// the file `input` into `output`, which must not exist.
fn sign_root(input: &CStr, output: &CStr, keys: &KeyFiles) -> c_int {
    if super::check_keys(&keys.pkey, &keys.cert) != 0 {
        return -EKEYREJECTED;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(super::path(input.to_bytes()));
    let mut file = match file {
        Ok(f) => f,
        Err(e) => return errno_of(&e),
    };
    let mut ret = match file.metadata() {
        Ok(m) if m.is_file() && m.size() == 64 => 0,
        Ok(_) => -EINVAL,
        Err(e) => errno_of(&e),
    };
    let mut root = [0u8; 64];
    let mut done = 0;
    while ret == 0 && done < root.len() {
        match file.read(&mut root[done..]) {
            Ok(0) => ret = -EIO,
            Ok(n) => done += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => ret = errno_of(&e),
        }
    }
    drop(file);
    if ret != 0 {
        return ret;
    }
    if !root.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return -EINVAL;
    }
    let signature = match super::sign::cms_sign(&root[..], &[], SIG_MAX, &keys.pkey, &keys.cert) {
        Ok((signature, _)) => signature,
        Err(err) => return err,
    };
    let ret = verify_root_signature(&root, &signature, &keys.cert);
    if ret != 0 {
        return ret;
    }
    let out = super::path(output.to_bytes());
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(out);
    let mut file = match file {
        Ok(f) => f,
        Err(e) => return errno_of(&e),
    };
    let ret = match file.write_all(&signature).and_then(|()| file.sync_all()) {
        Ok(()) => 0,
        Err(e) => errno_of(&e),
    };
    drop(file);
    if ret != 0 {
        let _ = std::fs::remove_file(out);
    }
    ret
}

const IMAGE_VERIFY_CERT: c_int = 0;

static IMAGE_VERIFY_OPTS: [OptSpec; 1] = [OptSpec::new(
    c"--cert",
    0,
    0,
    Some(c"<cert.der>"),
    c"the certificate the image's root hash is signed for",
)];

const IMAGE_SIGN_OUTPUT: c_int = 0;
const IMAGE_SIGN_KEYS_DIR: c_int = 1;
const IMAGE_SIGN_KEY: c_int = 2;
const IMAGE_SIGN_CERT: c_int = 3;

static IMAGE_SIGN_OPTS: [OptSpec; 4] = [
    OptSpec::new(
        c"--output",
        b'o',
        0,
        Some(c"<signature>"),
        c"where to write the signature",
    ),
    OptSpec::new(
        c"--keys-dir",
        0,
        0,
        Some(c"<dir>"),
        c"read signing_key.pem and cert.der from <dir>",
    ),
    OptSpec::new(
        c"--key",
        0,
        0,
        Some(c"<private.pem>"),
        c"the signing key, over --keys-dir",
    ),
    OptSpec::new(
        c"--cert",
        0,
        0,
        Some(c"<cert.der>"),
        c"the certificate, over --keys-dir",
    ),
];

static IMAGE_SECTIONS: [HelpSection; 1] =
    [HelpSection::options(c"verify options:", &IMAGE_VERIFY_OPTS)];

static IMAGE_HELP: Help = Help::new(
    c"shirudo image build <filesystem.img> -o <prefix> [--kind config|runtime]\n                     \
      [--keys-dir <dir>] [--key <private.pem>] [--cert <cert.der>]\n                     \
      [--salt <64-hex>]\n       \
      shirudo image verify <prefix> --cert <cert.der>",
    Some(
        c"build writes <prefix>.img, .verity, .roothash and .p7s from a 4096-byte\n\
          aligned ext4 file system image and refuses files that exist. Build and\n\
          offline verification require veritysetup.",
    ),
    &IMAGE_SECTIONS,
    None,
);

fn verify_cmd(args: &[&CStr]) -> c_int {
    let raw: Vec<*const c_char> = args.iter().map(|a| a.as_ptr()).collect();
    let mut p = OptParser::new(
        c"image verify",
        &IMAGE_VERIFY_OPTS,
        Some(&IMAGE_HELP),
        &raw,
        2,
    );
    let (mut prefix, mut cert) = (None, None);

    loop {
        let opt = p.next();
        let value = p.value();
        match opt {
            OPT_END => break,
            IMAGE_VERIFY_CERT => cert = value,
            OPT_ARG => {
                if prefix.is_some() {
                    p.usage_arg(b"unexpected argument ");
                    return EXIT_USAGE;
                }
                prefix = value;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let (Some(prefix), Some(cert)) = (prefix, cert) else {
        p.usage(b"takes <prefix> and --cert <cert.der>");
        return EXIT_USAGE;
    };
    let ret = verify(prefix, cert);
    if ret != 0 {
        error(&[b"image verify: ", strerr(-ret)].concat());
    }
    c_int::from(ret != 0)
}

/// What shirudo-gen-verity calls back with for the root hash it made.
fn sign_root_cmd(args: &[&CStr]) -> c_int {
    let raw: Vec<*const c_char> = args.iter().map(|a| a.as_ptr()).collect();
    let mut p = OptParser::new(c"image sign-root", &IMAGE_SIGN_OPTS, None, &raw, 2);
    let mut keys = KeyFiles::default();
    let (mut input, mut signature, mut keys_dir) = (None, None, None);

    loop {
        let opt = p.next();
        let value = p.value();
        match opt {
            OPT_END => break,
            IMAGE_SIGN_OUTPUT => signature = value,
            IMAGE_SIGN_KEYS_DIR => keys_dir = value,
            IMAGE_SIGN_KEY => keys.set_pkey(value.unwrap_or_default()),
            IMAGE_SIGN_CERT => keys.set_cert(value.unwrap_or_default()),
            OPT_ARG => {
                if input.is_some() {
                    p.usage_arg(b"unexpected argument ");
                    return EXIT_USAGE;
                }
                input = value;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let (Some(input), Some(signature)) = (input, signature) else {
        p.usage(b"takes <root-hash-file> and -o <signature>");
        return EXIT_USAGE;
    };
    if keys.resolve_both(keys_dir).is_err() {
        return EXIT_USAGE;
    }
    let ret = sign_root(input, signature, &keys);
    if ret != 0 {
        error(&[b"image sign-root: ", strerr(-ret)].concat());
    }
    c_int::from(ret != 0)
}

/// `shirudo-build image`, from `image` on.
pub(super) fn run(args: &[&CStr]) -> c_int {
    let word = args.get(1).map(|a| a.to_bytes());

    if word == Some(b"build") {
        return build(args);
    }
    if args.len() < 2 || is_help(word) {
        // SAFETY: help of C strings.
        unsafe { print_help(&IMAGE_HELP) };
        return if args.len() < 2 { EXIT_USAGE } else { 0 };
    }
    match word.unwrap_or_default() {
        b"verify" => verify_cmd(args),
        b"sign-root" => sign_root_cmd(args),
        other => {
            error(&[b"image: '", other, b"' is not a subcommand"].concat());
            EXIT_USAGE
        }
    }
}
