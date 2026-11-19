// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo genkey`: the operator's ML-DSA-87 signing key and the
//! self-signed X.509 certificate of its public half.

use core::ffi::{CStr, c_int};
use core::ptr;
use std::ffi::{CString, OsStr};
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use foreign_types::ForeignType;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::x509::{X509, X509Extension, X509NameBuilder, X509Ref};

use crate::errno::{EINVAL, ENAMETOOLONG, EPERM, describe, last_errno, text};
use crate::ffi::c_splice;
use crate::log;
use crate::sys::libc::{
    O_CLOEXEC, O_DIRECTORY, O_NOFOLLOW, O_RDONLY, PATH_MAX, Statx, geteuid, open, openat,
};
use crate::util::crypto_openssl::{complain_stack, openssl_complain};
use crate::util::help::{Help, HelpSection};
use crate::util::identity;
use crate::util::io::stat_fd;
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};
use crate::util::paths::{key_files, keys_dir, path_exists};
use crate::util::seal::mkdir_p;

const CERT_CN: &str = "shirudo";
const CERT_NO_EXPIRY: &str = "99991231235959Z";

/// ML-DSA-87 (FIPS 204, NIST category 5) is the only key type: the
/// kernel verifies it natively (CONFIG_CRYPTO_MLDSA) and the largest
/// parameter set gives a fleet-wide trust anchor that must outlive
/// hardware generations the most margin for about 2 KiB per signature.
/// Neither the smaller sets nor a classical algorithm are offered.
const GENKEY_ALG: &CStr = c"ML-DSA-87";

/// KEYS_DIR and the paths of `util/paths.h` the help names.
const KEYS_DIR_TEXT: &str = "/var/lib/shirudo/keys";
const KEYS_DIR: &CStr = c_splice!(KEYS_DIR_TEXT);
const KEYS_DIR_ENV: &str = "SHIRUDO_KEYS_DIR";
const NAME_MAX: usize = 255;

const USAGE: &CStr = c"shirudo genkey [--force] [--keys-dir <dir>]";
const SUMMARY: &CStr = c"Generate a self-signed X.509 certificate and an ML-DSA-87 (FIPS 204) \
    private key\nfor signing .upatch loader bytes. Operator-only; needs OpenSSL >= 3.5.";
const FOOTER: &CStr = c_splice!(
    "Default output paths:\n  ",
    KEYS_DIR_TEXT,
    "/signing_key.pem\n  ",
    KEYS_DIR_TEXT,
    "/cert.der\nIf unset on the command line, the ",
    KEYS_DIR_ENV,
    " environment variable\noverrides the default directory.",
);

/// A failure, logged from its parts.
fn err(parts: &[&[u8]]) {
    log::err(&parts.concat());
}

/// A path as std's file calls take one.
fn path(p: &CStr) -> &Path {
    Path::new(OsStr::from_bytes(p.to_bytes()))
}

/// The keys directory, made with mode 0700 where it is missing; Err
/// logged.
fn ensure_keys_dir(keys_dir: &CStr) -> Result<(), ()> {
    if keys_dir.to_bytes() == b"/" {
        err(&[b"keys dir cannot be /"]);
        return Err(());
    }
    mkdir_p(keys_dir.to_bytes(), 0o700).map_err(|ret| {
        err(&[b"mkdir ", keys_dir.to_bytes(), b": ", text(ret).as_bytes()]);
    })
}

/// The effective uid, asked each time the C's conditions asked it.
fn euid() -> u32 {
    // SAFETY: a call that takes nothing.
    unsafe { geteuid() }
}

/// The directory `name` under `dir`, a link not followed, or / for no
/// `dir`; and its status.
fn open_dir(dir: Option<&OwnedFd>, name: &[u8]) -> Result<(OwnedFd, Statx), c_int> {
    let name = CString::new(name).map_err(|_| -EINVAL)?;
    let fd = match dir {
        // SAFETY: a C string and flags.
        None => unsafe { open(name.as_ptr(), O_RDONLY | O_DIRECTORY | O_CLOEXEC) },
        // SAFETY: an open directory, a C string and flags.
        Some(dir) => unsafe {
            openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW,
            )
        },
    };
    if fd < 0 {
        return Err(last_errno());
    }
    // SAFETY: the fd just opened, owned from here.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let st = stat_fd(fd.as_fd())?;
    Ok((fd, st))
}

/// Whether the default keys directory may take a user's key: every
/// directory from / down root's or the user's, the last the user's, and
/// none writable by group or others.
fn check_user_keys_dir(keys_dir: &[u8]) -> Result<(), c_int> {
    let Some(rest) = keys_dir.strip_prefix(b"/") else {
        return Err(-EINVAL);
    };
    let (mut dir, st) = open_dir(None, b"/")?;
    if st.stx_uid != 0 || st.stx_mode & 0o022 != 0 {
        return Err(-EPERM);
    }
    let names: Vec<&[u8]> = rest
        .split(|&c| c == b'/')
        .filter(|n| !n.is_empty())
        .collect();
    for (i, name) in names.iter().enumerate() {
        if name.len() > NAME_MAX {
            return Err(-ENAMETOOLONG);
        }
        let (next, st) = open_dir(Some(&dir), name)?;
        let last = i + 1 == names.len();
        if (st.stx_uid != 0 && st.stx_uid != euid())
            || (last && st.stx_uid != euid())
            || st.stx_mode & 0o022 != 0
        {
            return Err(-EPERM);
        }
        dir = next;
    }
    Ok(())
}

/// A new ML-DSA-87 key; none, logged, when libcrypto cannot make one.
fn gen_keypair() -> Option<PKey<Private>> {
    // SAFETY: no library context, no properties, and an algorithm.
    let k = unsafe {
        openssl_sys::EVP_PKEY_Q_keygen(ptr::null_mut(), ptr::null(), GENKEY_ALG.as_ptr())
    };

    if !k.is_null() {
        // SAFETY: the key EVP_PKEY_Q_keygen() made, owned from here.
        return Some(unsafe { PKey::from_ptr(k) });
    }
    openssl_complain(c"EVP_PKEY_Q_keygen");
    let version = openssl::version::number();
    let (major, minor) = (version >> 28, (version >> 20) & 0xff);
    if major < 3 || (major == 3 && minor < 5) {
        err(&[
            b"genkey: ",
            GENKEY_ALG.to_bytes(),
            b" needs OpenSSL 3.5 or newer (running ",
            openssl::version::version().as_bytes(),
            b"); upgrade libcrypto",
        ]);
    }
    None
}

/// The certificate of `pkey`, self-signed: X.509 v3, serial 1, the name
/// CN=shirudo as subject and issuer, an end entity's extensions.
///
/// Neither shirudo nor the kernel compares a certificate's validity with
/// the clock; a key is retired by revoking it. notAfter therefore holds
/// the value RFC 5280 4.1.2.5 gives a certificate with no well-defined
/// expiration, not a date that reads as the end of the key's trust.
///
/// ML-DSA hashes the message internally; OpenSSL requires a NULL digest.
fn build_cert(pkey: &PKeyRef<Private>) -> Option<X509> {
    let failed = |what: &'static CStr| move |e: ErrorStack| complain_stack(what, &e);
    let mut cert = X509::builder().map_err(failed(c"X509_new")).ok()?;

    // X.509 v3.
    cert.set_version(2)
        .map_err(failed(c"X509_set_version"))
        .ok()?;
    let serial = BigNum::from_u32(1)
        .and_then(|n| Asn1Integer::from_bn(&n))
        .and_then(|n| cert.set_serial_number(&n))
        .map_err(failed(c"ASN1_INTEGER_set"));
    serial.ok()?;
    let not_before = Asn1Time::days_from_now(0)
        .and_then(|t| cert.set_not_before(&t))
        .map_err(failed(c"X509_gmtime_adj notBefore"));
    not_before.ok()?;
    let not_after = Asn1Time::from_str_x509(CERT_NO_EXPIRY)
        .and_then(|t| cert.set_not_after(&t))
        .map_err(failed(c"ASN1_TIME_set_string_X509 notAfter"));
    not_after.ok()?;
    cert.set_pubkey(pkey)
        .map_err(failed(c"X509_set_pubkey"))
        .ok()?;
    // OpenSSL 4.0 returns the certificate's own names const, so the name
    // is built apart and set as both, which copies it.
    let mut name = X509NameBuilder::new()
        .map_err(failed(c"X509_NAME_new"))
        .ok()?;
    name.append_entry_by_text("CN", CERT_CN)
        .map_err(failed(c"X509_NAME_add_entry_by_txt"))
        .ok()?;
    let name = name.build();
    cert.set_subject_name(&name)
        .map_err(failed(c"X509_set_subject_name"))
        .ok()?;
    cert.set_issuer_name(&name)
        .map_err(failed(c"X509_set_issuer_name"))
        .ok()?;
    for (nid, value) in [
        (Nid::BASIC_CONSTRAINTS, "critical,CA:FALSE"),
        (Nid::KEY_USAGE, "digitalSignature"),
        (Nid::SUBJECT_KEY_IDENTIFIER, "hash"),
        (Nid::AUTHORITY_KEY_IDENTIFIER, "keyid:always"),
    ] {
        // The certificate as issuer and subject, no configuration.
        let ext = {
            let ctx = cert.x509v3_context(None, None);
            #[allow(deprecated)]
            X509Extension::new_nid(None, Some(&ctx), nid, value)
        };
        let ext = ext.map_err(failed(c"X509V3_EXT_conf_nid")).ok()?;
        cert.append_extension(ext)
            .map_err(failed(c"X509_add_ext"))
            .ok()?;
    }
    // SAFETY: no digest, which X509_sign() takes as the key's own.
    let none = unsafe { MessageDigest::from_ptr(ptr::null()) };
    cert.sign(pkey, none).map_err(failed(c"X509_sign")).ok()?;
    Some(cert.build())
}

/// What goes into a new file: the key or the certificate.
enum Payload<'a> {
    Key(&'a PKeyRef<Private>),
    Cert(&'a X509Ref),
}

/// `payload` into a new file at `p`, mode 0600, synced; the file goes
/// when anything fails. Err logged.
fn write_new(payload: Payload, p: &CStr) -> Result<(), ()> {
    let fail = |what: &[u8], e: &io::Error| {
        err(&[what, b" ", p.to_bytes(), b": ", describe(e).as_bytes()]);
    };
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path(p))
        .map_err(|e| fail(b"open", &e))?;
    let written = fill(&file, payload, &fail);
    drop(file);
    if written.is_err() {
        let _ = fs::remove_file(path(p));
    }
    written
}

/// The new file `file` made 0600 whatever the umask, and `payload`
/// written into it and synced; Err logged by `fail`.
fn fill(file: &File, payload: Payload, fail: &dyn Fn(&[u8], &io::Error)) -> Result<(), ()> {
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(|e| fail(b"fchmod", &e))?;
    // Written unbuffered, and the allocator scrubs the key's text when
    // it goes, so no copy stays behind.
    let (text, what, sync): (_, _, &[u8]) = match payload {
        Payload::Key(k) => (
            k.private_key_to_pem_pkcs8(),
            c"PEM_write_bio_PrivateKey",
            b"flush",
        ),
        Payload::Cert(c) => (c.to_der(), c"i2d_X509_bio", b"fsync"),
    };
    let text = text.map_err(|e| complain_stack(what, &e))?;
    let mut out = file;
    out.write_all(&text).map_err(|e| fail(b"write", &e))?;
    file.sync_all().map_err(|e| fail(sync, &e))
}

/// The two renames cannot be one, so the old key stays linked aside
/// until the new certificate is in place: a rename that fails between
/// them puts the old key back rather than leave the new key beside a
/// certificate it does not match. Err logged.
fn replace_pair(
    pkey_new: &CStr,
    pkey_path: &CStr,
    cert_new: &CStr,
    cert_path: &CStr,
    pkey_old: &CStr,
) -> Result<(), ()> {
    let not_moved = |from: &CStr, to: &CStr, e: &io::Error| {
        err(&[
            b"genkey: cannot move ",
            from.to_bytes(),
            b" to ",
            to.to_bytes(),
            b": ",
            describe(e).as_bytes(),
        ]);
    };
    let had_old = match fs::hard_link(path(pkey_path), path(pkey_old)) {
        Ok(()) => true,
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => {
            err(&[
                b"genkey: cannot keep the old key aside as ",
                pkey_old.to_bytes(),
                b": ",
                describe(&e).as_bytes(),
            ]);
            return Err(());
        }
    };
    if let Err(e) = fs::rename(path(pkey_new), path(pkey_path)) {
        not_moved(pkey_new, pkey_path, &e);
        if had_old {
            let _ = fs::remove_file(path(pkey_old));
        }
        return Err(());
    }
    if let Err(e) = fs::rename(path(cert_new), path(cert_path)) {
        not_moved(cert_new, cert_path, &e);
        let undo = if had_old {
            fs::rename(path(pkey_old), path(pkey_path))
        } else {
            fs::remove_file(path(pkey_path))
        };
        if let Err(e) = undo {
            err(&[
                b"genkey: ",
                pkey_path.to_bytes(),
                b" and ",
                cert_path.to_bytes(),
                b" are no longer a pair (",
                describe(&e).as_bytes(),
                b"); remove both and run genkey again",
            ]);
        }
        return Err(());
    }
    if had_old {
        let _ = fs::remove_file(path(pkey_old));
    }
    Ok(())
}

const GENKEY_FORCE: c_int = 0;
const GENKEY_KEYS_DIR: c_int = 1;

static OPTS: [OptSpec; 2] = [
    OptSpec::new(
        c"--force",
        b'f',
        0,
        None,
        c"overwrite an existing key/cert (refused otherwise)",
    ),
    OptSpec::new(
        c"--keys-dir",
        0,
        0,
        Some(c"<dir>"),
        c"write signing_key.pem and cert.der under <dir> instead of the default",
    ),
];

static SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &OPTS)];

static HELP: Help = Help::new(USAGE, Some(SUMMARY), &SECTIONS, Some(FOOTER));

/// The new key and certificate written at `pkey_path` and `cert_path`:
/// beside them first and then moved over the old pair with `force`, or
/// else in place. Err logged.
fn write_pair(
    pkey: &PKeyRef<Private>,
    cert: &X509Ref,
    pkey_path: &CStr,
    cert_path: &CStr,
    force: bool,
) -> Result<(), ()> {
    if !force {
        write_new(Payload::Key(pkey), pkey_path)?;
        if write_new(Payload::Cert(cert), cert_path).is_err() {
            let _ = fs::remove_file(path(pkey_path));
            return Err(());
        }
        return Ok(());
    }
    // The old pair goes only once the new one is on disk.
    let beside = |p: &CStr, suffix: &[u8]| {
        let name = [p.to_bytes(), suffix].concat();
        CString::new(name)
            .ok()
            .filter(|n| n.as_bytes().len() < PATH_MAX)
    };
    let (Some(pkey_new), Some(cert_new), Some(pkey_old)) = (
        beside(pkey_path, b".new"),
        beside(cert_path, b".new"),
        beside(pkey_path, b".old"),
    ) else {
        err(&[
            b"genkey: no room for a temporary beside ",
            pkey_path.to_bytes(),
        ]);
        return Err(());
    };
    for p in [&pkey_new, &cert_new, &pkey_old] {
        let _ = fs::remove_file(path(p));
    }
    write_new(Payload::Key(pkey), &pkey_new)?;
    if write_new(Payload::Cert(cert), &cert_new).is_err() {
        let _ = fs::remove_file(path(&pkey_new));
        return Err(());
    }
    if replace_pair(&pkey_new, pkey_path, &cert_new, cert_path, &pkey_old).is_err() {
        let _ = fs::remove_file(path(&pkey_new));
        let _ = fs::remove_file(path(&cert_new));
        return Err(());
    }
    Ok(())
}

/// The command on `args`, its name first.
pub(super) fn cmd_genkey(args: &[&CStr]) -> c_int {
    let mut keys_dir_arg = None;
    let mut force = false;
    let mut p = OptParser::new(c"genkey", &OPTS, Some(&HELP), args, 1);

    loop {
        match p.next() {
            OPT_END => break,
            GENKEY_FORCE => force = true,
            GENKEY_KEYS_DIR => keys_dir_arg = p.value(),
            OPT_DONE => return 0,
            OPT_ARG => {
                p.usage_arg(b"takes no argument, got ");
                return EXIT_USAGE;
            }
            _ => return EXIT_USAGE,
        }
    }

    // A target never holds a private key, and its task has the authority
    // the seal denies root, which would write the pair wherever root
    // asks.
    if identity::enforcement_active() != 0 {
        err(&[b"genkey: refusing on a target: the signing key belongs on the operator host"]);
        return 1;
    }

    let keys_dir = keys_dir(keys_dir_arg);
    let dir = keys_dir.to_bytes();
    let (pkey_path, cert_path) = match key_files(dir) {
        Ok(paths) => paths,
        Err(ret) => {
            err(&[
                b"genkey: invalid keys dir ",
                dir,
                b": ",
                text(ret).as_bytes(),
            ]);
            return 1;
        }
    };
    if ensure_keys_dir(keys_dir).is_err() {
        return 1;
    }
    if euid() != 0
        && dir == KEYS_DIR.to_bytes()
        && let Err(ret) = check_user_keys_dir(dir)
    {
        err(&[
            b"genkey: default keys dir ",
            KEYS_DIR.to_bytes(),
            b" is not safe for user key generation: ",
            text(ret).as_bytes(),
        ]);
        err(&[b"it must be owned by the current user and not writable by group or others"]);
        err(&[b"rerun with sudo or pass --keys-dir <dir>"]);
        return 1;
    }

    if !force && (path_exists(&pkey_path) || path_exists(&cert_path)) {
        err(&[
            b"genkey: ",
            pkey_path.to_bytes(),
            b" or ",
            cert_path.to_bytes(),
            b" already exists; pass --force",
        ]);
        return 1;
    }

    let Some(pkey) = gen_keypair() else {
        return 1;
    };
    let Some(cert) = build_cert(&pkey) else {
        return 1;
    };
    if write_pair(&pkey, &cert, &pkey_path, &cert_path, force).is_err() {
        return 1;
    }
    let alg = GENKEY_ALG.to_bytes();
    log::info(&[b"wrote ", pkey_path.to_bytes(), b" (", alg, b", mode 0600)"].concat());
    log::info(
        &[
            b"wrote ",
            cert_path.to_bytes(),
            b" (X.509 self-signed, no expiration date)",
        ]
        .concat(),
    );
    log::audit(
        &[
            b"genkey: created shirudo ",
            alg,
            b" signing material at ",
            dir,
        ]
        .concat(),
    );
    0
}
