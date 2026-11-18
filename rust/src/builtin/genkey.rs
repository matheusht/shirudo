// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo genkey`: the operator's ML-DSA-87 signing key and the
//! self-signed X.509 certificate of its public half.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::fd::{FromRawFd, OwnedFd};

use foreign_types::ForeignType;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::x509::{X509, X509Extension, X509NameBuilder, X509Ref};

use crate::errno::{EINVAL, EIO, ENAMETOOLONG, ENOENT, EPERM};
use crate::ffi::{self, c_splice};
use crate::sys::libc::{
    O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_RDONLY, O_WRONLY, PATH_MAX, Statx,
    close, errno, fchmod, geteuid, link, open, openat, rename, strerror, unlink,
};
use crate::util::crypto_openssl::{complain_stack, openssl_complain};
use crate::util::help::{Help, HelpSection};
use crate::util::identity;
use crate::util::io::stat_fd;
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};
use crate::util::paths::{key_paths, keys_dir_resolve, path_exists};
use crate::util::seal::seal_mkdir_p;

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

fn ensure_keys_dir(keys_dir: *const c_char) -> c_int {
    // SAFETY: the caller's C string.
    if unsafe { ffi::c_str(keys_dir) } == b"/" {
        // SAFETY: a message without arguments.
        unsafe { crate::log::log_c!(crate::log::err, c"keys dir cannot be /".as_ptr()) };
        return -EINVAL;
    }
    // SAFETY: the caller's C string, and a mode.
    let ret = unsafe { seal_mkdir_p(keys_dir, 0o700) };
    if ret != 0 {
        // SAFETY: the C's format, the path and the error's text.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"mkdir %s: %s".as_ptr(),
                keys_dir,
                strerror(-ret)
            )
        };
    }
    ret
}

/// The effective uid, asked each time the C's conditions asked it.
fn euid() -> u32 {
    // SAFETY: a call that takes nothing.
    unsafe { geteuid() }
}

/// Whether the default keys directory may take a user's key: every
/// directory from / down root's or the user's, the last the user's, and
/// none writable by group or others.
fn check_user_keys_dir(keys_dir: &[u8]) -> c_int {
    let mut component = [0u8; NAME_MAX + 1];
    let mut st = Statx::zeroed();
    let mut ret = 0;

    if keys_dir.first() != Some(&b'/') {
        return -EINVAL;
    }
    // SAFETY: a path, and flags.
    let mut dirfd = unsafe { open(c"/".as_ptr(), O_RDONLY | O_DIRECTORY | O_CLOEXEC) };
    if dirfd < 0 {
        return -errno();
    }
    let r = stat_fd(dirfd, &mut st);
    if r != 0 {
        // SAFETY: the fd open() gave, closed once.
        unsafe { close(dirfd) };
        return r;
    }
    if st.uid != 0 || st.mode & 0o022 != 0 {
        // SAFETY: as above.
        unsafe { close(dirfd) };
        return -EPERM;
    }
    let mut p = 1;
    while p < keys_dir.len() {
        let rest = &keys_dir[p..];
        let end = rest.iter().position(|&c| c == b'/');
        let len = end.unwrap_or(rest.len());

        if len == 0 {
            p += 1;
            continue;
        }
        if len > NAME_MAX {
            ret = -ENAMETOOLONG;
            break;
        }
        component[..len].copy_from_slice(&rest[..len]);
        component[len] = 0;
        // SAFETY: the fd of the directory, a C string, and flags.
        let nextfd = unsafe {
            openat(
                dirfd,
                component.as_ptr().cast(),
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW,
            )
        };
        if nextfd < 0 {
            ret = -errno();
            break;
        }
        let r = stat_fd(nextfd, &mut st);
        if r != 0 {
            ret = r;
            // SAFETY: the fd openat() gave, closed once.
            unsafe { close(nextfd) };
            break;
        }
        let last = end.is_none_or(|e| rest.get(e + 1).is_none());
        if (st.uid != 0 && st.uid != euid()) || (last && st.uid != euid()) || st.mode & 0o022 != 0 {
            ret = -EPERM;
            // SAFETY: as above.
            unsafe { close(nextfd) };
            break;
        }
        // SAFETY: the directory's fd, closed once, replaced by the next.
        unsafe { close(dirfd) };
        dirfd = nextfd;
        if last {
            break;
        }
        p += len + 1;
    }
    // SAFETY: the fd of the last directory, closed once.
    unsafe { close(dirfd) };
    ret
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
    // SAFETY: a C string.
    unsafe { openssl_complain(c"EVP_PKEY_Q_keygen".as_ptr()) };
    let version = openssl::version::number();
    let (major, minor) = (version >> 28, (version >> 20) & 0xff);
    if major < 3 || (major == 3 && minor < 5) {
        let running = CString::new(openssl::version::version()).unwrap_or_default();
        // SAFETY: the C's format, the algorithm and OpenSSL's version.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"genkey: %s needs OpenSSL 3.5 or newer (running %s); upgrade libcrypto".as_ptr(),
                GENKEY_ALG.as_ptr(),
                running.as_ptr(),
            );
        }
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

/// `payload` into a new file at `path`, mode 0600, synced; the file goes
/// when anything fails. 0, or -1 logged.
///
/// # Safety
///
/// `path` is a C string.
unsafe fn write_new(payload: Payload, path: *const c_char) -> c_int {
    // SAFETY: the caller's C string, flags and a mode.
    let fd = unsafe {
        open(
            path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
            0o600 as c_int,
        )
    };
    if fd < 0 {
        // SAFETY: the C's format, the path and the error's text.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"open %s: %s".as_ptr(),
                path,
                strerror(errno())
            )
        };
        return -1;
    }
    // SAFETY: the fd open() gave, owned from here and closed with it.
    let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let fail = |format: &CStr, err: c_int| {
        // SAFETY: the C's format, the path and the error's text.
        unsafe { crate::log::log_c!(crate::log::err, format.as_ptr(), path, strerror(err)) };
        -1
    };
    let ret = 'out: {
        // SAFETY: the fd and a mode.
        if unsafe { fchmod(fd, 0o600) } != 0 {
            break 'out fail(c"fchmod %s: %s", errno());
        }
        // Written unbuffered, and the allocator scrubs the key's text when
        // it goes, so no copy stays behind.
        let (text, what, sync) = match payload {
            Payload::Key(k) => (
                k.private_key_to_pem_pkcs8(),
                c"PEM_write_bio_PrivateKey",
                c"flush %s: %s",
            ),
            Payload::Cert(c) => (c.to_der(), c"i2d_X509_bio", c"fsync %s: %s"),
        };
        let text = match text {
            Ok(text) => text,
            Err(e) => {
                complain_stack(what, &e);
                break 'out -1;
            }
        };
        if let Err(e) = (&file).write_all(&text) {
            break 'out fail(c"write %s: %s", e.raw_os_error().unwrap_or(EIO));
        }
        if let Err(e) = file.sync_all() {
            break 'out fail(sync, e.raw_os_error().unwrap_or(EIO));
        }
        0
    };
    drop(file);
    if ret != 0 {
        // SAFETY: the caller's C string.
        unsafe { unlink(path) };
    }
    ret
}

/// The two renames cannot be one, so the old key stays linked aside
/// until the new certificate is in place: a rename that fails between
/// them puts the old key back rather than leave the new key beside a
/// certificate it does not match.
///
/// # Safety
///
/// Each path is a C string.
unsafe fn replace_pair(
    pkey_new: *const c_char,
    pkey_path: *const c_char,
    cert_new: *const c_char,
    cert_path: *const c_char,
    pkey_old: *const c_char,
) -> c_int {
    let mut had_old = true;

    // SAFETY: the caller's C strings, and the C's formats with them and
    // the errors' texts.
    unsafe {
        if link(pkey_path, pkey_old) != 0 {
            if errno() != ENOENT {
                let err = errno();

                crate::log::log_c!(
                    crate::log::err,
                    c"genkey: cannot keep the old key aside as %s: %s".as_ptr(),
                    pkey_old,
                    strerror(err),
                );
                return -err;
            }
            had_old = false;
        }
        if rename(pkey_new, pkey_path) != 0 {
            let err = errno();

            crate::log::log_c!(
                crate::log::err,
                c"genkey: cannot move %s to %s: %s".as_ptr(),
                pkey_new,
                pkey_path,
                strerror(err),
            );
            if had_old {
                unlink(pkey_old);
            }
            return -err;
        }
        if rename(cert_new, cert_path) != 0 {
            let err = errno();

            crate::log::log_c!(
                crate::log::err,
                c"genkey: cannot move %s to %s: %s".as_ptr(),
                cert_new,
                cert_path,
                strerror(err),
            );
            let undo = if had_old {
                rename(pkey_old, pkey_path)
            } else {
                unlink(pkey_path)
            };
            if undo != 0 {
                crate::log::log_c!(crate::log::err,
                    c"genkey: %s and %s are no longer a pair (%s); remove both and run genkey again"
                        .as_ptr(),
                    pkey_path,
                    cert_path,
                    strerror(errno()),
                );
            }
            return -err;
        }
        if had_old {
            unlink(pkey_old);
        }
    }
    0
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
/// else in place. 0, or -1 logged.
///
/// # Safety
///
/// The key and certificate are valid, and the paths C strings.
unsafe fn write_pair(
    pkey: &PKeyRef<Private>,
    cert: &X509Ref,
    pkey_path: *const c_char,
    cert_path: *const c_char,
    force: bool,
) -> c_int {
    // SAFETY: the caller's key, certificate and paths; rooms of PATH_MAX
    // bytes for strsprintf() and the C's formats.
    unsafe {
        if !force {
            if write_new(Payload::Key(pkey), pkey_path) != 0 {
                return -1;
            }
            if write_new(Payload::Cert(cert), cert_path) != 0 {
                unlink(pkey_path);
                return -1;
            }
            return 0;
        }
        let mut pkey_new = [0u8; PATH_MAX];
        let mut cert_new = [0u8; PATH_MAX];
        let mut pkey_old = [0u8; PATH_MAX];
        let (pn, cn, po) = (
            pkey_new.as_mut_ptr().cast::<c_char>(),
            cert_new.as_mut_ptr().cast::<c_char>(),
            pkey_old.as_mut_ptr().cast::<c_char>(),
        );

        // The old pair goes only once the new one is on disk.
        if crate::text::csprintf!(pn, PATH_MAX, c"%s.new".as_ptr(), pkey_path) < 0
            || crate::text::csprintf!(cn, PATH_MAX, c"%s.new".as_ptr(), cert_path) < 0
            || crate::text::csprintf!(po, PATH_MAX, c"%s.old".as_ptr(), pkey_path) < 0
        {
            crate::log::log_c!(
                crate::log::err,
                c"genkey: no room for a temporary beside %s".as_ptr(),
                pkey_path,
            );
            return -1;
        }
        unlink(pn);
        unlink(cn);
        unlink(po);
        if write_new(Payload::Key(pkey), pn) != 0 {
            return -1;
        }
        if write_new(Payload::Cert(cert), cn) != 0 {
            unlink(pn);
            return -1;
        }
        if replace_pair(pn, pkey_path, cn, cert_path, po) != 0 {
            unlink(pn);
            unlink(cn);
            return -1;
        }
    }
    0
}

/// The command on `args`, its name first.
///
/// # Safety
///
/// Each of `args` is a C string.
unsafe fn genkey(args: &[*const c_char]) -> c_int {
    let mut keys_dir_arg: *const c_char = ptr::null();
    let mut pkey_path = [0u8; PATH_MAX];
    let mut cert_path = [0u8; PATH_MAX];
    let mut force = false;
    let mut p = OptParser::new(c"genkey", &OPTS, Some(&HELP), args, 1);

    loop {
        match p.next() {
            OPT_END => break,
            GENKEY_FORCE => force = true,
            GENKEY_KEYS_DIR => keys_dir_arg = p.value_ptr(),
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
        // SAFETY: a message without arguments.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"genkey: refusing on a target: the signing key belongs on the operator host"
                    .as_ptr(),
            )
        };
        return 1;
    }

    // SAFETY: NULL or the caller's word.
    let keys_dir = unsafe { keys_dir_resolve(keys_dir_arg) };
    let (pp, cp) = (
        pkey_path.as_mut_ptr().cast::<c_char>(),
        cert_path.as_mut_ptr().cast::<c_char>(),
    );
    // SAFETY: the directory, a C string, and rooms of PATH_MAX bytes.
    let ret = unsafe { key_paths(keys_dir, pp, PATH_MAX, cp, PATH_MAX) };
    if ret != 0 {
        // SAFETY: the C's format, the directory and the error's text.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"genkey: invalid keys dir %s: %s".as_ptr(),
                keys_dir,
                strerror(-ret),
            )
        };
        return 1;
    }
    if ensure_keys_dir(keys_dir) != 0 {
        return 1;
    }
    // SAFETY: the directory's C string.
    let dir = unsafe { ffi::c_str(keys_dir) };
    if euid() != 0 && dir == KEYS_DIR.to_bytes() {
        let ret = check_user_keys_dir(dir);

        if ret != 0 {
            // SAFETY: the C's formats, the directory and the error's
            // text.
            unsafe {
                crate::log::log_c!(
                    crate::log::err,
                    c"genkey: default keys dir %s is not safe for user key generation: %s".as_ptr(),
                    KEYS_DIR.as_ptr(),
                    strerror(-ret),
                );
                crate::log::log_c!(
                    crate::log::err,
                    c"it must be owned by the current user and not writable by group or others"
                        .as_ptr(),
                );
                crate::log::log_c!(
                    crate::log::err,
                    c"rerun with sudo or pass --keys-dir <dir>".as_ptr()
                );
            }
            return 1;
        }
    }

    // SAFETY: the paths key_paths() filled.
    if !force && unsafe { path_exists(pp) || path_exists(cp) } {
        // SAFETY: the C's format and the paths.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"genkey: %s or %s already exists; pass --force".as_ptr(),
                pp,
                cp,
            )
        };
        return 1;
    }

    let mut ret = 1;
    // SAFETY: the paths, C strings and the C's formats.
    unsafe {
        'out: {
            let Some(pkey) = gen_keypair() else {
                break 'out;
            };
            let Some(cert) = build_cert(&pkey) else {
                break 'out;
            };
            if write_pair(&pkey, &cert, pp, cp, force) != 0 {
                break 'out;
            }
            crate::log::log_c!(
                crate::log::info,
                c"wrote %s (%s, mode 0600)".as_ptr(),
                pp,
                GENKEY_ALG.as_ptr(),
            );
            crate::log::log_c!(
                crate::log::info,
                c"wrote %s (X.509 self-signed, no expiration date)".as_ptr(),
                cp,
            );
            crate::log::log_c!(
                crate::log::audit,
                c"genkey: created shirudo %s signing material at %s".as_ptr(),
                GENKEY_ALG.as_ptr(),
                keys_dir,
            );
            ret = 0;
        }
    }
    ret
}

pub(super) use capi::cmd_genkey;

mod capi {
    use core::ffi::{c_char, c_int};

    use super::super::words;

    /// # Safety
    ///
    /// `argv` holds `argc` C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cmd_genkey(argc: c_int, argv: *const *const c_char) -> c_int {
        // SAFETY: the caller passes the command line.
        unsafe { super::genkey(words(argc, argv)) }
    }
}
