// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo genkey`: the operator's ML-DSA-87 signing key and the
//! self-signed X.509 certificate of its public half.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use super::word;
use crate::errno::{EINVAL, ENAMETOOLONG, ENOENT, EPERM};
use crate::ffi::{self, c_splice};
use crate::sys::libc::{
    O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_RDONLY, O_WRONLY, PATH_MAX, Statx,
    close, errno, fchmod, fprintf, fsync, geteuid, link, open, openat, rename, stderr, strerror,
    unlink,
};
use crate::sys::openssl::{
    ASN1_INTEGER_set, ASN1_TIME_set_string_X509, BIO_NOCLOSE, BIO_free, BIO_new_fd,
    EVP_PKEY_Q_keygen, EVP_PKEY_free, EvpPkey, MBSTRING_UTF8, NID_AUTHORITY_KEY_IDENTIFIER,
    NID_BASIC_CONSTRAINTS, NID_KEY_USAGE, NID_SUBJECT_KEY_IDENTIFIER, OPENSSL_VERSION,
    OPENSSL_version_major, OPENSSL_version_minor, OpenSSL_version, PEM_write_bio_PrivateKey, X509,
    X509_EXTENSION_free, X509_NAME_add_entry_by_txt, X509_NAME_free, X509_NAME_new, X509_add_ext,
    X509_free, X509_get_serialNumber, X509_getm_notAfter, X509_getm_notBefore, X509_gmtime_adj,
    X509_new, X509_set_issuer_name, X509_set_pubkey, X509_set_subject_name, X509_set_version,
    X509_sign, X509V3_EXT_conf_nid, X509V3_set_ctx, X509v3Ctx, i2d_X509_bio,
};
use crate::util::crypto_openssl::openssl_complain;
use crate::util::help::{Help, HelpItem, HelpSection, is_help, print_help};
use crate::util::identity;
use crate::util::io::stat_fd;
use crate::util::paths::{key_paths, keys_dir_resolve, path_exists};
use crate::util::seal::seal_mkdir_p;

const CERT_CN: &CStr = c"shirudo";
const CERT_NO_EXPIRY: &CStr = c"99991231235959Z";

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

fn gen_keypair() -> *mut EvpPkey {
    // SAFETY: no library context, no properties, and an algorithm.
    let k = unsafe { EVP_PKEY_Q_keygen(ptr::null_mut(), ptr::null(), GENKEY_ALG.as_ptr()) };

    if k.is_null() {
        // SAFETY: a C string; calls that take nothing; the C's format,
        // the algorithm and OpenSSL's version.
        unsafe {
            openssl_complain(c"EVP_PKEY_Q_keygen".as_ptr());
            if OPENSSL_version_major() < 3
                || (OPENSSL_version_major() == 3 && OPENSSL_version_minor() < 5)
            {
                crate::log::log_c!(
                    crate::log::err,
                    c"genkey: %s needs OpenSSL 3.5 or newer (running %s); upgrade libcrypto"
                        .as_ptr(),
                    GENKEY_ALG.as_ptr(),
                    OpenSSL_version(OPENSSL_VERSION),
                );
            }
        }
    }
    k
}

/// OpenSSL 4.0 returns the certificate's own names const, so build the
/// name apart and set it as both, which copies it.
///
/// # Safety
///
/// `c` is a certificate.
unsafe fn set_subject_and_issuer(c: *mut X509) -> c_int {
    // SAFETY: a call that takes nothing.
    let name = unsafe { X509_NAME_new() };
    let mut ret = -1;

    // SAFETY: C strings, the name X509_NAME_new() gave, freed once, and
    // the caller's certificate.
    unsafe {
        if name.is_null() {
            openssl_complain(c"X509_NAME_new".as_ptr());
            return -1;
        }
        if X509_NAME_add_entry_by_txt(
            name,
            c"CN".as_ptr(),
            MBSTRING_UTF8,
            CERT_CN.as_ptr().cast(),
            -1,
            -1,
            0,
        ) != 1
        {
            openssl_complain(c"X509_NAME_add_entry_by_txt".as_ptr());
        } else if X509_set_subject_name(c, name) != 1 {
            openssl_complain(c"X509_set_subject_name".as_ptr());
        } else if X509_set_issuer_name(c, name) != 1 {
            openssl_complain(c"X509_set_issuer_name".as_ptr());
        } else {
            ret = 0;
        }
        X509_NAME_free(name);
    }
    ret
}

/// # Safety
///
/// `c` is a certificate, and `value` a C string.
unsafe fn add_ext(c: *mut X509, nid: c_int, value: *const c_char) -> c_int {
    let mut ctx = X509v3Ctx::zeroed();

    // X509V3_set_ctx_nodb(), a macro.
    ctx.db = ptr::null_mut();
    // SAFETY: the context, the caller's certificate as issuer and
    // subject, no request or list, no flags.
    unsafe { X509V3_set_ctx(&mut ctx, c, c, ptr::null_mut(), ptr::null_mut(), 0) };
    // SAFETY: no configuration, the context, and the caller's NID and
    // value.
    let ex = unsafe { X509V3_EXT_conf_nid(ptr::null_mut(), &mut ctx, nid, value) };
    if ex.is_null() {
        // SAFETY: a C string.
        unsafe { openssl_complain(c"X509V3_EXT_conf_nid".as_ptr()) };
        return -1;
    }
    // SAFETY: the certificate, the extension it copies, freed once, and
    // an index for the end.
    let ret = unsafe {
        let ret = X509_add_ext(c, ex, -1);

        X509_EXTENSION_free(ex);
        ret
    };
    if ret != 1 {
        // SAFETY: a C string.
        unsafe { openssl_complain(c"X509_add_ext".as_ptr()) };
        return -1;
    }
    0
}

/// # Safety
///
/// `c` is a certificate.
unsafe fn build_serial(c: *mut X509) -> c_int {
    // SAFETY: the certificate's own serial number.
    if unsafe { ASN1_INTEGER_set(X509_get_serialNumber(c), 1) } != 1 {
        // SAFETY: a C string.
        unsafe { openssl_complain(c"ASN1_INTEGER_set".as_ptr()) };
        return -1;
    }
    0
}

/// Neither shirudo nor the kernel compares a certificate's validity with
/// the clock; a key is retired by revoking it. notAfter therefore holds
/// the value RFC 5280 4.1.2.5 gives a certificate with no well-defined
/// expiration, not a date that reads as the end of the key's trust.
///
/// # Safety
///
/// `c` is a certificate.
unsafe fn build_validity(c: *mut X509) -> c_int {
    // SAFETY: the certificate's own times, and C strings.
    unsafe {
        if X509_gmtime_adj(X509_getm_notBefore(c), 0).is_null() {
            openssl_complain(c"X509_gmtime_adj notBefore".as_ptr());
            return -1;
        }
        if ASN1_TIME_set_string_X509(X509_getm_notAfter(c), CERT_NO_EXPIRY.as_ptr()) != 1 {
            openssl_complain(c"ASN1_TIME_set_string_X509 notAfter".as_ptr());
            return -1;
        }
    }
    0
}

/// ML-DSA hashes the message internally; OpenSSL requires a NULL digest.
///
/// # Safety
///
/// `c` is a certificate, and `pkey` a key.
unsafe fn build_cert(c: *mut X509, pkey: *mut EvpPkey) -> c_int {
    // SAFETY: the caller's certificate and key, and C strings.
    unsafe {
        // X.509 v3.
        if X509_set_version(c, 2) != 1 {
            openssl_complain(c"X509_set_version".as_ptr());
            return -1;
        }
        if build_serial(c) != 0 || build_validity(c) != 0 {
            return -1;
        }
        if X509_set_pubkey(c, pkey) != 1 {
            openssl_complain(c"X509_set_pubkey".as_ptr());
            return -1;
        }
        if set_subject_and_issuer(c) != 0
            || add_ext(c, NID_BASIC_CONSTRAINTS, c"critical,CA:FALSE".as_ptr()) != 0
            || add_ext(c, NID_KEY_USAGE, c"digitalSignature".as_ptr()) != 0
            || add_ext(c, NID_SUBJECT_KEY_IDENTIFIER, c"hash".as_ptr()) != 0
            || add_ext(c, NID_AUTHORITY_KEY_IDENTIFIER, c"keyid:always".as_ptr()) != 0
        {
            return -1;
        }
        if X509_sign(c, pkey, ptr::null()) == 0 {
            openssl_complain(c"X509_sign".as_ptr());
            return -1;
        }
    }
    0
}

/// What writes the key or the certificate into the BIO of a new file.
enum Payload {
    Key(*mut EvpPkey),
    Cert(*mut X509),
}

/// `payload` into a new file at `path`, mode 0600, synced; the file goes
/// when anything fails. 0, or -1 logged.
///
/// # Safety
///
/// `path` is a C string, and the payload's key or certificate valid.
unsafe fn write_new(payload: Payload, path: *const c_char) -> c_int {
    let mut ret = -1;
    let mut b = ptr::null_mut();

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
    // SAFETY: the fd open() gave, closed once at the end; the BIO on it,
    // freed once; the caller's key or certificate; C strings.
    unsafe {
        'out: {
            if fchmod(fd, 0o600) != 0 {
                crate::log::log_c!(
                    crate::log::err,
                    c"fchmod %s: %s".as_ptr(),
                    path,
                    strerror(errno())
                );
                break 'out;
            }
            // Unbuffered, where a FILE would keep the key in memory freed
            // unscrubbed.
            b = BIO_new_fd(fd, BIO_NOCLOSE);
            if b.is_null() {
                openssl_complain(c"BIO_new_fd".as_ptr());
                break 'out;
            }
            match payload {
                Payload::Key(pkey) => {
                    if PEM_write_bio_PrivateKey(
                        b,
                        pkey,
                        ptr::null(),
                        ptr::null(),
                        0,
                        None,
                        ptr::null_mut(),
                    ) != 1
                    {
                        openssl_complain(c"PEM_write_bio_PrivateKey".as_ptr());
                        break 'out;
                    }
                    if fsync(fd) != 0 {
                        crate::log::log_c!(
                            crate::log::err,
                            c"flush %s: %s".as_ptr(),
                            path,
                            strerror(errno())
                        );
                        break 'out;
                    }
                }
                Payload::Cert(c) => {
                    if i2d_X509_bio(b, c) != 1 {
                        openssl_complain(c"i2d_X509_bio".as_ptr());
                        break 'out;
                    }
                    if fsync(fd) != 0 {
                        crate::log::log_c!(
                            crate::log::err,
                            c"fsync %s: %s".as_ptr(),
                            path,
                            strerror(errno())
                        );
                        break 'out;
                    }
                }
            }
            ret = 0;
        }
        BIO_free(b);
        close(fd);
        if ret != 0 {
            unlink(path);
        }
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

fn usage() {
    // SAFETY: the C library's stderr, the C's format and the usage.
    unsafe { fprintf(stderr, c"usage: %s\n".as_ptr(), USAGE.as_ptr()) };
}

fn print_genkey_help() {
    let options = [
        HelpItem {
            name: c"--force, -f".as_ptr(),
            summary: c"overwrite an existing key/cert (refused otherwise)".as_ptr(),
        },
        HelpItem {
            name: c"--keys-dir <dir>".as_ptr(),
            summary: c"write signing_key.pem and cert.der under <dir> instead of the default"
                .as_ptr(),
        },
    ];
    let sections = [HelpSection {
        header: c"options:".as_ptr(),
        items: options.as_ptr(),
        n_items: options.len(),
    }];
    let help = Help {
        usage: USAGE.as_ptr(),
        summary: SUMMARY.as_ptr(),
        sections: sections.as_ptr(),
        n_sections: sections.len(),
        footer: FOOTER.as_ptr(),
    };

    // SAFETY: the help, its strings constants and its arrays the locals
    // above.
    unsafe { print_help(&help) };
}

/// The new key and certificate written at `pkey_path` and `cert_path`:
/// beside them first and then moved over the old pair with `force`, or
/// else in place. 0, or -1 logged.
///
/// # Safety
///
/// The key and certificate are valid, and the paths C strings.
unsafe fn write_pair(
    pkey: *mut EvpPkey,
    cert: *mut X509,
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
    let mut i = 1;

    while i < args.len() {
        // SAFETY: the caller's word.
        let arg = unsafe { word(args[i]) };

        match arg {
            Some(b"--force" | b"-f") => force = true,
            Some(b"--keys-dir") if i + 1 < args.len() => {
                i += 1;
                keys_dir_arg = args[i];
            }
            Some(a) if a.starts_with(b"--keys-dir=") => {
                // SAFETY: the word, past the 11 bytes of its prefix.
                keys_dir_arg = unsafe { args[i].add(11) };
            }
            _ if is_help(arg) => {
                print_genkey_help();
                return 0;
            }
            _ => {
                // SAFETY: the C's format and the caller's word.
                unsafe {
                    crate::log::log_c!(
                        crate::log::err,
                        c"genkey: unknown option '%s'".as_ptr(),
                        args[i]
                    )
                };
                usage();
                return 2;
            }
        }
        i += 1;
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
    let pkey = gen_keypair();
    let mut cert = ptr::null_mut();
    // SAFETY: the key gen_keypair() gave and the certificate X509_new()
    // gave, each freed once at the end; the paths; C strings and the C's
    // formats.
    unsafe {
        'out: {
            if pkey.is_null() {
                break 'out;
            }
            cert = X509_new();
            if cert.is_null() {
                openssl_complain(c"X509_new".as_ptr());
                break 'out;
            }
            if build_cert(cert, pkey) != 0 || write_pair(pkey, cert, pp, cp, force) != 0 {
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
        X509_free(cert);
        EVP_PKEY_free(pkey);
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
