// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo keys`: the key material a host holds, the operator's
//! certificate and signing key on disk, the trusted set a target enrols
//! and the kernel keyrings init filled, and adding a vouched certificate
//! to the set. Revoking goes through a signed config image, vouching
//! through shirudo-build.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use foreign_types::ForeignTypeRef;
use openssl::asn1::Asn1TimeRef;
use openssl::hash::MessageDigest;
use openssl::pkey::{HasPublic, PKey, PKeyRef, Private};
use openssl::x509::{X509, X509NameRef};

use super::{word, words};
use crate::errno::{EACCES, EINVAL, EIO, EKEYREJECTED, ENODEV, ENOENT, ENOKEY, ESTALE};
use crate::ffi;
use crate::heap::{libc_free, xfree};
use crate::sys::identity::Identity;
use crate::sys::libc::{
    Dirent, O_CLOEXEC, O_RDONLY, PATH_MAX, alphasort, errno, fwrite, open, scandir, stdout,
    strerror,
};
use crate::sys::openssl::{EVP_PKEY_get_base_id, X509_NAME_oneline};
use crate::text::cstr;
use crate::util::chain::{chain_extend, chain_key_event};
use crate::util::crypto_openssl::{
    Cert, cert_free, cert_key_algorithm, cert_read_der, cms_signed_by, complain_stack,
    key_type_name, openssl_complain, sha256, utc, x509_from_der_bio,
};
use crate::util::eventlog::{
    eventlog_append, eventlog_lock, eventlog_record_open, eventlog_unlock,
};
use crate::util::format::fputs_sanitized;
use crate::util::help::{
    Help, HelpItem, HelpSection, is_help, is_list_cmds, print_help, print_subcmd_list,
    resolve_subcommand,
};
use crate::util::identity;
use crate::util::image_config;
use crate::util::io::check_trusted;
use crate::util::json::JsonEmit;
use crate::util::keyring::{
    KeyringLink, keyring_bpf_serial, keyring_dm_verity_serial, keyring_find_cert,
    keyring_holds_cert, keyring_links, keyring_unlink_key,
};
use crate::util::keys::{
    KEYS_MAX, TrustedSet, keys_cert_der, keys_digest_der, keys_install, keys_is_revoked, keys_load,
    keys_read_der, keys_verify_vouch, members,
};
use crate::util::paths::{key_paths, keys_dir_resolve, path_exists};
use crate::util::upatch::{
    self, Upatch, upatch_close, upatch_open, upatch_select, upatch_signature,
};

const KEYS_DIR: &CStr = c"/var/lib/shirudo/keys";
const RUNTIME_KEYS_DIR: &CStr = c"/run/shirudo/runtime/keys";
const UPATCHES_DIR: &str = "/var/lib/shirudo/upatches";
/// `SIG_KEYRING_BPF`: the keyring type init records for the .bpf ring.
const SIG_KEYRING_BPF: u32 = 5;
const IDENTITY_KEYS_MAX: u32 = 16;
const EVP_PKEY_RSA: c_int = 6;
const EVP_PKEY_EC: c_int = 408;

fn print(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stdout.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stdout) };
}

fn message(parts: &[&[u8]]) -> CString {
    let mut text = parts.concat();

    if let Some(nul) = text.iter().position(|&c| c == 0) {
        text.truncate(nul);
    }
    CString::new(text).unwrap_or_default()
}

fn error(parts: &[&[u8]]) {
    let msg = message(parts);
    // SAFETY: a "%s" format with a C string.
    unsafe { crate::log::log_c!(crate::log::err, c"%s".as_ptr(), msg.as_ptr()) };
}

fn warn(parts: &[&[u8]]) {
    let msg = message(parts);
    // SAFETY: a "%s" format with a C string.
    unsafe { crate::log::log_c!(crate::log::warn, c"%s".as_ptr(), msg.as_ptr()) };
}

fn info(parts: &[&[u8]]) {
    let msg = message(parts);
    // SAFETY: a "%s" format with a C string.
    unsafe { crate::log::log_c!(crate::log::info, c"%s".as_ptr(), msg.as_ptr()) };
}

fn audit(parts: &[&[u8]]) {
    let msg = message(parts);
    // SAFETY: a "%s" format with a C string.
    unsafe { crate::log::log_c!(crate::log::audit, c"%s".as_ptr(), msg.as_ptr()) };
}

fn strerr(err: c_int) -> &'static [u8] {
    // SAFETY: strerror() gives a C string that outlives the message.
    unsafe { ffi::c_str(strerror(err)) }
}

fn hex(bytes: &[u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0; 64];

    for (i, b) in bytes.iter().enumerate() {
        out[2 * i] = HEX[usize::from(b >> 4)];
        out[2 * i + 1] = HEX[usize::from(b & 0xf)];
    }
    out
}

/// `s` left-justified in `width` bytes, as printf's "%-*s".
fn padded(s: &[u8], width: usize) -> Vec<u8> {
    let mut out = s.to_vec();

    out.resize(width.max(s.len()), b' ');
    out
}

/// A label line of the text output: two spaces and the label in 22.
fn line(label: &[u8], value: &[u8]) {
    print(&[b"  ", &padded(label, 22)[..], b" ", value, b"\n"].concat());
}

fn complain(what: &CStr) {
    // SAFETY: a C string.
    unsafe { openssl_complain(what.as_ptr()) };
}

/// The bytes of the file at `path`, checked first when `trusted`; none,
/// logged, when it cannot be opened or read. They are read unbuffered,
/// and the allocator scrubs them when they go, so that a key read this
/// way leaves no copy behind.
fn read_file(path: &CStr, trusted: bool) -> Option<Vec<u8>> {
    // SAFETY: a C string.
    let fd = unsafe { open(path.as_ptr(), O_RDONLY | O_CLOEXEC) };

    if fd < 0 {
        error(&[b"open ", path.to_bytes(), b": ", strerr(errno())]);
        return None;
    }
    // SAFETY: the fd open() gave, owned from here.
    let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    // SAFETY: the fd and a C string.
    if trusted && unsafe { check_trusted(file.as_raw_fd(), path.as_ptr(), false) } != 0 {
        return None;
    }
    let mut text = Vec::new();
    if let Err(e) = (&file).read_to_end(&mut text) {
        error(&[
            b"read ",
            path.to_bytes(),
            b": ",
            strerr(e.raw_os_error().unwrap_or(EIO)),
        ]);
        return None;
    }
    Some(text)
}

fn read_cert_der(path: &CStr) -> Option<X509> {
    let der = read_file(path, true)?;

    x509_from_der_bio(&der)
        .map_err(|e| complain_stack(c"d2i_X509_bio", &e))
        .ok()
}

/// The private key PEM at `path`.
fn read_priv_pem(path: &CStr) -> Option<PKey<Private>> {
    let pem = read_file(path, false)?;

    PKey::private_key_from_pem(&pem)
        .map_err(|e| complain_stack(c"PEM_read_bio_PrivateKey", &e))
        .ok()
}

fn name_text(name: &X509NameRef) -> Vec<u8> {
    let mut buf = [0u8; 256];

    // SAFETY: a name and the room for its line.
    let line =
        unsafe { X509_NAME_oneline(name.as_ptr(), buf.as_mut_ptr().cast(), buf.len() as c_int) };
    if line.is_null() {
        return b"(parse error)".to_vec();
    }
    cstr(&buf).to_vec()
}

/// The time as strftime()'s "%Y-%m-%dT%H:%M:%SZ" writes it.
fn time_text(t: &Asn1TimeRef) -> Vec<u8> {
    match utc(t) {
        None => b"(unparseable)".to_vec(),
        Some(t) => format!(
            "{}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            t.year, t.month, t.day, t.hour, t.minute, t.second
        )
        .into_bytes(),
    }
}

fn cert_fpr(c: &X509) -> Option<[u8; 32]> {
    let fpr = c
        .digest(MessageDigest::sha256())
        .map_err(|e| complain_stack(c"X509_digest", &e))
        .ok()?;

    (*fpr).try_into().ok()
}

/// SHA-256 over the SPKI, comparable across a certificate and its key.
fn spki_fpr<T: HasPublic>(pkey: &PKeyRef<T>) -> Option<[u8; 32]> {
    let der = pkey
        .public_key_to_der()
        .map_err(|e| complain_stack(c"i2d_PUBKEY", &e))
        .ok()?;

    sha256(&der).map_err(|_| complain(c"EVP_Digest")).ok()
}

/// "RSA-2048" or "EC-256" for the classical families, else the
/// provider's own name, "ML-DSA-87", whose parameter set says what a bit
/// count would.
fn pkey_algorithm<T: HasPublic>(pkey: &PKeyRef<T>) -> Vec<u8> {
    let name = key_type_name(pkey);
    let name = name.as_deref().map_or(&b"unknown"[..], CStr::to_bytes);
    // SAFETY: the key.
    let id = unsafe { EVP_PKEY_get_base_id(pkey.as_ptr()) };

    if id == EVP_PKEY_RSA || id == EVP_PKEY_EC {
        return [name, b"-", pkey.bits().to_string().as_bytes()].concat();
    }
    name[..name.len().min(63)].to_vec()
}

fn print_fpr(label: &[u8], fpr: &[u8; 32]) {
    print(&[b"  ", &padded(label, 22)[..], b" SHA256:", &hex(fpr), b"\n"].concat());
}

/// Where the material goes: text to stdout, or the JSON being built.
type Out<'a> = Option<&'a mut JsonEmit>;

fn dump_cert(out: &mut Out, cert: &X509, path: &CStr, spki: &[u8; 32]) {
    let (subj, iss) = (cert.subject_name(), cert.issuer_name());
    let pubkey = cert.public_key().ok();
    let (subj_s, iss_s, nb_s) = (
        name_text(subj),
        name_text(iss),
        time_text(cert.not_before()),
    );
    let self_signed = subj.try_cmp(iss).is_ok_and(|o| o.is_eq());

    if let Some(e) = out {
        e.obj_open_key(b"cert");
        e.kv_string(b"path", path.to_bytes());
        e.kv_string(b"subject", &subj_s);
        e.kv_string(b"issuer", &iss_s);
        e.kv_bool(b"self_signed", self_signed);
        match &pubkey {
            None => e.kv_null(b"algorithm"),
            Some(k) => e.kv_string(b"algorithm", &pkey_algorithm(k)),
        }
        match cert_fpr(cert) {
            Some(fpr) => e.kv_string(b"fingerprint", &hex(&fpr)),
            None => e.kv_null(b"fingerprint"),
        }
        e.kv_string(b"spki_fingerprint", &hex(spki));
        e.kv_string(b"not_before", &nb_s);
        e.obj_close();
        return;
    }
    print(&[b"Certificate (", path.to_bytes(), b"):\n"].concat());
    line(b"Subject:", &subj_s);
    line(
        b"Issuer:",
        &[
            &iss_s[..],
            if self_signed { b"  (self-signed)" } else { b"" },
        ]
        .concat(),
    );
    if let Some(k) = &pubkey {
        line(b"Public key:", &pkey_algorithm(k));
    }
    if let Some(fpr) = cert_fpr(cert) {
        print_fpr(b"Fingerprint:", &fpr);
    }
    print_fpr(b"SPKI fingerprint:", spki);
    line(b"Issued:", &nb_s);
}

/// The signing key beside the certificate, if any: whether it is the
/// certificate's. Err for one that cannot be read or is not.
fn dump_signing_key(out: &mut Out, pkey_path: &CStr, spki: &[u8; 32]) -> Result<(), ()> {
    // SAFETY: a C string.
    if !unsafe { path_exists(pkey_path.as_ptr()) } {
        if let Some(e) = out {
            e.obj_open_key(b"signing_key");
            e.kv_string(b"path", pkey_path.to_bytes());
            e.kv_bool(b"present", false);
            e.obj_close();
            return Ok(());
        }
        print(&[b"Signing key (", pkey_path.to_bytes(), b"):\n"].concat());
        line(b"Present:", b"no, a target holds no private key");
        return Ok(());
    }
    let priv_key = read_priv_pem(pkey_path).ok_or(())?;
    let alg = pkey_algorithm(&priv_key);
    match out {
        Some(e) => {
            e.obj_open_key(b"signing_key");
            e.kv_string(b"path", pkey_path.to_bytes());
            e.kv_bool(b"present", true);
            e.kv_string(b"algorithm", &alg);
        }
        None => {
            print(&[b"Signing key (", pkey_path.to_bytes(), b"):\n"].concat());
            line(b"Present:", b"yes");
            line(b"Algorithm:", &alg);
        }
    }
    let ret = match spki_fpr(&priv_key) {
        None => Err(()),
        Some(fpr) => {
            let matches = fpr == *spki;

            match out {
                Some(e) => {
                    e.kv_string(b"spki_fingerprint", &hex(&fpr));
                    e.kv_bool(b"matches_cert", matches);
                }
                None => {
                    print_fpr(b"SPKI fingerprint:", &fpr);
                    line(
                        b"Matches cert:",
                        if matches {
                            b"yes"
                        } else {
                            b"no, the private key is not the certificate's"
                        },
                    );
                }
            }
            if matches {
                Ok(())
            } else {
                warn(&[b"keys: private key and cert have different public keys"]);
                Err(())
            }
        }
    };
    if let Some(e) = out {
        e.obj_close();
    }
    ret
}

/// The certificate and signing key on disk: 0, or 1 when either is bad.
fn dump_disk_material(out: &mut Out, cert_path: &CStr, pkey_path: &CStr) -> c_int {
    let Some(cert) = read_cert_der(cert_path) else {
        return 1;
    };
    let Ok(pubkey) = cert.public_key() else {
        return 1;
    };
    let Some(spki) = spki_fpr(&pubkey) else {
        return 1;
    };
    dump_cert(out, &cert, cert_path, &spki);
    if out.is_none() {
        print(b"\n");
    }
    match dump_signing_key(out, pkey_path, &spki) {
        Ok(()) => 0,
        Err(()) => 1,
    }
}

/// A keyring init froze: its serial and the keys it recorded in it.
struct Anchor<'a> {
    label: &'a [u8],
    serial: extern "C" fn() -> i32,
    frozen: i32,
    keys: &'a [i32],
}

impl Anchor<'_> {
    fn holds(&self, key: i32) -> bool {
        self.keys.contains(&key)
    }
}

/// A member of a keyring: its serial, and its type and description
/// unless describing it failed with `err`.
struct Member {
    serial: i32,
    err: c_int,
    ty: Vec<u8>,
    description: Vec<u8>,
}

/// The members of `ring`, as keyring_links() gives them.
fn links(ring: i32) -> Result<Vec<Member>, c_int> {
    let mut list: *mut KeyringLink = ptr::null_mut();
    let mut n = 0;

    // SAFETY: room for the list and its count.
    let ret = unsafe { keyring_links(ring, &mut list, &mut n) };
    if ret != 0 {
        return Err(ret);
    }
    // SAFETY: the n links the list holds.
    let all = unsafe { ffi::slice(list, n) };
    let out = all
        .iter()
        .map(|l| Member {
            serial: l.serial(),
            err: l.err(),
            ty: l.ty().to_vec(),
            description: l.description().to_vec(),
        })
        .collect();
    // SAFETY: the list keyring_links() allocated.
    unsafe { xfree(list.cast(), n * size_of::<KeyringLink>()) };
    Ok(out)
}

fn list_keyring(out: &mut Out, ring: i32, a: &Anchor, id_rc: c_int) -> c_int {
    let frozen = id_rc == 0 && a.frozen > 0;

    if let Some(e) = out {
        e.obj_open();
        e.kv_string(b"name", a.label);
        e.kv_bool(b"present", true);
        e.kv_int(b"serial", ring.into());
        if frozen {
            e.kv_int(b"frozen_serial", a.frozen.into());
        } else {
            e.kv_null(b"frozen_serial");
        }
        let listed = links(ring);
        e.arr_open(b"members");
        for m in listed.as_deref().unwrap_or(&[]) {
            e.obj_open();
            e.kv_int(b"serial", m.serial.into());
            if m.err != 0 {
                e.kv_null(b"type");
                e.kv_null(b"description");
            } else {
                e.kv_string(b"type", &m.ty);
                e.kv_string(b"description", &m.description);
            }
            if frozen {
                e.kv_bool(b"frozen", a.holds(m.serial));
            } else {
                e.kv_null(b"frozen");
            }
            e.obj_close();
        }
        e.arr_close();
        e.obj_close();
        if let Err(err) = listed {
            error(&[b"keyring list: ", strerr(-err)]);
            return 1;
        }
        return 0;
    }
    print(&[b"Keyring (", a.label, b"):\n"].concat());
    line(b"Serial:", ring.to_string().as_bytes());
    if frozen {
        let same = a.frozen == ring;
        line(
            b"Frozen serial:",
            &[
                a.frozen.to_string().as_bytes(),
                b"  (",
                if same { b"matches" } else { b"swapped" },
                b")",
            ]
            .concat(),
        );
        if !same {
            warn(&[
                a.label,
                b" keyring serial ",
                ring.to_string().as_bytes(),
                b" is not the frozen ",
                a.frozen.to_string().as_bytes(),
                b": swapped",
            ]);
        }
    } else if id_rc == 0 || id_rc == -ENOENT {
        line(b"Frozen serial:", b"(none this boot)");
    } else {
        print(
            &[
                b"  ",
                &padded(b"Frozen serial:", 22)[..],
                b" unreadable: ",
                strerr(-id_rc),
                b"\n",
            ]
            .concat(),
        );
    }
    let listed = match links(ring) {
        Ok(listed) => listed,
        Err(err) => {
            error(&[b"keyring list: ", strerr(-err)]);
            return 1;
        }
    };
    print(&[b"  Members (", listed.len().to_string().as_bytes(), b"):\n"].concat());
    if listed.is_empty() {
        print(b"    (empty)\n");
    }
    for m in &listed {
        let (serial, err, desc) = (&m.serial, &m.err, &m.description);
        let ty: &[u8] = if *err != 0 { b"?" } else { &m.ty };
        print(
            &[
                b"    serial=",
                &padded(serial.to_string().as_bytes(), 10)[..],
                b"  type=",
                &padded(ty, 10),
                b"  ",
            ]
            .concat(),
        );
        if *err != 0 {
            print(&[b"(cannot describe: ", strerr(-err), b")"].concat());
        } else {
            // SAFETY: the description, to the C library's stdout.
            unsafe { fputs_sanitized(desc, stdout) };
        }
        if frozen {
            print(if a.holds(*serial) {
                b"  (frozen)"
            } else {
                b"  (not frozen)"
            });
        }
        print(b"\n");
    }
    0
}

fn keyring_absent(out: &mut Out, a: &Anchor, ret: i32, id_rc: c_int) {
    let frozen = id_rc == 0 && a.frozen > 0;
    let reason: Vec<u8> = if ret != -ENOKEY {
        [b"lookup error: ", strerr(-ret)].concat()
    } else if frozen {
        [
            b"gone, init froze serial ",
            a.frozen.to_string().as_bytes(),
            b" this boot",
        ]
        .concat()
    } else if id_rc == 0 || id_rc == -ENOENT {
        b"absent before init".to_vec()
    } else {
        [b"frozen identity unreadable: ", strerr(-id_rc)].concat()
    };
    let reason = if reason.len() >= 128 {
        b"?".to_vec()
    } else {
        reason
    };

    if let Some(e) = out {
        e.obj_open();
        e.kv_string(b"name", a.label);
        e.kv_bool(b"present", false);
        e.kv_null(b"serial");
        if frozen {
            e.kv_int(b"frozen_serial", a.frozen.into());
        } else {
            e.kv_null(b"frozen_serial");
        }
        e.kv_string(b"reason", &reason);
        e.obj_close();
        return;
    }
    print(&[b"Keyring (", a.label, b"):\n"].concat());
    print(
        &[
            b"  ",
            &padded(b"Present:", 22)[..],
            b" no, ",
            &reason,
            b"\n",
        ]
        .concat(),
    );
}

const fn item(name: &'static CStr, summary: &'static CStr) -> HelpItem {
    HelpItem {
        name: name.as_ptr(),
        summary: summary.as_ptr(),
    }
}

const SUBCMDS: [HelpItem; 3] = [
    item(
        c"add",
        c"trust a certificate an enrolled key vouched for (target)",
    ),
    item(
        c"revoke",
        c"stop trusting a certificate now and for good (target)",
    ),
    item(c"vouch", c"sign a vouch for a certificate (operator)"),
];
const OPTIONS: [HelpItem; 2] = [
    item(
        c"--keys-dir <dir>",
        c"read signing_key.pem and cert.der from <dir>",
    ),
    item(c"--json", c"print the key material as JSON"),
];
const ADD_OPTIONS: [HelpItem; 2] = [
    item(
        c"--vouch <file>",
        c"the vouch an enrolled key signed for the certificate",
    ),
    item(
        c"--keys-dir <dir>",
        c"the keys directory (default /var/lib/shirudo/keys)",
    ),
];
const VOUCH_OPTIONS: [HelpItem; 4] = [
    item(
        c"-o <file>",
        c"where to write the vouch (default <cert.der>.vouch)",
    ),
    item(
        c"--keys-dir <dir>",
        c"read signing_key.pem and cert.der from <dir>",
    ),
    item(c"--key <pem>", c"the signing key (overrides --keys-dir)"),
    item(
        c"--cert <der>",
        c"the signing certificate (overrides --keys-dir)",
    ),
];
const USAGE: &CStr = c"shirudo keys [--keys-dir <dir>] [--json]\n       \
shirudo keys add <cert.der> --vouch <file>\n       \
shirudo keys revoke\n       \
shirudo keys vouch <cert.der> [-o <file>]";

fn show_help(
    usage: &CStr,
    summary: &CStr,
    sections: &[(&CStr, &[HelpItem])],
    footer: Option<&CStr>,
) {
    let sections: Vec<HelpSection> = sections
        .iter()
        .map(|(header, items)| HelpSection {
            header: header.as_ptr(),
            items: items.as_ptr(),
            n_items: items.len(),
        })
        .collect();
    let help = Help {
        usage: usage.as_ptr(),
        summary: summary.as_ptr(),
        sections: if sections.is_empty() {
            ptr::null()
        } else {
            sections.as_ptr()
        },
        n_sections: sections.len(),
        footer: footer.map_or(ptr::null(), CStr::as_ptr),
    };

    // SAFETY: the help, its strings constants and its sections live.
    unsafe { print_help(&help) };
}

fn keys_help() {
    show_help(
        USAGE,
        c"Inspect the shirudo key material this host holds: the on-disk cert and\n\
signing key (if present), the trusted set a target enrols, and the kernel\n\
keyring holding it (if init'd). Local-only on either side.",
        &[(c"subcommands:", &SUBCMDS), (c"options:", &OPTIONS)],
        Some(
            c"Default paths:\n  /var/lib/shirudo/keys/cert.der\n  \
/var/lib/shirudo/keys/signing_key.pem\n\nOr set the SHIRUDO_KEYS_DIR environment variable.",
        ),
    );
}

fn add_help() {
    show_help(
        c"shirudo keys add <cert.der> --vouch <file> [--keys-dir <dir>]",
        c"Add a certificate to the trusted set this target enrols at its next boot.\n\
The vouch must verify under a certificate already in the set; regenerate\n\
the initrd afterwards (shirudo-gen-initrd). Prints the fingerprint.",
        &[(c"options:", &ADD_OPTIONS)],
        None,
    );
}

fn vouch_help() {
    show_help(
        c"shirudo keys vouch <cert.der> [-o <file>] [--keys-dir <dir>]",
        c"Sign a vouch for another operator's certificate with this operator's key,\n\
for `shirudo keys add --vouch` on the targets that enrol this key.\n\
Prints the vouched certificate's fingerprint.",
        &[(c"options:", &VOUCH_OPTIONS)],
        None,
    );
}

/// A trusted set, which takes some 66 KiB.
fn new_set() -> Box<TrustedSet> {
    // SAFETY: an all-zero set is an empty one.
    Box::new(unsafe { core::mem::zeroed() })
}

/// The bytes keys_read_der() read, freed when they go.
struct Der(*mut u8, usize);

impl Der {
    fn bytes(&self) -> &[u8] {
        if self.0.is_null() {
            return &[];
        }
        // SAFETY: the len bytes read.
        unsafe { core::slice::from_raw_parts(self.0, self.1) }
    }
}

impl Drop for Der {
    fn drop(&mut self) {
        // SAFETY: the reader's allocation, or NULL.
        unsafe { xfree(self.0.cast(), self.1) };
    }
}

fn read_der(path: &CStr) -> Result<Der, c_int> {
    let mut der = Der(ptr::null_mut(), 0);

    // SAFETY: a C string and room for the bytes and their length.
    match unsafe { keys_read_der(path.as_ptr(), &mut der.0, &mut der.1) } {
        0 => Ok(der),
        err => Err(err),
    }
}

/// The public key must be one the kernel verifies loaders with.
fn check_cert_algorithm(der: &[u8], what: &[u8]) -> c_int {
    let mut cert = Cert::new();
    let mut name = [0u8; 64];

    // SAFETY: the bytes and a certificate to fill.
    let ret = unsafe { cert_read_der(der.as_ptr(), der.len(), &mut cert) };
    if ret != 0 {
        error(&[b"keys add: ", what, b" is not a certificate"]);
        return ret;
    }
    // SAFETY: the certificate and room for its algorithm's name.
    let ret = unsafe { cert_key_algorithm(&cert, name.as_mut_ptr().cast(), name.len()) };
    // SAFETY: the certificate read above.
    unsafe { cert_free(&mut cert) };
    if ret != 0 || cstr(&name) != b"ML-DSA-87" {
        let what_alg: &[u8] = if ret != 0 {
            b"of an unknown algorithm"
        } else {
            cstr(&name)
        };
        error(&[
            b"keys add: ",
            what,
            b" is ",
            what_alg,
            b"; shirudo accepts only ML-DSA-87",
        ]);
        return -EKEYREJECTED;
    }
    0
}

/// The vouching certificate must be one the kernel verifies against
/// right now, not only one on disk, when the live target's set is the
/// one being extended.
fn check_voucher_live(set: &TrustedSet, voucher: &[u8; 32]) -> c_int {
    let mut id = Identity::zeroed();

    if identity::read(&mut id) != 0 || id.keyring_type != SIG_KEYRING_BPF {
        return 0;
    }
    let ring = keyring_bpf_serial();
    if ring <= 0 {
        return 0;
    }
    let Some(c) = members(set).iter().find(|c| c.fingerprint() == voucher) else {
        return -ENOKEY;
    };
    let mut der: *const u8 = ptr::null();
    let mut len = 0;
    // SAFETY: the member and room for its bytes.
    let ret = unsafe { keys_cert_der(c, &mut der, &mut len) };
    if ret != 0 {
        return ret;
    }
    // SAFETY: the member's kept bytes.
    let ret = unsafe { keyring_holds_cert(ring, der, len) };
    if ret < 0 {
        return ret;
    }
    if ret != 0 { 0 } else { -ENOKEY }
}

fn keys_add(args: &[&[u8]]) -> c_int {
    let (mut keys_dir_arg, mut vouch_path, mut cert) = (None, None, None);
    let mut a = 1;

    while a < args.len() {
        let arg = args[a];

        if arg == b"--vouch" && a + 1 < args.len() {
            a += 1;
            vouch_path = Some(args[a]);
        } else if let Some(v) = arg.strip_prefix(b"--vouch=") {
            vouch_path = Some(v);
        } else if arg == b"--keys-dir" && a + 1 < args.len() {
            a += 1;
            keys_dir_arg = Some(args[a]);
        } else if let Some(d) = arg.strip_prefix(b"--keys-dir=") {
            keys_dir_arg = Some(d);
        } else if is_help(Some(arg)) {
            add_help();
            return 0;
        } else if arg.first() == Some(&b'-') {
            error(&[b"keys add: unknown option '", arg, b"'"]);
            return 2;
        } else if cert.is_none() {
            cert = Some(arg);
        } else {
            error(&[b"keys add: unexpected argument '", arg, b"'"]);
            return 2;
        }
        a += 1;
    }
    let (Some(cert), Some(vouch_path)) = (cert, vouch_path) else {
        add_help();
        return 2;
    };
    if image_config::active() {
        error(&[b"target: add vouched BPF signers to the signed config selected for boot and reboot to enroll them"]);
        return 1;
    }
    let keys_dir_arg = keys_dir_arg.map(|d| message(&[d]));
    // SAFETY: NULL or a C string; the result is a C string.
    let keys_dir = unsafe {
        CStr::from_ptr(keys_dir_resolve(
            keys_dir_arg.as_ref().map_or(ptr::null(), |d| d.as_ptr()),
        ))
    };
    let revoked = [keys_dir.to_bytes(), b"/revoked"].concat();
    if revoked.len() >= PATH_MAX {
        error(&[b"keys add: keys directory path too long"]);
        return 2;
    }
    let revoked = message(&[&revoked]);
    let cert_c = message(&[cert]);
    let der = match read_der(&cert_c) {
        Ok(der) => der,
        Err(err) => {
            error(&[b"keys add: read ", cert, b": ", strerr(-err)]);
            return 1;
        }
    };
    let (mut sha256, mut fp) = ([0u8; 32], [0u8; 32]);
    // SAFETY: the bytes and room for the two digests.
    if unsafe { keys_digest_der(der.0, der.1, sha256.as_mut_ptr(), fp.as_mut_ptr()) } != 0 {
        error(&[b"keys add: ", cert, b" is not a certificate"]);
        return 1;
    }
    if check_cert_algorithm(der.bytes(), cert) != 0 {
        return 1;
    }
    let fp_hex = hex(&fp);
    let mut set = new_set();
    // SAFETY: a C string and room for the set.
    let ret = unsafe { keys_load(keys_dir.as_ptr(), ptr::null(), true, &mut *set) };
    if ret != 0 {
        error(&[
            b"keys add: no trusted set under ",
            keys_dir.to_bytes(),
            b": ",
            strerr(-ret),
            b" (install the primary certificate first)",
        ]);
        return 1;
    }
    // SAFETY: a C string and the fingerprint.
    if unsafe { keys_is_revoked(revoked.as_ptr(), &fp) } {
        error(&[b"keys add: ", &fp_hex, b" was revoked on this target"]);
        return 1;
    }
    let vouch_c = message(&[vouch_path]);
    let sig = match read_der(&vouch_c) {
        Ok(sig) => sig,
        Err(err) => {
            error(&[b"keys add: read ", vouch_path, b": ", strerr(-err)]);
            return 1;
        }
    };
    let mut by = [0u8; 32];
    // SAFETY: the set, the two byte runs and room for the voucher.
    if unsafe { keys_verify_vouch(&*set, der.0, der.1, sig.0, sig.1, by.as_mut_ptr()) } != 0 {
        let n = set.len();
        error(&[
            b"keys add: ",
            vouch_path,
            b" does not vouch for ",
            &fp_hex,
            b" under any of the ",
            n.to_string().as_bytes(),
            b" trusted certificate",
            if n == 1 { b"" } else { b"s" },
        ]);
        return 1;
    }
    let by_hex = hex(&by);
    if keys_dir == KEYS_DIR {
        let ret = check_voucher_live(&set, &by);
        if ret != 0 {
            let why: Vec<u8> = if ret == -ENOKEY {
                Vec::new()
            } else {
                [b": ", strerr(-ret)].concat()
            };
            error(&[
                b"keys add: the vouching certificate ",
                &by_hex,
                b" is not in the bpf keyring this boot",
                &why,
            ]);
            return 1;
        }
    }
    if members(&set).iter().any(|c| *c.fingerprint() == fp) {
        info(&[b"keys add: ", &fp_hex, b" is already trusted"]);
        print(&[&fp_hex[..], b"\n"].concat());
        return 0;
    }
    // A set past the limit would fail to load at all, init included.
    if set.len() >= KEYS_MAX {
        error(&[
            b"keys add: the trusted set holds ",
            KEYS_MAX.to_string().as_bytes(),
            b" certificates, the most a target enrols",
        ]);
        return 1;
    }
    let mut out = [0u8; PATH_MAX];
    // SAFETY: a C string, the two byte runs and room for the path.
    let ret = unsafe {
        keys_install(
            keys_dir.as_ptr(),
            der.0,
            der.1,
            sig.0,
            sig.1,
            out.as_mut_ptr().cast(),
            out.len(),
        )
    };
    if ret != 0 {
        error(&[
            b"keys add: install under ",
            keys_dir.to_bytes(),
            b"/trusted: ",
            strerr(-ret),
        ]);
        return 1;
    }
    audit(&[
        b"keys add: fingerprint=",
        &fp_hex,
        b" vouched_by=",
        &by_hex,
        b" path=",
        cstr(&out),
    ]);
    info(&[
        b"keys add: ",
        &fp_hex,
        b" joins the set at the next boot; regenerate the initrd (shirudo-gen-initrd)",
    ]);
    print(&[&fp_hex[..], b"\n"].concat());
    0
}

fn append_key_event(ty: &CStr, fp_hex: &[u8], sha_hex: &[u8], event: &[u8; 32]) -> c_int {
    let mut buf = [0u8; 1024];
    let mut e = JsonEmit::fixed(buf.as_mut_ptr().cast(), buf.len());

    // SAFETY: the emitter, a C string and the event.
    unsafe { eventlog_record_open(&mut e, ty.as_ptr(), event.as_ptr()) };
    e.obj_open_key(b"key");
    e.kv_string(b"fingerprint", fp_hex);
    e.kv_string(b"cert_sha256", sha_hex);
    e.obj_close();
    e.obj_close();
    if e.err() != 0 {
        error(&[
            b"eventlog: ",
            ty.to_bytes(),
            b" entry encode failed: ",
            strerr(-e.err()),
        ]);
        return e.err();
    }
    // SAFETY: the emitter's NUL-terminated line.
    unsafe { eventlog_append(buf.as_ptr().cast()) }
}

/// The register learns of the revocation before anything else changes
/// in the archive, so evidence taken at any point names it. As for an
/// upatch event, no TPM is an error, not an unmeasured success.
fn measure_revoke_locked(sha256: &[u8; 32], fp_hex: &[u8]) -> c_int {
    let (mut event, mut chain) = ([0u8; 32], [0u8; 32]);

    // SAFETY: a C string, the digest and room for the event.
    let ret = unsafe {
        chain_key_event(
            c"shirudo-key-revoke".as_ptr(),
            sha256.as_ptr(),
            event.as_mut_ptr(),
        )
    };
    if ret != 0 {
        error(&[
            b"keys revoke: cannot hash the revocation event: ",
            strerr(-ret),
            b"; the key is revoked but the revocation is NOT measured; operator must reconcile",
        ]);
        return ret;
    }
    // SAFETY: the event and room for the chain.
    let ret = unsafe { chain_extend(event.as_ptr(), chain.as_mut_ptr()) };
    if ret != 0 {
        let (what, category): (&[u8], &[u8]) = match ret {
            r if r == -ENODEV => (b"unavailable", b"tpm_error"),
            r if r == -EACCES => (b"is not the one init bound", b"tampered"),
            _ => (b"extend failed", b"tpm_error"),
        };
        error(&[
            b"keys revoke: register ",
            what,
            b" (category: ",
            category,
            b"); the key is revoked but the revocation is NOT measured; operator must reconcile",
        ]);
        return ret;
    }
    let ret = append_key_event(c"key_revoke", fp_hex, &hex(sha256), &event);
    if ret != 0 {
        error(&[b"keys revoke: eventlog append failed after the extend: register and log disagree; the operator must reconcile"]);
        return ret;
    }
    audit(&[
        b"key revoke measured: fingerprint=",
        fp_hex,
        b" chain=",
        &hex(&chain),
    ]);
    0
}

fn measure_revoke(sha256: &[u8; 32], fp_hex: &[u8]) -> c_int {
    let lock = eventlog_lock();

    if lock < 0 {
        error(&[
            b"keys revoke: cannot take the register lock: ",
            strerr(-lock),
            b"; the revocation is NOT measured",
        ]);
        return lock;
    }
    let ret = measure_revoke_locked(sha256, fp_hex);
    eventlog_unlock(lock);
    ret
}

/// Every archived upatch the revoked certificate signed goes: the kernel
/// would refuse to restore it at the next boot, and keeping it loaded
/// would keep running what a key nobody trusts any more authorised. The
/// rest are still tried when one fails. How many went, or the last
/// error.
fn purge_signed_by(der: &[u8]) -> c_int {
    let mut cert = Cert::new();
    let mut names: *mut *mut Dirent = ptr::null_mut();
    let dir = message(&[UPATCHES_DIR.as_bytes()]);
    let (mut ret, mut purged) = (0, 0);

    // SAFETY: the bytes and a certificate to fill.
    if unsafe { cert_read_der(der.as_ptr(), der.len(), &mut cert) } != 0 {
        return -EINVAL;
    }
    // SAFETY: a C string, room for the list, and the filter and order.
    let n = unsafe {
        scandir(
            dir.as_ptr(),
            &mut names,
            Some(upatch_select),
            Some(alphasort),
        )
    };
    if n < 0 {
        let e = errno();
        // SAFETY: the certificate read above.
        unsafe { cert_free(&mut cert) };
        return if e == ENOENT { 0 } else { -e };
    }
    // SAFETY: the n entries scandir() gave.
    let entries = unsafe { ffi::slice(names, n as usize) };
    for &entry in entries {
        // SAFETY: an entry, whose name is a C string.
        let file = unsafe { ffi::c_str((*entry).d_name.as_ptr()) };
        let path = [UPATCHES_DIR.as_bytes(), b"/", file].concat();
        if path.len() >= PATH_MAX {
            continue;
        }
        let path = message(&[&path]);
        // SAFETY: an all-zero container is a closed one.
        let mut u: Upatch = unsafe { core::mem::zeroed() };
        let mut name = [0u8; upatch::NAME_MAX + 1];
        // SAFETY: a C string and a container to fill.
        if unsafe { upatch_open(path.as_ptr(), &mut u) } != 0 {
            continue;
        }
        // SAFETY: the open container, its signature and the certificate.
        let signed_by = unsafe {
            cms_signed_by(
                upatch_signature(&u).cast(),
                u.hdr.signature_len as usize,
                &cert,
            )
        };
        upatch::header_name(&u, &mut name);
        // SAFETY: the container opened above.
        unsafe { upatch_close(&mut u) };
        if signed_by != 1 {
            continue;
        }
        let name = cstr(&name);
        let name_c = message(&[name]);
        let prc = crate::builtin::upatch::purge(&name_c, (&raw const cert).cast(), c"key_revoke");
        if prc == -ESTALE {
            info(&[
                b"keys revoke: ",
                name,
                b" was replaced by an upatch the key did not sign; left alone",
            ]);
            continue;
        }
        if prc < 0 {
            error(&[b"keys revoke: purge ", name, b": ", strerr(-prc)]);
            ret = prc;
            continue;
        }
        let what: &[u8] = if prc != 0 {
            b"unloaded and purged"
        } else {
            b"purged from the archive"
        };
        info(&[b"keys revoke: ", name, b" ", what]);
        purged += 1;
    }
    // SAFETY: scandir()'s entries and list, from the C library's malloc.
    unsafe {
        for &entry in entries {
            libc_free(entry.cast());
        }
        libc_free(names.cast());
        cert_free(&mut cert);
    }
    if ret != 0 { ret } else { purged }
}

/// Revokes the certificate `der` of a config image: out of the .bpf
/// keyring, measured unless at boot, and what it signed purged.
pub(crate) fn revoke_image(der: &[u8], boot: bool) -> c_int {
    let ring = keyring_bpf_serial();

    if ring < 0 {
        return ring;
    }
    // SAFETY: the certificate's bytes.
    let key = unsafe { keyring_find_cert(ring, der.as_ptr(), der.len()) };
    if key != -ENOKEY && key < 0 {
        return key;
    }
    if key >= 0 {
        let ret = keyring_unlink_key(ring, key);
        if ret != 0 {
            return ret;
        }
        if !boot {
            let (mut sha256, mut fp) = ([0u8; 32], [0u8; 32]);
            // SAFETY: the bytes and room for the two digests.
            let ret = unsafe {
                keys_digest_der(
                    der.as_ptr(),
                    der.len(),
                    sha256.as_mut_ptr(),
                    fp.as_mut_ptr(),
                )
            };
            if ret != 0 {
                return ret;
            }
            let ret = measure_revoke(&sha256, &hex(&fp));
            if ret != 0 {
                return ret;
            }
        }
    }
    purge_signed_by(der).min(0)
}

fn keys_show(args: &[&[u8]]) -> c_int {
    let mut keys_dir_arg = None;
    let mut json = false;
    let mut i = 1;

    while i < args.len() {
        let a = args[i];

        if a == b"--keys-dir" && i + 1 < args.len() {
            i += 1;
            keys_dir_arg = Some(args[i]);
        } else if let Some(d) = a.strip_prefix(b"--keys-dir=") {
            keys_dir_arg = Some(d);
        } else if a == b"--json" {
            json = true;
        } else if is_help(Some(a)) {
            keys_help();
            return 0;
        } else if is_list_cmds(Some(a)) {
            // SAFETY: items whose names are C strings.
            unsafe { print_subcmd_list(&SUBCMDS) };
            return 0;
        } else {
            error(&[b"keys: unknown option '", a, b"'"]);
            let usage = [b"usage: ", USAGE.to_bytes(), b"\n"].concat();
            // SAFETY: the bytes, to the C library's stderr.
            unsafe {
                fwrite(
                    usage.as_ptr().cast(),
                    1,
                    usage.len(),
                    crate::sys::libc::stderr,
                )
            };
            return 2;
        }
        i += 1;
    }
    let keys_dir_arg = keys_dir_arg.map(|d| message(&[d]));
    let keys_dir: &CStr = if image_config::active() {
        RUNTIME_KEYS_DIR
    } else {
        // SAFETY: NULL or a C string; the result is a C string.
        unsafe {
            CStr::from_ptr(keys_dir_resolve(
                keys_dir_arg.as_ref().map_or(ptr::null(), |d| d.as_ptr()),
            ))
        }
    };
    let (mut pkey_path, mut cert_path) = ([0u8; PATH_MAX], [0u8; PATH_MAX]);
    // SAFETY: a C string and the room for both paths.
    let ret = unsafe {
        key_paths(
            keys_dir.as_ptr(),
            pkey_path.as_mut_ptr().cast(),
            PATH_MAX,
            cert_path.as_mut_ptr().cast(),
            PATH_MAX,
        )
    };
    if ret != 0 {
        error(&[
            b"keys: invalid keys dir ",
            keys_dir.to_bytes(),
            b": ",
            strerr(-ret),
        ]);
        return 2;
    }
    let pkey_path = message(&[cstr(&pkey_path)]);
    let cert_path = message(&[cstr(&cert_path)]);
    // Both roles can coexist on one host, so report whatever is present:
    // the on-disk cert and signing key, then the kernel keyrings once
    // `shirudo init` has filled them.
    let mut buf = if json { vec![0u8; 65536] } else { Vec::new() };
    let mut emitter = json.then(|| JsonEmit::fixed(buf.as_mut_ptr().cast(), buf.len()));
    let mut out: Out = emitter.as_mut();
    let (mut shown, mut ret) = (false, 0);

    if let Some(e) = &mut out {
        e.obj_open();
        e.kv_int(b"schema", 1);
    }
    // SAFETY: a C string.
    if unsafe { path_exists(cert_path.as_ptr()) } {
        if dump_disk_material(&mut out, &cert_path, &pkey_path) != 0 {
            ret = 1;
        }
        shown = true;
    } else if let Some(e) = &mut out {
        e.kv_null(b"cert");
        e.kv_null(b"signing_key");
    }
    let mut set = new_set();
    // SAFETY: a C string and room for the set.
    let have_set = unsafe { keys_load(keys_dir.as_ptr(), ptr::null(), true, &mut *set) } == 0;
    if let Some(e) = &mut out {
        e.arr_open(b"trusted_set");
    }
    if have_set
        && (out.is_some() || set.len() > 1 || set.n_revoked() != 0 || set.n_unvouched() != 0)
    {
        if out.is_none() {
            let n = set.len();
            print(
                &[
                    if shown { &b"\n"[..] } else { b"" },
                    b"Trusted set (",
                    n.to_string().as_bytes(),
                    b" member",
                    if n == 1 { b"" } else { b"s" },
                    b", ",
                    set.n_revoked().to_string().as_bytes(),
                    b" revoked, ",
                    set.n_unvouched().to_string().as_bytes(),
                    b" unvouched):\n",
                ]
                .concat(),
            );
        }
        for c in members(&set) {
            let (fp, sha, voucher) = (hex(c.fingerprint()), hex(c.sha256()), hex(c.voucher()));

            if let Some(e) = &mut out {
                e.obj_open();
                e.kv_string(b"fingerprint", &fp);
                e.kv_string(b"sha256", &sha);
                e.kv_bool(b"primary", c.primary());
                if c.primary() {
                    e.kv_null(b"voucher");
                } else {
                    e.kv_string(b"voucher", &voucher);
                }
                e.obj_close();
                continue;
            }
            print(
                &[
                    &b"  "[..],
                    &fp[..],
                    if c.primary() {
                        &b"  (primary)"[..]
                    } else {
                        b""
                    },
                    b"\n    sha256 ",
                    &sha,
                    b"\n",
                ]
                .concat(),
            );
            if !c.primary() {
                print(&[b"    vouched by ", &voucher[..], b"\n"].concat());
            }
        }
        if out.is_none() {
            shown = true;
        }
    }
    if let Some(e) = &mut out {
        e.arr_close();
    }
    let mut id = Identity::zeroed();
    let id_rc = identity::read(&mut id);
    let n_keys = id.n_keys.min(IDENTITY_KEYS_MAX) as usize;
    let n_dm_keys = (id.n_dm_verity_keys as usize).min(IDENTITY_KEYS_MAX as usize);
    let anchors = [
        Anchor {
            label: b".bpf",
            serial: keyring_bpf_serial,
            frozen: id.keyring_serial,
            keys: &id.key_serials[..n_keys],
        },
        Anchor {
            label: b".dm-verity",
            serial: keyring_dm_verity_serial,
            frozen: id.dm_verity_ring,
            keys: &id.dm_verity_keys[..n_dm_keys],
        },
    ];
    if let Some(e) = &mut out {
        e.arr_open(b"keyrings");
    }
    for a in &anchors {
        let ring = if id_rc != 0 { -ENOKEY } else { (a.serial)() };

        if ring >= 0 {
            if shown && out.is_none() {
                print(b"\n");
            }
            if list_keyring(&mut out, ring, a, id_rc) != 0 {
                ret = 1;
            }
            shown = true;
        } else if ring == -ENOKEY && id_rc != 0 {
            if shown || out.is_some() {
                if out.is_none() {
                    print(b"\n");
                }
                keyring_absent(&mut out, a, ring, id_rc);
            }
        } else {
            if shown && out.is_none() {
                print(b"\n");
            }
            keyring_absent(&mut out, a, ring, id_rc);
            shown = true;
            ret = 1;
        }
    }
    if let Some(e) = &mut out {
        e.arr_close();
        e.obj_close();
        if e.err() != 0 {
            error(&[b"keys: json encode failed"]);
            ret = 1;
        } else {
            let n = e.written();
            print(&[&buf[..n], b"\n"].concat());
        }
    }
    if !shown {
        error(&[
            b"no shirudo key material on this host: no ",
            cert_path.to_bytes(),
            b" and no .bpf kernel keyring; run shirudo genkey on an operator or shirudo init on a target",
        ]);
        ret = 1;
    }
    ret
}

/// `shirudo keys`.
///
/// # Safety
///
/// `argv` holds `argc` C strings.
unsafe fn keys(argc: c_int, argv: *const *const c_char) -> c_int {
    // SAFETY: the caller's arguments.
    let raw = unsafe { words(argc, argv) };
    // SAFETY: each a C string.
    let args: Vec<&[u8]> = raw.iter().map(|&a| unsafe { ffi::c_str(a) }).collect();

    if args.len() < 2 || args[1].first() == Some(&b'-') || is_help(Some(args[1])) {
        return keys_show(&args);
    }
    // SAFETY: a label, the caller's word and items with names.
    let sub = unsafe { resolve_subcommand(c"shirudo keys".as_ptr(), raw[1], &SUBCMDS) };
    if sub.is_null() {
        return 2;
    }
    // SAFETY: the name of one of the items.
    match unsafe { CStr::from_ptr(sub) }.to_bytes() {
        b"add" => keys_add(&args[1..]),
        b"revoke" => {
            if args.len() == 3 && is_help(Some(args[2])) {
                show_help(
                    c"shirudo keys revoke",
                    c"Local revocation is disabled. Publish revocation records in a signed config image and activate it with image update.",
                    &[],
                    None,
                );
                return 0;
            }
            error(&[b"keys revoke: put revocation records in a signed config image, then run `shirudo image update`"]);
            1
        }
        _ => {
            // SAFETY: the caller's second word, when there is one.
            if args.len() >= 3 && is_help(unsafe { word(raw[2]) }) {
                vouch_help();
                return 0;
            }
            let words = [c"keys".as_ptr(), c"vouch".as_ptr(), ptr::null()];
            // SAFETY: a label, the words up to their NULL, and the
            // caller's arguments after the subcommand.
            unsafe {
                super::build::forward(
                    c"keys vouch".as_ptr(),
                    words.as_ptr(),
                    argc - 2,
                    argv.add(2),
                )
            }
        }
    }
}

pub(super) use capi::cmd_keys;

mod capi {
    use core::ffi::{c_char, c_int};

    /// # Safety
    ///
    /// `argv` holds `argc` C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cmd_keys(argc: c_int, argv: *const *const c_char) -> c_int {
        // SAFETY: the caller's arguments.
        unsafe { super::keys(argc, argv) }
    }
}
