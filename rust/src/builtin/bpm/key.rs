// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Package signing certificates: fingerprinting one, installing it as
//! the node's package signer, and listing those installed.

use core::ffi::{CStr, c_char, c_int};
use std::ffi::{CString, OsStr};
use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;

use super::{
    CERT_PATH, KEYS_DIR, Result, curl_ready, error, fail, finish, item, last_err, message, os_err,
    path, print, remove, show_help, status, temporary,
};
use crate::errno::{EEXIST, EIO, EKEYREJECTED, ENOENT, EPERM};
use crate::sys::libc::close;
use crate::text::name_has_suffix;
use crate::util::bpm_package::read_member_in;
use crate::util::crypto_openssl::{Cert, cert_free, cert_pubkey_digest, cert_read_file};
use crate::util::help::{HelpItem, is_help, is_list_cmds, print_subcmd_list, resolve_subcommand};
use crate::util::image_config;
use crate::util::json::JsonEmit;
use crate::util::seal::{seal_inherit_path, seal_mkdir_p};

const ITEMS: [HelpItem; 3] = [
    item(
        c"add",
        c"install a trusted package certificate and print its fingerprint",
    ),
    item(
        c"fingerprint",
        c"print the SHA-256 fingerprint of a certificate's SPKI",
    ),
    item(c"list", c"list installed certificate fingerprints"),
];

fn help() {
    show_help(
        c"shirudo bpm key <add|fingerprint|list>",
        c"Manage package signing certificates.",
        &ITEMS,
        Some(
            c"add and fingerprint accept a certificate file, .bee package, or\n\
oci://registry/repository:tag. list reads /var/lib/shirudo/keys.\n\
Examples:\n  shirudo bpm key fingerprint ./package.bee\n  \
shirudo bpm key add oci://quay.io/namespace/package:tag\n  shirudo bpm key list",
        ),
    );
}

fn os(path: &CStr) -> &OsStr {
    OsStr::from_bytes(path.to_bytes())
}

/// The SHA-256 of the SPKI of the certificate at `path`.
fn pubkey_digest(path: &CStr) -> Result<[u8; 32]> {
    let mut cert = Cert::new();
    let mut digest = [0; 32];

    // SAFETY: a C string and a certificate to fill, freed below.
    let mut ret = unsafe { cert_read_file(path.as_ptr(), &mut cert) };
    if ret == 0 {
        // SAFETY: the certificate read and room for the digest.
        ret = unsafe { cert_pubkey_digest(&cert, digest.as_mut_ptr()) };
    }
    // SAFETY: the certificate, read or not.
    unsafe { cert_free(&mut cert) };
    status(ret).map(|()| digest)
}

/// Whether the certificate at `path` has the key of the node's active
/// certificate.
pub(super) fn matches_active(path: &CStr) -> bool {
    matches!(
        (pubkey_digest(path), pubkey_digest(CERT_PATH)),
        (Ok(a), Ok(b)) if a == b
    )
}

/// The lowercase hex fingerprint of the certificate at `path`.
fn fingerprint(path: &CStr) -> Result<[u8; 64]> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = pubkey_digest(path)?;
    let mut hex = [0; 64];

    for (i, b) in digest.iter().enumerate() {
        hex[2 * i] = HEX[usize::from(b >> 4)];
        hex[2 * i + 1] = HEX[usize::from(b & 0xf)];
    }
    Ok(hex)
}

/// Installs the certificate at `src` under its fingerprint, and as the
/// active certificate when the node has none yet; one with another key
/// than an active certificate's is refused.
fn install(src: &CStr) -> Result {
    let hex = fingerprint(src)?;
    let keys_dir = message(&[KEYS_DIR.as_bytes()]);

    // SAFETY: a C string.
    status(unsafe { seal_mkdir_p(keys_dir.as_ptr(), 0o700) })?;
    let active = match fs::symlink_metadata(os(CERT_PATH)) {
        Ok(_) => true,
        Err(e) if e.raw_os_error() == Some(ENOENT) => false,
        Err(e) => return Err(os_err(e)),
    };
    if active && !matches_active(src) {
        return Err(-EPERM);
    }
    let dst = path(&[KEYS_DIR.as_bytes(), b"/", &hex, b".der"])?;
    let made = match fs::symlink_metadata(os(&dst)) {
        Ok(m) => {
            if !m.file_type().is_file() || fingerprint(&dst).ok() != Some(hex) {
                return Err(-EKEYREJECTED);
            }
            false
        }
        Err(e) if e.raw_os_error() == Some(ENOENT) => {
            super::package::copy_file(src, &dst, 0o644, true)?;
            true
        }
        Err(e) => return Err(os_err(e)),
    };
    if active {
        return Ok(());
    }
    let ret = match std::os::unix::fs::symlink(os(&dst), os(CERT_PATH)) {
        // SAFETY: a C string.
        Ok(()) => status(unsafe { seal_inherit_path(CERT_PATH.as_ptr()) }),
        Err(e) if e.raw_os_error() != Some(EEXIST) => Err(os_err(e)),
        Err(_) if matches_active(src) => Ok(()),
        Err(_) => Err(-EPERM),
    };
    if ret.is_err() && made {
        remove(&dst);
    }
    ret
}

/// The certificate a package carries, written to a temporary file.
fn extract_cert(archive: &CStr) -> Result<CString> {
    let body = read_member_in(archive, b"cert.der", None, None, 1 << 20)?;
    let (name, fd) = temporary(c"/tmp/shirudo-bpm-cert-XXXXXX")?;
    let mut file = fs::File::from(fd);
    let mut ret = file.write_all(body.bytes()).map_err(os_err);

    // SAFETY: the file's fd, closed once.
    if unsafe { close(file.into_raw_fd()) } != 0 && ret.is_ok() {
        ret = Err(last_err());
    }
    match ret {
        Ok(()) => Ok(name),
        Err(err) => {
            remove(&name);
            Err(err)
        }
    }
}

/// The certificate a source names, written to a temporary file when it
/// comes in a package or an OCI reference to one; None for a
/// certificate file itself.
fn certificate_of(source: &[u8]) -> Result<Option<CString>> {
    if source.starts_with(b"oci://") {
        let (archive, fd) = temporary(c"/tmp/shirudo-bpm-key-XXXXXX")?;
        let fetched = super::fetch::download(source, Some((&archive, fd.as_raw_fd())));
        drop(fd);
        let cert = fetched.and_then(|()| extract_cert(&archive));
        remove(&archive);
        return cert.map(Some);
    }
    if name_has_suffix(source, b".bee") {
        return extract_cert(&message(&[source])).map(Some);
    }
    Ok(None)
}

/// The fingerprints of the certificates installed, each a regular file
/// named after its own fingerprint.
fn installed() -> Result<Vec<[u8; 64]>> {
    let mut found = Vec::new();
    let entries = match fs::read_dir(KEYS_DIR) {
        Ok(entries) => entries,
        Err(e) if e.raw_os_error() == Some(ENOENT) => return Ok(found),
        Err(e) => return Err(os_err(e)),
    };

    for entry in entries {
        let name = entry.map_err(os_err)?.file_name();
        let name = name.as_bytes();

        if name.len() != 68
            || !name[64..].eq_ignore_ascii_case(b".der")
            || !name[..64].iter().all(u8::is_ascii_hexdigit)
        {
            continue;
        }
        let Ok(p) = path(&[KEYS_DIR.as_bytes(), b"/", name]) else {
            continue;
        };
        if !fs::symlink_metadata(os(&p)).is_ok_and(|m| m.file_type().is_file()) {
            continue;
        }
        match fingerprint(&p) {
            Ok(hex) if name[..64].eq_ignore_ascii_case(&hex) => found.push(hex),
            _ => continue,
        }
    }
    found.sort();
    Ok(found)
}

fn list(json: bool) -> Result {
    let found = installed()?;

    if json {
        let mut buf = [0u8; 8192];
        let mut e = JsonEmit::fixed(buf.as_mut_ptr().cast(), buf.len());

        e.obj_open();
        e.kv_int(b"schema", 1);
        e.arr_open(b"fingerprints");
        for hex in &found {
            e.str(hex);
        }
        e.arr_close();
        e.obj_close();
        if e.err() != 0 {
            return Err(e.err());
        }
        print(&[&buf[..e.written()], b"\n"].concat());
        return Ok(());
    }
    print(b"Package certificates:\n");
    if found.is_empty() {
        print(b"  none\n");
    }
    for hex in &found {
        print(&[b"  ", &hex[..], b"\n"].concat());
    }
    Ok(())
}

/// `shirudo bpm key`, `raw` and `args` from "key" on.
pub(super) fn key(raw: &[*const c_char], args: &[&[u8]]) -> c_int {
    let n = args.len();
    let arg = |i: usize| args.get(i).copied();

    if n < 2 || is_help(arg(1)) {
        help();
        return if n < 2 { 2 } else { 0 };
    }
    if is_list_cmds(arg(1)) {
        // SAFETY: items whose names are C strings.
        unsafe { print_subcmd_list(&ITEMS) };
        return 0;
    }
    // SAFETY: a label, the caller's word and items with names.
    let sub = unsafe { resolve_subcommand(c"bpm key".as_ptr(), raw[1], &ITEMS) };
    if sub.is_null() {
        return 2;
    }
    // SAFETY: the name of one of the items.
    let sub = unsafe { CStr::from_ptr(sub) }.to_bytes();
    if n == 3 && is_help(arg(2)) {
        help();
        return 0;
    }
    let listing = sub == b"list";
    if (listing && n != 2 && !(n == 3 && args[2] == b"--json")) || (!listing && n != 3) {
        help();
        return 2;
    }
    let add = sub == b"add";
    if add && image_config::active() {
        error(&[b"image mode: add vouched BPF signers to the signed config selected for boot and reboot to enroll them"]);
        return 1;
    }
    if listing {
        return match list(n == 3) {
            Ok(()) => 0,
            Err(err) => fail(b"key list", err),
        };
    }
    if !curl_ready() {
        return fail(b"initialize curl", -EIO);
    }
    let cert = certificate_of(args[2]);
    let ret = match &cert {
        Ok(cert) => {
            let src = cert.clone().unwrap_or_else(|| message(&[args[2]]));
            fingerprint(&src).and_then(|hex| {
                if add {
                    install(&src)?;
                }
                print(&[&hex[..], b"\n"].concat());
                Ok(())
            })
        }
        Err(err) => Err(*err),
    };
    if let Ok(Some(temp)) = &cert {
        remove(temp);
    }
    finish(None, ret, if add { b"key add" } else { b"key fingerprint" })
}
