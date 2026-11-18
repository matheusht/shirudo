// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! A package's identity: the name and version its build environment
//! records, and the signer of the certificate it carries.

use core::ffi::{c_char, c_int};
use core::ptr;

use openssl::x509::{X509, X509Ref};

use super::PackageInfo;
use super::archive::{Found, read_member_in};
use crate::errno::{EINVAL, EKEYREJECTED};
use crate::ffi;
use crate::heap::xfree;
use crate::text::cstr;
use crate::util::bpm_oci::{MAX_DIGEST, MAX_NAME, copy_string, package_name_ok, version_ok};
use crate::util::crypto_openssl::{pubkey_digest, x509_from_der_bio};
use crate::util::hex::hex_encode;
use crate::util::json::{JsonField, parse_schema};

/// The most a package's build environment or certificate may hold.
const MEMBER_MAX: usize = 4 * 1024 * 1024;

/// EVP_MAX_MD_SIZE hex digits and a NUL.
const HEX_SIZE: usize = 64 * 2 + 1;

/// What build-environment.json says of the package.
struct Parsed {
    name: [u8; MAX_NAME],
    version: [u8; MAX_NAME],
    signer: [u8; MAX_DIGEST],
}

/// The certificate in `body`, DER or PEM; none when it holds neither.
fn read_x509_memory(body: &[u8]) -> Option<X509> {
    if c_int::try_from(body.len()).is_err() {
        return None;
    }
    x509_from_der_bio(body)
        .or_else(|_| X509::from_pem(body))
        .ok()
}

/// The name, version and signer of the `.bee` at `archive` into `info`,
/// with the certificate that signed it.
pub(super) fn load_info(archive: *const c_char, info: &mut PackageInfo) -> c_int {
    let mut environment: *mut u8 = ptr::null_mut();
    let mut environment_len = 0;
    let ret = read_member_in(
        archive,
        Some(b"build-environment.json"),
        None,
        &mut Found {
            out: &mut environment,
            out_len: &mut environment_len,
            dir: None,
        },
        MEMBER_MAX,
    );
    if ret != 0 {
        return ret;
    }
    // SAFETY: read_member_in() gave environment_len bytes at
    // environment, which stay until freed below.
    let text = unsafe { ffi::slice(environment, environment_len) };
    let ret = identify(archive, text, info);

    // SAFETY: the allocation read_member_in() made, given back once.
    unsafe { xfree(environment.cast(), environment_len + 1) };
    if ret != 0 {
        // SAFETY: NULL, or the certificate read_member_in() gave.
        unsafe { xfree(info.cert.cast(), info.cert_len + 1) };
        info.cert = ptr::null_mut();
        info.cert_len = 0;
    }
    ret
}

fn identify(archive: *const c_char, environment: &[u8], info: &mut PackageInfo) -> c_int {
    let mut parsed = Parsed {
        name: [0; MAX_NAME],
        version: [0; MAX_NAME],
        signer: [0; MAX_DIGEST],
    };
    let mut package_fields = [
        JsonField::string(c"name", (&raw mut parsed.name).cast(), MAX_NAME),
        JsonField::string(c"version", (&raw mut parsed.version).cast(), MAX_NAME),
    ];
    let mut shirudo_fields = [JsonField::string(
        c"spki_sha256_fingerprint",
        (&raw mut parsed.signer).cast(),
        MAX_DIGEST,
    )];
    let mut root = [
        JsonField::object(
            c"package",
            package_fields.as_mut_ptr(),
            package_fields.len(),
        ),
        JsonField::object(
            c"shirudo",
            shirudo_fields.as_mut_ptr(),
            shirudo_fields.len(),
        ),
    ];
    // SAFETY: every pointer of the schema names a local of this frame,
    // which outlives the parse and is touched meanwhile only through
    // those pointers.
    let ret = unsafe { parse_schema(environment, root.as_mut_ptr(), root.len()) };

    if ret != 0
        || !root[0].seen()
        || parsed.name[0] == 0
        || parsed.version[0] == 0
        || !package_name_ok(cstr(&parsed.name))
        || !version_ok(cstr(&parsed.version))
    {
        return -EINVAL;
    }
    let ret = read_member_in(
        archive,
        Some(b"cert.der"),
        None,
        &mut Found {
            out: &mut info.cert,
            out_len: &mut info.cert_len,
            dir: None,
        },
        MEMBER_MAX,
    );
    if ret != 0 {
        return ret;
    }
    // SAFETY: the cert_len bytes read_member_in() left at cert.
    let body = unsafe { ffi::slice(info.cert.cast_const(), info.cert_len) };
    let cert = read_x509_memory(body);

    signed_by(cert.as_deref(), &parsed, info)
}

/// The signer `cert` names, checked against the one the build
/// environment records, and the identity into `info`.
fn signed_by(cert: Option<&X509Ref>, parsed: &Parsed, info: &mut PackageInfo) -> c_int {
    let mut hex = [0u8; HEX_SIZE];
    let Some(Ok(digest)) = cert.map(pubkey_digest) else {
        return -EINVAL;
    };
    // SAFETY: the digest, and room for its hex and a NUL.
    unsafe { hex_encode(digest.as_ptr(), digest.len(), hex.as_mut_ptr().cast()) };
    let hex = cstr(&hex);
    if parsed.signer[0] != 0 && !cstr(&parsed.signer).eq_ignore_ascii_case(hex) {
        // SAFETY: the C's format, and two terminated buffers for it.
        unsafe {
            crate::log::log_c!(crate::log::err,
                c"bpm: package signer fingerprint mismatch: certificate=%s build-environment.json=%s"
                    .as_ptr(),
                hex.as_ptr(),
                parsed.signer.as_ptr(),
            )
        };
        return -EKEYREJECTED;
    }
    copy_string(&mut info.name, cstr(&parsed.name));
    copy_string(&mut info.version, cstr(&parsed.version));
    copy_string(&mut info.signer, hex);
    0
}
