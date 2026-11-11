// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The OpenSSL wrappers of `util/crypto.h`.

use core::ffi::{c_char, c_int, c_void};

use super::curl::Curl;

pub const SHA256_LEN: usize = 32;

/// `struct cert`.
#[repr(C)]
pub struct Cert {
    imp: *mut c_void,
}

impl Cert {
    pub const fn new() -> Self {
        Cert {
            imp: core::ptr::null_mut(),
        }
    }

    /// The cert of an OpenSSL `X509`, which the caller keeps and frees.
    pub const fn of_x509(x509: *mut c_void) -> Self {
        Cert { imp: x509 }
    }
}

/// `struct tls_ca`: the CA file a client trusts, and what the TLS policy
/// made of it.
#[repr(C)]
pub struct TlsCa {
    pub path: *const c_char,
    imp: *mut c_void,
}

unsafe extern "C" {
    pub fn sha256_buffer(data: *const c_void, len: usize, out: *mut u8) -> c_int;
    pub fn cert_read_file(path: *const c_char, cert: *mut Cert) -> c_int;
    pub fn cert_read_fd(fd: c_int, cert: *mut Cert) -> c_int;
    pub fn cert_free(cert: *mut Cert);
    /// The SHA-256 of the cert's SubjectPublicKeyInfo, 32 bytes at `out`.
    pub fn cert_pubkey_digest(cert: *const Cert, out: *mut u8) -> c_int;
    /// 0 when `signature` is a detached CMS signature of `payload` by
    /// `cert`.
    pub fn verify_detached(
        payload: *const u8,
        payload_len: usize,
        signature: *const u8,
        signature_len: usize,
        cert: *const Cert,
    ) -> c_int;
    /// TLS 1.3 with hybrid ML-KEM alone, and the client's CA, on `curl`.
    pub fn tls_curl_policy(curl: *mut Curl, ca: *mut TlsCa) -> c_int;
    pub fn tls_ca_cleanup(ca: *mut TlsCa);
}
