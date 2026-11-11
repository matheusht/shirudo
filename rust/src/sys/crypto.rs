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
    pub fn cert_free(cert: *mut Cert);
    /// TLS 1.3 with hybrid ML-KEM alone, and the client's CA, on `curl`.
    pub fn tls_curl_policy(curl: *mut Curl, ca: *mut TlsCa) -> c_int;
    pub fn tls_ca_cleanup(ca: *mut TlsCa);
}
