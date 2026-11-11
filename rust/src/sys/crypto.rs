// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The TLS policy of `util/crypto.h`, which util/tls_openssl.c keeps;
//! the rest of the header is rust/src/util/crypto_openssl.rs.

use core::ffi::{c_char, c_int, c_void};

use super::curl::Curl;

/// `struct tls_ca`: the CA file a client trusts, and what the TLS policy
/// made of it.
#[repr(C)]
pub struct TlsCa {
    pub path: *const c_char,
    imp: *mut c_void,
}

unsafe extern "C" {
    /// TLS 1.3 with hybrid ML-KEM alone, and the client's CA, on `curl`.
    pub fn tls_curl_policy(curl: *mut Curl, ca: *mut TlsCa) -> c_int;
    pub fn tls_ca_cleanup(ca: *mut TlsCa);
}
