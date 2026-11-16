// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The CMS signer of `util/sign.h`, which only `shirudo-build` links.

use core::ffi::{c_char, c_int, c_void};

/// `struct sign_io`: what cms_sign() signs, and the room its signature
/// goes into, `signature_sz` its size and then the signature's.
#[repr(C)]
pub struct SignIo {
    pub insns: *const c_void,
    pub insns_sz: usize,
    pub data: *const c_void,
    pub data_sz: usize,
    pub signature: *mut c_void,
    pub signature_sz: usize,
    pub payload_sha256: [u8; 32],
}

unsafe extern "C" {
    /// Signs `io`'s instructions and data, CMS, with the key at
    /// `pkey_path` and the certificate at `cert_path`: 0 or -errno.
    pub fn cms_sign(io: *mut SignIo, pkey_path: *const c_char, cert_path: *const c_char) -> c_int;
    /// Opens the private key at `pkey_path` and checks, on that
    /// descriptor, that it is a regular file of mode 0600: the
    /// descriptor, or -errno logged.
    pub fn open_signing_key(pkey_path: *const c_char) -> c_int;
}
