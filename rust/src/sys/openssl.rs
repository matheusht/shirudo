// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The OpenSSL calls util/ makes past the wrappers of `util/crypto.h`.

use core::ffi::{c_char, c_int, c_long, c_void};

/// A `BIO`.
pub enum Bio {}

/// An `X509` certificate.
pub enum X509 {}

/// The `pem_password_cb` of a PEM read.
pub type PemPasswordCb =
    unsafe extern "C" fn(buf: *mut c_char, size: c_int, rwflag: c_int, u: *mut c_void) -> c_int;

/// The `BIO_ctrl()` command `BIO_reset()` sends.
pub const BIO_CTRL_RESET: c_int = 1;

unsafe extern "C" {
    pub fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut Bio;
    pub fn BIO_ctrl(bio: *mut Bio, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    pub fn BIO_free(bio: *mut Bio) -> c_int;
    pub fn d2i_X509_bio(bio: *mut Bio, x509: *mut *mut X509) -> *mut X509;
    pub fn PEM_read_bio_X509(
        bio: *mut Bio,
        x509: *mut *mut X509,
        cb: Option<PemPasswordCb>,
        u: *mut c_void,
    ) -> *mut X509;
    pub fn X509_free(x509: *mut X509);
}
