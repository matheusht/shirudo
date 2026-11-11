// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The gzip file reading of zlib.

use core::ffi::{c_char, c_int, c_uint, c_void};

pub const Z_OK: c_int = 0;

/// A `gzFile`'s `struct gzFile_s`, which only zlib looks into.
pub enum GzFileS {}

unsafe extern "C" {
    pub fn gzopen(path: *const c_char, mode: *const c_char) -> *mut GzFileS;
    pub fn gzdopen(fd: c_int, mode: *const c_char) -> *mut GzFileS;
    /// Whether the file is read as it is, not being gzip.
    pub fn gzdirect(file: *mut GzFileS) -> c_int;
    /// Up to `len` bytes into `buf`: how many, 0 at the end, -1 on error.
    pub fn gzread(file: *mut GzFileS, buf: *mut c_void, len: c_uint) -> c_int;
    /// Z_OK, or what went wrong reading the file, its trailer included.
    pub fn gzclose(file: *mut GzFileS) -> c_int;
}
