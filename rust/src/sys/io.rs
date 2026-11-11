// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The file helpers of `util/io.h`.

use core::ffi::{c_char, c_int, c_void};

unsafe extern "C" {
    /// All `len` bytes at `buf` to `fd`, or a negative errno.
    pub fn write_complete(fd: c_int, buf: *const c_void, len: usize) -> c_int;
    /// The file at `path`, of at most `max` bytes, into an allocation of
    /// `*len + 1` bytes ending in a NUL, which `xfree()` releases.
    pub fn read_file(path: *const c_char, max: usize, out: *mut c_void, len: *mut usize) -> c_int;
}
