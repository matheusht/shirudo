// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The file helpers of `util/io.h`.

use core::ffi::{c_char, c_int, c_void};

use super::libc::File;

unsafe extern "C" {
    /// All `len` bytes at `buf` to `fd`, or a negative errno.
    pub fn write_complete(fd: c_int, buf: *const c_void, len: usize) -> c_int;
    /// The file at `path`, of at most `max` bytes, into an allocation of
    /// `*len + 1` bytes ending in a NUL, which `xfree()` releases.
    pub fn read_file(path: *const c_char, max: usize, out: *mut c_void, len: *mut usize) -> c_int;
    /// One line of at most `max` bytes before its newline, in getline()'s
    /// buffer, which free() releases: 1, 0 at the end, -E2BIG for a
    /// longer line and -EINVAL for one holding a NUL.
    pub fn read_text_line(
        f: *mut File,
        line: *mut *mut c_char,
        cap: *mut usize,
        max: usize,
    ) -> c_int;
    /// Whether the file open on `fd` at `path` may steer what shirudo
    /// trusts: under /etc/shirudo and /var/lib/shirudo, a regular file
    /// nobody else can write, nor with `secret` read. 0, or -EPERM logged.
    pub fn check_trusted(fd: c_int, path: *const c_char, secret: bool) -> c_int;
}
