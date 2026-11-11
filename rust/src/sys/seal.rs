// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The labelled file creation of `util/seal.h`.

use core::ffi::{c_char, c_int, c_void};

/// `struct seal_output`: a file being written in place of another.
#[repr(C)]
pub struct SealOutput {
    fd: c_int,
    dfd: c_int,
    name: *const c_char,
}

impl SealOutput {
    /// One not open, for seal_output_create() to fill.
    pub const fn closed() -> Self {
        SealOutput {
            fd: -1,
            dfd: -1,
            name: core::ptr::null(),
        }
    }
}

unsafe extern "C" {
    /// open(2), an inode it creates labelled as its sealed directory is:
    /// the fd, or -errno.
    pub fn seal_open(path: *const c_char, flags: c_int, mode: u32) -> c_int;
    /// mkdir -p, every directory created labelled as its parent is.
    pub fn seal_mkdir_p(path: *const c_char, mode: u32) -> c_int;
    /// The lock file at `path`, created sealed when it is not there, held
    /// exclusively until the fd it returns is closed; or -errno.
    pub fn seal_lock(path: *const c_char) -> c_int;
    /// `line` appended as one record to the sealed log at `path`, under
    /// the lock that keeps its appenders apart: 0 or -errno.
    pub fn seal_append_line(path: *const c_char, line: *const c_char, len: usize) -> c_int;
    /// The sealed file at `path` opened to be written whole: 0, or the
    /// -errno seal_output_open() refused with.
    pub fn seal_output_create(out: *mut SealOutput, path: *const c_char, mode: u32) -> c_int;
    /// `len` bytes at `buf` and a newline into the output, which it
    /// closes, unlinking a file it could not finish: 0 or -errno.
    pub fn seal_output_commit(out: *mut SealOutput, buf: *const c_void, len: usize) -> c_int;
    /// The `len` bytes at `data` as the whole of the sealed file at
    /// `path`, written in place of what was there: 0 or -errno.
    pub fn seal_write_file(
        path: *const c_char,
        data: *const c_void,
        len: usize,
        mode: u32,
    ) -> c_int;
}
