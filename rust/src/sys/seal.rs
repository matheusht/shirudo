// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The labelled file creation of `util/seal.h`.

use core::ffi::{c_char, c_int};

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
}
