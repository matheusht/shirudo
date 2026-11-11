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
}
