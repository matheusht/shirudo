// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The parts of `shirudo-build` in tools/shirudo-build/ that are still
//! C: the bpm commands.

use core::ffi::{c_char, c_int};

unsafe extern "C" {
    /// `shirudo-build bpm ...`, from its command word on.
    pub fn build_bpm(argc: c_int, argv: *mut *mut c_char) -> c_int;
    /// The upatch name a source or object path gives, into `cap` bytes
    /// at `out`: 0, or -ENAMETOOLONG.
    pub fn build_upatch_name(source: *const c_char, out: *mut c_char, cap: usize) -> c_int;
}
