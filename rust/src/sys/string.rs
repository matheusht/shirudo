// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The formatter of `include/shirudo/string.h`, which as a C-variadic
//! function stays in C.

use core::ffi::{c_char, c_int};

unsafe extern "C" {
    /// snprintf() into the `size` bytes at `buf`: the length written, or
    /// -E2BIG, with `buf` left empty, when the output did not fit.
    pub fn strsprintf(buf: *mut c_char, size: usize, fmt: *const c_char, ...) -> c_int;
}
