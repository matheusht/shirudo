// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The string helpers of `include/shirudo/string.h` that stay in C.

use core::ffi::c_char;

unsafe extern "C" {
    /// A DNS host name: labels of letters, digits and inner hyphens, 1 to
    /// 63 bytes each and 253 in all, not all of them decimal or 0x
    /// numbers, which an IPv4 parser would read as an address.
    pub fn dns_name_valid(name: *const c_char) -> bool;
    /// The `len` bytes at `s` made safe to print on a terminal, their
    /// length unchanged; with `lines`, tabs and line feeds kept.
    pub fn text_sanitize(s: *mut c_char, len: usize, lines: bool);
}
