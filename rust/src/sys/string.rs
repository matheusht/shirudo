// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The string helpers of `include/shirudo/string.h` that stay in C.

use core::ffi::{c_char, c_int};

unsafe extern "C" {
    /// How many of the `len` bytes at `s`, from the first, are decimal
    /// digits.
    pub fn digits(s: *const c_char, len: usize) -> usize;
    /// The decimal number the `len` bytes at `s` spell, digits alone and
    /// at most `max`, into `*out`; -EINVAL or -ERANGE.
    pub fn parse_u64(s: *const c_char, len: usize, max: u64, out: *mut u64) -> c_int;
    /// parse_u64() of hexadecimal digits.
    pub fn parse_x64(s: *const c_char, len: usize, max: u64, out: *mut u64) -> c_int;
    /// The string `src` into the `size` bytes at `dst`, terminated
    /// whenever `size` is not 0: its length, or -E2BIG when it did not
    /// fit.
    pub fn strscpy(dst: *mut c_char, src: *const c_char, size: usize) -> isize;
    /// snprintf() into the `size` bytes at `buf`: the length written, or
    /// -E2BIG, with `buf` left empty, when the output did not fit.
    pub fn strsprintf(buf: *mut c_char, size: usize, fmt: *const c_char, ...) -> c_int;
    /// A DNS host name: labels of letters, digits and inner hyphens, 1 to
    /// 63 bytes each and 253 in all, not all of them decimal or 0x
    /// numbers, which an IPv4 parser would read as an address.
    pub fn dns_name_valid(name: *const c_char) -> bool;
    /// The `len` bytes at `s` made safe to print on a terminal, their
    /// length unchanged; with `lines`, tabs and line feeds kept.
    pub fn text_sanitize(s: *mut c_char, len: usize, lines: bool);
    /// Whether the `len` bytes of `name` end in `suffix` after at least
    /// one byte of their own.
    pub fn name_has_suffix(name: *const c_char, len: usize, suffix: *const c_char) -> bool;
}
