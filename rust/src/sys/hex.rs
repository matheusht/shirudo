// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The hex helpers of `util/hex.h`.

use core::ffi::{c_char, c_int};

unsafe extern "C" {
    /// The `2 * n` lowercase hex digits of the `n` bytes at `inp`, and a
    /// NUL, at `out`.
    pub fn hex_encode(inp: *const u8, n: usize, out: *mut c_char);
    /// The `n` bytes `2 * n` hex digits of either case spell; -EINVAL for
    /// anything else.
    pub fn hex_decode(hex: *const c_char, out: *mut u8, n: usize) -> c_int;
    /// An even run of at most `2 * cap` hex digits into `out`, and how
    /// many bytes; -EINVAL for anything else.
    pub fn hex_decode_max(hex: *const c_char, out: *mut u8, cap: usize, len: *mut usize) -> c_int;
    /// The 32 bytes of a `sha256:<64 hex digits>` digest; -EINVAL for
    /// anything else.
    pub fn sha256_digest_decode(digest: *const c_char, out: *mut u8) -> c_int;
}
