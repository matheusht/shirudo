// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The `.upatch` reader of `util/upatch.h`.

use core::ffi::c_char;

pub const NAME_MAX: usize = 256;
pub const PAYLOAD_HASH_LEN: usize = 32;

unsafe extern "C" {
    /// Whether `name` and `payload_hex` make a member of a measured set:
    /// a name upatch_name_valid() takes and the 64 hex digits of its
    /// payload's SHA-256.
    pub fn upatch_member_valid(name: *const c_char, payload_hex: *const c_char) -> bool;
}
