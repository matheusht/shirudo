// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The tamper counters of `util/tamper.h`: what the guards refused this
//! boot, read back from the map init pinned.

use core::ffi::{c_char, c_int};

/// `TAMPER_MAX` of `bpf/lib/tamper.h`: the tamper points there are.
pub const TAMPER_MAX: usize = 37;

/// `struct tamper_counts`.
#[repr(C)]
pub struct TamperCounts {
    pub count: [u64; TAMPER_MAX],
    pub total: u64,
}

const _: () = assert!(size_of::<TamperCounts>() == 8 * (TAMPER_MAX + 1));

unsafe extern "C" {
    /// The counters into `out`: 0, -ENOENT before init, or another
    /// -errno.
    pub fn tamper_read(out: *mut TamperCounts) -> c_int;
    /// The name of a tamper point, a static C string.
    pub fn tamper_name(point: c_int) -> *const c_char;
    /// What a tamper point's refusals mean, a static C string.
    pub fn tamper_meaning(point: c_int) -> *const c_char;
}
