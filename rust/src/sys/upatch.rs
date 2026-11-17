// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! What `util/upatch.h` and `util/upatch_maps.h` share with the C: an
//! install's result and a map's summary.

use core::ffi::{c_char, c_int};

/// What an install gives for a valid upatch whose target module is not
/// loaded.
pub const UPATCH_INSTALL_TARGET_MISSING: c_int = 2;

/// `struct map_summary`: a map of an upatch, as upatch_maps lists it.
#[repr(C)]
pub struct MapSummary {
    pub upatch: [u8; 257],
    pub name: [u8; 17],
    pub ty: u32,
    pub type_name: *const c_char,
    pub max_entries: u32,
    pub n_cpus: u32,
}

const _: () = assert!(size_of::<MapSummary>() == 296);
const _: () = assert!(core::mem::offset_of!(MapSummary, type_name) == 280);
