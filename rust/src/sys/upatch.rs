// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Loading and unloading upatches, of `util/upatch.h`, which
//! builtin-upatch.c implements.

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

unsafe extern "C" {
    /// The maps of upatch `name` into `*out`, their count into `*n`, which
    /// map_summary_free() frees: 0 or -errno.
    pub fn upatch_maps_list_one(
        upatch: *const c_char,
        out: *mut *mut MapSummary,
        n: *mut usize,
    ) -> c_int;
    /// The maps of every loaded upatch into `*out`, their count into
    /// `*n`, which map_summary_free() frees: 0 or -errno.
    pub fn upatch_maps_list_all(out: *mut *mut MapSummary, n: *mut usize) -> c_int;
    /// Prints the `n` summaries at `list` as a table to stdout.
    pub fn upatch_maps_print_summary(list: *const MapSummary, n: usize);
    /// Frees the `n` summaries at `list`, NULL for none.
    pub fn map_summary_free(list: *mut MapSummary, n: usize);
    /// Loads the archived upatch at `path`: 0 or -errno.
    pub fn upatch_apply(path: *const c_char) -> c_int;
}
