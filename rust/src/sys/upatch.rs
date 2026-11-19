// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! An install's result and a map's summary, as the C-shaped code
//! shares them.

use core::ffi::{CStr, c_int};

/// What an install gives for a valid upatch whose target module is not
/// loaded.
pub const UPATCH_INSTALL_TARGET_MISSING: c_int = 2;

/// `struct map_summary`: a map of an upatch, as upatch_maps lists it.
#[repr(C)]
pub struct MapSummary {
    pub upatch: [u8; 257],
    pub name: [u8; 17],
    pub ty: u32,
    pub type_name: Option<&'static CStr>,
    pub max_entries: u32,
    pub n_cpus: u32,
}

/// The summary of no map, which a listing fills in.
impl Default for MapSummary {
    fn default() -> Self {
        MapSummary {
            upatch: [0; 257],
            name: [0; 17],
            ty: 0,
            type_name: None,
            max_entries: 0,
            n_cpus: 0,
        }
    }
}
