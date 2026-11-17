// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The map reading of `util/upatch_maps.h`, which hands an export what
//! a map holds.

use core::ffi::{c_char, c_int, c_void};

use crate::sys::btf::Btf;
use crate::util::json::JsonEmit;

/// UPATCH_NAME_MAX, MAP_NAME_MAX, UPATCH_LOCATION_MAX, MAP_TYPENAME_MAX
/// and MAP_TYPEDEF_MAX.
const UPATCH_NAME_MAX: usize = 256;
const MAP_NAME_MAX: usize = 16;
const UPATCH_LOCATION_MAX: usize = 160;
const MAP_TYPENAME_MAX: usize = 64;
const MAP_TYPEDEF_MAX: usize = 1024;

/// The entries a read returns unless asked for all, which 0 asks.
pub const MAP_ENTRIES_DEFAULT: u32 = 256;
/// Reads a serializer's interval without taking it from the exporter.
pub const MAP_READ_PEEK: u32 = 1 << 0;

/// `struct map_entry`: a key and its value, or values per CPU.
#[repr(C)]
pub struct MapEntry {
    pub key: *mut c_void,
    pub value: *mut c_void,
}

/// `struct serial_page`: one page a serializer handed over.
#[repr(C)]
pub struct SerialPage {
    pub page_index: u32,
    pub cursor: u64,
    pub next_cursor: u64,
    pub flags: u32,
    pub chunks: u32,
    pub bytes: u32,
    pub done: bool,
    pub data: *mut c_void,
}

/// `struct map_view`: one map's contents, as upatch_maps_read() reads
/// them.
#[repr(C)]
pub struct MapView {
    pub upatch: [u8; UPATCH_NAME_MAX + 1],
    pub name: [u8; MAP_NAME_MAX + 1],
    pub location: [u8; UPATCH_LOCATION_MAX],
    pub ty: u32,
    pub type_name: *const c_char,
    pub key_size: u32,
    pub value_size: u32,
    pub value_stride: u32,
    pub max_entries: u32,
    pub n_entries: u32,
    pub n_cpus: u32,
    pub lifetime_start_ns: u64,
    pub truncated: bool,
    pub n_truncated_at: u32,
    pub serialized: bool,
    pub n_serial_pages: u32,
    pub serial_bytes_total: u64,
    pub serial_pages: *mut SerialPage,
    pub skipped: bool,
    pub skipped_reason: *const c_char,
    pub btf_key_type: [u8; MAP_TYPENAME_MAX],
    pub btf_value_type: [u8; MAP_TYPENAME_MAX],
    pub key_type_def: [u8; MAP_TYPEDEF_MAX],
    pub value_type_def: [u8; MAP_TYPEDEF_MAX],
    pub key_type_id: u32,
    pub value_type_id: u32,
    pub btf: *mut Btf,
    pub entries: *mut MapEntry,
    pub entries_cap: usize,
}

const _: () = assert!(size_of::<MapEntry>() == 16);
const _: () = assert!(size_of::<SerialPage>() == 48);
const _: () = assert!(core::mem::offset_of!(SerialPage, done) == 36);
const _: () = assert!(size_of::<MapView>() == 2736);
const _: () = assert!(core::mem::offset_of!(MapView, location) == 274);
const _: () = assert!(core::mem::offset_of!(MapView, ty) == 436);
const _: () = assert!(core::mem::offset_of!(MapView, lifetime_start_ns) == 472);
const _: () = assert!(core::mem::offset_of!(MapView, serial_bytes_total) == 496);
const _: () = assert!(core::mem::offset_of!(MapView, skipped_reason) == 520);
const _: () = assert!(core::mem::offset_of!(MapView, btf_key_type) == 528);
const _: () = assert!(core::mem::offset_of!(MapView, value_type_def) == 1680);
const _: () = assert!(core::mem::offset_of!(MapView, key_type_id) == 2704);
const _: () = assert!(core::mem::offset_of!(MapView, btf) == 2712);
const _: () = assert!(core::mem::offset_of!(MapView, entries_cap) == 2728);

unsafe extern "C" {
    /// Whether BPF_MAP_TYPE_* `ty` keeps a value per CPU.
    pub fn upatch_map_is_percpu(ty: u32) -> bool;
    /// The bytes between two CPUs' values of a per-CPU map.
    pub fn upatch_map_value_stride(v: *const MapView) -> u32;
    /// One key or value as text, through the map's BTF: an allocation
    /// for xstrfree(), or NULL.
    pub fn upatch_map_format_cell(
        v: *const MapView,
        type_id: u32,
        value: *const c_void,
        value_size: u32,
        btf_type: *const c_char,
    ) -> *mut c_char;
    /// The sum of a per-CPU value over its CPUs, as text, or NULL.
    pub fn upatch_map_format_percpu_sum(
        v: *const MapView,
        values_per_cpu: *const c_void,
        btf_type: *const c_char,
    ) -> *mut c_char;
    /// Map `map` of upatch `upatch` into `out`, at most `cap` entries or
    /// all for 0, MAP_READ_PEEK in `flags` to leave a serializer's
    /// interval for the exporter: 0 or -errno; map_view_free() frees it.
    pub fn upatch_maps_read(
        upatch: *const c_char,
        map: *const c_char,
        cap: u32,
        flags: u32,
        out: *mut MapView,
    ) -> c_int;
    /// Frees what a read put in `v`.
    pub fn map_view_free(v: *mut MapView);
    /// Prints the map read, its types and entries, to stdout.
    pub fn upatch_maps_print_detail(v: *const MapView);
    /// Emits the map read as a JSON object, as the status report has it.
    pub fn upatch_maps_emit_json_object(e: *mut JsonEmit, v: *const MapView);
}
