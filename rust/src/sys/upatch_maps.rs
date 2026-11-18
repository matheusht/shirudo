// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The map reading, which hands an export what
//! a map holds.

use core::ffi::{c_char, c_void};

use crate::bpf::btf::Btf;

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

/// `struct map_view`: one map's contents, as util::map_read reads
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
    /// The pin directory's payload digest, when it has one.
    pub has_payload: bool,
    pub payload: [u8; 32],
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
const _: () = assert!(size_of::<MapView>() == 2768);
const _: () = assert!(core::mem::offset_of!(MapView, location) == 274);
const _: () = assert!(core::mem::offset_of!(MapView, ty) == 436);
const _: () = assert!(core::mem::offset_of!(MapView, lifetime_start_ns) == 472);
const _: () = assert!(core::mem::offset_of!(MapView, has_payload) == 480);
const _: () = assert!(core::mem::offset_of!(MapView, truncated) == 513);
const _: () = assert!(core::mem::offset_of!(MapView, serial_bytes_total) == 528);
const _: () = assert!(core::mem::offset_of!(MapView, skipped_reason) == 552);
const _: () = assert!(core::mem::offset_of!(MapView, btf_key_type) == 560);
const _: () = assert!(core::mem::offset_of!(MapView, value_type_def) == 1712);
const _: () = assert!(core::mem::offset_of!(MapView, key_type_id) == 2736);
const _: () = assert!(core::mem::offset_of!(MapView, btf) == 2744);
const _: () = assert!(core::mem::offset_of!(MapView, entries_cap) == 2760);
