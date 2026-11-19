// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The map reading, which hands an export what
//! a map holds.

use core::ffi::CStr;

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

/// A key and its value, or its values per CPU a value stride apart, as
/// a read copied them.
pub struct MapEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// One page a serializer handed over.
pub struct SerialPage {
    pub page_index: u32,
    pub cursor: u64,
    pub next_cursor: u64,
    pub flags: u32,
    pub chunks: u32,
    pub done: bool,
    pub data: Vec<u8>,
}

impl SerialPage {
    /// The bytes the page holds, which a read bounds well below 4 GiB.
    pub fn bytes(&self) -> u32 {
        u32::try_from(self.data.len()).unwrap_or(u32::MAX)
    }
}

/// One map's contents, as util::map_read reads them.
pub struct MapView {
    pub upatch: [u8; UPATCH_NAME_MAX + 1],
    pub name: [u8; MAP_NAME_MAX + 1],
    pub location: [u8; UPATCH_LOCATION_MAX],
    pub ty: u32,
    pub type_name: Option<&'static CStr>,
    pub key_size: u32,
    pub value_size: u32,
    pub value_stride: u32,
    pub max_entries: u32,
    pub n_cpus: u32,
    pub lifetime_start_ns: u64,
    /// The pin directory's payload digest, when it has one.
    pub has_payload: bool,
    pub payload: [u8; 32],
    pub truncated: bool,
    pub n_truncated_at: u32,
    pub serialized: bool,
    pub serial_bytes_total: u64,
    pub serial_pages: Vec<SerialPage>,
    pub skipped: bool,
    pub skipped_reason: Option<&'static CStr>,
    pub btf_key_type: [u8; MAP_TYPENAME_MAX],
    pub btf_value_type: [u8; MAP_TYPENAME_MAX],
    pub key_type_def: [u8; MAP_TYPEDEF_MAX],
    pub value_type_def: [u8; MAP_TYPEDEF_MAX],
    pub key_type_id: u32,
    pub value_type_id: u32,
    pub btf: *mut Btf,
    pub entries: Vec<MapEntry>,
}

/// The view of no map, which a read or a test fills in.
impl Default for MapView {
    fn default() -> Self {
        MapView {
            upatch: [0; UPATCH_NAME_MAX + 1],
            name: [0; MAP_NAME_MAX + 1],
            location: [0; UPATCH_LOCATION_MAX],
            ty: 0,
            type_name: None,
            key_size: 0,
            value_size: 0,
            value_stride: 0,
            max_entries: 0,
            n_cpus: 0,
            lifetime_start_ns: 0,
            has_payload: false,
            payload: [0; 32],
            truncated: false,
            n_truncated_at: 0,
            serialized: false,
            serial_bytes_total: 0,
            serial_pages: Vec::new(),
            skipped: false,
            skipped_reason: None,
            btf_key_type: [0; MAP_TYPENAME_MAX],
            btf_value_type: [0; MAP_TYPENAME_MAX],
            key_type_def: [0; MAP_TYPEDEF_MAX],
            value_type_def: [0; MAP_TYPEDEF_MAX],
            key_type_id: 0,
            value_type_id: 0,
            btf: core::ptr::null_mut(),
            entries: Vec::new(),
        }
    }
}

impl MapView {
    /// The entries read, as many as a map's u32 count can say.
    pub fn n_entries(&self) -> u32 {
        u32::try_from(self.entries.len()).unwrap_or(u32::MAX)
    }

    /// The serialized pages read, at most SERIAL_MAX_PAGES.
    pub fn n_serial_pages(&self) -> u32 {
        u32::try_from(self.serial_pages.len()).unwrap_or(u32::MAX)
    }
}
