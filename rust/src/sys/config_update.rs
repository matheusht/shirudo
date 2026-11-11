// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The config update records of `util/config_update.h`.

use core::ffi::{c_int, c_void};

/// `struct config_update`, which only its own code reads.
pub enum ConfigUpdate {}

/// `struct config_update_record`: the fields read here, and the rest as
/// the header lays them out.
#[repr(C)]
pub struct ConfigUpdateRecord {
    prefix: [u8; 4096],
    pub root_hash: [u8; 32],
    pub initial_pcr: [u8; 32],
    pub sequence: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub pcr: u32,
    pub kind: c_int,
    pending: bool,
}

const _: () = assert!(size_of::<ConfigUpdateRecord>() == 4192);
const _: () = assert!(core::mem::offset_of!(ConfigUpdateRecord, sequence) == 4160);
const _: () = assert!(core::mem::offset_of!(ConfigUpdateRecord, kind) == 4180);

impl ConfigUpdateRecord {
    pub const fn zeroed() -> Self {
        ConfigUpdateRecord {
            prefix: [0; 4096],
            root_hash: [0; 32],
            initial_pcr: [0; 32],
            sequence: 0,
            reset_count: 0,
            restart_count: 0,
            pcr: 0,
            kind: 0,
            pending: false,
        }
    }
}

/// `shirudo_config_cb`.
pub type ConfigCb = unsafe extern "C" fn(r: *const ConfigUpdateRecord, ctx: *mut c_void) -> c_int;

unsafe extern "C" {
    /// The active record into `out`, refusing pending updates and PCR
    /// drift: 0 or -errno.
    pub fn config_update_check(update: *mut ConfigUpdate, out: *mut ConfigUpdateRecord) -> c_int;
    /// Each recorded event to `consume`, which stops the walk with what
    /// it returns when that is not 0.
    pub fn config_update_events(
        update: *mut ConfigUpdate,
        consume: Option<ConfigCb>,
        ctx: *mut c_void,
    ) -> c_int;
}
