// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The identity of `util/identity.h`, which init froze into the kernel,
//! and its reader.

use core::ffi::c_int;

/// `struct identity`, the frozen ABI shared with bpf/lib/identity.h: the
/// fields read here, and the rest as the header lays them out.
#[repr(C)]
pub struct Identity {
    sb_dev: u32,
    run_dev: u32,
    pub keyring_serial: i32,
    pub keyring_type: u32,
    pub n_keys: u32,
    pub key_serials: [i32; 16],
    runtime_root: [u8; 32],
    pub nv_writer_seed: [u8; 32],
    pub nv_writer_public: [u8; 384],
    pub ek_name: [u8; 34],
    pub dm_verity_ring: i32,
    pub dm_verity_key: i32,
    nv_index: u32,
}

const _: () = assert!(size_of::<Identity>() == 580);
const _: () = assert!(core::mem::offset_of!(Identity, nv_writer_seed) == 116);
const _: () = assert!(core::mem::offset_of!(Identity, nv_writer_public) == 148);

impl Identity {
    pub const fn zeroed() -> Self {
        Identity {
            sb_dev: 0,
            run_dev: 0,
            keyring_serial: 0,
            keyring_type: 0,
            n_keys: 0,
            key_serials: [0; 16],
            runtime_root: [0; 32],
            nv_writer_seed: [0; 32],
            nv_writer_public: [0; 384],
            ek_name: [0; 34],
            dm_verity_ring: 0,
            dm_verity_key: 0,
            nv_index: 0,
        }
    }
}

unsafe extern "C" {
    /// The identity map init populated, froze and pinned this boot, into
    /// `out`: 0, -ENOENT before init, or another -errno.
    pub fn identity_read(out: *mut Identity) -> c_int;
    /// Whether this boot enforces: 1, 0, or -errno when the
    /// enforcement map cannot be read.
    pub fn enforcement_active() -> c_int;
}
