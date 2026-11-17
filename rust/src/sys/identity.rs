// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The identity of `util/identity.h`, which init froze into the kernel;
//! util/identity.rs reads it.

/// `struct identity`, the frozen ABI shared with bpf/lib/identity.h: the
/// fields read here, and the rest as the header lays them out.
#[repr(C)]
pub struct Identity {
    pub sb_dev: u32,
    pub run_dev: u32,
    pub keyring_serial: i32,
    pub keyring_type: u32,
    pub n_keys: u32,
    pub key_serials: [i32; 16],
    pub runtime_root: [u8; 32],
    pub nv_writer_seed: [u8; 32],
    pub nv_writer_public: [u8; 384],
    pub ek_name: [u8; 34],
    pub dm_verity_ring: i32,
    pub dm_verity_key: i32,
    pub nv_index: u32,
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

/// DEVICE_RUNTIME and DEVICE_CONFIG of util/identity.h: what a mapping
/// the guards watched being made was made as.
pub const DEVICE_RUNTIME: u32 = 1;
pub const DEVICE_CONFIG: u32 = 2;

/// `struct device_authority`, a value of the guards' devices map: a
/// dm-verity mapping, its kind and root, and the disk sequence number
/// of the instance they watched.
#[repr(C)]
pub struct DeviceAuthority {
    pub dev: u32,
    pub kind: u32,
    pub root: [u8; 32],
    pub diskseq: u64,
}

const _: () = assert!(size_of::<DeviceAuthority>() == 48);

impl DeviceAuthority {
    pub const fn zeroed() -> Self {
        DeviceAuthority {
            dev: 0,
            kind: 0,
            root: [0; 32],
            diskseq: 0,
        }
    }
}
