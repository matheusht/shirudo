// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The identity of `util/identity.h`, which init froze into the kernel;
//! util/identity.rs reads it.

/// `struct identity` of util/identity.h, the value of the identity map,
/// which bpf/lib/identity.h calls `struct sb_id`: as bpf2's BTF lays it
/// out.
pub(crate) use crate::skel::bpf2::SbId as Identity;

/// DEVICE_RUNTIME and DEVICE_CONFIG of util/identity.h: what a mapping
/// the guards watched being made was made as.
pub const DEVICE_RUNTIME: u32 = 1;
pub const DEVICE_CONFIG: u32 = 2;

/// `struct device_authority`, a value of the guards' devices map, which
/// bpf/lib/verity.h calls `struct verity_device`: a dm-verity mapping,
/// its kind and root, and the disk sequence number of the instance they
/// watched.
pub(crate) use crate::skel::bpf2::VerityDevice as DeviceAuthority;
