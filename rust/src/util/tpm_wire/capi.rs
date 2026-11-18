// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C-shaped interface the crate still calls. A function copies its digests,
//! names and keys before it writes an output, so that an output may be
//! one of them, as the policy digests' `prev` and `out` are.

use core::ffi::c_int;

use super::policy::{self, RegisterPolicy};
use super::{DIGEST_LEN, NV_RSA_BYTES};
use crate::ffi;

/// The TCG default endorsement key policy,
/// PolicySecret(TPM_RH_ENDORSEMENT).
pub const EK_POLICY: [u8; DIGEST_LEN] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
    0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
];

/// A copy of the `N` bytes at `p`.
///
/// # Safety
///
/// `p` points to `N` readable bytes.
unsafe fn copy<const N: usize>(p: *const u8) -> [u8; N] {
    // SAFETY: the caller's N bytes, which have no alignment to keep.
    unsafe { p.cast::<[u8; N]>().read() }
}

/// The room for `N` bytes at `p`.
///
/// # Safety
///
/// `p` points to `N` writable bytes that nothing else accesses for `'a`.
unsafe fn room<'a, const N: usize>(p: *mut u8) -> &'a mut [u8; N] {
    // SAFETY: the caller's N bytes, which have no alignment to keep.
    unsafe { &mut *p.cast::<[u8; N]>() }
}

/// # Safety
///
/// `pcr_values` holds `n_values` digests, `writer_public` a modulus, and
/// `branch_written`, `branch_init` and `policy` are three distinct rooms
/// for a digest.
pub unsafe extern "C" fn tpm_register_policy(
    pcr_mask: u32,
    pcr_values: *const u8,
    n_values: usize,
    writer_public: *const u8,
    branch_written: *mut u8,
    branch_init: *mut u8,
    policy: *mut u8,
) -> c_int {
    // SAFETY: the caller passes the values, a modulus and three rooms.
    unsafe {
        let modulus = copy::<NV_RSA_BYTES>(writer_public);
        let out = RegisterPolicy {
            branch_written: room(branch_written),
            branch_init: room(branch_init),
            policy: room(policy),
        };

        policy::register_policy(
            pcr_mask,
            ffi::slice(pcr_values, n_values.wrapping_mul(DIGEST_LEN)),
            &modulus,
            out,
        )
    }
}

/// # Safety
///
/// `policy` holds a digest and `name` has room for a name.
pub unsafe extern "C" fn tpm_nv_name(
    index: u32,
    attrs: u32,
    policy: *const u8,
    data_size: u16,
    name: *mut u8,
) -> c_int {
    // SAFETY: the caller passes a digest and the room.
    unsafe {
        let policy = copy::<DIGEST_LEN>(policy);

        policy::nv_name(index, attrs, &policy, data_size, room(name))
    }
}
