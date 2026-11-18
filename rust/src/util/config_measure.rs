// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The measurement of a config root behind `util/config_measure.h`: the
//! PCRs a config may be measured into, and the event of a root.

use core::ffi::c_int;

use crate::errno::EINVAL;
use crate::util::crypto_openssl::sha256_buffer;

/// `enum config_event_kind`.
pub(crate) const EVENT_BOOT: c_int = 1;
pub(crate) const EVENT_UPDATE: c_int = 2;

const DOMAIN: &[u8] = b"shirudo-config-root-v1\0";

pub(crate) const CONFIG_NVPCR_INDEX: u32 = 0x0181_8e04;

pub(crate) fn nvpcr(pcr: u32) -> bool {
    pcr == CONFIG_NVPCR_INDEX
}

pub(crate) fn nvpcr_initial(out: &mut [u8; 32]) -> c_int {
    let zero = [0u8; 64];
    // SAFETY: 64 input bytes and a 32-byte output digest.
    unsafe { sha256_buffer(zero.as_ptr().cast(), zero.len(), out.as_mut_ptr()) }
}

/// A static config PCR or the config NvPCR: 0 or -EINVAL.
pub(crate) fn pcr_valid(pcr: u32) -> c_int {
    if (pcr < 16 && pcr != 9 && pcr != 11) || nvpcr(pcr) {
        0
    } else {
        -EINVAL
    }
}

/// The event that measures a config root: SHA-256 of the domain with its
/// NUL, the kind as a big-endian u32, and the root.
pub(crate) fn event(kind: c_int, root_hash: &[u8; 32], out: *mut u8) -> c_int {
    let mut data = [0u8; DOMAIN.len() + 4 + 32];

    if kind != EVENT_BOOT && kind != EVENT_UPDATE {
        return -EINVAL;
    }
    data[..DOMAIN.len()].copy_from_slice(DOMAIN);
    data[DOMAIN.len() + 3] = kind as u8;
    data[DOMAIN.len() + 4..].copy_from_slice(root_hash);
    // SAFETY: the bytes of data, and the caller's room for a digest.
    unsafe { sha256_buffer(data.as_ptr().cast(), data.len(), out) }
}

pub(crate) use capi::config_measure_pcr_valid;

mod capi {
    use core::ffi::c_int;

    use super::{event, pcr_valid};
    use crate::errno::EINVAL;
    use crate::util::crypto_openssl::sha256_buffer;

    pub extern "C" fn config_measure_pcr_valid(pcr: u32) -> c_int {
        pcr_valid(pcr)
    }

    /// The config register index accepted by the remaining C callers.
    #[unsafe(no_mangle)]
    pub extern "C" fn config_measure_nvpcr(pcr: u32) -> bool {
        pcr == 0x0181_8E04
    }

    /// # Safety
    ///
    /// out points to 32 writable bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_measure_nvpcr_initial(out: *mut u8) -> c_int {
        let zeros = [0u8; 64];

        // SAFETY: the input is 64 bytes and the caller provides the digest room.
        unsafe { sha256_buffer(zeros.as_ptr().cast(), zeros.len(), out) }
    }

    /// # Safety
    ///
    /// `root_hash` is NULL or holds 32 bytes, and `out` is NULL or has
    /// room for 32.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_measure_event(
        kind: c_int,
        root_hash: *const u8,
        out: *mut u8,
    ) -> c_int {
        if root_hash.is_null() || out.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller passes 32 bytes at root_hash.
        event(kind, unsafe { &*root_hash.cast::<[u8; 32]>() }, out)
    }
}
