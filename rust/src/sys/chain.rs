// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The measurement chain of `util/chain.h`.

unsafe extern "C" {
    /// The 32 bytes at `chain` extended with the 32-byte `event`, as the
    /// register folds an event in: 0 or -errno.
    pub fn chain_fold(chain: *mut u8, event: *const u8) -> core::ffi::c_int;
}
