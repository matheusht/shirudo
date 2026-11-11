// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The TPM client of `util/tpm.h`.

use core::ffi::c_int;

/// A `struct tpm`: an open connection to the TPM.
pub enum Tpm {}

unsafe extern "C" {
    /// Opens the TPM into `*out`: 0 or -errno.
    pub fn tpm_open(out: *mut *mut Tpm) -> c_int;
    /// Closes what tpm_open() opened; NULL is nothing to close.
    pub fn tpm_close(t: *mut Tpm);
    /// Creates the NV writer key from the 32 bytes of `seed`, and gives
    /// its RSA modulus in the 384 bytes at `public`: 0 or -errno.
    pub fn tpm_writer_create(t: *mut Tpm, seed: *const u8, public: *mut u8) -> c_int;
}
