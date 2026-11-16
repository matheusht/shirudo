// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Loading and unloading upatches, of `util/upatch.h`, which
//! builtin-upatch.c implements.

use core::ffi::{c_char, c_int, c_void};

/// What upatch_install() gives for a valid upatch whose target module
/// is not loaded.
pub const UPATCH_INSTALL_TARGET_MISSING: c_int = 2;

unsafe extern "C" {
    /// Loads the upatch at `path`: 0, UPATCH_INSTALL_TARGET_MISSING or
    /// -errno.
    pub fn upatch_install(path: *const c_char) -> c_int;
    /// Runs the unload directive at `path`: 0 or -errno.
    pub fn upatch_remove(path: *const c_char) -> c_int;
    /// Unloads, when loaded, and purges from the archive upatch `name`
    /// that the certificate at `signer` signed: 1 unloaded, 0 purged
    /// alone, -ESTALE for one the signer no longer signed, or -errno.
    pub fn upatch_purge(name: *const c_char, signer: *const c_void, reason: *const c_char)
    -> c_int;
}
