// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Loading and unloading upatches, of `util/upatch.h`, which
//! builtin-upatch.c implements.

use core::ffi::{c_char, c_int, c_void};

use crate::sys::btf::Btf;

/// What upatch_install() gives for a valid upatch whose target module
/// is not loaded.
pub const UPATCH_INSTALL_TARGET_MISSING: c_int = 2;

/// `struct map_summary`: a map of an upatch, as upatch_maps lists it.
pub enum MapSummary {}

unsafe extern "C" {
    /// Where upatch `name` attaches, as a C string into the `cap` bytes at
    /// `out`, looked up in `vbtf`, the vmlinux BTF or NULL: 0 or -errno.
    pub fn upatch_resolve_location(
        vbtf: *mut Btf,
        name: *const c_char,
        out: *mut c_char,
        cap: usize,
    ) -> c_int;
    /// When upatch `name` was loaded, or "" when unknown.
    pub fn upatch_loaded_at(name: *const c_char, out: *mut c_char, cap: usize);
    /// The hex payload digest of loaded upatch `name`, or "".
    pub fn upatch_payload_sha256(name: *const c_char, out: *mut c_char, cap: usize);
    /// The maps of upatch `name` into `*out`, their count into `*n`, which
    /// map_summary_free() frees: 0 or -errno.
    pub fn upatch_maps_list_one(
        upatch: *const c_char,
        out: *mut *mut MapSummary,
        n: *mut usize,
    ) -> c_int;
    /// Frees the `n` summaries at `list`, NULL for none.
    pub fn map_summary_free(list: *mut MapSummary, n: usize);
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
