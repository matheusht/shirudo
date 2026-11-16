// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The config image runtime of `util/image_runtime.h`.

use core::ffi::{c_char, c_int, c_void};

use crate::util::keys::TrustedSet;

unsafe extern "C" {
    /// Reads the authenticated image settings the bootstrap names: 0, a
    /// positive count, or -errno.
    pub fn image_bootstrap_load() -> c_int;
    /// The runtime image's root hash, 32 bytes, zero without one.
    pub fn image_runtime_root() -> *const u8;
    /// Mounts the authenticated runtime image: 0 or -errno.
    pub fn image_runtime_mount() -> c_int;
    /// The boot key image's trusted certificates into `set`: 0 or -errno.
    pub fn image_boot_keys(set: *mut TrustedSet) -> c_int;
    /// Closes the boot key image: 0 or -errno.
    pub fn image_boot_keys_close() -> c_int;
    /// Loads the runtime image's boot settings: 0 or -errno.
    pub fn image_boot() -> c_int;
    /// Completes the authenticated boot: 0 or -errno.
    pub fn image_boot_complete() -> c_int;
    /// Leaves the images this command entered.
    pub fn image_leave();
    /// The config activation's state: 0, -EINPROGRESS while one is
    /// pending, the integrity error the other commands refuse on, or
    /// -ENODEV without activation state; `root` the selected or pending
    /// config's root hash, zero when unknown.
    pub fn image_config_state(root: *mut [u8; 32]) -> c_int;
    /// The config activation journal of this command, which attestation
    /// reports on; NULL without one.
    pub fn image_update_context() -> *mut c_void;
    /// Activates the config image at `prefix`, a path or an https URL
    /// prefix: 0, -EINPROGRESS while an activation is pending, or -errno.
    pub fn image_update(prefix: *const c_char) -> c_int;
    /// Prints the config activation state, as JSON with `json`: 0,
    /// -ENODEV without activation state, or -errno.
    pub fn image_status(json: bool) -> c_int;
}
