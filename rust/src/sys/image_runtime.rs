// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The config image runtime of `util/image_runtime.h`.

use core::ffi::{c_char, c_int, c_void};

unsafe extern "C" {
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
