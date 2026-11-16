// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The config image runtime of `util/image_runtime.h`.

use core::ffi::{c_char, c_int};

unsafe extern "C" {
    /// Activates the config image at `prefix`, a path or an https URL
    /// prefix: 0, -EINPROGRESS while an activation is pending, or -errno.
    pub fn image_update(prefix: *const c_char) -> c_int;
    /// Prints the config activation state, as JSON with `json`: 0,
    /// -ENODEV without activation state, or -errno.
    pub fn image_status(json: bool) -> c_int;
}
