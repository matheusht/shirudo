// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The image configuration of `util/image_config.h`.

use core::ffi::{c_int, c_void};

unsafe extern "C" {
    /// The `struct config` a config image carries into `out`: nonzero
    /// when there is one.
    pub fn image_config_get(out: *mut c_void) -> c_int;
    /// Whether a target runs from a config image, whose paths no
    /// environment variable moves.
    pub fn image_config_active() -> bool;
}
