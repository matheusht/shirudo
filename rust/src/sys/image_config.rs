// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The image configuration of `util/image_config.h`.

unsafe extern "C" {
    /// Whether a target runs from a config image, whose paths no
    /// environment variable moves.
    pub fn image_config_active() -> bool;
}
