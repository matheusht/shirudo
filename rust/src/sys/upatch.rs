// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! An install's result, as the C-shaped code shares it.

use core::ffi::c_int;

/// What an install gives for a valid upatch whose target module is not
/// loaded.
pub const UPATCH_INSTALL_TARGET_MISSING: c_int = 2;
