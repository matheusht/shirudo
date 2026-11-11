// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The build identity of `util/version.h`, which the generated
//! util/version_id.c defines.

use core::ffi::c_char;

unsafe extern "C" {
    /// The first byte of the build's version ID, a C string.
    pub static shirudo_version_id: c_char;
}
