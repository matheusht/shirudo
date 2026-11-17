// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The build identity of `util/version.h`, which the generated
//! build/main/version_id.rs defines, an object of its own: each the
//! first byte of a C string.

use core::ffi::c_char;

unsafe extern "C" {
    pub static shirudo_version: c_char;
    pub static shirudo_version_id: c_char;
    pub static shirudo_extraversion: c_char;
    pub static shirudo_release_name: c_char;
}
