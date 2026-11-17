// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C-variadic logging of `util/log.h`, which formats a message in C
//! and hands it to rust/src/log.rs. A Rust caller passes the format the
//! C passed, with the same arguments, so that a message reads as before.

use core::ffi::c_char;

unsafe extern "C" {
    pub fn pr_err(fmt: *const c_char, ...);
    pub fn pr_warn(fmt: *const c_char, ...);
    pub fn pr_info(fmt: *const c_char, ...);
    pub fn pr_audit(fmt: *const c_char, ...);
}
