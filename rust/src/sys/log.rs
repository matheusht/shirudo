// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The logging of `util/log.h`. A Rust caller passes the format the C
//! passed, with the same arguments, so that a message reads as before,
//! cut and escaped by the same code.

use core::ffi::c_char;

unsafe extern "C" {
    /// Opens the log: syslog with the process's name, and stderr.
    pub fn log_init();
    pub fn pr_err(fmt: *const c_char, ...);
    pub fn pr_warn(fmt: *const c_char, ...);
    pub fn pr_info(fmt: *const c_char, ...);
    pub fn pr_audit(fmt: *const c_char, ...);
}
