// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The commands of `builtin.h` that have moved to Rust, one module for
//! each `builtin-<command>.c` they replace. The table in `commands`
//! dispatches to them with the command line from the command's name on.

use core::ffi::{c_char, c_int};

use crate::ffi;

mod attest;
mod bpm;
mod build;
mod commands;
mod config;
mod genkey;
mod image;
mod init;
pub(crate) mod keys;
mod status;
mod upatch;
mod version;

/// The commands the register CLI test helper runs.
#[cfg(feature = "test-helpers")]
pub(crate) use {attest::cmd_attest, status::cmd_status};

/// The `argc` words of a command line at `argv`.
///
/// # Safety
///
/// When `argc` is above 0, `argv` holds `argc` words that stay valid for
/// `'a`.
pub(crate) unsafe fn words<'a>(argc: c_int, argv: *const *const c_char) -> &'a [*const c_char] {
    // SAFETY: the caller passes the words.
    unsafe { ffi::slice(argv, usize::try_from(argc).unwrap_or(0)) }
}

/// A word of a command line, or none for NULL.
///
/// # Safety
///
/// `arg` is NULL or a C string that stays valid for `'a`.
unsafe fn word<'a>(arg: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller passes NULL or a C string.
    (!arg.is_null()).then(|| unsafe { ffi::c_str(arg) })
}
