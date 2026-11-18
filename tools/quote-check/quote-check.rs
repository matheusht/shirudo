// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! main() of the backend's keepalive quote checker, which hands the
//! command line to quote_check_main() in rust/src/quote_check.rs. An
//! object of its own, built with no std, for the reason shirudo.rs is
//! one: the tests link the Rust library with a main() of their own.

#![no_std]

use core::ffi::{c_char, c_int};

unsafe extern "C" {
    fn quote_check_main(argc: c_int, argv: *mut *mut c_char) -> c_int;
}

/// # Safety
///
/// The arguments the C runtime passes main().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn main(argc: c_int, argv: *mut *mut c_char) -> c_int {
    // SAFETY: the C runtime's arguments, handed on.
    unsafe { quote_check_main(argc, argv) }
}
