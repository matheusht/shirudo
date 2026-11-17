// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! main(), which hands the command line to shirudo_main(), the dispatch
//! table of rust/src/builtin/commands.rs. It is an object of its own,
//! built with no std, not a part of the Rust library: the unit, fuzz and
//! helper executables link that library with a main() of their own.

#![no_std]

use core::ffi::{c_char, c_int};

unsafe extern "C" {
    fn shirudo_main(argc: c_int, argv: *const *const c_char) -> c_int;
}

/// # Safety
///
/// The arguments the C runtime passes main().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn main(argc: c_int, argv: *const *const c_char) -> c_int {
    // SAFETY: the C runtime's arguments, handed on.
    unsafe { shirudo_main(argc, argv) }
}
