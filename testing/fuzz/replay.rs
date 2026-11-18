// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The main() of a fuzz target built for memcheck, without libFuzzer:
//! each file it is given, once, through the target its entry object
//! links.
//!
//!   build/fuzz-replay/fuzz-<target> <file or directory>...

#![no_std]

unsafe extern "C" {
    fn shirudo_fuzz_replay(argc: i32, argv: *const *const u8) -> i32;
}

/// # Safety
///
/// The arguments the C runtime passes main().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn main(argc: i32, argv: *const *const u8) -> i32 {
    // SAFETY: main()'s arguments, handed on.
    unsafe { shirudo_fuzz_replay(argc, argv) }
}
