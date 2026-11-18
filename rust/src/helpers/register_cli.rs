// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-register-cli: `shirudo attest` and `shirudo status` without
//! the rest of shirudo's start, for the register tests: protocol setup
//! and offline prediction do not enter the runtime.
//!
//!   test-register-cli attest|status [options]

use core::ffi::{c_char, c_int};

use super::err;
use crate::builtin::{cmd_attest, cmd_status};
use crate::util::harden::{harden_self, harden_stdio};
use crate::util::identity::enforcement_active;

/// # Safety
///
/// The arguments the C runtime passes main().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shirudo_helper_test_register_cli(
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    harden_stdio();
    crate::log::init();
    if harden_self() != 0 {
        return 1;
    }
    // SAFETY: main()'s arguments.
    let args = unsafe { super::args(argc, argv) };
    let word = |i: usize| args.get(i).map(|a| a.to_bytes());
    // SAFETY: the arguments past the program's name, handed on.
    let command = |run: unsafe extern "C" fn(c_int, *const *const c_char) -> c_int| unsafe {
        run(argc - 1, argv.add(1))
    };

    if word(1) == Some(b"attest") && word(2) == Some(b"predict") {
        return command(cmd_attest);
    }
    if enforcement_active() != 0 {
        err("register CLI fixture requires an uninitialized target\n");
        return 1;
    }
    match word(1) {
        Some(b"attest") => command(cmd_attest),
        Some(b"status") => command(cmd_status),
        _ => {
            err("usage: test-register-cli attest|status [options]\n");
            2
        }
    }
}
