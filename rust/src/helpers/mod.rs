// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The test helpers: programs the functional tests run, each a function
//! that a main object of its own, made from testing/helper/main.rs.in,
//! hands the command line. A build of the library with the test-helpers
//! feature holds them; the shipped one does not.

use core::ffi::{CStr, c_char, c_int};

use crate::sys::libc::{fwrite, stderr, stdout};

mod bpm_source;
mod conditions;
mod config_image;
mod harden;
mod image_cleanup;
mod image_cli;
mod mode_objects;
mod register_cli;
mod seal;
mod upatch_map_types;

/// The arguments the C runtime gave main(), as C strings.
///
/// # Safety
///
/// `argv` holds `argc` C strings that live as long as the process.
pub(crate) unsafe fn args(argc: c_int, argv: *const *const c_char) -> Vec<&'static CStr> {
    (0..argc.max(0) as usize)
        // SAFETY: the C runtime's arguments.
        .map(|i| unsafe { CStr::from_ptr(*argv.add(i)) })
        .collect()
}

/// `text` to standard output through the C library's stream, which the
/// crate's own output goes through and the C runtime flushes at exit.
pub(crate) fn out(text: &str) {
    // SAFETY: the bytes of text and the C library's stream.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stdout) };
}

/// `text` to standard error, as out() writes standard output.
pub(crate) fn err(text: &str) {
    // SAFETY: as out().
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stderr) };
}

/// The helper `name`'s main(): `run` of its arguments.
macro_rules! helper_main {
    ($symbol:ident, $run:path) => {
        /// # Safety
        ///
        /// The arguments the C runtime passes main().
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $symbol(
            argc: core::ffi::c_int,
            argv: *const *const core::ffi::c_char,
        ) -> core::ffi::c_int {
            // SAFETY: main()'s arguments, handed on.
            $run(&unsafe { crate::helpers::args(argc, argv) })
        }
    };
}
pub(crate) use helper_main;
