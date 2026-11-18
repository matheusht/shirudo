// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The test helpers: programs the functional tests run, each a function
//! that a main object of its own, made from testing/helper/main.rs.in,
//! hands the command line. A build of the library with the test-helpers
//! feature holds them; the shipped one does not.

use core::ffi::{CStr, c_char, c_int};

use crate::sys::libc::{fwrite, stderr, stdout};

mod bpf_cmd;
mod bpf_load;
mod bpm_source;
mod conditions;
mod config;
mod config_attest;
mod config_image;
mod config_update;
mod eventlog;
mod exec_churn;
mod exec_fail;
mod exec_shared;
mod harden;
mod image_cleanup;
mod image_cli;
mod image_config;
mod image_keys;
mod keepalive_quote;
mod keyring_seal;
mod keys;
mod mode_objects;
mod nv_cphash;
mod nv_writer;
mod perf_attach;
mod register;
mod register_cli;
mod seal;
mod seal_output;
mod signed_load;
mod tpm_client;
mod tpm_preopened;
mod tpm_session;
mod tpm_wire;
mod upatch_decode;
mod upatch_link_lockdown;
mod upatch_map_types;
mod upatch_prog_metadata;
mod upatch_rodata;
mod upatch_serializer_pages;
mod xdp;
mod xfs_attrmulti;

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

/// `bytes` to standard output through the C library's stream, which the
/// crate's own output goes through and the C runtime flushes at exit;
/// whether they all went.
pub(crate) fn out_bytes(bytes: &[u8]) -> bool {
    // SAFETY: the bytes and the C library's stream.
    unsafe { fwrite(bytes.as_ptr().cast(), 1, bytes.len(), stdout) == bytes.len() }
}

/// `text` to standard output, as out_bytes() writes.
pub(crate) fn out(text: &str) {
    out_bytes(text.as_bytes());
}

/// `text` to standard error, as out() writes standard output.
pub(crate) fn err(text: &str) {
    // SAFETY: as out().
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stderr) };
}

/// The C library's text for `errno`.
pub(crate) fn strerror(errno: c_int) -> String {
    // SAFETY: the C library's text for an errno, static.
    unsafe { CStr::from_ptr(crate::sys::libc::strerror(errno)) }
        .to_string_lossy()
        .into_owned()
}

/// `what`, and the text of the errno of the call that just failed, to
/// standard error, as perror() writes them.
pub(crate) fn perror(what: &str) {
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    err(&format!("{what}: {}\n", strerror(errno)));
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
