// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! What the libFuzzer targets share, in the build of the library with
//! libFuzzer's coverage, cfg shirudo_fuzz. Each target is a `fuzz.rs`
//! of the module it fuzzes, beside its `tests.rs`, whose entry points
//! fuzz_target!() exports and testing/fuzz/target.rs.in makes a
//! target's LLVMFuzzerTestOneInput() and LLVMFuzzerInitialize() call.

use std::ffi::CString;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// The target's entry points: `$run` of each input, and `$init` once
/// before the first.
macro_rules! fuzz_target {
    ($run_sym:ident, $init_sym:ident, $run:expr) => {
        $crate::fuzzing::fuzz_target!($run_sym, $init_sym, $run, || {});
    };
    ($run_sym:ident, $init_sym:ident, $run:expr, $init:expr) => {
        /// # Safety
        ///
        /// libFuzzer's input of `size` bytes.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $run_sym(data: *const u8, size: usize) -> core::ffi::c_int {
            let run: fn(&[u8]) = $run;
            // SAFETY: libFuzzer's input.
            run(unsafe { $crate::ffi::slice(data, size) });
            0
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn $init_sym() -> core::ffi::c_int {
            let init: fn() = $init;
            init();
            0
        }
    };
}
pub(crate) use fuzz_target;

/// An input as a file of its own: a memfd and its path through
/// /proc/self/fd, its offset past the data.
pub(crate) struct InputFile {
    pub(crate) fd: OwnedFd,
    pub(crate) path: CString,
}

pub(crate) fn input_file(data: &[u8]) -> Option<InputFile> {
    // SAFETY: memfd_create(2) of a C string and flags.
    let fd = unsafe { libc::memfd_create(c"fuzz".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return None;
    }
    // SAFETY: the descriptor just made, owned here.
    let mut file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    file.write_all(data).ok()?;
    let fd = OwnedFd::from(file);
    let path = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok()?;
    Some(InputFile { fd, path })
}

/// An input as a gzip file: as it is when it is one, else compressed.
pub(crate) fn input_gzip_file(data: &[u8]) -> Option<InputFile> {
    if data.starts_with(&[0x1f, 0x8b]) {
        return input_file(data);
    }
    input_file(&crate::util::gzip::gzip(data).ok()?)
}
