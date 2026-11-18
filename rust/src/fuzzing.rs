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

unsafe extern "C" {
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> core::ffi::c_int;
    fn LLVMFuzzerInitialize(
        argc: *mut core::ffi::c_int,
        argv: *mut *mut *mut core::ffi::c_char,
    ) -> core::ffi::c_int;
}

/// The files `paths` names, a directory's files sorted by name, each
/// given once to the target the binary links, without libFuzzer: for
/// memcheck, which takes the comparisons libFuzzer's coverage traces for
/// reads of memory never written. 0, or 1 when a path cannot be read.
fn replay(paths: &[&std::path::Path]) -> core::ffi::c_int {
    let mut files = Vec::new();
    for path in paths {
        match std::fs::read_dir(path) {
            Ok(dir) => {
                let mut names: Vec<_> = dir.flatten().map(|e| e.path()).collect();
                names.sort();
                files.extend(names.into_iter().filter(|p| p.is_file()));
            }
            Err(_) => files.push(path.to_path_buf()),
        }
    }
    // SAFETY: the target's setup, which takes no arguments.
    unsafe { LLVMFuzzerInitialize(core::ptr::null_mut(), core::ptr::null_mut()) };
    let mut ret = 0;
    for file in files {
        let Ok(data) = std::fs::read(&file) else {
            eprintln!("replay: cannot read {}", file.display());
            ret = 1;
            continue;
        };
        // Its own allocation of its length, so that memcheck sees a read
        // past the end.
        let data = data.into_boxed_slice();
        // SAFETY: the input's bytes, of its length.
        unsafe { LLVMFuzzerTestOneInput(data.as_ptr(), data.len()) };
    }
    ret
}

/// The main() of testing/fuzz/replay.rs: [`replay`] of its arguments.
///
/// # Safety
///
/// main()'s arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shirudo_fuzz_replay(
    argc: core::ffi::c_int,
    argv: *const *const core::ffi::c_char,
) -> core::ffi::c_int {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: main()'s argc C strings.
    let args = unsafe { crate::ffi::slice(argv, usize::try_from(argc).unwrap_or(0)) };
    let paths: Vec<&std::path::Path> = args
        .iter()
        .skip(1)
        .map(|&a| {
            // SAFETY: each a C string.
            let arg = unsafe { crate::ffi::c_str(a) };
            std::path::Path::new(std::ffi::OsStr::from_bytes(arg))
        })
        .collect();
    replay(&paths)
}
