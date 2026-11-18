// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-seal-output: seal_output_create() and seal_output_commit() with
//! the write failing, as a file size limit of 0 makes every write to a
//! regular file fail, and root's move made before it.
//!
//!   test-seal-output fail|swap-dir|swap-file <path> [<dir>]
//!
//! swap-dir puts a symbolic link to dir in place of the path's directory,
//! swap-file another file in place of the one being written. Prints what
//! the commit returned.

use core::ffi::{CStr, c_int};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use super::{err, helper_main, out};
use crate::util::seal::{SealOutput, seal_output_commit, seal_output_create};

helper_main!(shirudo_helper_test_seal_output, run);

fn errno(e: std::io::Error) -> c_int {
    -e.raw_os_error().unwrap_or(libc::EIO)
}

fn moved(path: &Path) -> std::path::PathBuf {
    let mut m = path.as_os_str().to_owned();
    m.push(".moved");
    m.into()
}

/// The path's directory moved aside and a link to `dir` in its place.
fn swap_dir(path: &Path, dir: &OsStr) -> std::io::Result<()> {
    let parent = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    std::fs::rename(parent, moved(parent))?;
    std::os::unix::fs::symlink(dir, parent)
}

/// The file moved aside and an empty one in its place.
fn swap_file(path: &Path) -> std::io::Result<()> {
    std::fs::rename(path, moved(path))?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map(drop)
}

/// Every write to a regular file from here fails with EFBIG.
fn fail_writes() -> std::io::Result<()> {
    // SAFETY: SIGXFSZ ignored, and this process's file size limit read
    // and lowered.
    unsafe {
        let mut lim: libc::rlimit = core::mem::zeroed();
        if libc::signal(libc::SIGXFSZ, libc::SIG_IGN) == libc::SIG_ERR
            || libc::getrlimit(libc::RLIMIT_FSIZE, &mut lim) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        lim.rlim_cur = 0;
        if libc::setrlimit(libc::RLIMIT_FSIZE, &lim) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn run(args: &[&CStr]) -> c_int {
    if args.len() < 3 {
        err("usage: test-seal-output <how> <path> [<dir>]\n");
        return 2;
    }
    let how = args[1].to_bytes();
    let path = Path::new(OsStr::from_bytes(args[2].to_bytes()));
    let dir = OsStr::from_bytes(args.get(3).map_or(&b""[..], |d| d.to_bytes()));

    let mut output = SealOutput::closed();
    // SAFETY: room for the output and a C string of main()'s, which
    // outlives it.
    let mut ret = unsafe { seal_output_create(&mut output, args[2].as_ptr(), 0o600) };
    if ret == 0 {
        let moved = match how {
            b"swap-dir" => swap_dir(path, dir),
            b"swap-file" => swap_file(path),
            _ => Ok(()),
        };
        if let Err(e) = moved.and_then(|()| fail_writes()) {
            // SAFETY: the C library's text for an errno, static.
            let text = unsafe { CStr::from_ptr(crate::sys::libc::strerror(-errno(e))) };
            err(&format!(
                "test-seal-output: {}: {}\n",
                String::from_utf8_lossy(how),
                text.to_string_lossy()
            ));
        }
        // SAFETY: the output just created, its path still main()'s.
        ret = unsafe { seal_output_commit(&mut output, c"{}".as_ptr().cast(), 2) };
    }
    out(&format!("{ret}\n"));
    0
}
