// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-seal: the seal's creation helpers on paths a shell test names,
//! and what it asserts on printed.
//!
//!   test-seal label|mkdir|inherit|get <path>
//!   test-seal open|write <path> <text>

use core::ffi::{CStr, c_int};
use std::io::Write;
use std::os::fd::IntoRawFd;

use super::{err, helper_main, out};
use crate::sys::libc::lgetxattr;
use crate::util::seal::{self, XATTR};

helper_main!(shirudo_helper_test_seal, run);

/// `text` appended to `path`, opened through the seal.
fn append(path: &CStr, text: &CStr) -> Result<(), c_int> {
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND;
    let mut file = std::fs::File::from(seal::open(path.to_bytes(), flags, 0o600)?);
    let written = file
        .write_all(text.to_bytes())
        .map_err(|e| -e.raw_os_error().unwrap_or(libc::EIO));
    // SAFETY: the file's descriptor, which the close takes over.
    if unsafe { libc::close(file.into_raw_fd()) } != 0 && written.is_ok() {
        return Err(-crate::sys::libc::errno());
    }
    written
}

/// The label an inode carries, or none, without following a link.
fn show_label(path: &CStr) {
    let mut label = [0u8; 128];
    // SAFETY: a C string, the attribute's name, and room for its value.
    let n = unsafe {
        lgetxattr(
            path.as_ptr(),
            XATTR.as_ptr(),
            label.as_mut_ptr().cast(),
            label.len() - 1,
        )
    };
    if n < 0 {
        out("label=none\n");
    } else {
        out(&format!(
            "label={}\n",
            String::from_utf8_lossy(&label[..n as usize])
        ));
    }
}

fn run(args: &[&CStr]) -> c_int {
    if args.len() < 3 {
        err(&format!(
            "usage: {} label|mkdir|open|write|inherit|get <path> [text]\n",
            args.first()
                .map_or("test-seal".into(), |a| a.to_string_lossy())
        ));
        return 2;
    }
    let path = args[2];
    let done = match (args[1].to_bytes(), args.get(3)) {
        (b"get", _) => {
            show_label(path);
            return 0;
        }
        (b"label", _) => seal::label(path),
        (b"mkdir", _) => seal::mkdir_p(path.to_bytes(), 0o700),
        (b"open", Some(text)) if args.len() == 4 => append(path, text),
        (b"write", Some(text)) if args.len() == 4 => {
            seal::write_file(path.to_bytes(), text.to_bytes(), 0o600)
        }
        (b"inherit", _) => seal::inherit_path(path),
        _ => {
            err("unknown subcommand\n");
            return 2;
        }
    };
    let ret = done.err().unwrap_or(0);
    out(&format!("rc={ret}\n"));
    c_int::from(ret != 0)
}
