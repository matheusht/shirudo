// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-seal: the seal's creation helpers on paths a shell test names,
//! and what it asserts on printed.
//!
//!   test-seal label|mkdir|inherit|get <path>
//!   test-seal open|write <path> <text>

use core::ffi::{CStr, c_int};

use super::{err, helper_main, out};
use crate::sys::libc::lgetxattr;
use crate::util::io::write_complete;
use crate::util::seal::{
    XATTR, seal_inherit_path, seal_label, seal_mkdir_p, seal_open, seal_write_file,
};

helper_main!(shirudo_helper_test_seal, run);

/// `text` appended to `path`, opened through the seal.
fn append(path: &CStr, text: &CStr) -> c_int {
    // SAFETY: a C string, flags and a mode.
    let fd = unsafe {
        seal_open(
            path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
            0o600,
        )
    };
    if fd < 0 {
        return fd;
    }
    // SAFETY: the descriptor seal_open() gave, written and closed once.
    unsafe {
        let ret = write_complete(fd, text.as_ptr().cast(), text.count_bytes());
        if libc::close(fd) != 0 && ret == 0 {
            return -crate::sys::libc::errno();
        }
        ret
    }
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
    // SAFETY: C strings of the command line, and modes.
    let ret = unsafe {
        match (args[1].to_bytes(), args.get(3)) {
            (b"get", _) => {
                show_label(path);
                return 0;
            }
            (b"label", _) => seal_label(path.as_ptr()),
            (b"mkdir", _) => seal_mkdir_p(path.as_ptr(), 0o700),
            (b"open", Some(text)) if args.len() == 4 => append(path, text),
            (b"write", Some(text)) if args.len() == 4 => seal_write_file(
                path.as_ptr(),
                text.as_ptr().cast(),
                text.count_bytes(),
                0o600,
            ),
            (b"inherit", _) => seal_inherit_path(path.as_ptr()),
            _ => {
                err("unknown subcommand\n");
                return 2;
            }
        }
    };
    out(&format!("rc={ret}\n"));
    c_int::from(ret != 0)
}
