// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo image`: activating and inspecting the signed config image on
//! a target; building and verifying one is the operator's, in
//! shirudo-build.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use std::ffi::CString;

use super::words;
use crate::errno::{EINPROGRESS, ENODEV};
use crate::ffi;
use crate::sys::libc::{fwrite, stderr, stdout, strerror};
use crate::util::image_runtime;

const HELP: &[u8] = b"usage: shirudo image build [image builder options]\n       \
shirudo image verify <prefix> --cert <certificate>\n       \
shirudo image update <prefix-or-https-prefix>\n       \
shirudo image status [--json]\n";

fn write(stream: *mut crate::sys::libc::File, text: &[u8]) {
    // SAFETY: the bytes, to one of the C library's streams.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stream) };
}

fn error(parts: &[&[u8]]) {
    let msg = CString::new(parts.concat()).unwrap_or_default();

    // SAFETY: a "%s" format with a C string.
    unsafe { crate::log::log_c!(crate::log::err, c"%s".as_ptr(), msg.as_ptr()) };
}

/// `shirudo image`.
///
/// # Safety
///
/// `argv` holds `argc` C strings.
unsafe fn image(argc: c_int, argv: *const *const c_char) -> c_int {
    // SAFETY: the caller's arguments.
    let raw = unsafe { words(argc, argv) };
    // SAFETY: each a C string.
    let args: Vec<&[u8]> = raw.iter().map(|&a| unsafe { ffi::c_str(a) }).collect();
    let n = args.len();

    if n == 2 && args[1] == b"--list-cmds" {
        // SAFETY: the C library's stdout.
        write(unsafe { stdout }, b"build verify update status\n");
        return 0;
    }
    if n < 2 || args[1] == b"--help" || args[1] == b"-h" {
        // SAFETY: the C library's stderr.
        write(unsafe { stderr }, HELP);
        return if n < 2 { 2 } else { 0 };
    }
    let ret = match args[1] {
        b"build" | b"verify" => {
            let label: &CStr = if args[1] == b"build" {
                c"image build"
            } else {
                c"image verify"
            };
            let words = [c"image".as_ptr(), ptr::null()];
            // SAFETY: a label, the words up to their NULL, and the
            // caller's arguments from the subcommand on.
            return unsafe {
                super::build::forward(label.as_ptr(), words.as_ptr(), argc - 1, argv.add(1))
            };
        }
        // SAFETY: the caller's C string.
        b"update" if n == 3 => image_runtime::update(unsafe { CStr::from_ptr(raw[2]) }),
        b"status" if n == 2 || (n == 3 && args[2] == b"--json") => {
            let ret = image_runtime::status(n == 3);
            if ret == -ENODEV {
                error(&[b"image status: no config activation state on this host"]);
                return 1;
            }
            ret
        }
        _ => {
            // SAFETY: the C library's stderr.
            write(unsafe { stderr }, HELP);
            return 2;
        }
    };
    if ret == -EINPROGRESS {
        error(&[b"image: activation is pending; further changes are blocked"]);
    } else if ret != 0 {
        // SAFETY: strerror() gives a C string.
        let why = unsafe { ffi::c_str(strerror(-ret)) };
        error(&[b"image ", args[1], b": ", why]);
    }
    if ret != 0 { 1 } else { 0 }
}

pub(super) use capi::cmd_image;

mod capi {
    use core::ffi::{c_char, c_int};

    /// # Safety
    ///
    /// `argv` holds `argc` C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cmd_image(argc: c_int, argv: *const *const c_char) -> c_int {
        // SAFETY: the caller's arguments.
        unsafe { super::image(argc, argv) }
    }
}
