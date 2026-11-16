// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo version`: the release name and SHIRUDO_VERSION_ID.

use core::ffi::{c_char, c_int};
use core::ptr;

use super::word;
use crate::sys::libc::printf;
use crate::sys::version::{
    shirudo_extraversion, shirudo_release_name, shirudo_version, shirudo_version_id,
};
use crate::util::help::{Help, HelpItem, HelpSection, is_help, print_help};

/// The command on `args`, its name first.
///
/// # Safety
///
/// Each of `args` is NULL or a C string.
unsafe fn version(args: &[*const c_char]) -> c_int {
    // SAFETY: the caller's word.
    let arg = args.get(1).and_then(|&arg| unsafe { word(arg) });

    if is_help(arg) {
        let options = [HelpItem {
            name: c"--version-id".as_ptr(),
            summary: c"print only the raw SHIRUDO_VERSION_ID, one line".as_ptr(),
        }];
        let sections = [HelpSection {
            header: c"options:".as_ptr(),
            items: options.as_ptr(),
            n_items: options.len(),
        }];
        let help = Help {
            usage: c"shirudo version [--version-id]".as_ptr(),
            summary: c"Print the release tag plus the architecture-stripped SHIRUDO_VERSION_ID\n\
                       that targets compare against the operator's signed artifacts."
                .as_ptr(),
            sections: sections.as_ptr(),
            n_sections: sections.len(),
            footer: ptr::null(),
        };

        // SAFETY: the help, its strings literals and its arrays the
        // locals above.
        unsafe { print_help(&help) };
        return 0;
    }
    // SAFETY: the C's formats, and the build's identity strings.
    unsafe {
        if matches!(arg, Some(b"--version-id")) {
            printf(c"%s\n".as_ptr(), &raw const shirudo_version_id);
            return 0;
        }
        printf(
            c"shirudo (%s%s, \"%s\")\n".as_ptr(),
            &raw const shirudo_version,
            &raw const shirudo_extraversion,
            &raw const shirudo_release_name,
        );
        printf(c"version-id: %s\n".as_ptr(), &raw const shirudo_version_id);
    }
    0
}

pub(super) use capi::cmd_version;

mod capi {
    use core::ffi::{c_char, c_int};

    use super::super::words;

    /// # Safety
    ///
    /// `argv` holds `argc` C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cmd_version(argc: c_int, argv: *const *const c_char) -> c_int {
        // SAFETY: the caller passes the command line.
        unsafe { super::version(words(argc, argv)) }
    }
}
