// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The sole exec site in the core shirudo binary: `shirudo build`, and
//! the operator's halves of other commands, run by the operator-only
//! helper, shirudo-build.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use super::word;
use crate::errno::ENOMEM;
use crate::ffi::c_splice;
use crate::sys::libc::{PATH_MAX, X_OK, access, env, errno, execv, execvp, strerror};
use crate::sys::log::pr_err;
use crate::sys::malloc::{xcalloc, xfree};
use crate::util::help::{Help, is_help, print_help};

/// LIBEXEC_DIR: where packages install the helper, which the build
/// passes in SHIRUDO_LIBEXEC_DIR as it passes the C its -D, with the C's
/// default.
const LIBEXEC_DIR: &str = match option_env!("SHIRUDO_LIBEXEC_DIR") {
    Some(dir) => dir,
    None => "/usr/local/libexec/shirudo",
};
const INSTALLED: &CStr = c_splice!(LIBEXEC_DIR, "/shirudo-build");
const USAGE: &CStr = c_splice!(
    "shirudo build <input.bpf.c|.bpf.o> [-o <output.upatch>] [options]\n",
    "       shirudo build --unload <upatch-name> [-o <output.upatch>] [options]",
);
const SUMMARY: &CStr = c_splice!(
    "Build a signed BPF .upatch artifact ready\nfor target-side loading. Operator-only: \
     dispatches to the separate\nshirudo-build binary. The helper is resolved in this order:\n\
     SHIRUDO_BUILD, ",
    LIBEXEC_DIR,
    "/shirudo-build, then shirudo-build on PATH.\n\
     Run the selected helper with --help for the full option list.",
);

/// The helper, and whether to look it up on PATH: SHIRUDO_BUILD,
/// possibly empty, which the callers refuse, the installed one, or else
/// the bare name.
fn resolve_helper() -> (&'static CStr, bool) {
    if let Some(over) = env(c"SHIRUDO_BUILD") {
        return (over, false);
    }
    // SAFETY: a path, and a mode.
    if unsafe { access(INSTALLED.as_ptr(), X_OK) } == 0 {
        return (INSTALLED, false);
    }
    (c"shirudo-build", true)
}

/// Whether `name` is executable in one of the directories of PATH that
/// has room for it.
fn on_path(name: &CStr) -> bool {
    let Some(path) = env(c"PATH") else {
        return false;
    };
    let name = name.to_bytes();

    for dir in path.to_bytes().split(|&c| c == b':') {
        let mut candidate = [0u8; PATH_MAX];

        if dir.is_empty() || dir.len() + 1 + name.len() >= PATH_MAX {
            continue;
        }
        candidate[..dir.len()].copy_from_slice(dir);
        candidate[dir.len()] = b'/';
        candidate[dir.len() + 1..][..name.len()].copy_from_slice(name);
        // SAFETY: the candidate, a C string within its array, and a mode.
        if unsafe { access(candidate.as_ptr().cast(), X_OK) } == 0 {
            return true;
        }
    }
    false
}

fn available() -> bool {
    let (helper, use_path) = resolve_helper();

    if helper.is_empty() {
        return false;
    }
    if use_path {
        on_path(helper)
    } else {
        // SAFETY: a path, and a mode.
        unsafe { access(helper.as_ptr(), X_OK) == 0 }
    }
}

/// Runs the helper with `argv`, whose first it points at the helper's
/// path; returns only when it cannot, with 127.
///
/// # Safety
///
/// `label` is a C string, and `argv` an array of C strings after its
/// first, up to a NULL.
unsafe fn exec(label: *const c_char, argv: *mut *const c_char) -> c_int {
    let (path, use_path) = resolve_helper();

    if path.is_empty() {
        // SAFETY: the C's format and the caller's label.
        unsafe { pr_err(c"'%s' cannot use empty SHIRUDO_BUILD".as_ptr(), label) };
        return 127;
    }
    // SAFETY: a path, and a mode.
    if !use_path && unsafe { access(path.as_ptr(), X_OK) } != 0 {
        // SAFETY: the C's format, the caller's label and the path.
        unsafe {
            pr_err(
                c"'%s' is an operator-only subcommand; shirudo-build helper '%s' is not \
                  executable. Set SHIRUDO_BUILD to a helper path or put shirudo-build on PATH."
                    .as_ptr(),
                label,
                path.as_ptr(),
            )
        };
        return 127;
    }
    // SAFETY: the caller's array, its first now the path and the rest C
    // strings up to a NULL.
    unsafe {
        *argv = path.as_ptr();
        if use_path {
            execvp(path.as_ptr(), argv.cast_const());
        } else {
            execv(path.as_ptr(), argv.cast_const());
        }
        pr_err(c"exec %s: %s".as_ptr(), path.as_ptr(), strerror(errno()));
    }
    127
}

/// Runs the helper with `words`, up to their NULL, and then the `argc`
/// arguments at `argv`.
///
/// # Safety
///
/// `label` is a C string, `words` C strings up to a NULL, and `argv`
/// holds `argc` C strings.
unsafe fn forward(
    label: *const c_char,
    words: *const *const c_char,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let argc = usize::try_from(argc).unwrap_or(0);
    let mut n = 0;

    // SAFETY: the caller's words, up to their NULL.
    while !unsafe { *words.add(n) }.is_null() {
        n += 1;
    }
    let count = n + argc + 2;
    // SAFETY: a count of pointers.
    let helper = unsafe { xcalloc(count, size_of::<*const c_char>()) }.cast::<*const c_char>();
    if helper.is_null() {
        // SAFETY: the C's format, the caller's label and the error's text.
        unsafe { pr_err(c"'%s': %s".as_ptr(), label, strerror(ENOMEM)) };
        return 1;
    }
    // SAFETY: room for count pointers, zeroed, so that the first and the
    // last stay NULL, filled from the caller's words and arguments; then
    // freed whole.
    unsafe {
        for i in 0..n {
            *helper.add(1 + i) = *words.add(i);
        }
        for i in 0..argc {
            *helper.add(1 + n + i) = *argv.add(i);
        }
        let ret = exec(label, helper);
        xfree(helper.cast(), count * size_of::<*const c_char>());
        ret
    }
}

/// `shirudo build`: the helper, run on the caller's arguments.
///
/// # Safety
///
/// `argv` holds `argc` C strings and a NULL after them.
unsafe fn build(argc: c_int, argv: *mut *const c_char) -> c_int {
    // SAFETY: the caller's second word, when there is one.
    if argc >= 2 && is_help(unsafe { word(*argv.add(1)) }) {
        let help = Help {
            usage: USAGE.as_ptr(),
            summary: SUMMARY.as_ptr(),
            sections: ptr::null(),
            n_sections: 0,
            footer: ptr::null(),
        };

        // SAFETY: the help, its strings constants.
        unsafe { print_help(&help) };
        return 0;
    }
    // SAFETY: a label, and the caller's arguments.
    unsafe { exec(c"build".as_ptr(), argv) }
}

mod capi {
    use core::ffi::{c_char, c_int};

    #[unsafe(no_mangle)]
    pub extern "C" fn build_available() -> bool {
        super::available()
    }

    /// # Safety
    ///
    /// `label` is a C string, and `argv` an array of C strings after its
    /// first, up to a NULL.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn build_exec(label: *const c_char, argv: *mut *const c_char) -> c_int {
        // SAFETY: the caller passes the label and the arguments.
        unsafe { super::exec(label, argv) }
    }

    /// # Safety
    ///
    /// `label` is a C string, `words` C strings up to a NULL, and `argv`
    /// holds `argc` C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn build_forward(
        label: *const c_char,
        words: *const *const c_char,
        argc: c_int,
        argv: *const *const c_char,
    ) -> c_int {
        // SAFETY: the caller passes the label, words and arguments.
        unsafe { super::forward(label, words, argc, argv) }
    }

    /// # Safety
    ///
    /// `argv` holds `argc` C strings and a NULL after them.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cmd_build(argc: c_int, argv: *mut *const c_char) -> c_int {
        // SAFETY: the caller passes the command line.
        unsafe { super::build(argc, argv) }
    }
}
