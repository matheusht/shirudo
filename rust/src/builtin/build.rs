// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The sole exec site in the core shirudo binary: `shirudo build`, and
//! the operator's halves of other commands, run by the operator-only
//! helper, shirudo-build.

use core::ffi::{CStr, c_int};
use core::ptr;

use crate::errno::ENOMEM;
use crate::ffi::c_splice;
use crate::sys::libc::{PATH_MAX, X_OK, access, env, errno, execv, execvp, strerror};
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

pub(super) fn available() -> bool {
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

/// The helper to run and whether to look it up on PATH, or 127 with why
/// it cannot run reported.
fn helper(label: &CStr) -> Result<(&'static CStr, bool), c_int> {
    let (path, use_path) = resolve_helper();

    if path.is_empty() {
        // SAFETY: the C's format and the label, a C string.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"'%s' cannot use empty SHIRUDO_BUILD".as_ptr(),
                label.as_ptr()
            )
        };
        return Err(127);
    }
    // SAFETY: a path, and a mode.
    if !use_path && unsafe { access(path.as_ptr(), X_OK) } != 0 {
        // SAFETY: the C's format, the label and the path, C strings.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"'%s' is an operator-only subcommand; shirudo-build helper '%s' is not \
                  executable. Set SHIRUDO_BUILD to a helper path or put shirudo-build on PATH."
                    .as_ptr(),
                label.as_ptr(),
                path.as_ptr(),
            )
        };
        return Err(127);
    }
    Ok((path, use_path))
}

/// Runs the helper with `words` and then `args`; returns only when it
/// cannot, with 127, or with 1 where its command line finds no memory.
pub(super) fn forward(label: &CStr, words: &[&CStr], args: &[&CStr]) -> c_int {
    let mut argv = Vec::new();

    if argv
        .try_reserve_exact(words.len() + args.len() + 2)
        .is_err()
    {
        // SAFETY: the C's format, the label and the error's text.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"'%s': %s".as_ptr(),
                label.as_ptr(),
                strerror(ENOMEM)
            )
        };
        return 1;
    }
    let (path, use_path) = match helper(label) {
        Ok(found) => found,
        Err(status) => return status,
    };
    argv.push(path.as_ptr());
    argv.extend(words.iter().chain(args).map(|w| w.as_ptr()));
    argv.push(ptr::null());
    if use_path {
        // SAFETY: the path, and C strings up to a NULL that outlive the
        // call.
        unsafe { execvp(path.as_ptr(), argv.as_ptr()) };
    } else {
        // SAFETY: as above.
        unsafe { execv(path.as_ptr(), argv.as_ptr()) };
    }
    // SAFETY: the C's format, the path and the error's text.
    unsafe {
        crate::log::log_c!(
            crate::log::err,
            c"exec %s: %s".as_ptr(),
            path.as_ptr(),
            strerror(errno())
        )
    };
    127
}

/// `shirudo build`: the helper, run on the caller's arguments.
pub(super) fn cmd_build(args: &[&CStr]) -> c_int {
    if is_help(args.get(1).map(|a| a.to_bytes())) {
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
    forward(c"build", &[], args.get(1..).unwrap_or_default())
}
