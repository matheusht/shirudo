// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo version`: the release name and SHIRUDO_VERSION_ID.

use core::ffi::{CStr, c_int};

use crate::sys::libc::printf;
use crate::sys::version::{
    shirudo_extraversion, shirudo_release_name, shirudo_version, shirudo_version_id,
};
use crate::util::help::{Help, HelpSection};
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};

const VERSION_ID: c_int = 0;

static OPTS: [OptSpec; 1] = [OptSpec::new(
    c"--version-id",
    0,
    0,
    None,
    c"print only the raw SHIRUDO_VERSION_ID, one line",
)];

static SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &OPTS)];

static HELP: Help = Help::new(
    c"shirudo version [--version-id]",
    Some(
        c"Print the release tag plus the architecture-stripped SHIRUDO_VERSION_ID\n\
          that targets compare against the operator's signed artifacts.",
    ),
    &SECTIONS,
    None,
);

/// The command on `args`, its name first.
pub(super) fn cmd_version(args: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"version", &OPTS, Some(&HELP), args, 1);
    let mut id_only = false;

    loop {
        match p.next() {
            OPT_END => break,
            VERSION_ID => id_only = true,
            OPT_ARG => {
                p.usage_arg(b"unexpected argument ");
                return EXIT_USAGE;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    // SAFETY: the C's formats, and the build's identity strings.
    unsafe {
        if id_only {
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
