// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo image`: activating and inspecting the signed config image on
//! a target; building and verifying one is the operator's, in
//! shirudo-build.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use super::words;
use crate::errno::{EINPROGRESS, ENODEV};
use crate::ffi;
use crate::sys::libc::strerror;
use crate::util::help::{
    Help, HelpItem, HelpSection, help_suggest, is_help, is_list_cmds, print_help, print_subcmd_list,
};
use crate::util::image_runtime;
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OPT_USAGE, OptParser, OptSpec};

static SUBCMDS: [HelpItem; 5] = [
    HelpItem::new(
        c"build",
        c"build a signed image from a file system image (operator)",
    ),
    HelpItem::new(
        c"verify",
        c"check an image's signature and hash tree (operator)",
    ),
    HelpItem::new(c"update", c"activate a config image now (target)"),
    HelpItem::new(
        c"stage",
        c"select a config image for the next boot (target)",
    ),
    HelpItem::new(c"status", c"print the state of config activation (target)"),
];

const IMAGE_STAGE_CANCEL: c_int = 0;

static STAGE_OPTS: [OptSpec; 1] = [OptSpec::new(
    c"--cancel",
    0,
    0,
    None,
    c"drop the selection for the next boot",
)];

const IMAGE_STATUS_JSON: c_int = 0;

static STATUS_OPTS: [OptSpec; 1] = [OptSpec::new(
    c"--json",
    0,
    0,
    None,
    c"print the state as JSON",
)];

static SECTIONS: [HelpSection; 3] = [
    HelpSection::items(c"subcommands:", &SUBCMDS),
    HelpSection::options(c"stage options:", &STAGE_OPTS),
    HelpSection::options(c"status options:", &STATUS_OPTS),
];

static HELP: Help = Help::new(
    c"shirudo image build [image builder options]\n       \
      shirudo image verify <prefix> --cert <certificate>\n       \
      shirudo image update <prefix-or-https-prefix>\n       \
      shirudo image stage <prefix-or-https-prefix>\n       \
      shirudo image stage --cancel\n       \
      shirudo image status [--json]",
    None,
    &SECTIONS,
    None,
);

fn done(sub: &[u8], ret: c_int) -> c_int {
    if ret == -EINPROGRESS {
        crate::log::err(b"image: activation is pending; further changes are blocked");
    } else if ret != 0 {
        // SAFETY: strerror() gives a C string.
        let why = unsafe { ffi::c_str(strerror(-ret)) };
        crate::log::err(&[b"image ", sub, b": ", why].concat());
    }
    c_int::from(ret != 0)
}

/// What an update or a stage takes: the prefix, or with `--cancel` none.
enum Target<'a> {
    Prefix(&'a CStr),
    Cancel,
}

/// The arguments of an update or a stage, or the code to stop at:
/// OPT_DONE or OPT_USAGE. `want` names what the command takes.
fn target<'a>(p: &mut OptParser<'a>, want: &[u8]) -> Result<Target<'a>, c_int> {
    let (mut cancel, mut prefix) = (false, None);

    loop {
        match p.next() {
            OPT_END => break,
            IMAGE_STAGE_CANCEL => cancel = true,
            OPT_ARG => {
                if prefix.is_some() {
                    p.usage_arg(b"unexpected argument ");
                    return Err(OPT_USAGE);
                }
                prefix = p.value();
            }
            opt => return Err(opt),
        }
    }
    match (cancel, prefix) {
        (true, None) => Ok(Target::Cancel),
        (false, Some(prefix)) => Ok(Target::Prefix(prefix)),
        _ => {
            p.usage(&[b"takes ", want].concat());
            Err(OPT_USAGE)
        }
    }
}

fn update(args: &[*const c_char]) -> c_int {
    let mut p = OptParser::new(c"image update", &[], Some(&HELP), args, 1);

    match target(&mut p, b"<prefix>") {
        Ok(Target::Prefix(prefix)) => done(b"update", image_runtime::update(prefix)),
        Ok(Target::Cancel) => EXIT_USAGE,
        Err(OPT_DONE) => 0,
        Err(_) => EXIT_USAGE,
    }
}

fn stage(args: &[*const c_char]) -> c_int {
    let mut p = OptParser::new(c"image stage", &STAGE_OPTS, Some(&HELP), args, 1);

    match target(&mut p, b"<prefix> or --cancel") {
        Ok(Target::Prefix(prefix)) => done(b"stage", image_runtime::stage(prefix)),
        Ok(Target::Cancel) => done(b"stage", image_runtime::stage_cancel()),
        Err(OPT_DONE) => 0,
        Err(_) => EXIT_USAGE,
    }
}

fn status(args: &[*const c_char]) -> c_int {
    let mut p = OptParser::new(c"image status", &STATUS_OPTS, Some(&HELP), args, 1);
    let mut json = false;

    loop {
        match p.next() {
            OPT_END => break,
            IMAGE_STATUS_JSON => json = true,
            OPT_ARG => {
                p.usage_arg(b"unexpected argument ");
                return EXIT_USAGE;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let ret = image_runtime::status(json);
    if ret == -ENODEV {
        crate::log::err(b"image status: no config activation state on this host");
        return 1;
    }
    done(b"status", ret)
}

/// `shirudo image` on `args`, its name first, C strings.
///
/// # Safety
///
/// Each of `args` is a C string.
unsafe fn image(args: &[*const c_char]) -> c_int {
    // SAFETY: the caller's C strings.
    let arg = args.get(1).map(|&a| unsafe { ffi::c_str(a) });

    if is_list_cmds(arg) {
        // SAFETY: the subcommands, of C strings.
        unsafe { print_subcmd_list(&SUBCMDS) };
        return 0;
    }
    let Some(sub) = arg.filter(|&a| !is_help(Some(a))) else {
        // SAFETY: the command's help, of C strings.
        unsafe { print_help(&HELP) };
        return if arg.is_none() { EXIT_USAGE } else { 0 };
    };
    match sub {
        b"build" | b"verify" => {
            let label: &CStr = if sub == b"build" {
                c"image build"
            } else {
                c"image verify"
            };
            let words = [c"image".as_ptr(), ptr::null()];
            // SAFETY: a label, the words up to their NULL, and the
            // caller's arguments from the subcommand on.
            unsafe {
                super::build::forward(
                    label.as_ptr(),
                    words.as_ptr(),
                    (args.len() - 1) as c_int,
                    args[1..].as_ptr(),
                )
            }
        }
        b"update" => update(&args[1..]),
        b"stage" => stage(&args[1..]),
        b"status" => status(&args[1..]),
        _ => {
            crate::log::err(&[b"image: '", sub, b"' is not a subcommand"].concat());
            let names: Vec<*const c_char> = SUBCMDS.iter().map(|s| s.name).collect();
            // SAFETY: the caller's C string and the subcommands' names.
            unsafe { help_suggest(args[1], &names) };
            EXIT_USAGE
        }
    }
}

pub(super) use capi::cmd_image;

mod capi {
    use core::ffi::{c_char, c_int};

    /// # Safety
    ///
    /// `argv` holds `argc` C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cmd_image(argc: c_int, argv: *const *const c_char) -> c_int {
        // SAFETY: the caller's arguments, each a C string.
        unsafe { super::image(super::words(argc, argv)) }
    }
}
