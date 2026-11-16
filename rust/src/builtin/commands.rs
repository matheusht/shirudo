// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The command table and the dispatch of `shirudo <command>`: hardening
//! the process, resolving the command from an exact name, a prefix or a
//! did-you-mean, and running it inside the image state it needs.
//!
//! Adding an entry updates the dispatch, `shirudo help` and bash
//! completion, which pulls the list live through --list-cmds.

use core::ffi::{CStr, c_char, c_int};

use super::{
    attest::cmd_attest, bpm::cmd_bpm, build::cmd_build, config::cmd_config, genkey::cmd_genkey,
    image::cmd_image, init::cmd_init, keys::cmd_keys, status::cmd_status, version::cmd_version,
    words,
};
use crate::ffi;
use crate::sys::libc::{fwrite, stderr, stdout, strerror};
use crate::sys::log::log_init;
use crate::sys::upatch::cmd_upatch;
use crate::util::harden::{harden_self, harden_stdio};
use crate::util::help::{help_suggest, is_help, is_list_cmds};
use crate::util::image_runtime;
use crate::util::similar;

type Run = unsafe extern "C" fn(argc: c_int, argv: *const *const c_char) -> c_int;

#[derive(Clone, Copy, PartialEq)]
enum Group {
    Operator,
    Target,
    Local,
    General,
}

struct Command {
    name: &'static CStr,
    run: Run,
    group: Group,
    summary: &'static str,
}

const fn command(name: &'static CStr, run: Run, group: Group, summary: &'static str) -> Command {
    Command {
        name,
        run,
        group,
        summary,
    }
}

/// `shirudo build`, whose words it execs as they are, with the NULL
/// after them; its C type has the outer pointer mutable.
unsafe extern "C" fn build(argc: c_int, argv: *const *const c_char) -> c_int {
    // SAFETY: the caller's words, with main()'s NULL after them.
    unsafe { cmd_build(argc, argv.cast_mut()) }
}

const N_COMMANDS: usize = 12;

static COMMANDS: [Command; N_COMMANDS] = [
    command(
        c"genkey",
        cmd_genkey,
        Group::Operator,
        "create the signing key and certificate",
    ),
    command(
        c"build",
        build,
        Group::Operator,
        "compile and sign a .upatch",
    ),
    command(
        c"image",
        cmd_image,
        Group::Local,
        "build, verify and activate dm-verity config images",
    ),
    command(
        c"init",
        cmd_init,
        Group::Target,
        "bootstrap shirudo enforcement on this target",
    ),
    command(
        c"upatch",
        cmd_upatch,
        Group::Target,
        "load / unload (target); list / info (read-only, anywhere)",
    ),
    command(
        c"bpm",
        cmd_bpm,
        Group::Target,
        "manage signed OCI packages on this target",
    ),
    command(
        c"status",
        cmd_status,
        Group::Local,
        "report the state of this host",
    ),
    command(
        c"attest",
        cmd_attest,
        Group::Local,
        "TPM-signed evidence (target); verify / predict (operator)",
    ),
    command(
        c"keys",
        cmd_keys,
        Group::Local,
        "inspect cert / keyring contents",
    ),
    command(
        c"version",
        cmd_version,
        Group::Local,
        "print version and SHIRUDO_VERSION_ID",
    ),
    command(
        c"config",
        cmd_config,
        Group::General,
        "print the effective shirudo.conf (defaults if absent)",
    ),
    command(c"help", cmd_help, Group::General, "show this list"),
];

const GROUPS: [(Group, &str); 4] = [
    (
        Group::Operator,
        "operator commands (hold the signing key; drive targets):",
    ),
    (
        Group::Target,
        "target commands (run locally on the target):",
    ),
    (Group::Local, "local commands (operator or target):"),
    (Group::General, "other:"),
];

fn out(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stdout.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stdout) };
}

fn err(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stderr.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stderr) };
}

/// The command names, one a line, for completion.
fn list() {
    for c in &COMMANDS {
        out(&[c.name.to_bytes(), b"\n"].concat());
    }
}

/// The usage and the commands by group, on stderr.
fn usage() {
    err(b"usage: shirudo <command> [<args>]\n\n");
    for (group, header) in GROUPS {
        let mut members = COMMANDS.iter().filter(|c| c.group == group).peekable();

        if members.peek().is_none() {
            continue;
        }
        err(format!("{header}\n").as_bytes());
        for c in members {
            let name = String::from_utf8_lossy(c.name.to_bytes());
            err(format!("  {name:<9} {}\n", c.summary).as_bytes());
        }
        err(b"\n");
    }
}

/// `shirudo help`: the usage, or the names with --list-cmds.
unsafe extern "C" fn cmd_help(argc: c_int, argv: *const *const c_char) -> c_int {
    // SAFETY: the caller's arguments.
    let args = unsafe { words(argc, argv) };
    // SAFETY: a C string.
    let first = args.get(1).map(|&a| unsafe { ffi::c_str(a) });

    if first == Some(&b"--list-cmds"[..]) {
        list();
    } else {
        usage();
    }
    0
}

fn run(args: &[*const c_char]) -> c_int {
    harden_stdio();
    // SAFETY: opens the log once, before anything logs.
    unsafe { log_init() };
    if harden_self() != 0 {
        return 1;
    }
    let Some(&word) = args.get(1) else {
        usage();
        return 1;
    };
    // SAFETY: a C string of the caller's.
    let first = unsafe { ffi::c_str(word) };
    if is_list_cmds(Some(first)) {
        list();
        return 0;
    }
    // With the rest of argv, so `--help --list-cmds` still lists.
    let rest = &args[1..];
    let n_rest = rest.len() as c_int;
    if is_help(Some(first)) {
        // SAFETY: the rest of the caller's arguments.
        return unsafe { cmd_help(n_rest, rest.as_ptr()) };
    }
    // Tolerant matching is help_suggest()'s Levenshtein pass below.
    let mut matches = [0usize; N_COMMANDS];
    let n = similar::resolve(
        first,
        COMMANDS.len(),
        |i| COMMANDS[i].name.to_bytes(),
        &mut matches,
    );
    let c = match n {
        0 => {
            err(&[
                b"'",
                first,
                b"' is not a shirudo command.\nSee 'shirudo help'.\n",
            ]
            .concat());
            let names: Vec<*const c_char> = COMMANDS.iter().map(|c| c.name.as_ptr()).collect();
            // SAFETY: the word and the names, C strings.
            unsafe { help_suggest(word, &names) };
            return 1;
        }
        1 => &COMMANDS[matches[0]],
        _ => {
            err(&[b"shirudo: '", first, b"' is ambiguous; matches:\n"].concat());
            for &i in &matches[..n] {
                err(&[b"\t", COMMANDS[i].name.to_bytes(), b"\n"].concat());
            }
            return 1;
        }
    };
    let words: Vec<&[u8]> = rest
        .iter()
        // SAFETY: the caller's arguments, C strings.
        .map(|&w| unsafe { ffi::c_str(w) })
        .collect();
    let ret = image_runtime::enter(c.name.to_bytes(), &words);
    if ret != 0 {
        // SAFETY: strerror() gives a C string.
        let why = unsafe { ffi::c_str(strerror(-ret)) };
        err(&[b"shirudo: image state: ", why, b"\n"].concat());
        image_runtime::leave();
        return 1;
    }
    // SAFETY: the command, with the rest of the caller's arguments.
    let ret = unsafe { (c.run)(n_rest, rest.as_ptr()) };
    image_runtime::leave();
    ret
}

mod capi {
    use core::ffi::{c_char, c_int};

    /// `shirudo`, from main(): the command line, whole.
    ///
    /// # Safety
    ///
    /// `argv` holds `argc` C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn shirudo_main(argc: c_int, argv: *const *const c_char) -> c_int {
        // SAFETY: the caller's arguments.
        super::run(unsafe { super::words(argc, argv) })
    }
}
