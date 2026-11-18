// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo upatch`: describe an upatch file, list the archived and the
//! loaded upatches, describe a loaded one and read its maps from the
//! kernel, and load and unload upatches through the signed loader.

mod get;
mod info;
mod list;
pub(crate) mod loader;
mod map;
mod ops;

use core::ffi::{CStr, c_char, c_int};
use std::ffi::CString;

use crate::heap::xfree;
use crate::sys::libc::{fwrite, stderr, stdout};
use crate::sys::upatch::MapSummary;
use crate::util::help::{
    Help, HelpItem, HelpSection, is_help, is_list_cmds, print_help, print_subcmd_list,
    resolve_subcommand,
};
use crate::util::json::JsonEmit;
use crate::util::map_read;

/// JSON_MAX_BYTES of util/json.h: the most a document grows to.
const JSON_MAX: usize = 8 * 1024 * 1024;

pub(crate) use ops::{install, purge, remove};

const fn item(name: &'static CStr, summary: &'static CStr) -> HelpItem {
    HelpItem {
        name: name.as_ptr(),
        summary: summary.as_ptr(),
    }
}

const SUBCMDS: [HelpItem; 6] = [
    item(
        c"load",
        c"load a signed .upatch into the target kernel (target-only)",
    ),
    item(
        c"unload",
        c"apply a signed UNLOAD directive (forward chain extension)",
    ),
    item(
        c"list",
        c"list the archived and the loaded upatches on this host",
    ),
    item(
        c"info",
        c"describe a .upatch file (any host; offline, no kernel state)",
    ),
    item(
        c"get",
        c"dump source of a loaded upatch from the target kernel (BTF line_info)",
    ),
    item(
        c"map",
        c"read pinned map contents (target-only; BTF type-aware)",
    ),
];

/// Help of a subcommand: its usage, summary, sections and examples.
fn help(usage: &CStr, summary: &CStr, sections: &[(&CStr, &[HelpItem])], footer: Option<&CStr>) {
    let sections: Vec<HelpSection> = sections
        .iter()
        .map(|(header, items)| HelpSection {
            header: header.as_ptr(),
            items: items.as_ptr(),
            n_items: items.len(),
            options: core::ptr::null(),
            n_options: 0,
        })
        .collect();
    let h = Help {
        usage: usage.as_ptr(),
        summary: summary.as_ptr(),
        sections: if sections.is_empty() {
            core::ptr::null()
        } else {
            sections.as_ptr()
        },
        n_sections: sections.len(),
        footer: footer.map_or(core::ptr::null(), CStr::as_ptr),
    };
    // SAFETY: the help, its strings and sections live through the call.
    unsafe { print_help(&h) };
}

/// Text to the C library's stdout, where the C subcommands write.
fn out(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stdout.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stdout) };
}

/// Text to the C library's stderr.
fn err(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stderr.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stderr) };
}

/// A message through the log function `f`, err() or its kin.
fn log(f: fn(&[u8]), text: &[u8]) {
    let text = CString::new(
        text.iter()
            .copied()
            .filter(|&c| c != 0)
            .collect::<Vec<u8>>(),
    )
    .unwrap_or_default();
    // SAFETY: a "%s" format with a C string.
    unsafe { crate::log::log_c!(f, c"%s".as_ptr(), text.as_ptr()) };
}

fn log_err(text: &[u8]) {
    log(crate::log::err, text);
}

fn log_warn(text: &[u8]) {
    log(crate::log::warn, text);
}

fn log_info(text: &[u8]) {
    log(crate::log::info, text);
}

fn log_audit(text: &[u8]) {
    log(crate::log::audit, text);
}

/// A valued option: its value after an equals sign or as the next
/// argument, which it steps past.
enum Opt<'a> {
    No,
    Value(&'a CStr),
    Missing,
}

fn opt<'a>(name: &[u8], args: &[&'a CStr], i: &mut usize) -> Opt<'a> {
    let a = args[*i].to_bytes_with_nul();
    let Some(rest) = a.strip_prefix(name) else {
        return Opt::No;
    };
    match rest {
        [b'=', value @ ..] => CStr::from_bytes_with_nul(value).map_or(Opt::No, Opt::Value),
        [0] if *i + 1 >= args.len() => Opt::Missing,
        [0] => {
            *i += 1;
            Opt::Value(args[*i])
        }
        _ => Opt::No,
    }
}

/// The maps the loaded upatches pin: upatch `upatch`'s, or every
/// upatch's for none.
struct Summaries(Vec<MapSummary>);

impl Summaries {
    fn of(upatch: Option<&CStr>) -> Self {
        Summaries(map_read::list(upatch.map(CStr::to_bytes)))
    }

    fn as_slice(&self) -> &[MapSummary] {
        &self.0
    }
}

/// A map's type name, "" for none.
fn type_name(m: &MapSummary) -> &'static [u8] {
    if m.type_name.is_null() {
        b""
    } else {
        // SAFETY: a static C string of the map type table.
        unsafe { crate::ffi::c_str(m.type_name) }
    }
}

fn strerr(err: c_int) -> &'static [u8] {
    // SAFETY: strerror() gives a C string that outlives the message.
    unsafe { crate::ffi::c_str(crate::sys::libc::strerror(err)) }
}

/// `s` padded with spaces to `width` bytes, as printf's %-Ns does.
fn pad(s: &[u8], width: usize) -> Vec<u8> {
    let mut v = s.to_vec();
    v.resize(width.max(s.len()), b' ');
    v
}

fn hex(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xf)]])
        .collect()
}

/// The document `e` built, printed with its newline, or the failure to
/// encode it reported for `cmd`: 0 or 1.
fn print_json(e: JsonEmit, cmd: &[u8]) -> c_int {
    let (buf, cap, len) = e.parts();
    let ret = if e.err() != 0 {
        err(&[cmd, b": json encode failed: ", strerr(-e.err()), b"\n"].concat());
        1
    } else {
        // SAFETY: the len bytes the emitter wrote.
        out(&[unsafe { crate::ffi::slice(buf.cast::<u8>(), len) }, b"\n"].concat());
        0
    };
    // SAFETY: the buffer the emitter grew, handed over and freed once.
    unsafe { xfree(buf.cast(), cap) };
    ret
}

fn upatch_help() {
    help(
        c"shirudo upatch <subcommand> [<args>...]",
        c"Manage signed BPF programs (.upatch). load/unload are target-only;\nlist/info/get are read-only and run on either side.",
        &[(c"subcommands:", &SUBCMDS)],
        None,
    );
}

/// `shirudo upatch`, from `upatch` on.
fn run(args: &[*const c_char]) -> c_int {
    let word = |i: usize| -> Option<&[u8]> {
        // SAFETY: the caller's C strings.
        args.get(i).map(|&a| unsafe { crate::ffi::c_str(a) })
    };
    if args.len() < 2 || is_help(word(1)) {
        upatch_help();
        return if args.len() < 2 { 2 } else { 0 };
    }
    if is_list_cmds(word(1)) {
        // SAFETY: the subcommands, constants.
        unsafe { print_subcmd_list(&SUBCMDS) };
        return 0;
    }
    // SAFETY: a C string, the caller's, and the subcommands.
    let canonical = unsafe { resolve_subcommand(c"shirudo upatch".as_ptr(), args[1], &SUBCMDS) };
    if canonical.is_null() {
        return 2;
    }
    let rest = &args[1..];
    // SAFETY: the caller's C strings.
    let cargs: Vec<&CStr> = rest.iter().map(|&a| unsafe { CStr::from_ptr(a) }).collect();
    // SAFETY: the subcommand's name, a C string.
    let words: Vec<&[u8]> = rest
        .iter()
        .map(|&a| unsafe { crate::ffi::c_str(a) })
        .collect();
    // SAFETY: as above.
    match unsafe { CStr::from_ptr(canonical) }.to_bytes() {
        b"info" => info::run(&words),
        b"list" => list::run(&words),
        b"get" => get::run(&words),
        b"load" => ops::run_load(&cargs),
        b"unload" => ops::run_unload(&cargs),
        b"map" => map::run(&cargs),
        _ => 2,
    }
}

mod capi {
    use core::ffi::{c_char, c_int};

    /// `shirudo upatch`.
    ///
    /// # Safety
    ///
    /// `argv` holds `argc` C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cmd_upatch(argc: c_int, argv: *const *const c_char) -> c_int {
        // SAFETY: the caller's argc words.
        super::run(unsafe { super::super::words(argc, argv) })
    }
}

pub(crate) use capi::cmd_upatch;
