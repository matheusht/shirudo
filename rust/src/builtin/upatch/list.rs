// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo upatch list`: the upatches archived for init to restore at
//! boot, whether each is loaded now, and those loaded with no archive.
//! Drift either way is the point: an archived upatch not loaded, or a
//! loaded one that will not survive a reboot.

use core::ffi::{c_char, c_int};
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;

use super::{JSON_MAX, hex, out, pad, print_json};
use crate::sys::libc::close;
use crate::util::help::{Help, HelpSection};
use crate::util::json::JsonEmit;
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};
use crate::util::upatch::{self, NAME_MAX, Opened, name_from_pin, pin_name};
use crate::util::upatch_resolve::open_first_link;

pub(super) const UPATCHES_DIR: &str = "/var/lib/shirudo/upatches";
pub(super) use crate::util::upatch_resolve::BPFFS_UPATCHES_DIR;

/// The names in `dir` that `keep` keeps, sorted bytewise as alphasort()
/// sorts them in the C locale; none when it cannot be read.
fn names(dir: &str, keep: impl Fn(&[u8]) -> bool) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = fs::read_dir(dir)
        .map(|d| {
            d.filter_map(Result::ok)
                .map(|e| e.file_name().as_bytes().to_vec())
                .filter(|n| keep(n))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Whether upatch `name` is loaded: a link pinned, or its test program.
fn loaded(name: &[u8]) -> bool {
    let fd = open_first_link(name);
    if fd >= 0 {
        // SAFETY: the descriptor opened above.
        unsafe { close(fd) };
        return true;
    }
    let pin = [
        BPFFS_UPATCHES_DIR.as_bytes(),
        b"/",
        &pin_name(name),
        b"/test",
    ]
    .concat();
    fs::metadata(std::ffi::OsStr::from_bytes(&pin)).is_ok()
}

/// An archived upatch, as its file describes it.
struct Archived {
    name: Vec<u8>,
    ty: &'static [u8],
    payload_type: &'static [u8],
    payload: Vec<u8>,
    loaded: bool,
}

fn archived(file: &[u8]) -> Option<Archived> {
    let u =
        Opened::open(&CString::new([UPATCHES_DIR.as_bytes(), b"/", file].concat()).ok()?).ok()?;
    let mut name = [0u8; NAME_MAX + 1];
    upatch::header_name(&u, &mut name);
    let name = crate::text::cstr(&name).to_vec();
    Some(Archived {
        ty: if upatch::is_unload(&u) {
            b"unload"
        } else {
            b"load"
        },
        payload_type: upatch::payload_type(&u),
        payload: hex(&u.hdr.payload_sha256),
        loaded: loaded(&name),
        name,
    })
}

fn row(cols: [&[u8]; 4], last: &[u8]) -> Vec<u8> {
    [
        &b"  "[..],
        &pad(cols[0], 24),
        b"  ",
        &pad(cols[1], 6),
        b"  ",
        &pad(cols[2], 6),
        b"  ",
        &pad(cols[3], 4),
        b"  ",
        last,
        b"\n",
    ]
    .concat()
}

const LIST_JSON: c_int = 0;

static LIST_OPTS: [OptSpec; 1] = [OptSpec::new(
    c"--json",
    0,
    0,
    None,
    c"print one JSON object",
)];

static LIST_SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &LIST_OPTS)];

static LIST_HELP: Help = Help::new(
    c"shirudo upatch list [--json]",
    Some(
        c"List the upatches archived under /var/lib/shirudo/upatches,\n\
          which init restores at boot, with whether each is loaded now,\n\
          and any upatch loaded without an archive.",
    ),
    &LIST_SECTIONS,
    Some(c"Examples:\n  shirudo upatch list\n  shirudo upatch list --json | jq"),
);

/// `upatch list`, from `list` on.
pub(super) fn run(args: &[*const c_char]) -> c_int {
    let mut p = OptParser::new(c"upatch list", &LIST_OPTS, Some(&LIST_HELP), args, 1);
    let mut json = false;

    loop {
        match p.next() {
            OPT_END => break,
            LIST_JSON => json = true,
            OPT_ARG => {
                p.usage_arg(b"unexpected argument ");
                return EXIT_USAGE;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let files = names(UPATCHES_DIR, |n| n.ends_with(b".upatch"));
    let pins = names(BPFFS_UPATCHES_DIR, |n| n != b"." && n != b"..");
    // The loaded upatches with no archive to survive a reboot.
    let unarchived: Vec<Vec<u8>> = pins
        .iter()
        .filter_map(|p| name_from_pin(p))
        .filter(|n| {
            let archive = [UPATCHES_DIR.as_bytes(), b"/", n, b".upatch"].concat();
            fs::metadata(std::ffi::OsStr::from_bytes(&archive)).is_err()
        })
        .collect();

    if json {
        let mut e = JsonEmit::growing(JSON_MAX);
        e.obj_open();
        e.kv_int(b"schema", 1);
        e.arr_open(b"upatches");
        for a in files.iter().filter_map(|f| archived(f)) {
            e.obj_open();
            e.kv_string(b"name", &a.name);
            e.kv_string(b"type", a.ty);
            e.kv_string(b"payload_type", a.payload_type);
            e.kv_bool(b"loaded", a.loaded);
            e.kv_bool(b"archived", true);
            e.kv_string(b"payload_sha256", &a.payload);
            e.obj_close();
        }
        for n in &unarchived {
            e.obj_open();
            e.kv_string(b"name", n);
            e.kv_null(b"type");
            e.kv_bool(b"loaded", true);
            e.kv_bool(b"archived", false);
            e.kv_null(b"payload_sha256");
            e.obj_close();
        }
        e.arr_close();
        e.obj_close();
        return print_json(e, b"upatch list");
    }

    let mut t = format!("Archived upatches ({UPATCHES_DIR}):\n").into_bytes();
    if files.is_empty() && pins.is_empty() {
        t.extend_from_slice(b"  none\n");
    } else {
        t.extend(row([b"NAME", b"LOADED", b"TYPE", b"KIND"], b"PAYLOAD"));
    }
    for f in &files {
        match archived(f) {
            Some(a) => {
                let shown = [&a.payload[..16], b".."].concat();
                t.extend(row(
                    [
                        &a.name,
                        if a.loaded { b"yes" } else { b"no" },
                        a.ty,
                        a.payload_type,
                    ],
                    &shown,
                ));
            }
            None => t.extend(row([f, b"?", b"?", b"?"], b"unreadable")),
        }
    }
    for n in &unarchived {
        t.extend(row(
            [n, b"yes", b"-", b"-"],
            b"not archived, gone at reboot",
        ));
    }
    out(&t);
    0
}
