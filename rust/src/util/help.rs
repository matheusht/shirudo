// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The structured help of the commands: their
//! usage and sections of items wrapped to the terminal, the subcommand
//! list bash completion reads, and the did-you-mean of a mistyped
//! subcommand. It prints through the C library's streams, as the C
//! callers around it do, so that its output keeps its place among
//! theirs.

use core::ffi::{CStr, c_int};

use crate::sys::libc::{fputc, fwrite, stderr, stdout};
use crate::util::options::{OptSpec, option_label};
use crate::util::similar::{Suggestion, resolve, suggest};

/// The most subcommands a command offers.
const SUBCMD_MAX: usize = 32;

/// The column an item's summary wraps at: a 100-column terminal, with
/// slack.
const HELP_WIDTH: usize = 90;

/// A subcommand, or another name a help section lists, and what it does.
pub struct HelpItem {
    pub(crate) name: &'static CStr,
    pub(crate) summary: &'static CStr,
}

/// A section of help: it lists items, or the options of a command's
/// option table.
pub struct HelpSection {
    header: &'static CStr,
    items: &'static [HelpItem],
    options: &'static [OptSpec],
}

impl HelpSection {
    /// A section named `header` listing `items`.
    pub(crate) const fn items(header: &'static CStr, items: &'static [HelpItem]) -> Self {
        HelpSection {
            header,
            items,
            options: &[],
        }
    }

    /// A section named `header` listing the options of `options`.
    pub(crate) const fn options(header: &'static CStr, options: &'static [OptSpec]) -> Self {
        HelpSection {
            header,
            items: &[],
            options,
        }
    }
}

/// A row of a section: the name in a column `w` wide, the summary
/// wrapped after it.
fn print_row(name: &[u8], summary: &CStr, w: usize) {
    let indent = 2 + w;
    let avail = if indent < HELP_WIDTH {
        HELP_WIDTH - indent
    } else {
        1
    };
    let mut row = b"  ".to_vec();

    row.extend_from_slice(name);
    row.resize(row.len().max(2 + w), b' ');
    err_write(&row);
    wrap_print(summary.to_bytes(), indent, avail);
}

/// A command's help: its usage, a summary and a footer, either of which
/// may be absent, around its sections.
pub struct Help {
    usage: &'static CStr,
    summary: Option<&'static CStr>,
    sections: &'static [HelpSection],
    footer: Option<&'static CStr>,
}

impl Help {
    pub(crate) const fn new(
        usage: &'static CStr,
        summary: Option<&'static CStr>,
        sections: &'static [HelpSection],
        footer: Option<&'static CStr>,
    ) -> Self {
        Help {
            usage,
            summary,
            sections,
            footer,
        }
    }
}

impl HelpItem {
    pub(crate) const fn new(name: &'static CStr, summary: &'static CStr) -> Self {
        HelpItem { name, summary }
    }
}

fn err_stream() -> *mut crate::sys::libc::File {
    // SAFETY: a read of the C library's stderr, which nothing changes.
    unsafe { stderr }
}

/// `bytes` on stderr, through the C library's stream, so that they keep
/// their place among the output of the C library's other callers.
fn err_write(bytes: &[u8]) {
    // SAFETY: the bytes, and the stream.
    unsafe { fwrite(bytes.as_ptr().cast(), 1, bytes.len(), err_stream()) };
}

/// `bytes` on stdout, as err_write() writes stderr.
pub(crate) fn out_write(bytes: &[u8]) {
    // SAFETY: the bytes, and the C library's stdout, which nothing
    // changes.
    unsafe { fwrite(bytes.as_ptr().cast(), 1, bytes.len(), stdout) };
}

/// `text` on stderr a word at a time, a word that would pass `avail`
/// columns starting a line of its own after `indent` spaces.
fn wrap_print(text: &[u8], indent: usize, avail: usize) {
    let f = err_stream();
    let avail = avail.max(1);
    let mut col = 0;
    let mut p = 0;

    while p < text.len() {
        while p < text.len() && matches!(text[p], b' ' | b'\t') {
            p += 1;
        }
        if p == text.len() {
            break;
        }
        let w = p;

        while p < text.len() && !matches!(text[p], b' ' | b'\t') {
            p += 1;
        }
        let word = &text[w..p];

        // SAFETY: the bytes of the word, and the stream.
        unsafe {
            if col == 0 {
                fwrite(word.as_ptr().cast(), 1, word.len(), f);
                col = word.len();
            } else if col + 1 + word.len() <= avail {
                fputc(c_int::from(b' '), f);
                fwrite(word.as_ptr().cast(), 1, word.len(), f);
                col += 1 + word.len();
            } else {
                fputc(c_int::from(b'\n'), f);
                for _ in 0..indent {
                    fputc(c_int::from(b' '), f);
                }
                fwrite(word.as_ptr().cast(), 1, word.len(), f);
                col = word.len();
            }
        }
    }
    // SAFETY: the stream.
    unsafe { fputc(c_int::from(b'\n'), f) };
}

/// Whether a command line word asks for help.
pub(crate) fn is_help(arg: Option<&[u8]>) -> bool {
    matches!(arg, Some(b"help" | b"--help" | b"-h"))
}

/// Whether a command line word asks for the subcommands, for bash
/// completion.
pub(crate) fn is_list_cmds(arg: Option<&[u8]>) -> bool {
    arg == Some(b"--list-cmds")
}

/// The names of `items`, one a line, for completion.
pub(crate) fn print_subcmd_list(items: &[HelpItem]) {
    for item in items {
        out_write(&[item.name.to_bytes(), b"\n"].concat());
    }
}

/// `h` on stderr.
pub(crate) fn print_help(h: &Help) {
    err_write(&[b"usage: ", h.usage.to_bytes(), b"\n"].concat());
    if let Some(summary) = h.summary.filter(|s| !s.is_empty()) {
        err_write(&[b"\n", summary.to_bytes(), b"\n"].concat());
    }
    for s in h.sections {
        if s.items.is_empty() && s.options.is_empty() {
            continue;
        }
        let labels: Vec<Vec<u8>> = s.options.iter().map(option_label).collect();
        // Per section, so an Options section reads as cleanly as a
        // Subcommands one.
        let w = s
            .items
            .iter()
            .map(|item| item.name.count_bytes())
            .chain(labels.iter().map(Vec::len))
            .max()
            .unwrap_or(0)
            + 2;

        err_write(&[b"\n", s.header.to_bytes(), b"\n"].concat());
        for item in s.items {
            print_row(item.name.to_bytes(), item.summary, w);
        }
        for (o, label) in s.options.iter().zip(&labels) {
            print_row(label, o.summary, w);
        }
    }
    if let Some(footer) = h.footer.filter(|f| !f.is_empty()) {
        err_write(&[b"\n", footer.to_bytes(), b"\n"].concat());
    }
}

/// The names close enough to `bad`, a word that matches none, printed
/// as a did-you-mean block on stderr.
pub(crate) fn help_suggest<'a>(bad: &[u8], names: impl IntoIterator<Item = &'a CStr>) {
    let mut sugg = [Suggestion { name: c"", dist: 0 }; 4];
    // A quarter of the length is too tight for short words and lets
    // anything through for long ones, so half plus one, at most 3.
    let max_dist = (bad.len() / 2 + 1).min(3) as c_int;
    let candidates = names.into_iter().map(|name| (name, name.to_bytes()));
    let n = suggest(bad, candidates, max_dist, &mut sugg);

    if n == 0 {
        return;
    }
    err_write(b"\nDid you mean one of:\n");
    for s in &sugg[..n] {
        err_write(&[b"\t", s.name.to_bytes(), b"\n"].concat());
    }
}

fn help_unknown_subcommand(cmd_label: &CStr, bad: &CStr, subcmds: &[HelpItem]) {
    let (label, typed) = (cmd_label.to_bytes(), bad.to_bytes());

    err_write(
        &[
            label,
            b": '",
            typed,
            b"' is not a known subcommand.\nSee '",
            label,
            b" --help'.\n",
        ]
        .concat(),
    );
    help_suggest(typed, subcmds.iter().take(SUBCMD_MAX).map(|item| item.name));
}

/// The subcommand `input` names, exactly or as the one subcommand it is
/// a prefix of, or a prefix of; None with stderr written, a did-you-mean
/// block or the ambiguous matches, when there is none or more than one.
pub(crate) fn resolve_subcommand(
    cmd_label: &CStr,
    input: &CStr,
    subcmds: &[HelpItem],
) -> Option<&'static CStr> {
    let names = &subcmds[..subcmds.len().min(SUBCMD_MAX)];
    let mut matches = [0usize; SUBCMD_MAX];

    if names.is_empty() {
        help_unknown_subcommand(cmd_label, input, subcmds);
        return None;
    }
    let candidate = |i: usize| names[i].name.to_bytes();
    let n = resolve(input.to_bytes(), names.len(), candidate, &mut matches);

    if n == 1 {
        return Some(names[matches[0]].name);
    }
    if n == 0 {
        help_unknown_subcommand(cmd_label, input, subcmds);
        return None;
    }
    err_write(
        &[
            cmd_label.to_bytes(),
            b": '",
            input.to_bytes(),
            b"' is ambiguous; matches:\n",
        ]
        .concat(),
    );
    for &i in &matches[..n] {
        err_write(&[b"\t", names[i].name.to_bytes(), b"\n"].concat());
    }
    None
}
