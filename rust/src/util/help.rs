// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The structured help of the commands, behind `util/help.h`: their
//! usage and sections of items wrapped to the terminal, the subcommand
//! list bash completion reads, and the did-you-mean of a mistyped
//! subcommand. It prints through the C library's streams, as the C
//! callers around it do, so that its output keeps its place among
//! theirs.

use core::ffi::{c_char, c_int};

use crate::ffi;
use crate::sys::libc::{fprintf, fputc, fwrite, printf, stderr};
use crate::util::options::{OptSpec, option_label};
use crate::util::similar::{Suggestion, resolve, suggest};

/// The most subcommands a command offers.
const SUBCMD_MAX: usize = 32;

/// The column an item's summary wraps at: a 100-column terminal, with
/// slack.
const HELP_WIDTH: usize = 90;

/// `struct help_item`.
#[repr(C)]
pub struct HelpItem {
    pub(crate) name: *const c_char,
    pub(crate) summary: *const c_char,
}

/// `struct help_section`: a section lists items, or the options of a
/// command's option table.
#[repr(C)]
pub struct HelpSection {
    pub(crate) header: *const c_char,
    pub(crate) items: *const HelpItem,
    pub(crate) n_items: usize,
    pub(crate) options: *const OptSpec,
    pub(crate) n_options: usize,
}

impl HelpSection {
    /// A section named `header` listing `items`, HELP_ITEMS().
    pub(crate) const fn items(header: &'static core::ffi::CStr, items: &[HelpItem]) -> Self {
        HelpSection {
            header: header.as_ptr(),
            items: items.as_ptr(),
            n_items: items.len(),
            options: core::ptr::null(),
            n_options: 0,
        }
    }

    /// A section named `header` listing the options of `options`,
    /// HELP_OPTIONS().
    pub(crate) const fn options(header: &'static core::ffi::CStr, options: &[OptSpec]) -> Self {
        HelpSection {
            header: header.as_ptr(),
            items: core::ptr::null(),
            n_items: 0,
            options: options.as_ptr(),
            n_options: options.len(),
        }
    }
}

/// A row of a section: the name in a column `w` wide, the summary
/// wrapped after it.
///
/// # Safety
///
/// `summary` is a C string.
unsafe fn print_row(name: &[u8], summary: *const c_char, w: usize) {
    let f = err_stream();
    let indent = 2 + w;
    let avail = if indent < HELP_WIDTH {
        HELP_WIDTH - indent
    } else {
        1
    };
    let mut row = b"  ".to_vec();

    row.extend_from_slice(name);
    row.resize(row.len().max(2 + w), b' ');
    // SAFETY: the stream and the row's bytes, and the caller's C string.
    unsafe {
        fwrite(row.as_ptr().cast(), 1, row.len(), f);
        wrap_print(ffi::c_str(summary), indent, avail);
    }
}

/// `struct help`.
#[repr(C)]
pub struct Help {
    pub(crate) usage: *const c_char,
    pub(crate) summary: *const c_char,
    pub(crate) sections: *const HelpSection,
    pub(crate) n_sections: usize,
    pub(crate) footer: *const c_char,
}

// SAFETY: help is tables of pointers to static C strings and arrays, read
// only, as a command's statics hold it.
unsafe impl Sync for Help {}
// SAFETY: as above.
unsafe impl Sync for HelpSection {}
// SAFETY: as above.
unsafe impl Sync for HelpItem {}

impl Help {
    /// A command's help: `usage`, `summary` and `footer` C strings or
    /// none, around `sections`.
    pub(crate) const fn new(
        usage: &'static core::ffi::CStr,
        summary: Option<&'static core::ffi::CStr>,
        sections: &'static [HelpSection],
        footer: Option<&'static core::ffi::CStr>,
    ) -> Self {
        Help {
            usage: usage.as_ptr(),
            summary: match summary {
                Some(s) => s.as_ptr(),
                None => core::ptr::null(),
            },
            sections: sections.as_ptr(),
            n_sections: sections.len(),
            footer: match footer {
                Some(s) => s.as_ptr(),
                None => core::ptr::null(),
            },
        }
    }
}

impl HelpItem {
    pub(crate) const fn new(
        name: &'static core::ffi::CStr,
        summary: &'static core::ffi::CStr,
    ) -> Self {
        HelpItem {
            name: name.as_ptr(),
            summary: summary.as_ptr(),
        }
    }
}

fn err_stream() -> *mut crate::sys::libc::File {
    // SAFETY: a read of the C library's stderr, which nothing changes.
    unsafe { stderr }
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

/// # Safety
///
/// Each of `items` has a name.
pub(crate) unsafe fn print_subcmd_list(items: &[HelpItem]) {
    for item in items {
        // SAFETY: a format of one C string, and the item's name.
        unsafe { printf(c"%s\n".as_ptr(), item.name) };
    }
}

/// # Safety
///
/// What `h` points to, and every item of its sections, holds C strings,
/// a header, usage, summary or footer possibly NULL, and arrays of the
/// lengths it gives.
pub(crate) unsafe fn print_help(h: &Help) {
    let f = err_stream();

    // SAFETY: the stream, the formats, and the C strings of h, which
    // fprintf() prints as "(null)" when a header is NULL, as before.
    unsafe {
        if !h.usage.is_null() {
            fprintf(f, c"usage: %s\n".as_ptr(), h.usage);
        }
        if !h.summary.is_null() && *h.summary != 0 {
            fprintf(f, c"\n%s\n".as_ptr(), h.summary);
        }
        for s in ffi::slice(h.sections, h.n_sections) {
            let items = ffi::slice(s.items, s.n_items);
            let options = ffi::slice(s.options, s.n_options);

            if items.is_empty() && options.is_empty() {
                continue;
            }
            let labels: Vec<Vec<u8>> = options.iter().map(option_label).collect();
            // Per section, so an Options section reads as cleanly as a
            // Subcommands one.
            let w = items
                .iter()
                .map(|item| ffi::c_str(item.name).len())
                .chain(labels.iter().map(Vec::len))
                .max()
                .unwrap_or(0)
                + 2;

            fprintf(f, c"\n%s\n".as_ptr(), s.header);
            for item in items {
                print_row(ffi::c_str(item.name), item.summary, w);
            }
            for (o, label) in options.iter().zip(&labels) {
                print_row(label, o.summary, w);
            }
        }
        if !h.footer.is_null() && *h.footer != 0 {
            fprintf(f, c"\n%s\n".as_ptr(), h.footer);
        }
    }
}

/// The names close enough to `bad`, a word that matches none, printed
/// as a did-you-mean block on stderr.
///
/// # Safety
///
/// `bad` and each of `names` are C strings.
pub(crate) unsafe fn help_suggest(bad: *const c_char, names: &[*const c_char]) {
    let mut sugg = [Suggestion {
        name: core::ptr::null::<c_char>(),
        dist: 0,
    }; 4];
    // SAFETY: the caller passes a C string.
    let bad_bytes = unsafe { ffi::c_str(bad) };
    // A quarter of the length is too tight for short words and lets
    // anything through for long ones, so half plus one, at most 3.
    let max_dist = ((bad_bytes.len() as c_int) / 2 + 1).min(3);
    let candidates = names.iter().map(|&name| {
        // SAFETY: each of the names is a C string.
        (name, unsafe { ffi::c_str(name) })
    });
    let n = suggest(bad_bytes, candidates, max_dist, &mut sugg);

    if n == 0 {
        return;
    }
    let f = err_stream();

    // SAFETY: the stream, the formats, and the names suggest() chose.
    unsafe {
        fprintf(f, c"\nDid you mean one of:\n".as_ptr());
        for s in &sugg[..n] {
            fprintf(f, c"\t%s\n".as_ptr(), s.name);
        }
    }
}

/// # Safety
///
/// `cmd_label` and `bad` are C strings, and each of `subcmds` has a
/// name.
unsafe fn help_unknown_subcommand(
    cmd_label: *const c_char,
    bad: *const c_char,
    subcmds: &[HelpItem],
) {
    let mut names = [core::ptr::null::<c_char>(); SUBCMD_MAX];
    let mut n_names = 0;

    // SAFETY: the stream, the format, and the caller's C strings.
    unsafe {
        fprintf(
            err_stream(),
            c"%s: '%s' is not a known subcommand.\nSee '%s --help'.\n".as_ptr(),
            cmd_label,
            bad,
            cmd_label,
        )
    };
    for (slot, item) in names.iter_mut().zip(subcmds) {
        *slot = item.name;
        n_names += 1;
    }
    // SAFETY: bad and the names are C strings.
    unsafe { help_suggest(bad, &names[..n_names]) };
}

/// The subcommand `input` names, exactly or as the one subcommand it is
/// a prefix of, or a prefix of; NULL with stderr written, a did-you-mean
/// block or the ambiguous matches, when there is none or more than one.
///
/// # Safety
///
/// `cmd_label` and `input` are C strings, and each of `subcmds` has a
/// name.
pub(crate) unsafe fn resolve_subcommand(
    cmd_label: *const c_char,
    input: *const c_char,
    subcmds: &[HelpItem],
) -> *const c_char {
    let mut names = [core::ptr::null::<c_char>(); SUBCMD_MAX];
    let mut matches = [0usize; SUBCMD_MAX];
    let mut n_names = 0;

    if subcmds.is_empty() {
        // SAFETY: the caller's C strings, and no subcommand.
        unsafe { help_unknown_subcommand(cmd_label, input, subcmds) };
        return core::ptr::null();
    }
    for (slot, item) in names.iter_mut().zip(subcmds) {
        *slot = item.name;
        n_names += 1;
    }
    let names = &names[..n_names];
    // SAFETY: the caller passes a C string.
    let typed = unsafe { ffi::c_str(input) };
    let candidate = |i: usize| {
        // SAFETY: each of the names is a C string.
        unsafe { ffi::c_str(names[i]) }
    };
    let n = resolve(typed, names.len(), candidate, &mut matches);

    if n == 1 {
        return names[matches[0]];
    }
    if n == 0 {
        // SAFETY: the caller's C strings and subcommands.
        unsafe { help_unknown_subcommand(cmd_label, input, subcmds) };
        return core::ptr::null();
    }
    let f = err_stream();

    // SAFETY: the stream, the formats, and the caller's C strings.
    unsafe {
        fprintf(
            f,
            c"%s: '%s' is ambiguous; matches:\n".as_ptr(),
            cmd_label,
            input,
        );
        for &i in &matches[..n] {
            fprintf(f, c"\t%s\n".as_ptr(), names[i]);
        }
    }
    core::ptr::null()
}

mod capi {
    use core::ffi::{c_char, c_int};

    use super::{Help, HelpItem};
    use crate::ffi;

    /// The word at `arg`, or none for NULL.
    ///
    /// # Safety
    ///
    /// `arg` is NULL or a C string.
    unsafe fn word<'a>(arg: *const c_char) -> Option<&'a [u8]> {
        // SAFETY: the caller passes NULL or a C string.
        (!arg.is_null()).then(|| unsafe { ffi::c_str(arg) })
    }

    /// # Safety
    ///
    /// `arg` is NULL or a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn is_help(arg: *const c_char) -> c_int {
        // SAFETY: the caller passes NULL or a C string.
        c_int::from(super::is_help(unsafe { word(arg) }))
    }

    /// # Safety
    ///
    /// `arg` is NULL or a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn is_list_cmds(arg: *const c_char) -> c_int {
        // SAFETY: the caller passes NULL or a C string.
        c_int::from(super::is_list_cmds(unsafe { word(arg) }))
    }

    /// # Safety
    ///
    /// `items` holds `n_items` items, each with a name.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn print_subcmd_list(items: *const HelpItem, n_items: usize) {
        // SAFETY: the caller passes the items.
        unsafe { super::print_subcmd_list(ffi::slice(items, n_items)) }
    }

    /// # Safety
    ///
    /// `h` points to a help whose strings and arrays are as
    /// `util/help.h` lays them out.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn print_help(h: *const Help) {
        // SAFETY: the caller passes a help.
        unsafe { super::print_help(&*h) }
    }

    /// # Safety
    ///
    /// `bad` is a C string and `names` holds `n_names` of them.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn help_suggest(
        bad: *const c_char,
        names: *const *const c_char,
        n_names: usize,
    ) {
        // SAFETY: the caller passes the strings.
        unsafe { super::help_suggest(bad, ffi::slice(names, n_names)) }
    }

    /// # Safety
    ///
    /// `cmd_label` and `input` are C strings, and `subcmds` is NULL or
    /// holds `n_subcmds` items, each with a name.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn resolve_subcommand(
        cmd_label: *const c_char,
        input: *const c_char,
        subcmds: *const HelpItem,
        n_subcmds: usize,
    ) -> *const c_char {
        let subcmds = if subcmds.is_null() {
            &[][..]
        } else {
            // SAFETY: the caller passes the items.
            unsafe { ffi::slice(subcmds, n_subcmds) }
        };

        // SAFETY: the caller passes the strings and the items.
        unsafe { super::resolve_subcommand(cmd_label, input, subcmds) }
    }
}
