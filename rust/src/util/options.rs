// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The one parser of command line options: every
//! command's options come from a table indexed by its own enum of them,
//! and the parser holds each to the same rules.

use core::ffi::{CStr, c_int};

use crate::text::parse_u64;
use crate::util::help::{Help, help_suggest, is_list_cmds, out_write, print_help};
use crate::util::similar::MAX_LEN as SIMILAR_MAX_LEN;

/// The exit status of every usage error.
pub(crate) const EXIT_USAGE: c_int = 2;

/// The most options one command has: a bit each in [`OptParser::given`].
pub(crate) const OPT_MAX: usize = 64;

/// May be given more than once.
pub(crate) const OPT_REPEAT: u32 = 1 << 0;
/// May be given an empty value.
pub(crate) const OPT_EMPTY: u32 = 1 << 1;
/// Takes a value after `=` alone, or none.
pub(crate) const OPT_OPTIONAL: u32 = 1 << 2;

/// No argument is left.
pub(crate) const OPT_END: c_int = -1;
/// An argument, in the value.
pub(crate) const OPT_ARG: c_int = -2;
/// Help or the option list printed: exit 0.
pub(crate) const OPT_DONE: c_int = -3;
/// A usage error, already reported.
pub(crate) const OPT_USAGE: c_int = -4;

/// One option. Where `metavar` names a value, the option takes one as
/// the next argument or after `=`; where it is None, it is a flag.
pub struct OptSpec {
    name: &'static CStr,
    short_name: u8,
    flags: u32,
    metavar: Option<&'static CStr>,
    pub(crate) summary: &'static CStr,
}

impl OptSpec {
    /// A flag, or with `metavar` an option that takes a value.
    pub(crate) const fn new(
        name: &'static CStr,
        short_name: u8,
        flags: u32,
        metavar: Option<&'static CStr>,
        summary: &'static CStr,
    ) -> Self {
        OptSpec {
            name,
            short_name,
            flags,
            metavar,
            summary,
        }
    }
}

/// A name an option's value may be, and the value it stands for.
pub struct OptName {
    name: &'static CStr,
    value: c_int,
}

impl OptName {
    pub(crate) const fn new(name: &'static CStr, value: c_int) -> Self {
        OptName { name, value }
    }
}

/// A parse of a command's arguments from `next` on, against the options
/// of `specs`, whose index is the command's enum of them. It borrows the
/// command, its table, help and arguments for `'a`.
pub struct OptParser<'a> {
    command: &'a CStr,
    specs: &'a [OptSpec],
    help: Option<&'a Help>,
    args: &'a [&'a CStr],
    next: usize,
    checked: bool,
    /// After "--".
    args_only: bool,
    given: u64,
    /// The option last returned.
    opt: Option<usize>,
    value: Option<&'a CStr>,
}

impl<'a> OptParser<'a> {
    /// A parser of `args` from `first` on, against `specs`. Its errors
    /// start with `command`, and -h or --help prints `help`.
    pub(crate) fn new(
        command: &'a CStr,
        specs: &'a [OptSpec],
        help: Option<&'a Help>,
        args: &'a [&'a CStr],
        first: usize,
    ) -> Self {
        OptParser {
            command,
            specs,
            help,
            args,
            next: first,
            checked: false,
            args_only: false,
            given: 0,
            opt: None,
            value: None,
        }
    }

    /// The value of the option or argument last returned, None for an
    /// option that takes none or an optional one given without.
    pub(crate) fn value(&self) -> Option<&'a CStr> {
        self.value
    }

    /// Whether the option of index `opt` was given.
    pub(crate) fn given(&self, opt: c_int) -> bool {
        self.given & (1u64 << opt) != 0
    }

    /// Reports a usage error the command finds, as "<command>:
    /// <message>"; the caller returns OPT_USAGE or EXIT_USAGE.
    pub(crate) fn usage(&self, message: &[u8]) {
        crate::log::err(&[self.command.to_bytes(), b": ", message].concat());
    }

    /// Reports the argument last returned, a usage error, as
    /// "<command>: <before>'<argument>'".
    pub(crate) fn usage_arg(&self, before: &[u8]) {
        let value = self.value.map_or(&b""[..], CStr::to_bytes);

        self.usage(&[before, b"'", value, b"'"].concat());
    }

    /// The index of the next option, with its value set where it takes
    /// one; otherwise one of the OPT_ codes. An unknown option, a value
    /// missing, empty or given to a flag, and an option given twice are
    /// usage errors. --list-opts prints the options, for completion, and
    /// --list-cmds the subcommands, which are none.
    pub(crate) fn next(&mut self) -> c_int {
        if !self.checked && !specs_valid(self.specs) {
            self.usage(b"the table of its options is malformed");
            return OPT_USAGE;
        }
        self.checked = true;
        self.value = None;
        self.opt = None;
        let arg = loop {
            let Some(&arg) = self.args.get(self.next) else {
                return OPT_END;
            };
            self.next += 1;
            let bytes = arg.to_bytes();
            if self.args_only || bytes.first() != Some(&b'-') || bytes.len() == 1 {
                self.value = Some(arg);
                return OPT_ARG;
            }
            if bytes != b"--" {
                break arg;
            }
            self.args_only = true;
        };
        let bytes = arg.to_bytes();
        if bytes == b"-h" || bytes == b"--help" {
            if let Some(h) = self.help {
                print_help(h);
            }
            return OPT_DONE;
        }
        if bytes == b"--list-opts" {
            return self.list();
        }
        // A command whose options this parser reads has no subcommands.
        if is_list_cmds(Some(bytes)) {
            return OPT_DONE;
        }
        let Some((opt, eq)) = self.find(arg) else {
            return self.unknown(arg);
        };
        // A table that passed specs_valid() has at most OPT_MAX options.
        let index = opt as c_int;
        if self.given(index) && self.specs[opt].flags & OPT_REPEAT == 0 {
            self.usage(&[self.opt_name(opt), b" given twice"].concat());
            return OPT_USAGE;
        }
        if self.take_value(opt, eq) != 0 {
            return OPT_USAGE;
        }
        self.given |= 1u64 << opt;
        self.opt = Some(opt);
        index
    }

    /// The index of the option `arg` names, and what follows its `=`
    /// where it has one. A short option stands alone: -o, never -ovalue
    /// or -fo.
    fn find(&self, arg: &'a CStr) -> Option<(usize, Option<&'a CStr>)> {
        match arg.to_bytes() {
            [b'-', b'-', ..] => {
                let (name, value) = long_parts(arg);
                self.specs
                    .iter()
                    .position(|s| s.name.to_bytes() == name)
                    .map(|i| (i, value))
            }
            &[b'-', short] => self
                .specs
                .iter()
                .position(|s| s.short_name == short)
                .map(|i| (i, None)),
            _ => None,
        }
    }

    fn unknown(&self, arg: &CStr) -> c_int {
        let typed = if arg.to_bytes().starts_with(b"--") {
            long_parts(arg).0
        } else {
            arg.to_bytes()
        };
        crate::log::err(&[self.command.to_bytes(), b": unknown option '", typed, b"'"].concat());
        if typed.len() > SIMILAR_MAX_LEN {
            return OPT_USAGE;
        }
        help_suggest(typed, self.specs.iter().map(|s| s.name));
        OPT_USAGE
    }

    /// What bash completion reads: "--json=\t<path>", "--cert\t<path>",
    /// "-o".
    fn list(&self) -> c_int {
        for s in self.specs {
            let name = s.name.to_bytes();
            let eq: &[u8] = if s.flags & OPT_OPTIONAL != 0 {
                b"="
            } else {
                b""
            };
            let (tab, metavar): (&[u8], &[u8]) = match s.metavar {
                Some(m) => (b"\t", m.to_bytes()),
                None => (b"", b""),
            };

            if s.short_name != 0 {
                out_write(&[b"-", &[s.short_name][..], tab, metavar, b"\n"].concat());
            }
            if s.metavar.is_none() {
                out_write(&[name, b"\n"].concat());
            } else {
                out_write(&[name, eq, b"\t", metavar, b"\n"].concat());
            }
        }
        OPT_DONE
    }

    fn take_value(&mut self, opt: usize, eq: Option<&'a CStr>) -> c_int {
        let s = &self.specs[opt];
        let (flags, metavar) = (s.flags, s.metavar);
        let name = self.opt_name(opt);

        if metavar.is_none() {
            if eq.is_none() {
                return 0;
            }
            self.usage(&[name, b" takes no value"].concat());
            return OPT_USAGE;
        }
        if eq.is_some() {
            self.value = eq;
        } else if flags & OPT_OPTIONAL != 0 {
            return 0;
        } else if let Some(&arg) = self.args.get(self.next) {
            self.value = Some(arg);
            self.next += 1;
        } else {
            self.usage(&[name, b" takes a value"].concat());
            return OPT_USAGE;
        }
        if self.value.is_some_and(CStr::is_empty) && flags & OPT_EMPTY == 0 {
            self.usage(&[name, b" takes a value, not an empty one"].concat());
            return OPT_USAGE;
        }
        0
    }

    /// The name of the option of index `opt`.
    fn opt_name(&self, opt: usize) -> &'a [u8] {
        self.specs[opt].name.to_bytes()
    }

    /// The value of the option last returned as a number from `min` to
    /// `max`, or OPT_USAGE, reported.
    pub(crate) fn number(&self, min: u64, max: u64) -> Result<u64, c_int> {
        let (Some(opt), Some(value)) = (self.opt, self.value) else {
            self.usage(b"no option value to read as a number");
            return Err(OPT_USAGE);
        };
        match parse_u64(value.to_bytes(), max) {
            Ok(v) if v >= min => Ok(v),
            _ => {
                self.usage(
                    &[
                        self.opt_name(opt),
                        format!(" takes a number from {min} to {max}").as_bytes(),
                    ]
                    .concat(),
                );
                Err(OPT_USAGE)
            }
        }
    }

    /// The value of the name the option last returned was given, from
    /// `names`, or OPT_USAGE, reported with the names it takes.
    pub(crate) fn choice(&self, names: &[OptName]) -> Result<c_int, c_int> {
        let (Some(opt), Some(value)) = (self.opt, self.value) else {
            self.usage(b"no option value to read as a name");
            return Err(OPT_USAGE);
        };
        let name = |n: &OptName| n.name.to_bytes();
        if let Some(n) = names.iter().find(|n| name(n) == value.to_bytes()) {
            return Ok(n.value);
        }
        // The list as strsprintf() would leave it in 256 bytes: the names
        // that fit whole.
        let mut list = Vec::new();
        for (i, n) in names.iter().enumerate() {
            let sep: &[u8] = if i == 0 {
                b""
            } else if i + 1 < names.len() {
                b", "
            } else {
                b" or "
            };
            if list.len() + sep.len() + name(n).len() >= 256 {
                break;
            }
            list.extend_from_slice(sep);
            list.extend_from_slice(name(n));
        }
        self.usage(&[self.opt_name(opt), b" takes ", &list[..]].concat());
        Err(OPT_USAGE)
    }
}

/// A long option's name, up to its first `=`, and what follows that `=`,
/// a C string of its own.
fn long_parts(arg: &CStr) -> (&[u8], Option<&CStr>) {
    let bytes = arg.to_bytes_with_nul();
    match bytes.iter().position(|&c| c == b'=') {
        Some(eq) => {
            let (name, value) = bytes.split_at(eq);
            let value = value
                .get(1..)
                .and_then(|v| CStr::from_bytes_with_nul(v).ok());
            (name, value)
        }
        None => (arg.to_bytes(), None),
    }
}

/// A table with a name that is no long option, a name twice, or a flag
/// marked as taking a value would leave an option unreachable or read
/// wrong, whatever the command line; refuse it before any argument is
/// read.
fn specs_valid(specs: &[OptSpec]) -> bool {
    if specs.len() > OPT_MAX {
        return false;
    }
    for (i, s) in specs.iter().enumerate() {
        let name = s.name.to_bytes();
        if !name.starts_with(b"--") || name.len() == 2 || name.contains(&b'=') {
            return false;
        }
        if s.metavar.is_none() && s.flags & (OPT_EMPTY | OPT_OPTIONAL) != 0 {
            return false;
        }
        for o in &specs[..i] {
            if o.name == s.name || (s.short_name != 0 && s.short_name == o.short_name) {
                return false;
            }
        }
    }
    true
}

/// The option label help shows: "-o, --output <path>",
/// "--json[=<path>]".
pub(crate) fn option_label(o: &OptSpec) -> Vec<u8> {
    let mut label = Vec::new();

    if o.short_name != 0 {
        label.extend_from_slice(&[b'-', o.short_name, b',', b' ']);
    }
    label.extend_from_slice(o.name.to_bytes());
    match o.metavar {
        None => {}
        Some(m) if o.flags & OPT_OPTIONAL != 0 => {
            label.extend_from_slice(b"[=");
            label.extend_from_slice(m.to_bytes());
            label.push(b']');
        }
        Some(m) => {
            label.push(b' ');
            label.extend_from_slice(m.to_bytes());
        }
    }
    label
}

#[cfg(test)]
mod tests;
