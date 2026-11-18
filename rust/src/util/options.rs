// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The one parser of command line options: every
//! command's options come from a table indexed by its own enum of them,
//! and the parser holds each to the same rules.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use crate::ffi;
use crate::sys::libc::printf;
use crate::text::parse_u64;
use crate::util::help::{Help, help_suggest, is_list_cmds, print_help};
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

/// `struct opt_spec`: one option. Where `metavar` names a value, the
/// option takes one as the next argument or after `=`; where it is NULL,
/// it is a flag.
#[repr(C)]
pub struct OptSpec {
    pub(crate) name: *const c_char,
    pub(crate) short_name: c_char,
    pub(crate) flags: u32,
    pub(crate) metavar: *const c_char,
    pub(crate) summary: *const c_char,
}

const _: () = assert!(size_of::<OptSpec>() == 32);

// SAFETY: a table of pointers to static C strings, read only.
unsafe impl Sync for OptSpec {}

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
            name: name.as_ptr(),
            short_name: short_name as c_char,
            flags,
            metavar: match metavar {
                Some(m) => m.as_ptr(),
                None => ptr::null(),
            },
            summary: summary.as_ptr(),
        }
    }

    /// # Safety
    ///
    /// The spec's name is NULL or a C string.
    unsafe fn name_bytes(&self) -> Option<&[u8]> {
        // SAFETY: as the caller says.
        (!self.name.is_null()).then(|| unsafe { ffi::c_str(self.name) })
    }
}

/// `struct opt_name`: a name an option's value may be, and the value it
/// stands for.
#[repr(C)]
pub struct OptName {
    pub(crate) name: *const c_char,
    pub(crate) value: c_int,
}

// SAFETY: as OptSpec.
unsafe impl Sync for OptName {}

impl OptName {
    pub(crate) const fn new(name: &'static CStr, value: c_int) -> Self {
        OptName {
            name: name.as_ptr(),
            value,
        }
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
                // SAFETY: a command's help, of C strings.
                unsafe { print_help(h) };
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
                    // SAFETY: a table that passed specs_valid(), whose
                    // names are C strings.
                    .position(|s| unsafe { s.name_bytes() } == Some(name))
                    .map(|i| (i, value))
            }
            &[b'-', short] => self
                .specs
                .iter()
                .position(|s| s.short_name as u8 == short)
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
        let mut bad = typed.to_vec();
        bad.push(0);
        let names: Vec<*const c_char> = self.specs.iter().map(|s| s.name).collect();
        // SAFETY: a C string, and the names of the specs, C strings.
        unsafe { help_suggest(bad.as_ptr().cast(), &names) };
        OPT_USAGE
    }

    /// What bash completion reads: "--json=\t<path>", "--cert\t<path>",
    /// "-o".
    fn list(&self) -> c_int {
        for s in self.specs {
            let eq = if s.flags & OPT_OPTIONAL != 0 {
                c"="
            } else {
                c""
            };
            let (tab, metavar) = if s.metavar.is_null() {
                (c"", c"".as_ptr())
            } else {
                (c"\t", s.metavar)
            };

            // SAFETY: formats and C strings of the spec's.
            unsafe {
                if s.short_name != 0 {
                    printf(
                        c"-%c%s%s\n".as_ptr(),
                        c_int::from(s.short_name),
                        tab.as_ptr(),
                        metavar,
                    );
                }
                if s.metavar.is_null() {
                    printf(c"%s\n".as_ptr(), s.name);
                } else {
                    printf(c"%s%s\t%s\n".as_ptr(), s.name, eq.as_ptr(), s.metavar);
                }
            }
        }
        OPT_DONE
    }

    fn take_value(&mut self, opt: usize, eq: Option<&'a CStr>) -> c_int {
        let s = &self.specs[opt];
        let (flags, metavar) = (s.flags, s.metavar);
        let name = self.opt_name(opt);

        if metavar.is_null() {
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
        // SAFETY: an option of a table that passed specs_valid(), whose
        // name is a C string.
        unsafe { ffi::c_str(self.specs[opt].name) }
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
        // SAFETY: the names a command gives, C strings.
        let name = |n: &OptName| unsafe { ffi::c_str(n.name) };
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

/// A table with a hole, a name twice, or a flag marked as taking a value
/// would leave an option unreachable or read wrong, whatever the command
/// line; refuse it before any argument is read.
fn specs_valid(specs: &[OptSpec]) -> bool {
    if specs.len() > OPT_MAX {
        return false;
    }
    for (i, s) in specs.iter().enumerate() {
        // SAFETY: a name, NULL or a C string.
        let Some(name) = (unsafe { s.name_bytes() }) else {
            return false;
        };
        if !name.starts_with(b"--")
            || name.len() == 2
            || name.contains(&b'=')
            || s.summary.is_null()
        {
            return false;
        }
        if s.metavar.is_null() && s.flags & (OPT_EMPTY | OPT_OPTIONAL) != 0 {
            return false;
        }
        for o in &specs[..i] {
            // SAFETY: as above, for an earlier spec, checked already.
            if unsafe { o.name_bytes() } == Some(name)
                || (s.short_name != 0 && s.short_name == o.short_name)
            {
                return false;
            }
        }
    }
    true
}

/// The option label help shows: "-o, --output <path>",
/// "--json[=<path>]".
pub(crate) fn option_label(o: &OptSpec) -> Vec<u8> {
    // SAFETY: a spec's name and metavar, C strings or a NULL metavar.
    let (name, metavar) = unsafe {
        (
            ffi::c_str(o.name),
            (!o.metavar.is_null()).then(|| ffi::c_str(o.metavar)),
        )
    };
    let mut label = Vec::new();

    if o.short_name != 0 {
        label.extend_from_slice(&[b'-', o.short_name as u8, b',', b' ']);
    }
    label.extend_from_slice(name);
    match metavar {
        None => {}
        Some(m) if o.flags & OPT_OPTIONAL != 0 => {
            label.extend_from_slice(b"[=");
            label.extend_from_slice(m);
            label.push(b']');
        }
        Some(m) => {
            label.push(b' ');
            label.extend_from_slice(m);
        }
    }
    label
}

#[cfg(test)]
mod tests;
