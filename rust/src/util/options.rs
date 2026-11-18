// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The one parser of command line options: every
//! command's options come from a table indexed by its own enum of them,
//! and the parser holds each to the same rules.

use core::ffi::{CStr, c_char, c_int};
use core::marker::PhantomData;
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

/// `struct opt_parser`: the arguments from `next` on, against the
/// `n_specs` options of `specs`, whose index is the command's enum of
/// them. It borrows the command, its table, help and arguments for `'a`.
#[repr(C)]
pub struct OptParser<'a> {
    pub(crate) command: *const c_char,
    pub(crate) specs: *const OptSpec,
    pub(crate) n_specs: usize,
    pub(crate) help: *const Help,
    pub(crate) argv: *const *const c_char,
    pub(crate) argc: c_int,
    pub(crate) next: c_int,
    pub(crate) checked: bool,
    /// After "--".
    pub(crate) args_only: bool,
    pub(crate) given: u64,
    /// The option last returned.
    pub(crate) opt: c_int,
    pub(crate) value: *const c_char,
    pub(crate) borrow: PhantomData<&'a ()>,
}

const _: () = assert!(size_of::<OptParser>() == 80);

impl<'a> OptParser<'a> {
    /// A parser of `args`, C strings, from `first` on, against `specs`.
    /// Its errors start with `command`, and -h or --help prints `help`.
    pub(crate) fn new(
        command: &'a CStr,
        specs: &'a [OptSpec],
        help: Option<&'a Help>,
        args: &'a [*const c_char],
        first: usize,
    ) -> Self {
        OptParser {
            command: command.as_ptr(),
            specs: specs.as_ptr(),
            n_specs: specs.len(),
            help: help.map_or(ptr::null(), ptr::from_ref),
            argv: args.as_ptr(),
            argc: args.len() as c_int,
            next: first as c_int,
            checked: false,
            args_only: false,
            given: 0,
            opt: OPT_END,
            value: ptr::null(),
            borrow: PhantomData,
        }
    }

    fn specs(&self) -> &[OptSpec] {
        // SAFETY: the table the parser was made with, of n_specs specs.
        unsafe { ffi::slice(self.specs, self.n_specs) }
    }

    fn arg(&self, i: c_int) -> *const c_char {
        // SAFETY: argv holds argc arguments, and i is below argc.
        unsafe { *self.argv.add(i as usize) }
    }

    fn command(&self) -> &[u8] {
        // SAFETY: the parser's command, a C string.
        unsafe { ffi::c_str(self.command) }
    }

    /// The value of the option or argument last returned, None for an
    /// option that takes none or an optional one given without.
    pub(crate) fn value(&self) -> Option<&'a CStr> {
        // SAFETY: the value points into an argument, a C string, or is
        // NULL.
        (!self.value.is_null()).then(|| unsafe { CStr::from_ptr(self.value) })
    }

    /// Whether the option of index `opt` was given.
    pub(crate) fn given(&self, opt: c_int) -> bool {
        self.given & (1u64 << opt) != 0
    }

    /// Reports a usage error the command finds, as "<command>:
    /// <message>"; the caller returns OPT_USAGE or EXIT_USAGE.
    pub(crate) fn usage(&self, message: &[u8]) {
        crate::log::err(&[self.command(), b": ", message].concat());
    }

    /// Reports the argument last returned, a usage error, as
    /// "<command>: <before>'<argument>'".
    pub(crate) fn usage_arg(&self, before: &[u8]) {
        let value = self.value().map_or(&b""[..], CStr::to_bytes);

        self.usage(&[before, b"'", value, b"'"].concat());
    }

    /// The index of the next option, with its value set where it takes
    /// one; otherwise one of the OPT_ codes. An unknown option, a value
    /// missing, empty or given to a flag, and an option given twice are
    /// usage errors. --list-opts prints the options, for completion, and
    /// --list-cmds the subcommands, which are none.
    pub(crate) fn next(&mut self) -> c_int {
        if !self.checked && !specs_valid(self.specs()) {
            self.usage(b"the table of its options is malformed");
            return OPT_USAGE;
        }
        self.checked = true;
        self.value = ptr::null();
        self.opt = OPT_END;
        let arg = loop {
            if self.next >= self.argc {
                return OPT_END;
            }
            let arg = self.arg(self.next);
            self.next += 1;
            // SAFETY: an argument, a C string.
            let bytes = unsafe { ffi::c_str(arg) };
            if self.args_only || bytes.first() != Some(&b'-') || bytes.len() == 1 {
                self.value = arg;
                return OPT_ARG;
            }
            if bytes != b"--" {
                break arg;
            }
            self.args_only = true;
        };
        // SAFETY: as above.
        let bytes = unsafe { ffi::c_str(arg) };
        if bytes == b"-h" || bytes == b"--help" {
            // SAFETY: the help the command gave, or NULL.
            if let Some(h) = unsafe { self.help.as_ref() } {
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
            return self.unknown(bytes);
        };
        let s = &self.specs()[opt];
        let (flags, name) = (s.flags, s.name);
        if self.given(opt as c_int) && flags & OPT_REPEAT == 0 {
            // SAFETY: the spec's name, a C string.
            let name = unsafe { ffi::c_str(name) };
            self.usage(&[name, b" given twice"].concat());
            return OPT_USAGE;
        }
        if self.take_value(opt, eq) != 0 {
            return OPT_USAGE;
        }
        self.given |= 1u64 << opt;
        self.opt = opt as c_int;
        opt as c_int
    }

    /// The index of the option `arg` names, and what follows its `=`
    /// where it has one. A short option stands alone: -o, never -ovalue
    /// or -fo.
    fn find(&self, arg: *const c_char) -> Option<(usize, *const c_char)> {
        // SAFETY: an argument, a C string.
        let bytes = unsafe { ffi::c_str(arg) };
        if bytes[1] != b'-' {
            if bytes.len() != 2 {
                return None;
            }
            return self
                .specs()
                .iter()
                .position(|s| s.short_name as u8 == bytes[1])
                .map(|i| (i, ptr::null()));
        }
        let len = bytes.iter().position(|&c| c == b'=').unwrap_or(bytes.len());
        let eq = if len < bytes.len() {
            // SAFETY: the byte past the =, within the argument, its NUL at
            // the last.
            unsafe { arg.add(len + 1) }
        } else {
            ptr::null()
        };
        self.specs()
            .iter()
            // SAFETY: a table that passed specs_valid(), whose names are
            // C strings.
            .position(|s| unsafe { s.name_bytes() } == Some(&bytes[..len]))
            .map(|i| (i, eq))
    }

    fn unknown(&self, arg: &[u8]) -> c_int {
        let len = if arg[1] == b'-' {
            arg.iter().position(|&c| c == b'=').unwrap_or(arg.len())
        } else {
            arg.len()
        };
        crate::log::err(&[self.command(), b": unknown option '", &arg[..len], b"'"].concat());
        if len > SIMILAR_MAX_LEN {
            return OPT_USAGE;
        }
        let mut bad = arg[..len].to_vec();
        bad.push(0);
        let names: Vec<*const c_char> = self.specs().iter().map(|s| s.name).collect();
        // SAFETY: a C string, and the names of the specs, C strings.
        unsafe { help_suggest(bad.as_ptr().cast(), &names) };
        OPT_USAGE
    }

    /// What bash completion reads: "--json=\t<path>", "--cert\t<path>",
    /// "-o".
    fn list(&self) -> c_int {
        for s in self.specs() {
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

    fn take_value(&mut self, opt: usize, eq: *const c_char) -> c_int {
        let s = &self.specs()[opt];
        let (flags, metavar) = (s.flags, s.metavar);
        // SAFETY: the spec's name, a C string.
        let name = unsafe { ffi::c_str(s.name) };

        if metavar.is_null() {
            if eq.is_null() {
                return 0;
            }
            self.usage(&[name, b" takes no value"].concat());
            return OPT_USAGE;
        }
        if !eq.is_null() {
            self.value = eq;
        } else if flags & OPT_OPTIONAL != 0 {
            return 0;
        } else if self.next < self.argc {
            self.value = self.arg(self.next);
            self.next += 1;
        } else {
            self.usage(&[name, b" takes a value"].concat());
            return OPT_USAGE;
        }
        // SAFETY: the value, a C string.
        if unsafe { *self.value } == 0 && flags & OPT_EMPTY == 0 {
            self.usage(&[name, b" takes a value, not an empty one"].concat());
            return OPT_USAGE;
        }
        0
    }

    fn opt_name(&self) -> &[u8] {
        // SAFETY: the option last returned, whose name is a C string.
        unsafe { ffi::c_str(self.specs()[self.opt as usize].name) }
    }

    /// The value of the option last returned as a number from `min` to
    /// `max`, or OPT_USAGE, reported.
    pub(crate) fn number(&self, min: u64, max: u64) -> Result<u64, c_int> {
        let Some(value) = self.value().filter(|_| self.opt >= 0) else {
            self.usage(b"no option value to read as a number");
            return Err(OPT_USAGE);
        };
        match parse_u64(value.to_bytes(), max) {
            Ok(v) if v >= min => Ok(v),
            _ => {
                self.usage(
                    &[
                        self.opt_name(),
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
        let Some(value) = self.value().filter(|_| self.opt >= 0) else {
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
        self.usage(&[self.opt_name(), b" takes ", &list[..]].concat());
        Err(OPT_USAGE)
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
