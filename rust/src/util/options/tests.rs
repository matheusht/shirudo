// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::testutil::serial;

const T_CERT: c_int = 0;
const T_FORCE: c_int = 1;
const T_OUTPUT: c_int = 2;
const T_JSON: c_int = 3;
const T_ADD: c_int = 4;
const T_TAG: c_int = 5;
const T_COUNT: c_int = 6;

static SPECS: [OptSpec; 7] = [
    OptSpec::new(c"--cert", 0, 0, Some(c"<path>"), c"a certificate"),
    OptSpec::new(c"--force", b'f', 0, None, c"overwrite"),
    OptSpec::new(c"--output", b'o', 0, Some(c"<path>"), c"where to write"),
    OptSpec::new(
        c"--json",
        0,
        OPT_OPTIONAL,
        Some(c"<path>"),
        c"JSON, to a file",
    ),
    OptSpec::new(c"--add", 0, OPT_REPEAT, Some(c"<name>"), c"one more name"),
    OptSpec::new(
        c"--tag",
        0,
        OPT_EMPTY,
        Some(c"<tag>"),
        c"a tag, may be empty",
    ),
    OptSpec::new(c"--count", 0, 0, Some(c"<n>"), c"how many"),
];

/// `check` of a parser of `args` against `specs`.
fn with_specs<T>(
    specs: &[OptSpec],
    args: &[&CStr],
    check: impl FnOnce(&mut OptParser<'_>) -> T,
) -> T {
    let argv: Vec<*const c_char> = args.iter().map(|a| a.as_ptr()).collect();
    let mut p = OptParser::new(c"test", specs, None, &argv, 0);
    check(&mut p)
}

fn with<T>(args: &[&CStr], check: impl FnOnce(&mut OptParser<'_>) -> T) -> T {
    with_specs(&SPECS, args, check)
}

/// What a parser of `args` gives, up to its end, each with its value.
fn parsed(args: &[&CStr]) -> Vec<(c_int, Option<Vec<u8>>)> {
    with(args, |p| {
        let mut out = Vec::new();
        loop {
            let opt = p.next();
            out.push((opt, p.value().map(|v| v.to_bytes().to_vec())));
            if matches!(opt, OPT_END | OPT_USAGE | OPT_DONE) {
                return out;
            }
        }
    })
}

/// An option or argument and its value.
fn v(opt: c_int, value: &str) -> (c_int, Option<Vec<u8>>) {
    (opt, Some(value.as_bytes().to_vec()))
}

/// An end of the parse, or a flag.
fn bare(opt: c_int) -> (c_int, Option<Vec<u8>>) {
    (opt, None)
}

#[test]
fn both_value_forms_give_the_same() {
    assert_eq!(
        parsed(&[c"--cert", c"a.der", c"--output=b"]),
        [v(T_CERT, "a.der"), v(T_OUTPUT, "b"), bare(OPT_END)]
    );
    with(&[c"--cert", c"a.der"], |p| {
        while p.next() >= 0 {}
        assert!(p.given(T_CERT));
        assert!(!p.given(T_FORCE));
    });
}

#[test]
fn a_value_must_be_there_and_not_empty() {
    assert_eq!(parsed(&[c"--cert"]).last().unwrap().0, OPT_USAGE);
    assert_eq!(parsed(&[c"--cert="]).last().unwrap().0, OPT_USAGE);
    assert_eq!(parsed(&[c"--tag="])[0], v(T_TAG, ""));
}

#[test]
fn a_flag_takes_no_value() {
    assert_eq!(parsed(&[c"-f"])[0], bare(T_FORCE));
    assert_eq!(parsed(&[c"--force=yes"])[0].0, OPT_USAGE);
}

#[test]
fn an_option_comes_once_unless_it_repeats() {
    let twice = parsed(&[c"--cert", c"a", c"--cert=b"]);
    assert_eq!((twice[0].0, twice[1].0), (T_CERT, OPT_USAGE));
    let alias = parsed(&[c"-f", c"--force"]);
    assert_eq!((alias[0].0, alias[1].0), (T_FORCE, OPT_USAGE));
    assert_eq!(
        parsed(&[c"--add", c"x", c"--add=y"]),
        [v(T_ADD, "x"), v(T_ADD, "y"), bare(OPT_END)]
    );
}

#[test]
fn unknown_and_glued_options_are_refused() {
    for bad in [c"--crt", c"--cert-file=x", c"-x", c"-oout", c"-fo", c"--c"] {
        assert_eq!(parsed(&[bad])[0].0, OPT_USAGE, "{bad:?}");
    }
}

#[test]
fn arguments_interleave_and_double_dash_ends_options() {
    assert_eq!(
        parsed(&[c"pkg", c"-o", c"x", c"-", c"--", c"--cert", c"-f"]),
        [
            v(OPT_ARG, "pkg"),
            v(T_OUTPUT, "x"),
            v(OPT_ARG, "-"),
            v(OPT_ARG, "--cert"),
            v(OPT_ARG, "-f"),
            bare(OPT_END)
        ]
    );
}

#[test]
fn an_optional_value_comes_after_equals_alone() {
    let given = parsed(&[c"--json", c"file", c"--output", c"o"]);
    assert_eq!(given[..2], [bare(T_JSON), v(OPT_ARG, "file")]);
    assert_eq!(parsed(&[c"--json=log.ndjson"])[0], v(T_JSON, "log.ndjson"));
}

#[test]
fn help_and_the_option_list_end_parsing() {
    let help = parsed(&[c"--cert", c"a", c"-h", c"--bogus"]);
    assert_eq!((help[0].0, help[1].0), (T_CERT, OPT_DONE));

    // The lists go to standard output, here to /dev/null.
    let _serial = serial();
    let null = std::fs::File::options()
        .write(true)
        .open("/dev/null")
        .unwrap();
    // SAFETY: standard output saved, pointed at /dev/null for the lists,
    // flushed and put back.
    let saved = unsafe { libc::dup(1) };
    // SAFETY: as above.
    let ret = unsafe { libc::dup2(std::os::fd::AsRawFd::as_raw_fd(&null), 1) };
    assert_eq!(ret, 1);
    let list = parsed(&[c"--list-opts"])[0].0;
    let cmds = parsed(&[c"--list-cmds"])[0].0;
    // SAFETY: as above.
    unsafe {
        libc::fflush(ptr::null_mut());
        assert_eq!(libc::dup2(saved, 1), 1);
        libc::close(saved);
    }
    assert_eq!((list, cmds), (OPT_DONE, OPT_DONE));
}

#[test]
fn a_number_is_bounded() {
    with(&[c"--count", c"512"], |p| {
        assert_eq!(p.next(), T_COUNT);
        assert_eq!(p.number(1, 512), Ok(512));
    });
    for bad in [c"--count=0", c"--count=513", c"--count=ten"] {
        with(&[bad], |p| {
            assert_eq!(p.next(), T_COUNT);
            assert_eq!(p.number(1, 512), Err(OPT_USAGE), "{bad:?}");
        });
    }
    with(&[], |p| {
        assert_eq!(p.next(), OPT_END);
        assert_eq!(p.number(1, 512), Err(OPT_USAGE));
    });
}

#[test]
fn a_choice_names_its_value() {
    let ops = [OptName::new(c"add", 0), OptName::new(c"delete", 1)];

    with(&[c"--tag=delete"], |p| {
        assert_eq!(p.next(), T_TAG);
        assert_eq!(p.choice(&ops), Ok(1));
    });
    with(&[c"--tag=remove"], |p| {
        assert_eq!(p.next(), T_TAG);
        assert_eq!(p.choice(&ops), Err(OPT_USAGE));
    });
}

#[test]
fn a_malformed_table_is_refused_before_any_argument() {
    let hole = OptSpec {
        name: ptr::null(),
        short_name: 0,
        flags: 0,
        metavar: ptr::null(),
        summary: ptr::null(),
    };
    let a = || OptSpec::new(c"--a", 0, 0, None, c"a");
    let tables = [
        vec![hole, a()],
        vec![a(), OptSpec::new(c"--a", 0, 0, Some(c"<x>"), c"a again")],
        vec![OptSpec::new(c"--a", 0, OPT_EMPTY, None, c"a")],
        vec![OptSpec::new(c"a", 0, 0, None, c"a")],
    ];

    for specs in &tables {
        with_specs(specs, &[c"arg"], |p| assert_eq!(p.next(), OPT_USAGE));
    }
}
