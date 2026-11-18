// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The command line of `shirudo bpm`: its subcommands, their option
//! tables and help, and the words each takes, handed to the code that
//! acts on them. The operator-only subcommands go to shirudo-build,
//! which parses them itself.

use core::ffi::{CStr, c_int};

use super::{fail, fetch, finish, info, key, package, source, tree};
use crate::errno::{E2BIG, EIO};
use crate::util::help::{
    Help, HelpItem, HelpSection, is_help, is_list_cmds, print_help, print_subcmd_list,
    resolve_subcommand,
};
use crate::util::image_config;
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OPT_USAGE, OptParser, OptSpec};

static BPM_SUBCMDS: [HelpItem; 12] = [
    HelpItem::new(c"config", c"manage package inputs and OCI repositories"),
    HelpItem::new(c"repo", c"refresh signed repository indexes"),
    HelpItem::new(c"tree", c"synchronize or publish the signed upatch tree"),
    HelpItem::new(c"key", c"add, fingerprint, and list package certificates"),
    HelpItem::new(
        c"pull",
        c"download an OCI package into the current directory",
    ),
    HelpItem::new(c"info", c"print a local or OCI package README"),
    HelpItem::new(
        c"push",
        c"publish an OCI package and its signed index entry",
    ),
    HelpItem::new(c"build", c"build a signed OCI package from a Beefile"),
    HelpItem::new(
        c"install",
        c"download and activate a repository or OCI package",
    ),
    HelpItem::new(c"upgrade", c"activate newer cached package versions"),
    HelpItem::new(c"list", c"list installed packages"),
    HelpItem::new(c"uninstall", c"unload and remove an installed package"),
];

static TARGET_SUBCMDS: [HelpItem; 10] = [
    HelpItem::new(c"config", c"register and manage OCI repositories"),
    HelpItem::new(c"repo", c"refresh signed repository indexes"),
    HelpItem::new(c"tree", c"synchronize the optional signed upatch tree"),
    HelpItem::new(c"key", c"add, fingerprint, and list package certificates"),
    HelpItem::new(
        c"pull",
        c"download an OCI package into the current directory",
    ),
    HelpItem::new(c"info", c"print a local or OCI package README"),
    HelpItem::new(
        c"install",
        c"download and activate a repository or OCI package",
    ),
    HelpItem::new(c"upgrade", c"activate newer cached package versions"),
    HelpItem::new(c"list", c"list installed packages"),
    HelpItem::new(c"uninstall", c"unload and remove an installed package"),
];

static OPERATOR_SECTIONS: [HelpSection; 1] = [HelpSection::items(c"subcommands:", &BPM_SUBCMDS)];
static TARGET_SECTIONS: [HelpSection; 1] = [HelpSection::items(c"subcommands:", &TARGET_SUBCMDS)];

static OPERATOR_HELP: Help = Help::new(
    c"shirudo bpm <config|repo|tree|key|pull|info|push|build|install|upgrade|list|uninstall>",
    Some(c"Manage signed OCI packages and publish packages from the operator."),
    &OPERATOR_SECTIONS,
    None,
);

static TARGET_HELP: Help = Help::new(
    c"shirudo bpm <config|repo|tree|key|pull|info|install|upgrade|list|uninstall>",
    Some(c"Manage signed target-local BPM packages backed by OCI repositories."),
    &TARGET_SECTIONS,
    None,
);

const REGISTER_ADD_CERT: usize = 0;
const REGISTER_ADD_INDEX_REPOSITORY: usize = 1;

static REGISTER_ADD_OPTS: [OptSpec; 2] = [
    OptSpec::new(
        c"--cert",
        0,
        0,
        Some(c"<certificate>"),
        c"the certificate the source's index and packages are signed for",
    ),
    OptSpec::new(
        c"--index-repository",
        0,
        0,
        Some(c"<repository>"),
        c"the repository of the signed index (default <source>/bpm-index)",
    ),
];

const REGISTER_LIST_JSON: c_int = 0;

static REGISTER_LIST_OPTS: [OptSpec; 1] = [OptSpec::new(
    c"--json",
    0,
    0,
    None,
    c"print the registered sources as JSON",
)];

static CONFIG_SUBCMDS: [HelpItem; 2] = [
    HelpItem::new(c"register", c"register, list and remove OCI repositories"),
    HelpItem::new(c"update", c"build a config update package (operator)"),
];

static REGISTER_ACTIONS: [HelpItem; 3] = [
    HelpItem::new(c"add", c"register a source and its certificate"),
    HelpItem::new(c"list", c"list the registered sources"),
    HelpItem::new(c"remove", c"remove a source and its certificate"),
];

static CONFIG_SECTIONS: [HelpSection; 4] = [
    HelpSection::items(c"subcommands:", &CONFIG_SUBCMDS),
    HelpSection::items(c"register actions:", &REGISTER_ACTIONS),
    HelpSection::options(c"register add options:", &REGISTER_ADD_OPTS),
    HelpSection::options(c"register list options:", &REGISTER_LIST_OPTS),
];

static CONFIG_HELP: Help = Help::new(
    c"shirudo bpm config register add <source> oci://<registry> --cert <certificate>\n           \
      [--index-repository <repository>]\n       \
      shirudo bpm config register list [--json]\n       \
      shirudo bpm config register remove <source>\n       \
      shirudo bpm config update --base-package <package.bee|oci://host/repo:tag> --version <version> [--file <name>.bee] [options]",
    Some(c"Register the OCI repositories packages come from, or build a config\nupdate package (operator)."),
    &CONFIG_SECTIONS,
    None,
);

static KEY_SUBCMDS: [HelpItem; 3] = [
    HelpItem::new(
        c"add",
        c"install a trusted package certificate and print its fingerprint",
    ),
    HelpItem::new(
        c"fingerprint",
        c"print the SHA-256 fingerprint of a certificate's SPKI",
    ),
    HelpItem::new(c"list", c"list installed certificate fingerprints"),
];

const KEY_LIST_JSON: c_int = 0;

static KEY_LIST_OPTS: [OptSpec; 1] = [OptSpec::new(
    c"--json",
    0,
    0,
    None,
    c"print the certificates as JSON",
)];

static KEY_SECTIONS: [HelpSection; 2] = [
    HelpSection::items(c"subcommands:", &KEY_SUBCMDS),
    HelpSection::options(c"list options:", &KEY_LIST_OPTS),
];

static KEY_HELP: Help = Help::new(
    c"shirudo bpm key <add|fingerprint|list>",
    Some(c"Manage package signing certificates."),
    &KEY_SECTIONS,
    Some(
        c"add and fingerprint accept a certificate file, .bee package, or\n\
          oci://registry/repository:tag. list reads /var/lib/shirudo/keys.\n\
          Examples:\n  shirudo bpm key fingerprint ./package.bee\n  \
          shirudo bpm key add oci://quay.io/namespace/package:tag\n  shirudo bpm key list",
    ),
);

const INFO_ALL: c_int = 0;
const INFO_JSON: c_int = 1;

static INFO_OPTS: [OptSpec; 2] = [
    OptSpec::new(
        c"--all",
        0,
        0,
        None,
        c"with upatches: the .unload.upatch directives too",
    ),
    OptSpec::new(
        c"--json",
        0,
        0,
        None,
        c"with data: the decoded .rodata as JSON",
    ),
];

static INFO_SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &INFO_OPTS)];

static INFO_HELP: Help = Help::new(
    c"shirudo bpm info <package-file|package-reference>\n       \
      shirudo bpm info upatches <package> [--all]\n       \
      shirudo bpm info data <package> <upatch-member> [--json]",
    Some(
        c"Print a package's README.md, list its upatches, or decode the BPF\n\
          .rodata initial data through its BTF types. A package is a local .bee\n\
          file or an oci:// reference.",
    ),
    &INFO_SECTIONS,
    Some(
        c"Examples:\n  shirudo bpm info ./package.bee\n  \
          shirudo bpm info upatches ./package.bee --all\n  \
          shirudo bpm info data ./package.bee upatches/kernel-obs.upatch --json",
    ),
);

const TREE_SYNC_DRY_RUN: c_int = 0;
const TREE_SYNC_REPORT: usize = 1;

static TREE_SYNC_OPTS: [OptSpec; 2] = [
    OptSpec::new(
        c"--dry-run",
        0,
        0,
        None,
        c"say what would change and change nothing",
    ),
    OptSpec::new(
        c"--report",
        0,
        0,
        Some(c"<path>"),
        c"write the JSON report there",
    ),
];

static TREE_SUBCMDS: [HelpItem; 3] = [
    HelpItem::new(c"sync", c"apply the configured tree on a target"),
    HelpItem::new(c"append", c"publish a package's tree entries (operator)"),
    HelpItem::new(c"show", c"print a verified publication (operator)"),
];

static TREE_SECTIONS: [HelpSection; 2] = [
    HelpSection::items(c"subcommands:", &TREE_SUBCMDS),
    HelpSection::options(c"sync options:", &TREE_SYNC_OPTS),
];

static TREE_HELP: Help = Help::new(
    c"shirudo bpm tree sync [--dry-run] [--report=<path>]\n       \
      shirudo bpm tree append <package-file> <repository> [options]\n       \
      shirudo bpm tree show <repository> --cert <file> [--reference <ref>] [--walk]",
    Some(
        c"sync applies the configured tree on a target. append and show are\n\
          operator-only and run in shirudo-build: append publishes the\n\
          [upatches.tree] entries of a built package as the next operations of the\n\
          signed tree, show prints a verified publication; see their --help where\n\
          the operator package is installed.",
    ),
    &TREE_SECTIONS,
    None,
);

static PULL_HELP: Help = Help::new(
    c"shirudo bpm pull <package-reference>",
    Some(c"Download an OCI package into the current directory. The reference\nstarts with oci://."),
    &[],
    Some(c"Example:\n  shirudo bpm pull oci://quay.io/namespace/package:tag"),
);

static REPO_SUBCMDS: [HelpItem; 1] = [HelpItem::new(
    c"update",
    c"refresh the signed index of a source, or of all",
)];

static REPO_SECTIONS: [HelpSection; 1] = [HelpSection::items(c"subcommands:", &REPO_SUBCMDS)];

static REPO_HELP: Help = Help::new(
    c"shirudo bpm repo update [<source>]",
    Some(c"Refresh the signed index of one registered source, or of all of them."),
    &REPO_SECTIONS,
    None,
);

static INSTALL_HELP: Help = Help::new(
    c"shirudo bpm install <package>",
    Some(c"Download and activate a repository or OCI package."),
    &[],
    None,
);

const LIST_JSON: c_int = 0;

static LIST_OPTS: [OptSpec; 1] = [OptSpec::new(
    c"--json",
    0,
    0,
    None,
    c"print the installed packages as JSON",
)];

static LIST_SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &LIST_OPTS)];

static LIST_HELP: Help = Help::new(
    c"shirudo bpm list [--json]",
    Some(c"List the installed packages."),
    &LIST_SECTIONS,
    None,
);

static UNINSTALL_HELP: Help = Help::new(
    c"shirudo bpm uninstall <package>",
    Some(c"Unload and remove an installed package."),
    &[],
    None,
);

static UPGRADE_HELP: Help = Help::new(
    c"shirudo bpm upgrade",
    Some(c"Activate the newer package versions the cached indexes offer."),
    &[],
    None,
);

/// The word at `i` of `argv`, if there is one.
fn word<'a>(argv: &[&'a CStr], i: usize) -> Option<&'a [u8]> {
    argv.get(i).map(|a| a.to_bytes())
}

/// The words of a bpm subcommand, `min` to `max` of them, with the value
/// of each option given into `values` where there is one: Ok to act, or
/// the status to stop with, 0 where help or the option list was printed.
/// `want` names the words a command short of `min` lacks.
fn words<'a>(
    p: &mut OptParser<'a>,
    mut values: Option<&mut [Option<&'a CStr>]>,
    min: usize,
    max: usize,
    want: &[u8],
) -> Result<Vec<&'a CStr>, c_int> {
    let mut args = Vec::new();

    loop {
        match p.next() {
            OPT_END => break,
            OPT_DONE => return Err(0),
            OPT_USAGE => return Err(EXIT_USAGE),
            OPT_ARG => {
                if args.len() == max {
                    p.usage_arg(b"unexpected argument ");
                    return Err(EXIT_USAGE);
                }
                args.push(p.value().unwrap_or_default());
            }
            opt => {
                if let Some(v) = values.as_deref_mut() {
                    v[opt as usize] = p.value();
                }
            }
        }
    }
    if args.len() < min {
        p.usage(&[b"takes ", want].concat());
        return Err(EXIT_USAGE);
    }
    Ok(args)
}

/// Operator-only subcommands live in shirudo-build; the bpm argument
/// vector goes over unchanged so the helper parses it itself.
fn exec_operator(sub: &CStr, argv: &[&CStr]) -> c_int {
    let label = [b"bpm ", sub.to_bytes()].concat();

    if label.len() >= 64 {
        return fail(sub.to_bytes(), -E2BIG);
    }
    let label = super::message(&[&label]);
    let rest = argv.get(2..).unwrap_or_default();
    super::super::build::forward(&label, &[c"bpm", sub], rest)
}

fn curl_failed() -> c_int {
    fail(b"initialize curl", -EIO)
}

/// `bpm config`, `argv` from "config" on.
fn config(argv: &[&CStr]) -> c_int {
    let action = word(argv, 2);

    if argv.len() < 2 || is_help(word(argv, 1)) {
        print_help(&CONFIG_HELP);
        return if argv.len() < 2 { EXIT_USAGE } else { 0 };
    }
    if is_list_cmds(word(argv, 1)) {
        print_subcmd_list(&CONFIG_SUBCMDS);
        return 0;
    }
    if word(argv, 1) != Some(b"register") {
        super::error(&[
            b"bpm config: '",
            word(argv, 1).unwrap_or_default(),
            b"' is not a subcommand",
        ]);
        return EXIT_USAGE;
    }
    if action.is_none() || is_help(action) {
        print_help(&CONFIG_HELP);
        return if action.is_some() { 0 } else { EXIT_USAGE };
    }
    if is_list_cmds(action) {
        print_subcmd_list(&REGISTER_ACTIONS);
        return 0;
    }
    match action.unwrap_or_default() {
        b"list" => register_list(argv),
        b"add" => register_add(argv),
        b"remove" => register_remove(argv, c"bpm config register remove"),
        b"rm" => register_remove(argv, c"bpm config register rm"),
        a => {
            super::error(&[b"bpm config register: '", a, b"' is not an action"]);
            EXIT_USAGE
        }
    }
}

fn image_mode_refuses() -> bool {
    if image_config::active() {
        super::error(&[b"image mode: change repository definitions and keys in \
                         a signed config image, then run `shirudo image update`"]);
        return true;
    }
    false
}

fn register_list(argv: &[&CStr]) -> c_int {
    let mut p = OptParser::new(
        c"bpm config register list",
        &REGISTER_LIST_OPTS,
        Some(&CONFIG_HELP),
        argv,
        3,
    );

    match words(&mut p, None, 0, 0, b"") {
        Ok(_) => source::list(p.given(REGISTER_LIST_JSON)),
        Err(status) => status,
    }
}

fn register_remove(argv: &[&CStr], command: &CStr) -> c_int {
    let mut p = OptParser::new(command, &[], Some(&CONFIG_HELP), argv, 3);

    match words(&mut p, None, 1, 1, b"<source>") {
        Ok(_) if image_mode_refuses() => 1,
        Ok(args) => source::unregister(args[0].to_bytes()),
        Err(status) => status,
    }
}

fn register_add(argv: &[&CStr]) -> c_int {
    let mut p = OptParser::new(
        c"bpm config register add",
        &REGISTER_ADD_OPTS,
        Some(&CONFIG_HELP),
        argv,
        3,
    );
    let mut values = [None; 2];
    let args = match words(
        &mut p,
        Some(&mut values),
        2,
        2,
        b"<source> and oci://<registry>",
    ) {
        Ok(args) => args,
        Err(status) => return status,
    };

    if image_mode_refuses() {
        return 1;
    }
    let Some(cert) = values[REGISTER_ADD_CERT] else {
        p.usage(b"takes --cert <certificate>");
        return EXIT_USAGE;
    };
    let (name, endpoint) = (args[0].to_bytes(), args[1].to_bytes());
    if !source::fits(name, endpoint) {
        p.usage(b"name or endpoint too long");
        return EXIT_USAGE;
    }
    source::register(
        name,
        endpoint,
        cert.to_bytes(),
        values[REGISTER_ADD_INDEX_REPOSITORY].map(CStr::to_bytes),
    )
}

/// `bpm key`, `argv` from "key" on.
fn key(argv: &[&CStr]) -> c_int {
    if argv.len() < 2 || is_help(word(argv, 1)) {
        print_help(&KEY_HELP);
        return if argv.len() < 2 { EXIT_USAGE } else { 0 };
    }
    if is_list_cmds(word(argv, 1)) {
        print_subcmd_list(&KEY_SUBCMDS);
        return 0;
    }
    let Some(sub) = resolve_subcommand(c"bpm key", argv[1], &KEY_SUBCMDS) else {
        return EXIT_USAGE;
    };
    let sub = sub.to_bytes();
    if sub == b"list" {
        let mut p = OptParser::new(c"bpm key list", &KEY_LIST_OPTS, Some(&KEY_HELP), argv, 2);
        return match words(&mut p, None, 0, 0, b"") {
            Ok(_) => match key::list(p.given(KEY_LIST_JSON)) {
                Ok(()) => 0,
                Err(err) => fail(b"key list", err),
            },
            Err(status) => status,
        };
    }
    let add = sub == b"add";
    let command = if add {
        c"bpm key add"
    } else {
        c"bpm key fingerprint"
    };
    let mut p = OptParser::new(command, &[], Some(&KEY_HELP), argv, 2);
    let args = match words(
        &mut p,
        None,
        1,
        1,
        b"a certificate, a .bee package or an oci:// reference",
    ) {
        Ok(args) => args,
        Err(status) => return status,
    };
    if add && image_config::active() {
        super::error(
            &[b"image mode: add vouched BPF signers to the signed config \
                         selected for boot and reboot to enroll them"],
        );
        return 1;
    }
    if !super::curl_ready() {
        return curl_failed();
    }
    let action: &[u8] = if add { b"key add" } else { b"key fingerprint" };
    finish(None, key::show(args[0].to_bytes(), add), action)
}

/// What `bpm info` shows.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Show {
    /// `<package>`
    Readme,
    /// `upatches <package>`
    Upatches,
    /// `data <package> <upatch-member>`
    Data,
}

/// Whether the words and options of bpm info go together, saying why
/// not.
fn info_usage_ok(p: &OptParser<'_>, show: Show, args: &[&CStr]) -> bool {
    let n = args.len();
    let why: Vec<u8> = if show == Show::Upatches && n != 2 {
        b"upatches takes <package>".to_vec()
    } else if show == Show::Data && n != 3 {
        b"data takes <package> <upatch-member>".to_vec()
    } else if show == Show::Readme && n != 1 {
        [b"unexpected argument '", args[1].to_bytes(), b"'"].concat()
    } else if p.given(INFO_ALL) && show != Show::Upatches {
        b"--all goes with upatches alone".to_vec()
    } else if p.given(INFO_JSON) && show != Show::Data {
        b"--json goes with data alone".to_vec()
    } else {
        return true;
    };
    p.usage(&why);
    false
}

fn info_cmd(argv: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"bpm info", &INFO_OPTS, Some(&INFO_HELP), argv, 2);
    let args = match words(&mut p, None, 1, 3, b"a package") {
        Ok(args) => args,
        Err(status) => return status,
    };
    let show = match args[0].to_bytes() {
        b"upatches" => Show::Upatches,
        b"data" => Show::Data,
        _ => Show::Readme,
    };

    if !info_usage_ok(&p, show, &args) {
        return EXIT_USAGE;
    }
    if !super::curl_ready() {
        return curl_failed();
    }
    let ret = match show {
        Show::Upatches => info::upatches(args[1].to_bytes(), p.given(INFO_ALL)),
        Show::Data => info::data(args[1].to_bytes(), args[2].to_bytes(), p.given(INFO_JSON)),
        Show::Readme => info::readme(args[0].to_bytes()),
    };
    finish(None, ret, b"info")
}

fn tree_cmd(argv: &[&CStr]) -> c_int {
    if argv.len() < 3 || is_help(word(argv, 2)) {
        print_help(&TREE_HELP);
        return if argv.len() < 3 { EXIT_USAGE } else { 0 };
    }
    if is_list_cmds(word(argv, 2)) {
        print_subcmd_list(&TREE_SUBCMDS);
        return 0;
    }
    match word(argv, 2).unwrap_or_default() {
        b"append" => return exec_operator(c"tree", argv),
        b"show" => return exec_operator(c"tree", argv),
        b"sync" => {}
        other => {
            super::error(&[b"bpm tree: '", other, b"' is not a subcommand"]);
            return EXIT_USAGE;
        }
    }
    let mut p = OptParser::new(c"bpm tree sync", &TREE_SYNC_OPTS, Some(&TREE_HELP), argv, 3);
    let mut values = [None; 2];
    if let Err(status) = words(&mut p, Some(&mut values), 0, 0, b"") {
        return status;
    }
    tree::sync_cmd(
        p.given(TREE_SYNC_DRY_RUN),
        values[TREE_SYNC_REPORT].map(CStr::to_bytes),
    )
}

fn pull(argv: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"bpm pull", &[], Some(&PULL_HELP), argv, 2);
    let args = match words(
        &mut p,
        None,
        1,
        1,
        b"a package reference starting with oci://, such as oci://quay.io/namespace/package:tag",
    ) {
        Ok(args) => args,
        Err(status) => return status,
    };

    if !super::curl_ready() {
        return curl_failed();
    }
    finish(None, fetch::download(args[0].to_bytes(), None), b"pull")
}

fn repo(argv: &[&CStr]) -> c_int {
    if argv.len() < 3 || is_help(word(argv, 2)) {
        print_help(&REPO_HELP);
        return if argv.len() < 3 { EXIT_USAGE } else { 0 };
    }
    if is_list_cmds(word(argv, 2)) {
        print_subcmd_list(&REPO_SUBCMDS);
        return 0;
    }
    if word(argv, 2) != Some(b"update") {
        super::error(&[
            b"bpm repo: '",
            word(argv, 2).unwrap_or_default(),
            b"' is not a subcommand",
        ]);
        return EXIT_USAGE;
    }
    let mut p = OptParser::new(c"bpm repo update", &[], Some(&REPO_HELP), argv, 3);
    match words(&mut p, None, 0, 1, b"") {
        Ok(args) => fetch::repo_update(args.first().map(|a| a.to_bytes())),
        Err(status) => status,
    }
}

fn install(argv: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"bpm install", &[], Some(&INSTALL_HELP), argv, 2);
    match words(&mut p, None, 1, 1, b"<package>") {
        Ok(args) => package::install(args[0].to_bytes()),
        Err(status) => status,
    }
}

fn list(argv: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"bpm list", &LIST_OPTS, Some(&LIST_HELP), argv, 2);
    match words(&mut p, None, 0, 0, b"") {
        Ok(_) => package::list(p.given(LIST_JSON)),
        Err(status) => status,
    }
}

fn uninstall(argv: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"bpm uninstall", &[], Some(&UNINSTALL_HELP), argv, 2);
    match words(&mut p, None, 1, 1, b"<package>") {
        Ok(args) => package::uninstall(args[0].to_bytes()),
        Err(status) => status,
    }
}

fn upgrade(argv: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"bpm upgrade", &[], Some(&UPGRADE_HELP), argv, 2);
    match words(&mut p, None, 0, 0, b"") {
        Ok(_) => package::upgrade(),
        Err(status) => status,
    }
}

/// `shirudo bpm`, `argv` from "bpm" on.
pub(super) fn run(argv: &[&CStr]) -> c_int {
    let operator = super::super::build::available();
    let (h, items): (&Help, &[HelpItem]) = if operator {
        (&OPERATOR_HELP, &BPM_SUBCMDS)
    } else {
        (&TARGET_HELP, &TARGET_SUBCMDS)
    };

    if argv.len() < 2 || is_help(word(argv, 1)) {
        print_help(h);
        return if argv.len() < 2 { EXIT_USAGE } else { 0 };
    }
    if is_list_cmds(word(argv, 1)) {
        print_subcmd_list(items);
        return 0;
    }
    let Some(sub) = resolve_subcommand(c"shirudo bpm", argv[1], items) else {
        return EXIT_USAGE;
    };
    match sub.to_bytes() {
        b"config" if word(argv, 2) == Some(b"update") => exec_operator(sub, argv),
        b"config" => config(&argv[1..]),
        b"build" | b"push" => exec_operator(sub, argv),
        b"key" => key(&argv[1..]),
        b"info" => info_cmd(argv),
        b"tree" => tree_cmd(argv),
        b"pull" => pull(argv),
        b"repo" => repo(argv),
        b"install" => install(argv),
        b"list" => list(argv),
        b"uninstall" => uninstall(argv),
        _ => upgrade(argv),
    }
}
