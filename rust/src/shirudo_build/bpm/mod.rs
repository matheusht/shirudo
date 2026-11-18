// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The operator's `bpm` commands, which `shirudo bpm` reaches through
//! shirudo-build: `build` a signed package from a Beefile, `config
//! update` one's .rodata, `push` it to an OCI registry and `tree append`
//! its upatches to a signed tree.

mod archive;
mod beefile;
mod build;
mod config_update;
mod publish;
mod show;
mod tree;

use core::ffi::{CStr, c_int};
use std::os::unix::ffi::OsStrExt;

use crate::errno::{EINVAL, EIO};
use crate::sys::curl::{CURL_GLOBAL_DEFAULT, curl_global_cleanup, curl_global_init};
use crate::text::name_has_suffix;
use crate::util::help::{Help, print_help};
use crate::util::options::EXIT_USAGE;
use crate::util::paths::keys_dir;

pub(crate) use build::upatch_name;

/// BPM_MAX_ENDPOINT: the longest registry and repository.
const MAX_ENDPOINT: usize = 512;

use super::{error, hex, last_err, path, print, strerr};

/// Keeps libcurl initialized for the lifetime of one operator command.
struct Curl;

impl Curl {
    fn init() -> Result<Self, c_int> {
        // SAFETY: called before opening any libcurl handles.
        if unsafe { curl_global_init(CURL_GLOBAL_DEFAULT) } == 0 {
            Ok(Self)
        } else {
            Err(-EIO)
        }
    }
}

impl Drop for Curl {
    fn drop(&mut self) {
        // SAFETY: the command has dropped all handles before this guard.
        unsafe { curl_global_cleanup() };
    }
}

/// The keys directory: `arg`, else SHIRUDO_KEYS_DIR or the default, with
/// a leading `~` for $HOME; None when it cannot be spelled.
fn resolve_keys_dir(arg: Option<&CStr>) -> Option<Vec<u8>> {
    let arg = match arg.map(CStr::to_bytes).filter(|a| !a.is_empty()) {
        Some(a) => a.to_vec(),
        None => keys_dir(None).to_bytes().to_vec(),
    };
    let out = match arg.strip_prefix(b"~") {
        Some(rest) if rest.is_empty() || rest[0] == b'/' => {
            let home = std::env::var_os("HOME")?;
            [home.as_bytes(), rest].concat()
        }
        _ => arg,
    };
    (out.len() < build_path_max()).then_some(out)
}

const fn build_path_max() -> usize {
    beefile::PATH_MAX
}

static OPERATOR_HELP: Help = Help::new(
    c"shirudo bpm build [context] --version <version> [options]\n       \
      shirudo bpm config update --base-package <package> --version <version> [options]\n       \
      shirudo bpm push <package-file> <repository> [options]\n       \
      shirudo bpm tree append <package-file> <repository> [options]\n       \
      shirudo bpm tree show <repository> --cert <cert.der> [options]",
    Some(
        c"Operator-only BPM commands, implemented in shirudo-build and reached\n\
          through `shirudo bpm`. Each takes --help.",
    ),
    &[],
    None,
);

/// The exit of `build` or `config update`: a usage error's, or 1 for a
/// failure, said where the command did not say it.
fn reported(what: &str, ret: c_int) -> c_int {
    if ret == EXIT_USAGE {
        return EXIT_USAGE;
    }
    if ret < 0 && ret != -EINVAL {
        error(format!("bpm {what}: {}", String::from_utf8_lossy(strerr(-ret))).as_bytes());
    }
    c_int::from(ret != 0)
}

/// `shirudo-build bpm`, from `bpm` on.
pub(super) fn run(args: &[&CStr]) -> c_int {
    let sub = args.get(1).map(|a| a.to_bytes());

    if args.len() < 2 || crate::util::help::is_help(sub) {
        print_help(&OPERATOR_HELP);
        return if args.len() < 2 { EXIT_USAGE } else { 0 };
    }
    match sub.unwrap_or_default() {
        b"build" => reported("build", build::run(&args[1..])),
        b"config" if args.get(2).map(|a| a.to_bytes()) == Some(b"update") => {
            reported("config update", config_update::run(&args[2..]))
        }
        b"push" => publish::run(&args[1..]),
        b"tree" => tree::run(&args[1..]),
        other => {
            error(&[b"bpm: '", other, b"' is not an operator bpm command"].concat());
            EXIT_USAGE
        }
    }
}
