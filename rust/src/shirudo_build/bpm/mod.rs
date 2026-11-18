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
use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;

use crate::errno::{EINVAL, EIO};
use crate::text::cstr;
use crate::text::name_has_suffix;
use crate::util::paths::keys_dir_resolve;

pub(crate) use build::upatch_name;

/// BPM_MAX_ENDPOINT: the longest registry and repository.
const MAX_ENDPOINT: usize = 512;

fn say(level: fn(&[u8]), text: &[u8]) {
    let msg = CString::new(cstr(text).to_vec()).unwrap_or_default();

    // SAFETY: a "%s" format with a C string.
    unsafe { crate::log::log_c!(level, c"%s".as_ptr(), msg.as_ptr()) };
}

fn error(text: &[u8]) {
    say(crate::log::err, text);
}

#[allow(dead_code)]
fn info(text: &[u8]) {
    say(crate::log::info, text);
}

fn strerr(err: c_int) -> &'static [u8] {
    // SAFETY: strerror() gives a C string that outlives the message.
    unsafe { crate::ffi::c_str(crate::sys::libc::strerror(err)) }
}

fn last_err() -> c_int {
    -std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(EIO)
}

fn print(to_stdout: bool, text: &[u8]) {
    // SAFETY: the bytes, to one of the C library's streams.
    unsafe {
        let f = if to_stdout {
            crate::sys::libc::stdout
        } else {
            crate::sys::libc::stderr
        };
        crate::sys::libc::fwrite(text.as_ptr().cast(), 1, text.len(), f);
    }
}

fn hex(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    bytes
        .iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xf)]])
        .collect()
}

fn path(p: &[u8]) -> &OsStr {
    OsStr::from_bytes(p)
}

/// `--help`, `-h` or `help`.
fn is_help(arg: &[u8]) -> bool {
    matches!(arg, b"--help" | b"-h" | b"help")
}

/// The keys directory: `arg`, else SHIRUDO_KEYS_DIR or the default, with
/// a leading `~` for $HOME; None when it cannot be spelled.
fn resolve_keys_dir(arg: Option<&CStr>) -> Option<Vec<u8>> {
    let arg = match arg.map(CStr::to_bytes).filter(|a| !a.is_empty()) {
        Some(a) => a.to_vec(),
        // SAFETY: NULL for the environment or the default, a C string.
        None => unsafe { crate::ffi::c_str(keys_dir_resolve(core::ptr::null())) }.to_vec(),
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

fn usage(to_stdout: bool) {
    print(
        to_stdout,
        b"usage: shirudo bpm build [context] --version <version> [--file <name>.bee]
                         [--keys-dir <dir>] [--vmlinux <vmlinux.h>]
                         [--rodata-input <name>=<path>]...
       shirudo bpm config update --base-package <package.bee|oci://...>
                         --version <version> [--file <name>.bee]
                         [--rodata-input <name>=<path>]...
       shirudo bpm push <package-file> <repository> [--keys-dir <dir> |
                        --index-cert <cert.der> --index-key <key.pem>]
       shirudo bpm tree append <package-file> <repository> [options]

Operator-only BPM commands, implemented in shirudo-build and reached
through `shirudo bpm`. Each accepts --help.
",
    );
}

/// The exit of `build` or `config update`, reporting an error the
/// command did not.
fn reported(what: &str, ret: c_int) -> c_int {
    if ret < 0 && ret != -EINVAL {
        error(format!("bpm {what}: {}", String::from_utf8_lossy(strerr(-ret))).as_bytes());
    }
    if ret != 0 { 1 } else { 0 }
}

/// `shirudo-build bpm`, from `bpm` on.
pub(super) fn run(args: &[&CStr]) -> c_int {
    let Some(sub) = args.get(1).map(|a| a.to_bytes()) else {
        usage(false);
        return 2;
    };
    if is_help(sub) {
        usage(true);
        return 0;
    }
    match sub {
        b"build" => reported("build", build::run(&args[1..])),
        b"config" if args.get(2).map(|a| a.to_bytes()) == Some(b"update") => {
            reported("config update", config_update::run(&args[2..]))
        }
        b"push" => publish::run(&args[1..]),
        b"tree" => tree::run(&args[1..]),
        _ => {
            error(
                &[
                    b"shirudo-build bpm: '",
                    sub,
                    b"' is not an operator bpm command",
                ]
                .concat(),
            );
            usage(false);
            2
        }
    }
}
