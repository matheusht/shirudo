// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `.bpf.c` to `.bpf.o`: clang -target bpf, run from the path the build
//! configured, never one PATH finds; and the vmlinux.h it compiles
//! against.

use core::ffi::{CStr, c_int};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use super::{error, strerr};
use crate::errno::{E2BIG, EINTR, EIO, ENAMETOOLONG, ENOENT};
use crate::ffi::c_splice;

/// The clang the build configured, as SHIRUDO_CLANG_PATH passes it.
const CLANG_PATH: &str = match option_env!("SHIRUDO_CLANG_PATH") {
    Some(p) => p,
    None => "/usr/bin/clang",
};
const CLANG: &CStr = c_splice!(CLANG_PATH);
/// Where the libbpf and shirudo BPF headers are installed.
const BPF_INCDIR: &str = match option_env!("SHIRUDO_BPF_INCDIR") {
    Some(p) => p,
    None => "/usr/share/shirudo/bpf/include",
};
/// The vmlinux.h installed with shirudo.
pub(super) const VMLINUX_PATH: &str = match option_env!("SHIRUDO_VMLINUX_PATH") {
    Some(p) => p,
    None => "/usr/local/share/shirudo/vmlinux.h",
};
const VMLINUX: &CStr = c_splice!(VMLINUX_PATH);
/// The words a compile passes, clang's own included.
const MAX_ARGS: usize = 63;
const PATH_MAX: usize = 4096;
const R_OK: c_int = 4;
const X_OK: c_int = 1;

pub(super) fn readable(path: &CStr) -> bool {
    super::check_access(path, R_OK).is_ok()
}

fn exists(path: &str) -> bool {
    std::fs::metadata(path).is_ok()
}

/// The vmlinux.h to compile against: the one named, which must be
/// readable, else ./vmlinux.h, ./vendor/linux/vmlinux.h, then the
/// installed one.
pub(super) fn locate_vmlinux(named: Option<&CStr>) -> Option<&CStr> {
    if let Some(path) = named {
        return readable(path).then_some(path);
    }
    [c"./vmlinux.h", c"./vendor/linux/vmlinux.h", VMLINUX]
        .into_iter()
        .find(|p| readable(p))
}

/// The -I of libbpf's BPF headers: in the tree, else installed.
fn bpf_headers() -> Option<Vec<u8>> {
    if exists("./vendor/libbpf/bpf/bpf_helpers.h") {
        return Some(b"-I./vendor/libbpf".to_vec());
    }
    exists(&format!("{BPF_INCDIR}/bpf/bpf_helpers.h"))
        .then(|| format!("-I{BPF_INCDIR}").into_bytes())
}

/// The -I of shirudo's BPF headers: in the tree, else installed.
fn shirudo_bpf_headers() -> Option<Vec<u8>> {
    if exists("./bpf/lib/serializer.h") {
        return Some(b"-I./bpf/lib".to_vec());
    }
    exists(&format!("{BPF_INCDIR}/serializer.h")).then(|| format!("-I{BPF_INCDIR}").into_bytes())
}

/// Compiles `source` into `output` against `vmlinux_h`, with
/// `extra_cflags` split on blanks after the rest, and shirudo's BPF
/// headers from `incdir` when named.
pub(super) fn compile(
    source: &CStr,
    output: &CStr,
    vmlinux_h: &CStr,
    extra_cflags: Option<&CStr>,
    incdir: Option<&CStr>,
) -> Result<(), c_int> {
    if let Err(err) = super::check_access(CLANG, X_OK) {
        error(
            &[
                b"clang not at hardcoded path ",
                CLANG.to_bytes(),
                b": ",
                strerr(-err),
            ]
            .concat(),
        );
        return Err(-ENOENT);
    }
    let vh = vmlinux_h.to_bytes();
    if vh.len() >= 1024 {
        error(&[b"vmlinux.h path too long: ", vh].concat());
        return Err(-ENAMETOOLONG);
    }
    let dir: &[u8] = match vh.iter().rposition(|&c| c == b'/') {
        Some(slash) => &vh[..slash],
        None => b".",
    };
    let shirudo_inc = match incdir {
        Some(d) if d.to_bytes().len() + 2 >= PATH_MAX + 8 => return Err(-ENAMETOOLONG),
        Some(d) => Some([b"-I", d.to_bytes()].concat()),
        None => shirudo_bpf_headers(),
    };
    let mut args: Vec<Vec<u8>> = [
        "-target",
        "bpf",
        // The newest instruction set, which every kernel with signed BPF
        // loaders runs, and not -mcpu=probe: the operator builds for its
        // targets, not for the kernel it runs on.
        "-mcpu=v4",
        // A switch stays in branches: clang 23 otherwise reads its
        // results from a table in .rodata at an offset the verifier
        // cannot bound.
        "-fno-jump-tables",
        "-O2",
        "-g",
        "-Wall",
        "-Wextra",
        "-Wshadow",
        "-Wtype-limits",
        // vmlinux.h dumps anonymous struct forward declarations that trip
        // -Wmissing-declarations, unfixable upstream of us; BPF_PROG()
        // expands to named but unused parameters that trip
        // -Wunused-parameter. Both are noise; --extra-cflags can turn
        // them back on.
        "-Wno-missing-declarations",
        "-Wno-unused-parameter",
    ]
    .map(|a| a.as_bytes().to_vec())
    .into();
    args.push([b"-I", dir].concat());
    args.extend(bpf_headers());
    args.extend(shirudo_inc);
    args.extend([
        b"-c".to_vec(),
        source.to_bytes().to_vec(),
        b"-o".to_vec(),
        output.to_bytes().to_vec(),
    ]);
    let extra = extra_cflags.map_or(&b""[..], CStr::to_bytes);
    for word in extra
        .split(|c| b" \t\n".contains(c))
        .filter(|w| !w.is_empty())
    {
        // clang itself is the first word.
        if args.len() + 1 >= MAX_ARGS {
            return Err(-E2BIG);
        }
        args.push(word.to_vec());
    }

    let status = Command::new(OsStr::from_bytes(CLANG.to_bytes()))
        .args(args.iter().map(|a| OsStr::from_bytes(a)))
        .status();
    match status {
        Err(e) => {
            // As the child of a fork whose exec failed reports it.
            let msg = [
                b"exec ",
                CLANG.to_bytes(),
                b": ",
                strerr(e.raw_os_error().unwrap_or(EIO)),
                b"\n",
            ]
            .concat();
            super::print(false, &msg);
            error(b"clang exited with status 127");
            Err(-EIO)
        }
        Ok(s) => match (s.code(), s.signal()) {
            (Some(0), _) => Ok(()),
            (Some(es), _) => {
                error(format!("clang exited with status {es}").as_bytes());
                Err(-EIO)
            }
            (None, Some(sig)) => {
                error(format!("clang killed by signal {sig}").as_bytes());
                Err(-EINTR)
            }
            (None, None) => Err(-EIO),
        },
    }
}
