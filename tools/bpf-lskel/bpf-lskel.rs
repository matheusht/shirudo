// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! bpf-lskel: the light skeleton of an object of bpf/, which
//! util/loader.c embeds so that init loads the object without reading
//! it. The loader is generated at build time, as libbpf's gen_loader
//! generates it, by shirudo's own reading of the object
//! (rust/src/bpf/), which this build tool takes with std alone.
//!
//!   bpf-lskel <object.bpf.o> <name>
//!             [--share <object.bpf.o> --maps <map>[,<map>...]]
//!             [--rust <out.rs>] -o <out>
//!
//! The object is named `name`, which its global data maps are named
//! after. With --share, the maps --maps names, which both objects
//! declare in .maps, are the caller's to pass, the other object's: the
//! loader takes them from its context instead of creating them. With
//! --rust, the skeleton's Rust side is written too (rskel.rs): the types
//! of its maps, the other object's where laid out alike, and handles to
//! its maps and programs.

#![allow(dead_code)]

use std::process::ExitCode;

#[path = "../../rust/src/errno.rs"]
mod errno;

mod log {
    pub(crate) fn warn(msg: &[u8]) {
        eprintln!("bpf-lskel: {}", String::from_utf8_lossy(msg));
    }
}

mod sys {
    pub(crate) mod libc {
        unsafe extern "C" {
            pub(crate) fn sysconf(name: core::ffi::c_int) -> core::ffi::c_long;
        }
    }
}

/// The skeleton writer's signing, which a build tool does not do.
mod util {
    pub(crate) mod crypto_openssl {
        use core::ffi::{c_int, c_void};

        pub(crate) unsafe fn sha256_buffer(_: *const c_void, _: usize, _: *mut u8) -> c_int {
            -crate::errno::EOPNOTSUPP
        }
    }
}

#[path = "../../rust/src/bpf/mod.rs"]
mod bpf;
mod rskel;

use bpf::lskel::{Lskel, Program};
use bpf::object::{GenOpts, Object};

fn open(path: &str, name: &[u8]) -> Result<Object, String> {
    let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    Object::open(&data, name).map_err(|e| format!("{path}: open: {e}"))
}

fn run(args: &[String]) -> Result<(), String> {
    let usage = || "usage: bpf-lskel <object.bpf.o> <name> [--share <object.bpf.o> --maps <map>[,<map>...]] [--rust <out.rs>] -o <out>";
    let (mut pos, mut share, mut names, mut out) = (Vec::new(), None, None, None);
    let mut rust = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--share" => share = Some(it.next().ok_or_else(usage)?),
            "--maps" => names = Some(it.next().ok_or_else(usage)?),
            "--rust" => rust = Some(it.next().ok_or_else(usage)?),
            "-o" => out = Some(it.next().ok_or_else(usage)?),
            _ => pos.push(a),
        }
    }
    let (&[path, name], Some(out)) = (pos.as_slice(), out) else {
        return Err(usage().into());
    };
    let mut obj = open(path, name.as_bytes())?;
    let mut reuse_map_mask = 0u64;
    let mut shared = None;
    match (share, names) {
        (None, None) => {}
        (Some(other_path), Some(names)) => {
            let other_name = bpf::object::object_name(other_path.as_bytes());
            let other = open(other_path, other_name)?;
            let declared =
                |o: &Object, n: &[u8]| o.maps.iter().position(|m| !m.is_internal() && m.name == n);
            for n in names.split(',') {
                let Some(i) = declared(&obj, n.as_bytes()).filter(|&i| i < 64) else {
                    return Err(format!("{path}: no map {n} the loader can take"));
                };
                let Some(j) = declared(&other, n.as_bytes()) else {
                    return Err(format!("{other_path}: no map {n}"));
                };
                let def = |m: &bpf::object::Map| {
                    let k = (m.key_size(), m.value_size(), m.max_entries());
                    (m.map_type(), m.map_flags(), k)
                };
                if def(&obj.maps[i]) != def(&other.maps[j]) {
                    return Err(format!("{path}: map {n} is not defined as {other_path}'s"));
                }
                reuse_map_mask |= 1 << i;
            }
            let module = String::from_utf8_lossy(other_name).into_owned();
            let (_, structs) = rskel::write(&other, &module, other_path, None)
                .map_err(|e| format!("{other_path}: {e}"))?;
            shared = Some((module, structs));
        }
        _ => return Err(usage().into()),
    }
    if let Some(rust_out) = rust {
        let share = shared.as_ref().map(|(module, structs)| rskel::Share {
            module,
            structs,
            maps: (0..64).filter(|i| reuse_map_mask & (1 << i) != 0).collect(),
        });
        let (src, _) =
            rskel::write(&obj, name, path, share.as_ref()).map_err(|e| format!("{path}: {e}"))?;
        let tmp = format!("{rust_out}.tmp");
        std::fs::write(&tmp, src)
            .and_then(|()| std::fs::rename(&tmp, rust_out))
            .map_err(|e| format!("{rust_out}: {e}"))?;
    }
    let maps: Vec<Vec<u8>> = obj.maps.iter().map(|m| m.name.clone()).collect();
    let progs: Vec<(u32, u32, Vec<u8>)> = obj
        .loaded_programs()
        .map(|p| (p.prog_type, p.attach, p.name.clone()))
        .collect();
    let externs: Vec<Vec<u8>> = obj.extern_names().map(<[u8]>::to_vec).collect();
    let opts = GenOpts {
        gen_hash: false,
        reuse_map_mask,
    };
    let (insns, data) = obj
        .gen_loader(&opts)
        .map_err(|e| format!("{path}: generate loader: {e}"))?;
    let skel = Lskel {
        maps: maps.iter().map(Vec::as_slice).collect(),
        progs: progs
            .iter()
            .map(|(prog_type, attach_type, name)| Program {
                prog_type: *prog_type,
                attach_type: *attach_type,
                name,
            })
            .collect(),
        externs: externs.iter().map(Vec::as_slice).collect(),
        reuse_map_mask,
        insns: &insns,
        data: &data,
    };
    let tmp = format!("{out}.tmp");
    std::fs::write(&tmp, skel.to_bytes())
        .and_then(|()| std::fs::rename(&tmp, out))
        .map_err(|e| format!("{out}: {e}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bpf-lskel: {e}");
            ExitCode::FAILURE
        }
    }
}
