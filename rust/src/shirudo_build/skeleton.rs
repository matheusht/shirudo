// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo-build skeleton`: the C light skeleton of a BPF object, the
//! header `bpftool gen skeleton -L` writes for it, byte for byte, made
//! without bpftool or libbpf; signed with a key and certificate, as
//! bpftool's `-S`.

use core::ffi::{CStr, c_int};
use std::io::Write as _;

use super::sign::cms_sign;
use crate::bpf::skel;

fn usage() {
    crate::log::err(
        b"usage: shirudo-build skeleton <object.bpf.o> [name <name>] [--key <signing_key.pem> --cert <cert.der>] [-o <out.lskel.h>]",
    );
}

pub(super) fn run(args: &[&CStr]) -> c_int {
    let (mut file, mut name, mut key, mut cert, mut output) = (None, None, None, None, None);
    let mut i = 1;
    while i < args.len() {
        let a = args[i].to_bytes();
        let next = args.get(i + 1).copied();
        let slot = match a {
            b"name" => &mut name,
            b"--key" => &mut key,
            b"--cert" => &mut cert,
            b"-o" | b"--output" => &mut output,
            _ if file.is_none() && !a.starts_with(b"-") => {
                file = Some(args[i]);
                i += 1;
                continue;
            }
            _ => {
                usage();
                return 2;
            }
        };
        let Some(v) = next else {
            usage();
            return 2;
        };
        *slot = Some(v);
        i += 2;
    }
    let Some(file) = file else {
        usage();
        return 2;
    };
    if key.is_some() != cert.is_some() {
        usage();
        return 2;
    }
    let path = String::from_utf8_lossy(file.to_bytes()).into_owned();
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            crate::log::err(format!("{path}: {e}").as_bytes());
            return 1;
        }
    };
    let signer = key.zip(cert).map(|(k, c)| {
        move |insns: &[u8], blob: &[u8], max: usize| {
            cms_sign(insns, blob, max, k, c).map(|(sig, _)| sig)
        }
    });
    let res = skel::skeleton(
        &data,
        file.to_bytes(),
        name.map(CStr::to_bytes),
        signer.as_ref().map(|s| s as &skel::Signer<'_>),
    );
    let text = match res {
        Ok(t) => t,
        Err(e) => {
            crate::log::err(
                &[
                    format!("{path}: no skeleton: ").as_bytes(),
                    super::strerr(e),
                ]
                .concat(),
            );
            return 1;
        }
    };
    let written = match output {
        Some(o) => std::fs::write(
            String::from_utf8_lossy(o.to_bytes()).as_ref(),
            text.as_bytes(),
        ),
        None => std::io::stdout().write_all(text.as_bytes()),
    };
    if let Err(e) = written {
        crate::log::err(format!("writing the skeleton: {e}").as_bytes());
        return 1;
    }
    0
}
