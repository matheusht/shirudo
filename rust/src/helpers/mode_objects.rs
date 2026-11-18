// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-mode-objects: what the light skeletons of bpf2 and the seal
//! built into shirudo load, their maps, their programs and the kernel
//! symbols their loaders resolve, read from the format of
//! rust/src/bpf/lskel.rs.

use core::ffi::{CStr, c_int};

use super::{helper_main, out};
use crate::skel::embedded;

helper_main!(shirudo_helper_test_mode_objects, run);

const LSKEL_HEADER: usize = 40;

fn le32(b: &[u8], off: usize) -> usize {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]) as usize
}

/// The `n` names of `kind` from the front of `names`, each after `skip`
/// bytes, printed; None for names that run past the table.
fn list<'a>(
    kind: &str,
    selection: &str,
    n: usize,
    skip: usize,
    mut names: &'a [u8],
) -> Option<&'a [u8]> {
    for _ in 0..n {
        names = names.get(skip..)?;
        let nul = names.iter().position(|&c| c == 0)?;
        out(&format!(
            "{kind} {selection} {}\n",
            String::from_utf8_lossy(&names[..nul])
        ));
        names = &names[nul + 1..];
    }
    Some(names)
}

fn inspect(selection: &str, name: &[u8], b: &[u8]) -> Option<()> {
    if b.len() < LSKEL_HEADER || &b[..8] != b"SHLSKEL1" {
        return None;
    }
    let names_len = le32(b, 28);
    let names = b[LSKEL_HEADER..].get(..names_len)?;
    out(&format!(
        "blob {selection} {}\n",
        String::from_utf8_lossy(name)
    ));
    // Each program's type and attach type come before its name.
    let names = list("map", selection, le32(b, 8), 0, names)?;
    let names = list("program", selection, le32(b, 12), 8, names)?;
    list("extern", selection, le32(b, 16), 0, names).map(|_| ())
}

fn run(_: &[&CStr]) -> c_int {
    let ok = embedded()
        .iter()
        .zip(["admission", "seal"])
        .all(|(obj, selection)| inspect(selection, obj.name(), obj.data()).is_some());
    c_int::from(!ok)
}
