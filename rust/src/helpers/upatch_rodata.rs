// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-upatch-rodata: the type names and the dump guard of upatch
//! rodata on BTF built for the case: a typedef of a long name behind
//! pointers named into a small buffer, or a struct spoiled as the case
//! says, which the walk that guards the dumper must refuse.
//!
//!   test-upatch-rodata <name length> <pointers>
//!   test-upatch-rodata dumpable plain|member|enum|pointee|proto|loop|elements|overlaid|shared|deep

use core::ffi::{CStr, c_int};

use super::{helper_main, out};
use crate::btf_builder::BtfBuilder;
use crate::errno::EINVAL;
use crate::text::parse_u64;
use crate::util::upatch_rodata::{DumpCost, append_type_name, dump_cost};

helper_main!(shirudo_helper_test_upatch_rodata, run);

const INT_SIGNED: u32 = 1;

/// A typedef of `len` characters behind `ptrs` pointers, named into a
/// buffer of `cap` bytes: the result, and whether the buffer kept its
/// terminator.
fn name_into(len: usize, ptrs: u32, cap: usize) -> c_int {
    let mut buf = [b'x'; 512];
    // libbpf refuses a typedef of no name, as the C helper found.
    if len == 0 || len >= 512 || cap > buf.len() {
        return 2;
    }
    let mut b = BtfBuilder::new();
    let int = b.int("int", 4, INT_SIGNED);
    let mut id = b.typedef(&"n".repeat(len), int);
    for _ in 0..ptrs {
        id = b.ptr(id);
    }
    let Ok(btf) = b.parse() else {
        return 2;
    };
    let mut off = 0;
    let ret = append_type_name(&btf, id, &mut buf[..cap], &mut off, 0);
    let terminated = buf[..cap].contains(&0);
    out(&format!(
        "rc={ret} off={off} terminated={}\n",
        c_int::from(terminated)
    ));
    if !terminated {
        return 1;
    }
    if ret != 0 { 3 } else { 0 }
}

/// A chain of `n` typedefs to `ty`, named prefix n-1 down to prefix 0.
fn typedefs(b: &mut BtfBuilder, prefix: &str, n: u32, mut ty: u32) -> u32 {
    for i in (0..n).rev() {
        ty = b.typedef(&format!("{prefix}{i}"), ty);
    }
    ty
}

/// Four levels of 64 members all laid over the bytes of an int.
fn overlaid(b: &mut BtfBuilder, mut ty: u32) -> u32 {
    for _ in 0..4 {
        let members = vec![("", ty, 0u32); 64];
        ty = b.structure("", 4, &members);
    }
    ty
}

/// A struct of an int, an enum and a pointer, spoiled as `what` says,
/// through the walk that guards libbpf's dumper: 0 when it may be
/// dumped, 1 when it is refused.
fn dumpable(what: &[u8]) -> c_int {
    let member = if what == b"member" { "a\x1b[2J" } else { "a" };
    let value = if what == b"enum" { "E\x07" } else { "E" };
    let pointee = if what == b"pointee" {
        "int\u{9b}"
    } else {
        "int"
    };
    let mut b = BtfBuilder::new();
    let ints = b.int("int", 4, INT_SIGNED);
    let mut target = b.int(pointee, 4, INT_SIGNED);
    let en = b.enumeration("e", 4, &[(value, 0)]);
    if what == b"proto" {
        target = b.func_proto(ints, &[("x", ints)]);
    }
    // A pointer to itself for "loop".
    let ptr = if what == b"loop" {
        b.ptr(b.next_id())
    } else {
        b.ptr(target)
    };
    let (a, bb) = match what {
        b"elements" => (b.array(ints, ints, 1 << 20), en),
        b"overlaid" => (overlaid(&mut b, ints), en),
        b"shared" => {
            let a = typedefs(&mut b, "t", 6, ints);
            (a, a)
        }
        b"deep" => {
            let a = typedefs(&mut b, "t", 6, ints);
            (a, typedefs(&mut b, "u", 2, a))
        }
        _ => (ints, en),
    };
    let st = b.structure("s", 16, &[(member, a, 0), ("b", bb, 32), ("p", ptr, 64)]);
    let ret = match b.parse() {
        Ok(btf) => {
            let mut cost = vec![DumpCost::default(); btf.type_cnt() as usize];
            dump_cost(&btf, st, 0, &mut cost)
        }
        Err(_) => -EINVAL,
    };
    out(&format!(
        "{} dumpable={} rc={ret}\n",
        String::from_utf8_lossy(what),
        c_int::from(ret == 0)
    ));
    c_int::from(ret != 0)
}

fn run(args: &[&CStr]) -> c_int {
    match args {
        [_, how, what] if how.to_bytes() == b"dumpable" => dumpable(what.to_bytes()),
        [_, len, ptrs] => match (
            parse_u64(len.to_bytes(), 500),
            parse_u64(ptrs.to_bytes(), 4),
        ) {
            (Ok(len), Ok(ptrs)) => name_into(len as usize, ptrs as u32, 256),
            _ => 2,
        },
        _ => 2,
    }
}
