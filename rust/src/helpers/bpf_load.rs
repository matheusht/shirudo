// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-bpf-load: an unsigned userspace BPF_PROG_LOAD of a trivial
//! program through the raw bpf() syscall, and its outcome printed,
//! "loaded" or "errno=<n>". With shirudo's lsm/bpf hook attached, an
//! unsigned userspace load must be denied: the headline enforcement
//! property.

use core::ffi::{CStr, c_int};

use super::{helper_main, out};
use crate::util::bpf_sys::{Attr, BPF_PROG_LOAD};

helper_main!(shirudo_helper_test_bpf_load, run);

const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;

fn run(_: &[&CStr]) -> c_int {
    // r0 = 0; exit: BPF_MOV64_IMM and BPF_EXIT, a minimal valid program.
    let insns: [[u8; 8]; 2] = [[0xb7, 0, 0, 0, 0, 0, 0, 0], [0x95, 0, 0, 0, 0, 0, 0, 0]];
    let ret = Attr::new()
        .u32(0, BPF_PROG_TYPE_SOCKET_FILTER)
        .u32(4, insns.len() as u32)
        .ptr(8, insns.as_ptr())
        .ptr(16, c"GPL".as_ptr())
        .fd(BPF_PROG_LOAD);
    match ret {
        Ok(_prog) => out("loaded\n"),
        Err(errno) => out(&format!("errno={errno}\n")),
    }
    0
}
