// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-bpf-cmd: one bpf() command by name, with an all-zero attribute,
//! through the raw syscall, and its outcome printed, "ok" or
//! "errno=<n>". shirudo's lsm/bpf hook answers before the kernel looks
//! at the attribute, so a command the policy denies reports EACCES
//! whatever the attribute says, and one it allows whatever the kernel
//! makes of an empty one.
//!
//!   test-bpf-cmd <BPF_CMD name without prefix>

use core::ffi::{CStr, c_int, c_long};

use super::{err, helper_main, out};
use crate::util::bpf_sys::Attr;

helper_main!(shirudo_helper_test_bpf_cmd, run);

/// The commands by name, as enum bpf_cmd numbers them.
const CMDS: [(&str, c_long); 24] = [
    ("MAP_CREATE", 0),
    ("MAP_LOOKUP_ELEM", 1),
    ("MAP_UPDATE_ELEM", 2),
    ("MAP_DELETE_ELEM", 3),
    ("MAP_GET_NEXT_KEY", 4),
    ("OBJ_PIN", 6),
    ("OBJ_GET", 7),
    ("PROG_ATTACH", 8),
    ("PROG_DETACH", 9),
    ("PROG_TEST_RUN", 10),
    ("MAP_GET_NEXT_ID", 12),
    ("MAP_GET_FD_BY_ID", 14),
    ("LINK_GET_FD_BY_ID", 30),
    ("RAW_TRACEPOINT_OPEN", 17),
    ("BTF_LOAD", 18),
    ("MAP_LOOKUP_AND_DELETE_ELEM", 21),
    ("MAP_FREEZE", 22),
    ("MAP_UPDATE_BATCH", 26),
    ("MAP_DELETE_BATCH", 27),
    ("LINK_CREATE", 28),
    ("LINK_UPDATE", 29),
    ("ITER_CREATE", 33),
    ("LINK_DETACH", 34),
    ("PROG_BIND_MAP", 35),
];

fn run(args: &[&CStr]) -> c_int {
    let me = args
        .first()
        .map_or("test-bpf-cmd".into(), |a| a.to_string_lossy());
    let [_, name] = args else {
        err(&format!("usage: {me} <BPF_CMD name without prefix>\n"));
        return 2;
    };
    let name = name.to_string_lossy();
    let Some(&(_, cmd)) = CMDS.iter().find(|(n, _)| **n == *name) else {
        err(&format!("{me}: unknown command {name}\n"));
        return 2;
    };
    match Attr::new().run(cmd) {
        Ok(fd) => {
            // A command that made a descriptor leaves it for the exit to
            // close, as the C helper did.
            let _ = fd;
            out("ok\n");
        }
        Err(errno) => out(&format!("errno={errno}\n")),
    }
    0
}
