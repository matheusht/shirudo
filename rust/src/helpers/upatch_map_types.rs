// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-upatch-map-types: the names upatch maps go by and the types read
//! generically skips, offline, so that the arena policy is tested without
//! root or a pinned map.
//!
//!   test-upatch-map-types arena-name|arena-skip|array-skip|ringbuf-name

use core::ffi::{CStr, c_int};

use super::{helper_main, out};
use crate::util::map_read::{map_skip_reason, map_type_name};

helper_main!(shirudo_helper_test_upatch_map_types, run);

/// BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_RINGBUF and BPF_MAP_TYPE_ARENA.
const ARRAY: u32 = 2;
const RINGBUF: u32 = 27;
const ARENA: u32 = 33;

fn run(args: &[&CStr]) -> c_int {
    let skip = |ty| map_skip_reason(ty).map_or(String::new(), |r| r.to_string_lossy().into_owned());
    let line = match args {
        [_, a] => match a.to_bytes() {
            b"arena-name" => map_type_name(ARENA).to_string_lossy().into_owned(),
            b"arena-skip" => skip(ARENA),
            b"array-skip" => skip(ARRAY),
            b"ringbuf-name" => map_type_name(RINGBUF).to_string_lossy().into_owned(),
            _ => return 2,
        },
        _ => return 2,
    };
    out(&(line + "\n"));
    0
}
