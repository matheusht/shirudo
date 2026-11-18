// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::text::cstr;

const PAYLOAD: &CStr = c"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// An init event lists each upatch once, by a name an upatch can have.
#[test]
fn set_takes_each_upatch_once() {
    // SAFETY: two members of byte arrays, for which zeros are a value.
    let mut set: [MeasuredUpatch; 2] = unsafe { core::mem::zeroed() };
    let mut n = 0;
    let mut add = |name: &CStr, payload: &CStr| {
        // SAFETY: room for two members, their count, and two C strings.
        unsafe { set_add(set.as_mut_ptr(), &mut n, 2, name.as_ptr(), payload.as_ptr()) }
    };
    let crafted = std::ffi::CString::new(format!("a\n{} b", PAYLOAD.to_str().unwrap())).unwrap();

    assert_eq!(add(c"a", PAYLOAD), 0);
    assert_eq!(add(c"a", PAYLOAD), -EEXIST);
    assert_eq!(add(&crafted, PAYLOAD), -EINVAL);
    assert_eq!(add(c"b", c"00"), -EINVAL);
    assert_eq!(add(c"b", PAYLOAD), 0);
    assert_eq!(add(c"c", PAYLOAD), -E2BIG);
    assert_eq!(n, 2);
    assert_eq!(cstr(&set[0].name), b"a");
    assert_eq!(cstr(&set[1].payload_hex), PAYLOAD.to_bytes());
}

#[test]
fn name_from_bpffs_takes_back_each_dot() {
    let mut out = [0u8; 32];

    assert_eq!(name_from_bpffs(&mut out, b"a~db~d~dc"), 0);
    assert_eq!(cstr(&out), b"a.b..c");
    assert_eq!(name_from_bpffs(&mut out, b"a~x"), -EINVAL);
    assert_eq!(name_from_bpffs(&mut out, b"a~"), -EINVAL);
    assert_eq!(name_from_bpffs(&mut out[..3], b"abc"), -ENAMETOOLONG);
}
