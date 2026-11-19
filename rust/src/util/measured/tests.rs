// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::util::eventlog::UPATCH_LOAD;

const PAYLOAD: &CStr = c"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// An init event lists each upatch once, by a name an upatch can have.
#[test]
fn set_takes_each_upatch_once() {
    let p = PAYLOAD.to_bytes();
    let mut set = Vec::new();
    let mut add = |name: &[u8], payload: &[u8]| set_add(&mut set, 2, name, payload);
    let crafted = [&b"a\n"[..], p, b" b"].concat();

    assert_eq!(add(b"a", p), Ok(()));
    assert_eq!(add(b"a", p), Err(-EEXIST));
    assert_eq!(add(&crafted, p), Err(-EINVAL));
    assert_eq!(add(b"b", b"00"), Err(-EINVAL));
    assert_eq!(add(b"b", p), Ok(()));
    assert_eq!(add(b"c", p), Err(-E2BIG));
    assert_eq!(set.len(), 2);
    assert_eq!(cstr(&set[0].name), b"a");
    assert_eq!(cstr(&set[1].payload_hex), p);
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

/// A load adds a name or sets its payload, an unload moves the last
/// member into the place it leaves, and an init starts over.
#[test]
fn events_fold_into_the_set() {
    let (p, q) = (PAYLOAD.to_bytes(), &b"ff".repeat(PAYLOAD_HASH_LEN)[..]);
    let mut s = MeasuredSet::default();
    let names = |s: &MeasuredSet| s.entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>();

    for n in [&b"a"[..], b"b", b"c"] {
        assert_eq!(s.event(UPATCH_LOAD, n, p), 0);
    }
    assert_eq!(s.event(UPATCH_LOAD, b"b", q), 0);
    assert!(s.holds(b"a", p) && s.holds(b"b", q) && !s.holds(b"b", p));
    assert_eq!(s.event(UPATCH_UNLOAD, b"a", b""), 0);
    assert_eq!(names(&s), [b"c".to_vec(), b"b".to_vec()]);
    assert_eq!(s.event(UPATCH_UNLOAD, b"gone", b""), 0);
    assert_eq!(s.event(UPATCH_LOAD, &[b'n'; NAME_MAX], p), 0);
    assert_eq!(s.event(UPATCH_LOAD, &[b'n'; NAME_MAX + 1], p), -EINVAL);
    let long = [b'0'; 2 * PAYLOAD_HASH_LEN + 1];
    assert_eq!(s.event(UPATCH_LOAD, b"d", &long), -EINVAL);
    assert_eq!(names(&s).len(), 3);
    assert_eq!(s.event(UPATCH_INIT, b"", b""), 0);
    assert!(s.entries.is_empty());
}

/// A full set still takes a load of a name it holds, not a new one.
#[test]
#[cfg_attr(miri, ignore = "4096 loads, each a scan of the set, take Miri hours")]
fn a_full_set_takes_no_new_name() {
    let p = PAYLOAD.to_bytes();
    let mut s = MeasuredSet::default();

    for i in 0..MEASURED_MAX {
        assert_eq!(s.event(UPATCH_LOAD, format!("u{i}").as_bytes(), p), 0);
    }
    assert_eq!(s.event(UPATCH_LOAD, b"one-more", p), -ENOSPC);
    assert_eq!(s.event(UPATCH_LOAD, b"u7", p), 0);
}
