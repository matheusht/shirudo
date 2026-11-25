// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::sys::libc::PATH_MAX;

#[test]
fn pin_path_is_the_bpffs_name_and_its_parts() {
    let pin = |name: &[u8], parts: &[&[u8]]| pin_path(name, parts).unwrap().into_bytes();

    assert_eq!(
        pin(b"kernel.obs", &[]),
        format!("{BPFFS_UPATCHES_DIR}/kernel~dobs").as_bytes()
    );
    assert_eq!(
        pin(b"a", &[b"link"]),
        format!("{BPFFS_UPATCHES_DIR}/a/link").as_bytes()
    );
    assert_eq!(
        pin(b"a.b", &[b"maps", b"m.1"]),
        format!("{BPFFS_UPATCHES_DIR}/a~db/maps/m.1").as_bytes()
    );
}

#[test]
fn pin_path_too_long_is_refused() {
    let long = vec![b'p'; PATH_MAX];

    assert_eq!(pin_path(&[b'a'; NAME_MAX + 1], &[]), Err(-ENAMETOOLONG));
    assert_eq!(pin_path(b"a", &[&long]), Err(-ENAMETOOLONG));
}

#[test]
fn links_of_an_absent_upatch_are_not_read() {
    let mut calls = 0;

    assert_eq!(
        each_link_info(b"shirudo-unit-no-such-upatch", &mut |_, _, _| {
            calls += 1;
            0
        }),
        -ENOENT
    );
    assert_eq!(calls, 0);
}

#[test]
fn a_tracing_link_names_the_kind_of_its_program() {
    let tracing = |attach_type| {
        let mut info = Info::<LINK_INFO_SIZE>::new();
        info.set(LINK_TYPE, &BPF_LINK_TYPE_TRACING.to_ne_bytes());
        info.set(LINK_TRACING_ATTACH_TYPE, &u32::to_ne_bytes(attach_type));
        info
    };

    assert_eq!(
        tracing_link_kind(&tracing(BPF_TRACE_FENTRY)),
        Some(&b"fentry"[..])
    );
    assert_eq!(
        tracing_link_kind(&tracing(BPF_TRACE_FEXIT)),
        Some(&b"fexit"[..])
    );
    assert_eq!(
        tracing_link_kind(&tracing(BPF_MODIFY_RETURN)),
        Some(&b"fmod_ret"[..])
    );
    assert_eq!(tracing_link_kind(&tracing(BPF_LSM_MAC)), Some(&b"lsm"[..]));

    let mut other = Info::<LINK_INFO_SIZE>::new();
    other.set(LINK_TYPE, &BPF_LINK_TYPE_PERF_EVENT.to_ne_bytes());
    assert_eq!(tracing_link_kind(&other), None);
    other.set(LINK_TYPE, &1u32.to_ne_bytes());
    assert_eq!(tracing_link_kind(&other), None);
}
