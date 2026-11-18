// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::errno::{EACCES, EBADMSG, ENOENT, EXDEV};
use crate::text::{cstr, find};

/// A reachable, parsed status with the LSM attached.
fn input() -> ConditionsInput {
    // SAFETY: an input of flags, counts and NULL strings, for which zeros
    // are a value.
    let mut i: ConditionsInput = unsafe { core::mem::zeroed() };
    i.reachable = true;
    i.parsed = true;
    i.lsm_attached = 1;
    i
}

/// The status and detail of condition `kind` for `i`.
fn condition_of(i: &ConditionsInput, kind: &CStr) -> Option<(Vec<u8>, Vec<u8>)> {
    // SAFETY: conditions of NULL strings and empty details.
    let mut c: [Condition; CONDITIONS_MAX] = unsafe { core::mem::zeroed() };
    let n = conditions(i, &mut c);

    c[..n].iter().find_map(|c| {
        // SAFETY: the kind and status conditions() set, static C strings.
        let (k, status) = unsafe { (CStr::from_ptr(c.kind), CStr::from_ptr(c.status)) };
        (k == kind).then(|| (status.to_bytes().to_vec(), cstr(&c.detail).to_vec()))
    })
}

fn upatches_measured(i: &ConditionsInput) -> (Vec<u8>, Vec<u8>) {
    condition_of(i, c"UpatchesMeasured").unwrap()
}

fn has(text: &[u8], part: &[u8]) -> bool {
    find(text, part).is_some()
}

fn reason(i: &ConditionsInput) -> Vec<u8> {
    let mut buf = [0u8; 128];
    // SAFETY: an input of NULL or C strings.
    unsafe { status_reason(i, &mut buf) };
    cstr(&buf).to_vec()
}

#[test]
fn changed_xdp_archive_is_tampered() {
    let mut i = input();
    i.xdp_tampered = 1;
    i.xdp_tampered_detail = c"fix".as_ptr();
    let (status, detail) = upatches_measured(&i);

    assert_eq!(status, b"ALERT");
    assert!(has(&detail, b"1 XDP archives differ") && has(&detail, b"fix"));
    assert_eq!(status_verdict(&i), c"tampered");
}

#[test]
fn a_changed_archive_outranks_a_pin_warning() {
    let mut i = input();
    i.lsm_attached = 0;
    i.pins_rc = -ENOENT;
    i.xdp_tampered = 2;

    assert_eq!(upatches_measured(&i).0, b"ALERT");
}

#[test]
fn a_lost_link_is_tampered() {
    let mut i = input();
    i.lsm_attached = 0;
    i.pins_rc = -ENOENT;
    i.links_lost = 1;
    i.links_lost_detail = c"fix".as_ptr();
    let (status, detail) = upatches_measured(&i);

    assert_eq!(status, b"ALERT");
    assert!(has(&detail, b"missing a link or their archive: fix"));
    assert_eq!(status_verdict(&i), c"tampered");
}

#[test]
fn records_the_register_does_not_vouch_for_are_tampered() {
    let mut i = input();
    i.pins_rc = -EBADMSG;
    let (status, detail) = upatches_measured(&i);

    assert_eq!(status, b"ALERT");
    assert!(has(&detail, b"do not fold to the measurement register"));
    assert_eq!(status_verdict(&i), c"tampered");
    assert!(has(&reason(&i), b"do not fold to the measurement register"));
}

#[test]
fn a_check_that_could_not_run_warns() {
    let mut i = input();
    i.checks_rc = -EACCES;
    let (status, detail) = upatches_measured(&i);

    assert_eq!(status, b"WARN");
    assert!(has(&detail, b"not checked"));
    assert_ne!(status_verdict(&i), c"tampered");
}

#[test]
fn no_change_leaves_the_condition_alone() {
    let i = input();

    assert_eq!(upatches_measured(&i).0, b"OK");
    assert_ne!(status_verdict(&i), c"tampered");
}

/// Reachable, parsed, the LSM attached, the keyring there and the chain
/// seen: what an XDP condition needs to stand alone.
fn healthy() -> ConditionsInput {
    let mut i = input();
    i.keyring_present = 1;
    i.chain_seen = 1;
    i
}

#[test]
fn an_uncovered_device_degrades() {
    let mut i = healthy();
    i.xdp_uncovered = 1;
    i.xdp_uncovered_detail = c"fw on eth1 (no multi-buffer XDP)".as_ptr();
    let (status, detail) = condition_of(&i, c"XdpCovered").unwrap();

    assert_eq!(status, b"WARN");
    assert!(has(&detail, b"fw on eth1 (no multi-buffer XDP)"));
    assert_eq!(status_verdict(&i), c"degraded");
    assert!(has(&reason(&i), b"XDP upatch selects"));
}

#[test]
fn unchecked_coverage_warns_without_degrading() {
    let mut i = healthy();
    i.xdp_coverage_rc = -EACCES;
    let (status, detail) = condition_of(&i, c"XdpCovered").unwrap();

    assert_eq!(status, b"WARN");
    assert!(has(&detail, b"not checked"));
    assert_eq!(status_verdict(&i), c"ok");
    i.xdp_coverage_rc = -EXDEV;
    assert_eq!(
        condition_of(&i, c"XdpCovered").unwrap().1,
        b"XDP coverage not checked: not in the initial network namespace"
    );
}

#[test]
fn covered_devices_are_ok() {
    let i = healthy();

    assert_eq!(condition_of(&i, c"XdpCovered").unwrap().0, b"OK");
    assert_eq!(status_verdict(&i), c"ok");
}

#[test]
fn a_long_list_is_cut_not_dropped() {
    let mut names = [b'x'; 255].to_vec();
    names[..10].copy_from_slice(b"fw on eth1");
    let names = std::ffi::CString::new(names).unwrap();
    let mut i = healthy();
    i.xdp_uncovered = 20;
    i.xdp_uncovered_detail = names.as_ptr();
    let detail = condition_of(&i, c"XdpCovered").unwrap().1;

    assert_eq!(detail.len(), 191);
    assert!(has(&detail, b"fw on eth1"));
    assert!(detail.ends_with(b"..."));
}
