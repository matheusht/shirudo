// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-conditions: the conditions and verdict of `shirudo status` for
//! t6004, from what it would read off the host.
//!
//!   test-conditions <lsm 0|1> <bpf|none> <serial> <pinned> \
//!                   <notpm|none|match|mismatch>
//!
//! serial is the live keyring's, -1 when it is absent; pinned the one
//! init froze, 0 when it froze none; the last word the register's
//! replay, with notpm for no TPM answering and none for no register
//! bound. The dm-verity keyring follows the bpf one at serial 200 unless
//! SHIRUDO_TEST_DMV_SERIAL and SHIRUDO_TEST_DMV_PINNED say otherwise;
//! SHIRUDO_TEST_BPF_UNFROZEN and SHIRUDO_TEST_DMV_UNFROZEN count links
//! init did not freeze, and SHIRUDO_TEST_DMV_KEY=missing drops the config
//! key.

use core::ffi::{CStr, c_int};
use std::ffi::CString;

use super::{err, helper_main, out};
use crate::errno::{EACCES, EINPROGRESS, ENOENT, ESTALE, EUCLEAN};
use crate::text::{cstr, parse_s64};
use crate::util::conditions::{
    CONDITIONS_MAX, Condition, ConditionsInput, conditions, status_reason, status_verdict,
};

helper_main!(shirudo_helper_test_conditions, run);

fn number(s: &[u8]) -> Option<i64> {
    parse_s64(s, -1, i64::from(i32::MAX)).ok()
}

fn env_number(name: &str, default: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|v| number(v.as_bytes()))
        .unwrap_or(default)
}

fn text(p: *const core::ffi::c_char) -> String {
    // SAFETY: a static C string conditions() set.
    String::from_utf8_lossy(unsafe { CStr::from_ptr(p) }.to_bytes()).into_owned()
}

fn run(args: &[&CStr]) -> c_int {
    let parsed = (args.len() == 6).then(|| {
        (
            number(args[1].to_bytes()),
            number(args[3].to_bytes()),
            number(args[4].to_bytes()),
        )
    });
    let Some((Some(lsm), Some(serial), Some(pinned))) = parsed else {
        err("usage: test-conditions <lsm> <mode> <serial> <pinned> <notpm|none|match|mismatch>\n");
        return 2;
    };
    let tpm = args[5].to_bytes();
    let config = std::env::var("SHIRUDO_TEST_CONFIG_STATE").ok();
    let dmv_key = std::env::var("SHIRUDO_TEST_DMV_KEY").ok();
    let pins = std::env::var("SHIRUDO_TEST_PINS").ok();
    let pins_detail = pins
        .as_deref()
        .and_then(|p| p.strip_prefix("unmeasured:"))
        .map(|d| CString::new(d).unwrap());
    // SAFETY: an input of flags, counts and NULL strings, for which zeros
    // are a value.
    let mut i: ConditionsInput = unsafe { core::mem::zeroed() };

    i.reachable = true;
    i.parsed = true;
    i.lsm_attached = c_int::from(lsm != 0);
    i.keyring_present = c_int::from(serial >= 0);
    i.keyring_mode = args[2].as_ptr();
    i.keyring_serial = serial;
    i.keyring_serial_pinned = pinned;
    i.ks_seen = i.keyring_present;
    i.ksp_seen = c_int::from(pinned >= 1);
    i.ksm_seen = c_int::from(i.keyring_present != 0 && pinned >= 1);
    i.keyring_serial_matches = c_int::from(i.ksm_seen != 0 && serial == pinned);
    i.bpf_unfrozen = env_number("SHIRUDO_TEST_BPF_UNFROZEN", 0) as c_int;
    i.dmv_serial = env_number(
        "SHIRUDO_TEST_DMV_SERIAL",
        if serial >= 0 { 200 } else { -1 },
    );
    i.dmv_serial_pinned = env_number("SHIRUDO_TEST_DMV_PINNED", if pinned >= 1 { 200 } else { 0 });
    i.dmv_present = c_int::from(i.dmv_serial >= 0);
    i.dmvp_seen = c_int::from(i.dmv_serial_pinned >= 1);
    i.dmvm_seen = c_int::from(i.dmv_present != 0 && i.dmvp_seen != 0);
    i.dmv_serial_matches = c_int::from(i.dmvm_seen != 0 && i.dmv_serial == i.dmv_serial_pinned);
    i.dmv_unfrozen = env_number("SHIRUDO_TEST_DMV_UNFROZEN", 0) as c_int;
    i.dmv_key_missing = c_int::from(dmv_key.as_deref() == Some("missing"));
    i.tpm_reachable = c_int::from(tpm != b"notpm");
    i.chain_seen = c_int::from(i.tpm_reachable != 0 && tpm != b"none");
    i.cm_seen = i.chain_seen;
    i.chain_matches = c_int::from(tpm == b"match");
    i.nv_index = c"0x01818E00".as_ptr();
    i.config_seen = c_int::from(config.as_deref() != Some("none"));
    i.config_state = match config.as_deref() {
        Some("pending") => -EINPROGRESS,
        Some("untrusted") => -EUCLEAN,
        Some("stale") => -ESTALE,
        _ => 0,
    };
    i.config_root = c"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".as_ptr();
    match pins.as_deref() {
        Some("norecord") => i.pins_rc = -ENOENT,
        Some("error") => i.pins_rc = -EACCES,
        _ => {
            if let Some(detail) = &pins_detail {
                i.pins_detail = detail.as_ptr();
                i.pins_unmeasured =
                    1 + detail.as_bytes().iter().filter(|&&c| c == b',').count() as c_int;
            }
        }
    }

    let mut reason = [0u8; 160];
    // SAFETY: an input of NULL or C strings that outlive the call.
    unsafe { status_reason(&i, &mut reason) };
    out(&format!(
        "status={}\n",
        status_verdict(&i).to_string_lossy()
    ));
    out(&format!(
        "reason={}\n",
        String::from_utf8_lossy(cstr(&reason))
    ));
    // SAFETY: conditions of NULL strings and empty details.
    let mut conds: [Condition; CONDITIONS_MAX] = unsafe { core::mem::zeroed() };
    let n = conditions(&i, &mut conds);
    for c in &conds[..n] {
        out(&format!(
            "{} {} {}\n",
            text(c.kind),
            text(c.status),
            String::from_utf8_lossy(cstr(&c.detail))
        ));
    }
    0
}
