// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-attest: evidence verified against a nonce, made a credential
//! challenge of with presented keys trusted, and read as a challenge.

use core::ffi::c_char;

use super::capi::{attest_challenge_make, attest_challenge_read};
use super::{AttestChallenge, AttestChallengePolicy, AttestExpect, Report, verify};
use crate::fuzzing::{fuzz_target, input_file};
use crate::heap::xfree;
use crate::util::tpm_wire::CREDENTIAL_LEN;

const NONCE: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const REPORT_MAX: usize = 4096;

fuzz_target!(shirudo_fuzz_attest, shirudo_fuzz_attest_init, |data| {
    // SAFETY: a policy of nothing, for which zeros are the value, filled
    // as the C target set it.
    let mut pol: AttestChallengePolicy = unsafe { core::mem::zeroed() };
    pol.trust_presented = true;
    let expect = AttestExpect {
        nonce: NONCE.to_vec(),
        allow_runtime_events: true,
        ..AttestExpect::default()
    };
    let _ = verify(data, &expect, &mut Report::new(REPORT_MAX));
    let mut report = [0 as c_char; REPORT_MAX];
    let mut credential = [0u8; CREDENTIAL_LEN];
    let (mut out, mut out_len, mut cap): (*mut c_char, usize, usize) =
        (core::ptr::null_mut(), 0, 0);
    let evidence = data.as_ptr().cast::<c_char>();
    // SAFETY: the evidence's bytes, the policy, and rooms for the report,
    // credential and challenge, which is freed.
    unsafe {
        if attest_challenge_make(
            evidence,
            data.len(),
            &pol,
            credential.as_mut_ptr(),
            &mut out,
            &mut out_len,
            &mut cap,
            report.as_mut_ptr(),
            report.len(),
        ) == 0
        {
            xfree(out.cast(), cap);
        }
    }
    if let Some(input) = input_file(data) {
        // SAFETY: a challenge of nothing, which the read fills.
        let mut challenge: Box<AttestChallenge> = Box::new(unsafe { core::mem::zeroed() });
        // SAFETY: a C string and the room.
        unsafe { attest_challenge_read(input.path.as_ptr(), &mut *challenge) };
    }
});
