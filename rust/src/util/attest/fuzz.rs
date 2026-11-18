// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-attest: evidence verified against a nonce, made a credential
//! challenge of with presented keys trusted, and read as a challenge.

use super::{AttestChallengePolicy, AttestExpect, Report, challenge_make, challenge_read, verify};
use crate::fuzzing::{fuzz_target, input_file};

const NONCE: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const REPORT_MAX: usize = 4096;

fuzz_target!(shirudo_fuzz_attest, shirudo_fuzz_attest_init, |data| {
    let pol = AttestChallengePolicy {
        trust_presented: true,
        ..AttestChallengePolicy::default()
    };
    let expect = AttestExpect {
        nonce: NONCE.to_vec(),
        allow_runtime_events: true,
        ..AttestExpect::default()
    };
    let _ = verify(data, &expect, &mut Report::new(REPORT_MAX));
    let _ = challenge_make(data, &pol, &mut Report::new(REPORT_MAX));
    if let Some(input) = input_file(data) {
        let _ = challenge_read(&input.path);
    }
});
