// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

#[test]
fn anchor_digest_of_one_is_that_one() {
    assert_eq!(anchor_digest(&[digest(7)]), Ok(digest(7)));
}

#[test]
fn anchor_digest_hashes_the_sorted_digests() {
    let mut sorted = Vec::new();
    for d in [digest(1), digest(2), digest(3)] {
        sorted.extend_from_slice(&d);
    }
    let expected = crypto_openssl::sha256(&sorted).unwrap();

    assert_eq!(
        anchor_digest(&[digest(3), digest(1), digest(2)]),
        Ok(expected)
    );
    assert_eq!(
        anchor_digest(&[digest(2), digest(3), digest(1)]),
        Ok(expected)
    );
}

#[test]
fn anchor_digest_wants_one_to_keys_max() {
    assert_eq!(anchor_digest(&[]), Err(-EINVAL));
    assert!(anchor_digest(&[digest(0); KEYS_MAX]).is_ok());
    assert_eq!(anchor_digest(&[digest(0); KEYS_MAX + 1]), Err(-EINVAL));
}

#[test]
fn vouch_payload_is_the_prefix_its_nul_and_the_der() {
    assert_eq!(
        vouch_payload(b"\x30\x03der").unwrap(),
        b"shirudo-key-vouch\0\x30\x03der"
    );
    assert_eq!(vouch_payload(b"").unwrap(), b"shirudo-key-vouch\0");
}

#[test]
fn digest_der_refuses_what_is_not_a_certificate() {
    assert_eq!(digest_der(b"").err(), Some(-EINVAL));
    assert_eq!(digest_der(b"\x30\x03abc").err(), Some(-EINVAL));
}
