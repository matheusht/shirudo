// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;

const WANT: &[u8] = b"attest=/1RD;sig=ABg=;ak=ACMACw==";

/// A quote of three bytes, a signature of two and a key of four.
fn small() -> (TpmAttestation, TpmKey) {
    let mut att = TpmAttestation::zeroed();
    let mut ak = TpmKey::zeroed();

    att.attest[..3].copy_from_slice(&[0xff, 0x54, 0x43]);
    att.attest_len = 3;
    att.signature[..2].copy_from_slice(&[0x00, 0x18]);
    att.signature_len = 2;
    ak.public[..4].copy_from_slice(&[0x00, 0x23, 0x00, 0x0b]);
    ak.public_len = 4;
    (att, ak)
}

#[test]
fn quote_is_the_three_fields_in_base64() {
    let (att, ak) = small();

    assert_eq!(format(&att, &ak).unwrap(), WANT);
}

#[test]
fn quote_of_the_largest_fields_fits() {
    let mut att = TpmAttestation::zeroed();
    let mut ak = TpmKey::zeroed();

    att.attest_len = ATTEST_MAX;
    att.signature_len = SIGNATURE_MAX;
    ak.public_len = PUBLIC_MAX;
    let text = format(&att, &ak).unwrap();
    assert_eq!(
        text.len(),
        "attest=;sig=;ak=".len()
            + base64_size(ATTEST_MAX)
            + base64_size(SIGNATURE_MAX)
            + base64_size(PUBLIC_MAX)
            - 3
    );
}
