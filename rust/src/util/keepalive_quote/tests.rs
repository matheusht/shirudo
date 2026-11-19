// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::util::tpm::{ATTEST_MAX, PUBLIC_MAX, SIGNATURE_MAX};

/// The room base64 takes for `n` bytes, its terminator included.
const fn base64_size(n: usize) -> usize {
    4 * n.div_ceil(3) + 1
}

const WANT: &[u8] = b"attest=/1RD;sig=ABg=;ak=ACMACw==";

/// A quote, a signature and a key of the lengths given, of zeros.
fn sized(attest: usize, signature: usize, public: usize) -> (Attestation, KeyPublic) {
    let att = Attestation {
        attest: vec![0; attest],
        signature: vec![0; signature],
    };
    let ak = KeyPublic {
        area: vec![0; public],
        name: [0; 34],
    };

    (att, ak)
}

/// A quote of three bytes, a signature of two and a key of four.
fn small() -> (Attestation, KeyPublic) {
    let (mut att, mut ak) = sized(3, 2, 4);

    att.attest.copy_from_slice(&[0xff, 0x54, 0x43]);
    att.signature.copy_from_slice(&[0x00, 0x18]);
    ak.area.copy_from_slice(&[0x00, 0x23, 0x00, 0x0b]);
    (att, ak)
}

#[test]
fn quote_is_the_three_fields_in_base64() {
    let (att, ak) = small();

    assert_eq!(format(&att, &ak).unwrap(), WANT);
}

#[test]
fn quote_of_the_largest_fields_fits() {
    let (att, ak) = sized(ATTEST_MAX, SIGNATURE_MAX, PUBLIC_MAX);
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
