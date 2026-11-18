// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;

#[test]
fn sha256_matches_fips_180_vector() {
    let d = sha256(b"abc").unwrap();

    assert_eq!(
        crate::util::hex::encode(&d),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn sha256_buffer_zeroes_a_failed_digest() {
    let mut out = [0xffu8; SHA256_LEN];

    // SAFETY: no bytes, which it refuses, and room for a digest.
    let ret = unsafe { sha256_buffer(core::ptr::null(), 3, out.as_mut_ptr()) };
    assert_ne!(ret, 0);
    assert_eq!(out, [0; SHA256_LEN]);
}
