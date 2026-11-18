// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::util::crypto_openssl::sha256_buffer;

/// SHA-256 of `data`.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: the bytes and room for a digest.
    let ret = unsafe { sha256_buffer(data.as_ptr().cast(), data.len(), out.as_mut_ptr()) };
    assert_eq!(ret, 0);
    out
}

#[test]
fn sha256_2_hashes_the_concatenation() {
    let mut two = [0u8; 32];

    // SAFETY: the bytes of each and room for a digest.
    unsafe {
        assert_eq!(
            sha256_2(
                b"ab".as_ptr().cast(),
                2,
                b"c".as_ptr().cast(),
                1,
                two.as_mut_ptr()
            ),
            0
        );
        assert_eq!(two, sha256(b"abc"));
        assert_eq!(
            sha256_2(b"abc".as_ptr().cast(), 3, ptr::null(), 0, two.as_mut_ptr()),
            0
        );
    }
    assert_eq!(two, sha256(b"abc"));
}

/// A failure must be reported, not left to a zeroed digest to mismatch.
#[test]
fn sha256_2_reports_a_failure() {
    let mut out = [0xffu8; 32];

    // SAFETY: no first part, which it refuses, and room for a digest.
    let ret = unsafe { sha256_2(ptr::null(), 3, b"c".as_ptr().cast(), 1, out.as_mut_ptr()) };
    assert_ne!(ret, 0);
    assert_eq!(out, [0; 32]);
}

#[test]
fn chain_events_hash_their_documented_input() {
    let cert = [0xa5u8; 32];
    let mut event = [0u8; 32];
    let input = [&b"shirudo-key-revoke\0"[..], &cert].concat();

    // SAFETY: a C string, a digest and room for one.
    let ret = unsafe {
        capi::chain_key_event(
            c"shirudo-key-revoke".as_ptr(),
            cert.as_ptr(),
            event.as_mut_ptr(),
        )
    };
    assert_eq!(ret, 0);
    assert_eq!(event, sha256(&input));
}

#[test]
fn chain_fold_extends_like_the_register() {
    let mut chain = [0u8; 32];
    let event = [0x5au8; 32];
    let input = [[0u8; 32], event].concat();

    // SAFETY: two digests, the first written.
    assert_eq!(unsafe { fold(chain.as_mut_ptr(), event.as_ptr()) }, 0);
    assert_eq!(chain, sha256(&input));
}
