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

/// The operation digests of a three-operation tree, and the history root
/// after none, one, two and all of them as Python's hashlib gives it:
///
///   root = bytes(32)
///   for d in digests:
///       root = sha256(b"shirudo-tree-history\0" + root + d).digest()
const TREE_OPERATIONS: [&[u8]; 3] = [
    b"13b248d4a85d91150717e3e96dc9c2d7a8a43633e3b58f8f6168d408aed26c43",
    b"5ce215313f29f87bfb87aa0cc65c237bf21bdc7702606e9cc29be187f950074b",
    b"bd98b27dd5cfc9deeb0e4f49a7d4bd0f991762ec784be9ea838a59966d9dd0dc",
];
const HISTORY_ROOTS: [&[u8]; 4] = [
    b"0000000000000000000000000000000000000000000000000000000000000000",
    b"470779d64e1302c4826a4be3222020050e70784ae6016040eabde9d0d8770d80",
    b"889efeb27650c0111168d523c935f051addbcc049d079e440e518dd3939722f0",
    b"bdc9ee89e753beca03d6e9ae89344269cb3a2e8ba3662122f55b1e3f7ff34011",
];

fn operation(i: usize) -> [u8; 32] {
    let mut digest = [0u8; 32];
    crate::util::hex::decode(TREE_OPERATIONS[i], &mut digest).unwrap();
    digest
}

/// The history root after the first `n` operations, in hex.
fn history_root_after(n: usize) -> Vec<u8> {
    let root = (0..n).fold([0u8; 32], |root, i| {
        history_step(&root, &operation(i)).unwrap()
    });
    crate::util::hex::encode(&root)
}

#[test]
fn history_root_matches_the_reference() {
    for n in [0, 1, 3] {
        assert_eq!(history_root_after(n), HISTORY_ROOTS[n]);
    }
}

/// The C form writes the root it is given room for, its input untouched
/// unless that room is the input.
#[test]
fn history_step_writes_beside_its_input() {
    let (prev, digest) = ([0u8; 32], operation(0));
    let mut out = [0u8; 32];

    // SAFETY: two digests, read before the room for the third is written.
    let ret = unsafe { capi::chain_history_step(&prev, &digest, &mut out) };
    assert_eq!(ret, 0);
    assert_eq!(crate::util::hex::encode(&out), HISTORY_ROOTS[1]);
    assert_eq!(prev, [0; 32]);
}

#[test]
fn history_root_differs_from_the_projection_root() {
    const PROJECTION_ROOTS: [&[u8]; 3] = [
        b"04f83540c1727aefcf3c53449a99594c8fd1cc15e1466dbdbf3168cc8f9dc136",
        b"a042a582b3a3d8c1b633b8ed0356e0b52f1f5aa25af85b06cc3f481562dcda93",
        b"154522480ff8884daa95589e80f26f20248bbf9c192dfbb3cee04e03b4f136a1",
    ];
    let (mut history, mut projection) = ([0u8; 32], [0u8; 32]);

    for i in 0..TREE_OPERATIONS.len() {
        let digest = operation(i);
        let prev = projection;

        history = history_step(&history, &digest).unwrap();
        // SAFETY: two digests of 32 bytes and room for a third.
        let ret = unsafe {
            sha256_2(
                prev.as_ptr().cast(),
                32,
                digest.as_ptr().cast(),
                32,
                projection.as_mut_ptr(),
            )
        };
        assert_eq!(ret, 0);
        assert_eq!(crate::util::hex::encode(&projection), PROJECTION_ROOTS[i]);
        assert_eq!(crate::util::hex::encode(&history), HISTORY_ROOTS[i + 1]);
        assert_ne!(history, projection);
    }
}
