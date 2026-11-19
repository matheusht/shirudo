// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::errno::{EINVAL, ENOENT};

/// One GNU build-id note with a four-byte descriptor: 01 23 45 67.
const NOTES: [u8; 20] = [
    4, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, b'G', b'N', b'U', 0, 0x01, 0x23, 0x45, 0x67,
];

/// from_notes() of `notes`, and the ID it wrote.
fn id(notes: &[u8]) -> (c_int, Vec<u8>) {
    match from_notes(notes) {
        Ok(hex) => (0, hex),
        Err(err) => (err, Vec::new()),
    }
}

#[test]
fn gnu_note_gives_the_build_id() {
    assert_eq!(id(&NOTES), (0, b"01234567".to_vec()));
}

#[test]
fn empty_notes_have_no_build_id() {
    assert_eq!(id(&[]).0, -ENOENT);
}

#[test]
fn oversized_name_is_malformed() {
    let mut bad = NOTES;

    bad[..4].copy_from_slice(&u32::MAX.to_ne_bytes());
    assert_eq!(id(&bad).0, -EINVAL);
}

/// A vendor's type-3 note first, then the GNU one.
#[test]
fn only_the_gnu_name_names_the_build_id() {
    let vendor = [
        &[
            4, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, b'G', b'N', b'U', b'X', 0x89, 0xab, 0xcd, 0xef,
        ][..],
        &NOTES,
    ]
    .concat();

    assert_eq!(id(&vendor), (0, b"01234567".to_vec()));
    assert_eq!(id(&vendor[..20]).0, -ENOENT);
}
