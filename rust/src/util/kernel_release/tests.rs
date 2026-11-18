// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;

#[test]
fn prefix_matches_at_a_boundary() {
    assert!(prefix_matches(b"6.1.0", b"6.1"));
    assert!(prefix_matches(b"6.1-custom", b"6.1"));
    assert!(prefix_matches(b"6.1", b"6.1"));
    assert!(!prefix_matches(b"6.10.0", b"6.1"));
}

#[test]
fn empty_prefix_matches_any_release() {
    assert!(prefix_matches(b"6.1.0", b""));
    assert!(!prefix_matches(b"", b"6.1"));
}
