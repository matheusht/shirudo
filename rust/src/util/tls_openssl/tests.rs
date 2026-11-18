// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;

#[test]
fn listed_host_matches_case_aside() {
    assert!(host_listed(b"registry.example", b"registry.example"));
    assert!(host_listed(
        b"Registry.EXAMPLE",
        b"a.example,registry.example"
    ));
    assert!(host_listed(b"registry.example.", b"registry.example"));
}

#[test]
fn unlisted_or_invalid_host_does_not_match() {
    assert!(!host_listed(b"other.example", b"registry.example"));
    assert!(!host_listed(b"registry.example", b""));
    assert!(!host_listed(b"", b"registry.example"));
    assert!(!host_listed(b"10.0.0.1", b"10.0.0.1"));
    assert!(!host_listed(b"registry.example..", b"registry.example"));
}

#[test]
fn entry_that_is_no_name_matches_nothing() {
    assert!(!host_listed(
        b"registry.example",
        b"a.example, registry.example"
    ));
    assert!(!host_listed(b"registry.example", b"registry.example."));
    assert!(!host_listed(b"registry.example", b"*.example"));
    let long = [
        b"a".repeat(63),
        b"b".repeat(63),
        b"c".repeat(63),
        b"d".repeat(63),
    ]
    .join(&b'.');
    assert_eq!(long.len(), 255);
    assert!(!host_listed(&long, &long));
}
