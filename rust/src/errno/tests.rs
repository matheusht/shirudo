// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;

#[test]
fn text_words_an_errno_as_strerror_does() {
    assert_eq!(text(-ENOENT), "No such file or directory");
    assert_eq!(text(-EPERM), "Operation not permitted");
}

#[test]
fn describe_keeps_a_message_that_is_not_an_errno() {
    let e = std::io::Error::other("no room");
    assert_eq!(describe(&e), "no room");
}
