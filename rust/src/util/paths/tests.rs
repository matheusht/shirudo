// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;

#[test]
fn key_file_spells_the_path() {
    assert_eq!(
        key_file(b"/k", c"cert.der").unwrap().as_bytes(),
        b"/k/cert.der"
    );
    assert_eq!(
        key_file(b"/k/", c"cert.der").unwrap().as_bytes(),
        b"/k/cert.der"
    );
    assert_eq!(key_file(b"", c"cert.der"), Err(-EINVAL));
    assert_eq!(key_file(b"/a\0b", c"cert.der"), Err(-EINVAL));
    let long = vec![b'a'; PATH_MAX - 1 - b"/cert.der".len()];
    assert!(key_file(&long, c"cert.der").is_ok());
    assert_eq!(
        key_file(&[&long[..], b"a"].concat(), c"cert.der"),
        Err(-ENAMETOOLONG)
    );
}

#[test]
fn keys_dir_takes_the_argument_first() {
    assert_eq!(keys_dir(Some(c"/x")), c"/x");
}
