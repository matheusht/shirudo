// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::text::cstr;

/// What fputs_sanitized() prints of `s`.
fn shown(s: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 1024];
    // SAFETY: a stream over out, all but whose last byte it may write,
    // closed once.
    unsafe {
        let f = libc::fmemopen(out.as_mut_ptr().cast(), out.len() - 1, c"w".as_ptr());
        assert!(!f.is_null());
        fputs_sanitized(s, f);
        assert_eq!(libc::fclose(f), 0);
    }
    cstr(&out).to_vec()
}

#[test]
fn fputs_sanitized_keeps_a_terminal_safe() {
    assert_eq!(shown(b"CN=shirudo, O=Example"), b"CN=shirudo, O=Example");
    assert_eq!(shown(b"CN=\x1b]0;owned\x07\n"), b"CN=?]0;owned??");
    assert_eq!(shown(b"CN=caf\xc3\xa9 \xff"), b"CN=caf\xc3\xa9 ?");
}

#[test]
fn fputs_sanitized_cuts_after_511_bytes() {
    assert_eq!(shown(&[b'a'; 599]).len(), 511);
}

#[test]
fn human_size_picks_the_unit() {
    let mut out = [0u8; 16];

    assert_eq!(human_size(512, &mut out), 0);
    assert_eq!(cstr(&out), b"512B");
    assert_eq!(human_size(1536, &mut out), 0);
    assert_eq!(cstr(&out), b"1.50K");
    assert_eq!(human_size(1536, &mut out[..4]), -E2BIG);
}
