// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;

#[test]
fn pcrs_are_a_list_up_to_23() {
    assert_eq!(parse_pcrs(b"0"), Ok(1));
    assert_eq!(parse_pcrs(b"0,9,23"), Ok(1 | 1 << 9 | 1 << 23));
    assert_eq!(parse_pcrs(b"9,9"), Ok(1 << 9));
    for bad in [
        &b""[..],
        b"24",
        b"1,,2",
        b",1",
        b"1,",
        b"1,2,",
        b"1 ",
        b"+1",
        b"0x1",
    ] {
        assert_eq!(parse_pcrs(bad), Err(-EINVAL), "{bad:?}");
    }
}

#[test]
fn pcr_value_is_a_pcr_and_an_equals() {
    assert_eq!(parse_pcr_value(b"15=ab"), Ok((15, &b"ab"[..])));
    assert_eq!(parse_pcr_value(b"0="), Ok((0, &b""[..])));
    for bad in [&b"24=ab"[..], b"=ab", b"15", b"1 5=ab"] {
        assert_eq!(parse_pcr_value(bad), Err(-EINVAL), "{bad:?}");
    }
}

const D64: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// parse_name_digest() of `spec`: the name and the digest, or the error.
fn name_digest(spec: &str) -> Result<(Vec<u8>, [u8; 32]), c_int> {
    parse_name_digest(spec.as_bytes()).map(|(name, digest)| (name.to_vec(), digest))
}

#[test]
fn name_digest_is_a_name_and_64_digits() {
    let (name, digest) = name_digest(&format!("fix={D64}")).unwrap();
    assert_eq!((name.as_slice(), digest[1]), (&b"fix"[..], 0x11));
    assert_eq!(name_digest(&format!("a:b={D64}")).unwrap().0, b"a:b");
    for bad in [
        format!("={D64}"),
        format!("fix{D64}"),
        format!("fix={D64}0"),
        format!("fix=={D64}"),
    ] {
        assert_eq!(name_digest(&bad), Err(-EINVAL), "{bad}");
    }
    let longest = "n".repeat(UPATCH_NAME_MAX);
    assert_eq!(
        name_digest(&format!("{longest}={D64}")).unwrap().0.len(),
        UPATCH_NAME_MAX
    );
    assert_eq!(name_digest(&format!("{longest}n={D64}")), Err(-EINVAL));
}

#[test]
fn report_lines_are_a_tag_the_text_and_a_line_feed() {
    let mut rep = Report::new(64);

    rep.check(true, b"abc");
    rep.check(false, b"def");
    rep.note(b"ghi");
    assert_eq!(rep.text(), b"  OK    abc\n  FAIL  def\n  NOTE  ghi\n");
    assert_eq!(rep.failed, 1);
}

#[test]
fn report_is_bounded_as_the_c_buffer_was() {
    // A text that does not fit whole with a NUL after it is left out,
    // the line feed kept while there is room for it and the NUL.
    let mut rep = Report::new(24);
    rep.check(false, b"x");
    rep.note(b"too long a text");
    assert_eq!(rep.text(), b"  FAIL  x\n  NOTE  \n");
    // No line once a tag and its NUL would not fit, though the failure
    // still counts.
    rep.check(false, b"y");
    assert_eq!(rep.text(), b"  FAIL  x\n  NOTE  \n");
    assert_eq!(rep.failed, 2);

    // A text that ends at the last byte before the NUL leaves no room for
    // the line feed, nor for another line.
    let mut rep = Report::new(12);
    rep.check(true, b"abc");
    rep.note(b"d");
    assert_eq!(rep.text(), b"  OK    abc");

    let mut rep = Report::new(0);
    rep.check(true, b"abc");
    assert_eq!(rep.text(), b"");
}
