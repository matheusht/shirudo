// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::errno::EINVAL;

const HEX64: &str = "00112233445566778899aabbccddeeffFFEEDDCCBBAA99887766554433221100";
const HEX64_LOWER: &str = "00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100";

/// sha256_digest_decode() of `digest`, as a C string, into `out`.
fn digest_decode(digest: &str, out: &mut [u8; 32]) -> c_int {
    let digest = std::ffi::CString::new(digest).unwrap();
    // SAFETY: a C string and room for 32 bytes.
    unsafe { sha256_digest_decode(digest.as_ptr(), out.as_mut_ptr()) }
}

#[test]
fn encode_is_lower_case() {
    assert_eq!(
        encode(&[0x00, 0x0a, 0xde, 0xad, 0xbe, 0xff]),
        b"000adeadbeff"
    );
}

#[test]
fn decode_takes_either_case() {
    let mut out = [0u8; 3];

    decode(b"0aFf", &mut out[..2]).unwrap();
    assert_eq!(out[..2], [0x0a, 0xff]);
    decode(b"DEadBE", &mut out).unwrap();
    assert_eq!(out, [0xde, 0xad, 0xbe]);
}

#[test]
fn decode_wants_the_exact_length() {
    let mut out = [0u8; 1];

    assert_eq!(decode(b"abc", &mut out), Err(-EINVAL));
    assert_eq!(decode(b"abcd", &mut out), Err(-EINVAL));
    // The C string form counts the digits to the terminator.
    // SAFETY: a C string and room for one byte.
    let ret = unsafe { hex_decode(c"abc".as_ptr(), out.as_mut_ptr(), 1) };
    assert_eq!(ret, -EINVAL);
}

#[test]
fn decode_refuses_non_hex() {
    assert_eq!(decode(b"zz", &mut [0u8; 1]), Err(-EINVAL));
}

#[test]
fn decode_max_takes_an_even_count_up_to_cap() {
    let mut out = [0u8; 3];
    let mut len = 9;
    let max = |hex: &core::ffi::CStr, out: &mut [u8; 3], len: &mut usize| {
        // SAFETY: a C string, room for three bytes and for their count.
        unsafe { hex_decode_max(hex.as_ptr(), out.as_mut_ptr(), out.len(), len) }
    };

    assert_eq!(max(c"", &mut out, &mut len), 0);
    assert_eq!(len, 0);
    assert_eq!(max(c"aB", &mut out, &mut len), 0);
    assert_eq!((len, out[0]), (1, 0xab));
    assert_eq!(max(c"00ff10", &mut out, &mut len), 0);
    assert_eq!((len, out[2]), (3, 0x10));
    len = 9;
    assert_eq!(max(c"abc", &mut out, &mut len), -EINVAL);
    assert_eq!(max(c"00ff1022", &mut out, &mut len), -EINVAL);
    assert_eq!(max(c"0g", &mut out, &mut len), -EINVAL);
    assert_eq!(len, 9);
}

#[test]
fn decode_max_of_a_slice_fills_the_start() {
    let mut out = [0u8; 3];

    assert_eq!(decode_max(b"", &mut out), Ok(0));
    assert_eq!(decode_max(b"aB", &mut out), Ok(1));
    assert_eq!(out[0], 0xab);
    assert_eq!(decode_max(b"00ff10", &mut out), Ok(3));
    assert_eq!(out, [0x00, 0xff, 0x10]);
    for bad in [&b"abc"[..], b"00ff1022", b"0g"] {
        assert_eq!(decode_max(bad, &mut out), Err(-EINVAL), "{bad:?}");
    }
}

#[test]
fn sha256_digest_is_prefix_and_64_digits() {
    let mut out = [0u8; 32];

    assert_eq!(digest_decode(&format!("sha256:{HEX64}"), &mut out), 0);
    assert_eq!((out[0], out[1], out[16], out[31]), (0x00, 0x11, 0xff, 0x00));
    // SAFETY: no digest, which it refuses, and room for 32 bytes.
    let ret = unsafe { sha256_digest_decode(core::ptr::null(), out.as_mut_ptr()) };
    assert_eq!(ret, -EINVAL);
    for bad in [
        HEX64.to_string(),
        format!("sha512:{HEX64}"),
        format!("SHA256:{HEX64}"),
        format!("sha256:{HEX64}0"),
        "sha256:".to_string(),
        format!("sha256:g{}", &HEX64[1..]),
    ] {
        assert_eq!(digest_decode(&bad, &mut out), -EINVAL, "{bad}");
    }
}

/// The digest written reads back, in lowercase whatever case it came in.
#[test]
fn sha256_digest_encodes_in_lowercase() {
    let (mut digest, mut back) = ([0u8; 32], [0u8; 32]);

    assert_eq!(digest_decode(&format!("sha256:{HEX64}"), &mut digest), 0);
    let text = sha256_digest_encode(&digest);
    assert_eq!(&text[..71], format!("sha256:{HEX64_LOWER}").as_bytes());
    assert_eq!(text[71], 0);
    assert_eq!(
        digest_decode(&format!("sha256:{HEX64_LOWER}"), &mut back),
        0
    );
    assert_eq!(back, digest);
}
