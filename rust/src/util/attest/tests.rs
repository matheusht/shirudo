// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;

/// parse_pcrs() of `list`: the mask, or the error.
fn pcrs(list: &CStr) -> Result<u32, c_int> {
    let mut mask = 0;
    // SAFETY: a C string.
    match unsafe { parse_pcrs(list.as_ptr(), &mut mask) } {
        0 => Ok(mask),
        err => Err(err),
    }
}

#[test]
fn pcrs_are_a_list_up_to_23() {
    assert_eq!(pcrs(c"0"), Ok(1));
    assert_eq!(pcrs(c"0,9,23"), Ok(1 | 1 << 9 | 1 << 23));
    assert_eq!(pcrs(c"9,9"), Ok(1 << 9));
    for bad in [
        c"", c"24", c"1,,2", c",1", c"1,", c"1,2,", c"1 ", c"+1", c"0x1",
    ] {
        assert_eq!(pcrs(bad), Err(-EINVAL), "{bad:?}");
    }
}

/// parse_pcr_value() of `arg`: the PCR and the value after the equals
/// sign, or the error.
fn pcr_value(arg: &CStr) -> Result<(u64, &CStr), c_int> {
    let (mut pcr, mut value) = (0, ptr::null());
    // SAFETY: a C string, and room for the number and the value.
    match unsafe { parse_pcr_value(arg.as_ptr(), &mut pcr, &mut value) } {
        // SAFETY: the value points into arg, its own terminator kept.
        0 => Ok((pcr, unsafe { CStr::from_ptr(value) })),
        err => Err(err),
    }
}

#[test]
fn pcr_value_is_a_pcr_and_an_equals() {
    assert_eq!(pcr_value(c"15=ab"), Ok((15, c"ab")));
    assert_eq!(pcr_value(c"0="), Ok((0, c"")));
    for bad in [c"24=ab", c"=ab", c"15", c"1 5=ab"] {
        assert_eq!(pcr_value(bad), Err(-EINVAL), "{bad:?}");
    }
}

const D64: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// parse_name_digest() of `spec`: the name and the digest, or the error.
fn name_digest(spec: &str) -> Result<(Vec<u8>, [u8; 32]), c_int> {
    let spec = std::ffi::CString::new(spec).unwrap();
    let mut name = [0u8; UPATCH_NAME_MAX + 1];
    let mut digest = [0u8; 32];
    // SAFETY: a C string, room for the longest name and for a digest.
    match unsafe { parse_name_digest(spec.as_ptr(), name.as_mut_ptr().cast(), digest.as_mut_ptr()) }
    {
        0 => Ok((cstr(&name).to_vec(), digest)),
        err => Err(err),
    }
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
