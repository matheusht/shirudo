// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-json: a document parsed against a schema of every kind of field,
//! and walked, each string and key valid UTF-8 as the walk gives them.

use core::ffi::{CStr, c_char, c_int, c_void};

use super::parse::{Visit, walk};
use super::{JsonArray, JsonField, JsonMap, parse_schema};
use crate::fuzzing::fuzz_target;
use crate::text::utf8_width;

type Result = core::result::Result<(), c_int>;

fn check_text(s: &[u8]) {
    let mut i = 0;
    while i < s.len() {
        let w = utf8_width(&s[i..]);
        if w == 0 {
            std::process::abort();
        }
        i += w;
    }
}

/// # Safety
///
/// `ctx` is the count the array hands.
unsafe extern "C" fn on_elem(ctx: *mut c_void) -> c_int {
    // SAFETY: the caller's count.
    unsafe { *ctx.cast::<c_int>() += 1 };
    0
}

/// # Safety
///
/// `key` is a C string.
unsafe extern "C" fn on_member(_: *mut c_void, key: *const c_char) -> c_int {
    // SAFETY: the parser's key.
    check_text(unsafe { CStr::from_ptr(key) }.to_bytes());
    0
}

struct Checker;

impl Visit for Checker {
    fn open(&mut self, _: bool) -> Result {
        Ok(())
    }
    fn close(&mut self, _: bool) -> Result {
        Ok(())
    }
    fn key(&mut self, key: &CStr) -> Result {
        check_text(key.to_bytes());
        Ok(())
    }
    fn string(&mut self, s: &CStr) -> Result {
        check_text(s.to_bytes());
        Ok(())
    }
    fn number(&mut self, _: &[u8], _: bool) -> Result {
        Ok(())
    }
    fn literal(&mut self, _: c_int) -> Result {
        Ok(())
    }
}

fuzz_target!(shirudo_fuzz_json, shirudo_fuzz_json_init, |data| {
    let (mut s, mut k, mut v, mut w) = ([0u8; 64], [0u8; 32], [0u8; 16], [0u8; 16]);
    let (mut i, mut n) = (0i64, 0i64);
    let mut b: c_int = 0;
    let (mut elems, mut words): (c_int, c_int) = (0, 0);
    let mut arr = JsonArray::new(on_elem, (&raw mut elems).cast());
    let mut list = JsonArray::new(on_elem, (&raw mut words).cast());
    let mut map = JsonMap::new(on_member, core::ptr::null_mut());
    let mut obj = [
        JsonField::string(c"k", k.as_mut_ptr(), k.len()),
        JsonField::int(c"n", &raw mut n),
    ];
    let mut elem = [
        JsonField::string(c"v", v.as_mut_ptr(), v.len()),
        JsonField::object(c"o", obj.as_mut_ptr(), obj.len()),
    ];
    let mut word = [JsonField::string(c"", w.as_mut_ptr(), w.len())];
    let mut member = [JsonField::array(
        c"",
        &raw mut list,
        word.as_mut_ptr(),
        word.len(),
    )];
    let mut root = [
        JsonField::string(c"s", s.as_mut_ptr(), s.len()),
        JsonField::int(c"i", &raw mut i),
        JsonField::boolean(c"b", &raw mut b),
        JsonField::object(c"o", obj.as_mut_ptr(), obj.len()),
        JsonField::array(c"a", &raw mut arr, elem.as_mut_ptr(), elem.len()),
        JsonField::map(c"m", &raw mut map, member.as_mut_ptr(), member.len()),
    ];
    // SAFETY: the schema, its destinations and sinks live through the
    // parse.
    let _ = unsafe { parse_schema(data, root.as_mut_ptr(), root.len()) };
    let _ = walk(data, &mut Checker);
});
