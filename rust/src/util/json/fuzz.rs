// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-json: a document parsed against a schema of every kind of field,
//! and walked, each string and key valid UTF-8 as the walk gives them.

use core::ffi::{CStr, c_int};

use super::parse::{Visit, walk};
use super::{JsonField, parse_schema};
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

/// What the schema of every kind of field fills.
struct Parsed {
    s: [u8; 64],
    k: [u8; 32],
    v: [u8; 16],
    w: [u8; 16],
    i: i64,
    n: i64,
    b: bool,
    elems: c_int,
    words: c_int,
}

fn on_elem(f: &mut Parsed) -> Result {
    f.elems += 1;
    Ok(())
}

fn on_word(f: &mut Parsed) -> Result {
    f.words += 1;
    Ok(())
}

fn on_member(_: &mut Parsed, key: &CStr) -> Result {
    check_text(key.to_bytes());
    Ok(())
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
    let mut parsed = Parsed {
        s: [0; 64],
        k: [0; 32],
        v: [0; 16],
        w: [0; 16],
        i: 0,
        n: 0,
        b: false,
        elems: 0,
        words: 0,
    };
    let obj = [
        JsonField::string(c"k", |f: &mut Parsed| &mut f.k),
        JsonField::int(c"n", |f| &mut f.n),
    ];
    let elem = [
        JsonField::string(c"v", |f: &mut Parsed| &mut f.v),
        JsonField::object(c"o", &obj),
    ];
    let word = [JsonField::string(c"", |f: &mut Parsed| &mut f.w)];
    let member = JsonField::array(c"", &word, &on_word);
    let root = [
        JsonField::string(c"s", |f: &mut Parsed| &mut f.s),
        JsonField::int(c"i", |f| &mut f.i),
        JsonField::boolean(c"b", |f| &mut f.b),
        JsonField::object(c"o", &obj),
        JsonField::array(c"a", &elem, &on_elem),
        JsonField::map(c"m", &member, &on_member),
    ];
    let _ = parse_schema(data, &root, &mut parsed);
    let _ = walk(data, &mut Checker);
});
