// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::parse::{Visit, walk};
use super::*;
use crate::errno::{E2BIG, EEXIST, EILSEQ, EINVAL, ENOENT, ENOSPC};
use crate::text::{cstr, strscpy};
use core::ffi::{CStr, c_int};

/// What an eventlog-shaped schema extracts from one document.
struct Doc {
    digest: [u8; 65],
    ty: [u8; 64],
    schema: i64,
    names: c_int,
    first_name: [u8; 64],
    name: [u8; 64],
    events: c_int,
    last_type: [u8; 32],
    ev_type: [u8; 32],
    ev_digest: [u8; 65],
}

impl Doc {
    fn new() -> Self {
        Doc {
            digest: [0; 65],
            ty: [0; 64],
            schema: -1,
            names: 0,
            first_name: [0; 64],
            name: [0; 64],
            events: 0,
            last_type: [0; 32],
            ev_type: [0; 32],
            ev_digest: [0; 65],
        }
    }
}

fn name_on_elem(d: &mut Doc) -> core::result::Result<(), c_int> {
    if d.names == 0 {
        let _ = strscpy(&mut d.first_name, cstr(&d.name));
    }
    d.names += 1;
    Ok(())
}

fn event_on_elem(d: &mut Doc) -> core::result::Result<(), c_int> {
    let _ = strscpy(&mut d.last_type, cstr(&d.ev_type));
    d.events += 1;
    Ok(())
}

/// The document `text` parsed into a fresh `d`.
fn parse_into(text: &[u8], d: &mut Doc) -> c_int {
    *d = Doc::new();
    let name_sub = [JsonField::string(c"", |d: &mut Doc| &mut d.name)];
    let event_sub = [
        JsonField::string(c"type", |d: &mut Doc| &mut d.ev_type),
        JsonField::string(c"digest", |d| &mut d.ev_digest),
    ];
    let f = [
        JsonField::int(c"schema", |d: &mut Doc| &mut d.schema),
        JsonField::string(c"type", |d| &mut d.ty),
        JsonField::string(c"digest", |d| &mut d.digest),
        JsonField::array(c"names", &name_sub, &name_on_elem),
        JsonField::array(c"events", &event_sub, &event_on_elem),
        // An empty schema slot must be ignored.
        JsonField::string(c"", |_| &mut []).keyless(),
    ];
    parse_schema(text, &f, d).err().unwrap_or(0)
}

fn parse(text: &str) -> (c_int, Doc) {
    let mut d = Doc::new();
    let ret = parse_into(text.as_bytes(), &mut d);
    (ret, d)
}

fn ok(text: &str) -> Doc {
    let (ret, d) = parse(text);
    assert_eq!(ret, 0, "{text}");
    d
}

fn err(text: &str) -> c_int {
    parse(text).0
}

#[test]
fn extracts_scalars_and_skips_nested_sets() {
    let d = ok(r#"{"schema":1,"digest":"abcdef","type":"init","set":[{"name":"x"}]}"#);

    assert_eq!(
        (cstr(&d.digest), cstr(&d.ty), d.schema),
        (&b"abcdef"[..], &b"init"[..], 1)
    );
}

#[test]
fn skips_unknown_keys_and_objects() {
    assert_eq!(
        cstr(&ok(r#"{"a":{"b":[1,2,3]},"digest":"ff","c":true}"#).digest),
        b"ff"
    );
    assert_eq!(cstr(&ok(r#"{"unknown":true,"digest":"ff"}"#).digest), b"ff");
}

#[test]
fn discarded_key_does_not_dispatch() {
    let d = ok(r#"{"a":{"digest":123,"type":true},"digest":"ff","type":"init"}"#);

    assert_eq!((cstr(&d.digest), cstr(&d.ty)), (&b"ff"[..], &b"init"[..]));
}

/// A value read as a C string would end at the NUL and pass checks meant
/// for the whole value; a key would be dispatched as its prefix.
#[test]
fn escaped_nul_is_refused() {
    assert_eq!(err(r#"{"digest":"ab\u0000cd"}"#), -EINVAL);
    assert_eq!(err(r#"{"digest\u0000x":"ff"}"#), -EINVAL);
    assert_eq!(cstr(&ok(r#"{"digest":"ab\u0041"}"#).digest), b"abA");
}

#[test]
fn malformed_documents_are_refused() {
    for bad in [
        r#"{"digest":"abc"#,
        r#"{"digest":"a"}xyz"#,
        r#"{"digest":123}"#,
    ] {
        assert_eq!(err(bad), -EINVAL, "{bad}");
    }
}

#[test]
fn overlong_string_is_enospc() {
    assert_eq!(
        err(&format!(r#"{{"digest":"{}"}}"#, "0".repeat(200))),
        -ENOSPC
    );
}

#[test]
fn deep_nesting_is_e2big() {
    assert_eq!(
        err(&(r#"{"a":"#.repeat(40) + "1" + &"}".repeat(40))),
        -E2BIG
    );
}

#[test]
fn garbage_fails_cleanly() {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut buf = vec![0u8; 4096];

    for _ in 0..64 {
        for b in buf.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        let mut d = Doc::new();
        assert!(parse_into(&buf, &mut d) <= 0);
    }
}

#[test]
fn empty_object_parses() {
    assert_eq!(err("{}"), 0);
}

#[test]
fn string_array_dispatches_each_element() {
    let d = ok(r#"{"names":["alpha","beta","gamma"]}"#);

    assert_eq!((d.names, cstr(&d.first_name)), (3, &b"alpha"[..]));
    assert_eq!(ok(r#"{"names":[]}"#).names, 0);
}

#[test]
fn object_array_uses_element_schema() {
    let d =
        ok(r#"{"events":[{"type":"init","digest":"00"},{"type":"upatch_load","digest":"ff"}]}"#);

    assert_eq!((d.events, cstr(&d.last_type)), (2, &b"upatch_load"[..]));
}

#[test]
fn nested_array_then_trailing_scalar() {
    let d = ok(r#"{"events":[{"type":"init","digest":"aa","set":[{"name":"x"}]}],"digest":"top"}"#);

    assert_eq!(
        (cstr(&d.digest), d.events, cstr(&d.last_type)),
        (&b"top"[..], 1, &b"init"[..])
    );
}

/// What an array of items, each with an id and a meta object of a tag,
/// tells of the fields each element gave.
struct Nested {
    meta_seen: [bool; 4],
    tag_seen: [bool; 4],
    id: [u8; 8],
    tag: [u8; 8],
    n: usize,
}

fn parse_nested(text: &str) -> (c_int, Nested) {
    let mut x = Nested {
        meta_seen: [false; 4],
        tag_seen: [false; 4],
        id: [0; 8],
        tag: [0; 8],
        n: 0,
    };
    let meta_sub = [JsonField::string(c"tag", |x: &mut Nested| &mut x.tag)];
    let item_sub = [
        JsonField::string(c"id", |x: &mut Nested| &mut x.id),
        JsonField::object(c"meta", &meta_sub),
    ];
    let nested_on_elem = |x: &mut Nested| {
        if x.n < 4 {
            x.meta_seen[x.n] = item_sub[1].seen();
            x.tag_seen[x.n] = meta_sub[0].seen();
        }
        x.n += 1;
        Ok(())
    };
    let f = [JsonField::array(c"items", &item_sub, &nested_on_elem)];
    let ret = parse_schema(text.as_bytes(), &f, &mut x).err().unwrap_or(0);
    (ret, x)
}

/// A field an element or a document leaves out is not given, however
/// deep in the schema it sits and whatever the one before gave.
#[test]
fn seen_flags_are_the_elements_own() {
    let (ret, x) = parse_nested(r#"{"items":[{"id":"a","meta":{"tag":"x"}},{"id":"b"}]}"#);

    assert_eq!((ret, x.n), (0, 2));
    assert_eq!(
        (&x.meta_seen[..2], &x.tag_seen[..2]),
        (&[true, false][..], &[true, false][..])
    );
    let mut k = [0u8; 8];
    let sub = [JsonField::string(c"k", |k: &mut [u8; 8]| k)];
    let top = [JsonField::object(c"o", &sub)];
    assert_eq!(parse_schema(br#"{"o":{"k":"v"}}"#, &top, &mut k), Ok(()));
    assert!(sub[0].seen());
    assert_eq!(parse_schema(b"{}", &top, &mut k), Ok(()));
    assert!(!top[0].seen());
    assert!(!sub[0].seen());
}

#[test]
fn declared_key_takes_one_value() {
    for bad in [
        r#"{"type":"a","type":"b"}"#,
        r#"{"type":"a","type":null}"#,
        r#"{"schema":1,"schema":1}"#,
        r#"{"names":["a"],"names":["b"]}"#,
        r#"{"events":[{"type":"a","type":"b"}]}"#,
        r#"{"type":null,"type":"b"}"#,
        r#"{"type":null,"type":null}"#,
    ] {
        assert_eq!(err(bad), -EINVAL, "{bad}");
    }
    let mut k = [0u8; 8];
    let sub = [JsonField::string(c"k", |k: &mut [u8; 8]| k)];
    let top = [JsonField::object(c"o", &sub)];
    let ret = parse_schema(br#"{"o":{"k":"v"},"o":{}}"#, &top, &mut k);
    assert_eq!(ret, Err(-EINVAL));
    assert_eq!(cstr(&ok(r#"{"x":1,"x":{},"type":"t"}"#).ty), b"t");
    assert_eq!(ok(r#"{"events":[{"type":"a"},{"type":"b"}]}"#).events, 2);
}

#[test]
fn malformed_arrays_are_refused() {
    for bad in [
        r#"{"names":[123]}"#,
        r#"{"names":["a","b""#,
        r#"{"names":[{"":"a"}]}"#,
    ] {
        assert_eq!(err(bad), -EINVAL, "{bad}");
    }
}

/// An element that is not an object would land in the first field of
/// the element schema, a type in place of a whole record.
#[test]
fn object_array_takes_objects_only() {
    for bad in [
        r#"{"events":["init"]}"#,
        r#"{"events":[1]}"#,
        r#"{"events":[null]}"#,
        r#"{"events":[{"type":"a"},true]}"#,
        r#"{"events":[[]]}"#,
    ] {
        assert_eq!(err(bad), -EINVAL, "{bad}");
    }
    assert_eq!(ok(r#"{"events":[{},{"type":"a"}]}"#).events, 2);
}

#[test]
fn integer_takes_json_integers_only() {
    for bad in [
        "1.9", "1e9", "1E9", "7-3", "1+1", "-", ".", "01", "-01", "1.", ".5", "1e", "--1", "0x1",
        "+1",
    ] {
        assert_eq!(err(&format!(r#"{{"schema":{bad}}}"#)), -EINVAL, "{bad}");
    }
}

#[test]
fn integer_holds_any_s64_and_no_more() {
    assert_eq!(ok(r#"{"schema":-9223372036854775808}"#).schema, i64::MIN);
    assert_eq!(ok(r#"{"schema":9223372036854775807}"#).schema, i64::MAX);
    assert_eq!(ok(r#"{"schema":-0}"#).schema, 0);
    assert_eq!(err(r#"{"schema":9223372036854775808}"#), -EINVAL);
    assert_eq!(err(r#"{"schema":-9223372036854775809}"#), -EINVAL);
}

#[test]
fn discarded_number_follows_the_grammar() {
    assert_eq!(ok(r#"{"x":[1.5e+10,-0.0E-1,2e5,0],"schema":2}"#).schema, 2);
    for bad in ["1.", "01", "1e+", "-.5", "1.e5"] {
        assert_eq!(
            err(&format!(r#"{{"x":{bad},"schema":2}}"#)),
            -EINVAL,
            "{bad}"
        );
    }
}

const BAD_UTF8: [&[u8]; 10] = [
    b"\xc0\xaf",
    b"\xc0\x80",
    b"\xe0\x80\xaf",
    b"\xed\xa0\x80",
    b"\xf4\x90\x80\x80",
    b"\xf5\x80\x80\x80",
    b"\xff",
    b"\x80",
    b"a\xc3",
    b"\xe2\x82z",
];

/// Whatever the parser takes, the emitter writes back: a value it would
/// refuse to write must not be read in the first place.
#[test]
fn malformed_utf8_is_refused() {
    let parse_bytes = |parts: &[&[u8]]| {
        let mut d = Doc::new();
        parse_into(&parts.concat(), &mut d)
    };

    assert_eq!(
        cstr(&ok("{\"type\":\"caf\u{e9} \u{1f41d}\"}").ty),
        "caf\u{e9} \u{1f41d}".as_bytes()
    );
    for bad in BAD_UTF8 {
        assert_eq!(
            parse_bytes(&[b"{\"type\":\"", bad, b"\"}"]),
            -EINVAL,
            "{bad:?}"
        );
        assert_eq!(
            parse_bytes(&[b"{\"x\":\"", bad, b"\",\"type\":\"t\"}"]),
            -EINVAL,
            "{bad:?}"
        );
        assert_eq!(
            parse_bytes(&[b"{\"", bad, b"\":1,\"type\":\"t\"}"]),
            -EINVAL,
            "{bad:?}"
        );
    }
    assert_eq!(parse_bytes(&[b"{\"type\":\"\xe2\x82"]), -EINVAL);
}

/// The text a fixed emitter of `cap` bytes wrote, and its error.
fn fixed(cap: usize, emit: impl FnOnce(&mut JsonEmit)) -> (c_int, Vec<u8>) {
    let mut buf = vec![0u8; cap];
    let mut e = JsonEmit::fixed(&mut buf[..cap]);
    emit(&mut e);
    let n = e.written();
    (e.err(), buf[..n].to_vec())
}

/// The error of a growing emitter of at most `max` bytes, the text it
/// wrote and the bytes it allocated.
fn growing(max: usize, emit: impl FnOnce(&mut JsonEmit)) -> (c_int, Vec<u8>, usize) {
    let mut e = JsonEmit::growing(max);
    emit(&mut e);
    (e.err(), e.output().to_vec(), e.allocated())
}

fn emit_string(val: &[u8]) -> (c_int, Vec<u8>) {
    fixed(64, |e| {
        e.obj_open();
        e.kv_string(b"v", val);
        e.obj_close();
    })
}

#[test]
fn emitter_takes_well_formed_utf8_only() {
    let good = "caf\u{e9} \u{1f41d}";

    assert_eq!(
        emit_string(good.as_bytes()),
        (0, format!(r#"{{"v":"{good}"}}"#).into_bytes())
    );
    for bad in BAD_UTF8.iter().filter(|b| **b != b"\x80") {
        assert_eq!(emit_string(bad).0, -EILSEQ, "{bad:?}");
    }
}

#[test]
fn emitter_takes_a_string_of_its_length() {
    assert_eq!(
        emit_string(&b"a\"bc"[..3]),
        (0, br#"{"v":"a\"b"}"#.to_vec())
    );
    assert_eq!(emit_string(b"a\0b").0, -EILSEQ);
    assert_eq!(emit_string(b"a\xc3").0, -EILSEQ);
}

/// All 64 bits of a u64, as a member and as an array element.
#[test]
fn emitter_writes_any_u64() {
    let (ret, text, _) = growing(256, |e| {
        e.obj_open();
        e.kv_u64(b"max", u64::MAX);
        e.kv_u64(b"zero", 0);
        e.arr_open(b"a");
        e.u64_value(1 << 63);
        e.u64_value(7);
        e.arr_close();
        e.obj_close();
    });
    assert_eq!(ret, 0);
    assert_eq!(
        text,
        br#"{"max":18446744073709551615,"zero":0,"a":[9223372036854775808,7]}"#
    );
    let (ret, _) = fixed(16, |e| {
        e.obj_open();
        e.kv_u64(b"v", u64::MAX);
        assert_eq!(e.err(), -ENOSPC);
        e.kv_u64(b"w", 1);
    });
    assert_eq!(ret, -ENOSPC);
}

#[test]
fn emitter_grows_up_to_its_max() {
    let text = vec![b'x'; 5999];
    let string = |e: &mut JsonEmit| {
        e.obj_open();
        e.kv_string(b"v", &text);
        e.obj_close();
    };

    let (ret, big, _) = growing(1 << 20, string);
    assert_eq!((ret, big.len()), (0, 5999 + 8));
    assert_eq!(growing(64, string).0, -E2BIG);
    let (ret, _, _) = growing(1 << 20, |e| {
        for _ in 0..150 {
            e.arr_open_value();
        }
        for _ in 0..150 {
            e.arr_close();
        }
    });
    assert_eq!(ret, 0);
}

#[test]
fn lossy_writes_replace_bad_bytes() {
    let (ret, text) = fixed(128, |e| {
        e.obj_open();
        e.key_lossy(b"k\xc3");
        e.str_lossy(b"a\xff\x62\0c\xc0\xaf\xc3\xa9");
        e.obj_close();
    });

    assert_eq!(ret, 0);
    assert_eq!(
        text,
        "{\"k\\ufffd\":\"a\\ufffdb\\ufffdc\\ufffd\\ufffd\u{e9}\"}".as_bytes()
    );
}

/// Every token a walk reports, in order.
#[derive(Default)]
struct Trace(Vec<u8>);

impl Trace {
    fn put(&mut self, parts: &[&[u8]]) -> core::result::Result<(), c_int> {
        for p in parts {
            self.0.extend_from_slice(p);
        }
        Ok(())
    }
}

impl Visit for Trace {
    fn open(&mut self, array: bool) -> core::result::Result<(), c_int> {
        self.put(&[if array { b"[" } else { b"{" }])
    }

    fn close(&mut self, array: bool) -> core::result::Result<(), c_int> {
        self.put(&[if array { b"]" } else { b"}" }])
    }

    fn key(&mut self, key: &CStr) -> core::result::Result<(), c_int> {
        self.put(&[b"k:", key.to_bytes(), b" "])
    }

    fn string(&mut self, s: &CStr) -> core::result::Result<(), c_int> {
        self.put(&[b"s:", s.to_bytes(), b" "])
    }

    fn number(&mut self, text: &[u8], integer: bool) -> core::result::Result<(), c_int> {
        self.put(&[if integer { b"i:" } else { b"d:" }, text, b" "])
    }

    fn literal(&mut self, value: c_int) -> core::result::Result<(), c_int> {
        self.put(&[match value {
            1.. => &b"true "[..],
            0 => b"false ",
            _ => b"null ",
        }])
    }
}

fn walked(text: &[u8]) -> core::result::Result<Vec<u8>, c_int> {
    let mut t = Trace::default();
    walk(text, &mut t).map(|()| t.0)
}

/// The walk reports a document in order, held to the parser's rules.
#[test]
fn walk_reports_every_token() {
    assert_eq!(
        walked(br#" {"a":[1,"x\u00e9",true,null,{"b":-2.5e3}],"c":{},"d":false} "#),
        Ok(
            "{k:a [i:1 s:x\u{e9} true null {k:b d:-2.5e3 }]k:c {}k:d false }"
                .as_bytes()
                .to_vec()
        )
    );
    assert_eq!(walked(br#""top""#), Ok(b"s:top ".to_vec()));
    assert_eq!(walked(b"-0"), Ok(b"i:-0 ".to_vec()));
    for bad in [
        &br#"{"a":1,}"#[..],
        br#"{"a":"\u0000"}"#,
        b"[\"\xff\"]",
        b"[1] 2",
        b"",
    ] {
        assert_eq!(walked(bad), Err(-EINVAL), "{bad:?}");
    }
    assert_eq!(walked(&[b'['; 40]), Err(-E2BIG));
}

/// ECMA-404, 2nd edition: what the grammar holds is taken, what it does
/// not is refused, and the restrictions json.h lists are refused too.
#[test]
fn walk_follows_ecma_404() {
    let conforming: [&[u8]; 17] = [
        b"[]",
        b"{}",
        b"0",
        b"-0",
        b"1.5e+10",
        b"1E-2",
        b"-0.0e0",
        b"true",
        b"null",
        b"\"\"",
        b"{\"\":0}",
        b" \t\n\r[1] ",
        br#"["\u002F\u002f\/"]"#,
        br#""\uD834\uDD1E""#,
        br#"["\b\f\n\r\t\"\\"]"#,
        b"[\"\x7f\"]",
        b"{\"a\":[{\"b\":null}],\"c\":\"\xf0\x9d\x84\x9e\"}",
    ];
    let nonconforming: [&[u8]; 27] = [
        b"[01]",
        b"[1.]",
        b"[.5]",
        b"[+1]",
        b"[-]",
        b"[1e]",
        b"[1e+]",
        b"[NaN]",
        b"[Infinity]",
        b"[\"\x01\"]",
        br#"["\x41"]"#,
        br#"["\u12"]"#,
        b"[True]",
        b"[1,]",
        br#"{"a":1,}"#,
        b"{a:1}",
        b"['a']",
        br#"["a" "b"]"#,
        b"\x0b[1]",
        b"\x0c[1]",
        b"\xef\xbb\xbf[1]",
        b"[1]x",
        br#"["a]"#,
        br#"{"a"}"#,
        br#"{"a" 1}"#,
        b"[1 2]",
        b"",
    ];
    let restricted: [&[u8]; 6] = [
        br#""\u0000""#,
        br#""\uD800""#,
        br#""\uDC00""#,
        br#""\uD800\u0041""#,
        b"[\"\xff\"]",
        b"[\"\xed\xa0\x80\"]",
    ];

    for doc in conforming {
        assert!(walked(doc).is_ok(), "{doc:?}");
    }
    for doc in nonconforming.iter().chain(&restricted) {
        assert_eq!(walked(doc), Err(-EINVAL), "{doc:?}");
    }
}

/// What a map's members told: each key with the count of its values,
/// -1 where it had none.
struct Members {
    keys: Vec<u8>,
    value: [u8; 16],
    values: c_int,
    members: c_int,
}

fn member_value(m: &mut Members) -> core::result::Result<(), c_int> {
    m.values += 1;
    Ok(())
}

fn parse_members(text: &str) -> (c_int, Members) {
    let mut m = Members {
        keys: Vec::new(),
        value: [0; 16],
        values: 0,
        members: 0,
    };
    let value_sub = [JsonField::string(c"", |m: &mut Members| &mut m.value)];
    let slot = JsonField::array(c"", &value_sub, &member_value);
    let member_key = |m: &mut Members, key: &CStr| {
        let key = key.to_bytes();
        if crate::text::find(&m.keys, key).is_some() {
            return Err(-EEXIST);
        }
        let count = if slot.seen() { m.values } else { -1 };
        m.keys
            .extend_from_slice(&[key, b"=", count.to_string().as_bytes(), b" "].concat());
        m.values = 0;
        m.members += 1;
        Ok(())
    };
    let f = [JsonField::map(c"map", &slot, &member_key)];
    let ret = match parse_schema(text.as_bytes(), &f, &mut m) {
        Ok(()) if !f[0].seen() => -ENOENT,
        ret => ret.err().unwrap_or(0),
    };
    (ret, m)
}

/// A map takes keys no schema names, each value as sub[0] takes it.
#[test]
fn map_takes_any_key() {
    let (ret, m) = parse_members(r#"{"map":{"a":["x","y"],"b":[],"c":null}}"#);

    assert_eq!(
        (ret, m.keys.as_slice(), m.members),
        (0, &b"a=2 b=0 c=-1 "[..], 3)
    );
    let (ret, m) = parse_members(r#"{"map":{}}"#);
    assert_eq!((ret, m.members), (0, 0));
    assert_eq!(parse_members("{}").0, -ENOENT);
    assert_eq!(parse_members(r#"{"map":{"a":[],"a":[]}}"#).0, -EEXIST);
    for bad in [
        r#"{"map":{"a":"x"}}"#,
        r#"{"map":{"a":[1]}}"#,
        r#"{"map":[]}"#,
        r#"{"map":{},"map":{}}"#,
        r#"{"map":{"a":[]}"#,
    ] {
        assert_eq!(parse_members(bad).0, -EINVAL, "{bad}");
    }
}

#[test]
fn walk_stops_where_a_callback_says() {
    struct Stop;
    impl Visit for Stop {
        fn open(&mut self, _: bool) -> core::result::Result<(), c_int> {
            Ok(())
        }
        fn close(&mut self, _: bool) -> core::result::Result<(), c_int> {
            Ok(())
        }
        fn key(&mut self, _: &CStr) -> core::result::Result<(), c_int> {
            Ok(())
        }
        fn string(&mut self, _: &CStr) -> core::result::Result<(), c_int> {
            Ok(())
        }
        fn number(&mut self, _: &[u8], _: bool) -> core::result::Result<(), c_int> {
            Err(-::libc::ECANCELED)
        }
        fn literal(&mut self, _: c_int) -> core::result::Result<(), c_int> {
            Ok(())
        }
    }

    assert_eq!(walk(br#"["a",2,3]"#, &mut Stop), Err(-::libc::ECANCELED));
    assert_eq!(walk(br#"["a"]"#, &mut Stop), Ok(()));
}

/// An emitter that may grow to max bytes holds max - 1 of text and a NUL.
#[test]
fn growth_keeps_room_for_the_nul() {
    let (ret, text, _) = growing(1, |e| e.obj_open());
    assert_eq!((ret, text.len()), (-E2BIG, 0));
    for (max, want) in [(1, -E2BIG), (2, -E2BIG), (3, 0)] {
        let (ret, text, cap) = growing(max, |e| {
            e.obj_open();
            e.obj_close();
        });
        assert_eq!(ret, want, "{max}");
        assert!(cap <= max);
        if want == 0 {
            assert_eq!(text, b"{}");
        }
    }
}

/// A string field has room for nothing without a byte for its NUL.
#[test]
fn string_field_needs_room_for_the_nul() {
    let mut guard = [b'x', b'y'];
    let f = [JsonField::string(c"s", |g: &mut [u8; 2]| &mut g[1..1])];

    assert_eq!(parse_schema(br#"{"s":""}"#, &f, &mut guard), Err(-ENOSPC));
    assert_eq!(guard[1], b'y');
    let f = [JsonField::string(c"s", |g: &mut [u8; 2]| &mut g[..1])];
    assert_eq!(parse_schema(br#"{"s":""}"#, &f, &mut guard), Ok(()));
    assert_eq!(guard, [0, b'y']);
}
