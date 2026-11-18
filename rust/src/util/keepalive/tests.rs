// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::testutil::testing_path;
use crate::util::conditions::{ConditionsInput, conditions};
use crate::util::json::{Visit, walk};

const APPLIED: u8 = 1;
const PASSED_OVER: u8 = 2;
const NOT_ATTACHED: u8 = 3;
const FIXTURE_BODY_MAX: usize = 1200;
const ALL_OK: u16 = 5461;
const STRING_MAX: usize = 255;
const VERSION_ID: &[u8] = b"d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f";
const CONFIG_ROOT_A: &[u8] = b"1d8465c5b17838303fee92b3905420d294d2c22c576a0bdef0f69f190ed22807";
const CONFIG_ROOT_B: &[u8] = b"ff2cbeff5d0e9c41a7b36f28d14ce09b73a5182e6fc40d97b5e2a1683c0f7ff8";
const IMAGE_ROOT: &[u8] = b"a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c";
const ZEROS: &[u8] = b"0000000000000000000000000000000000000000000000000000000000000000";
const ONES: &[u8] = b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const ROOT_AFTER_1: &[u8] = b"04f83540c1727aefcf3c53449a99594c8fd1cc15e1466dbdbf3168cc8f9dc136";
const ROOT_AFTER_3: &[u8] = b"154522480ff8884daa95589e80f26f20248bbf9c192dfbb3cee04e03b4f136a1";
const SET_1_0_0: &[u8] = b"6c9e113d02cd14646f617d7bba4a092b91bc3802dfdaae50e2fef7a01e0580aa";
const SET_1_1_0: &[u8] = b"74e5bd2c665109f6d8f926af5476c266ad70ab07293ff13b1a13d0b89aa5c1bf";
const SET_EMPTY: &[u8] = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const NO_TAMPER: [u64; TAMPER_MAX] = [0; TAMPER_MAX];
const NO_INTEGRITY: [u64; INTEGRITY_MAX] = [0; INTEGRITY_MAX];

/// The mask of `codes` as mask() writes it.
fn mask_of(codes: &[u8]) -> Vec<u8> {
    let mut b64 = [0u8; MASK_B64_MAX];
    assert_eq!(mask(codes, &mut b64), 0);
    cstr(&b64).to_vec()
}

#[test]
fn mask_of_one_operation() {
    assert_eq!(mask_of(&[APPLIED]), b"QA==");
    assert_eq!(mask_of(&[PASSED_OVER]), b"gA==");
}

#[test]
fn mask_of_the_release_example() {
    assert_eq!(mask_of(&[APPLIED; 3]), b"VA==");
    assert_eq!(mask_of(&[PASSED_OVER; 3]), b"qA==");
}

#[test]
fn mask_of_sixteen_operations() {
    let codes = [
        APPLIED,
        APPLIED,
        PASSED_OVER,
        APPLIED,
        NOT_ATTACHED,
        APPLIED,
        PASSED_OVER,
        APPLIED,
        APPLIED,
        APPLIED,
        PASSED_OVER,
        APPLIED,
        0,
        0,
        0,
        0,
    ];
    assert_eq!(mask_of(&codes), b"WdlZAA==");
}

#[test]
fn mask_of_no_operation_is_empty() {
    assert_eq!(mask_of(&[]), b"");
}

#[test]
fn mask_fills_a_byte_then_pads_the_next() {
    assert_eq!(mask_of(&[APPLIED; 4]), b"VQ==");
    assert_eq!(mask_of(&[APPLIED; 5]), b"VUA=");
}

#[test]
fn mask_of_a_full_window() {
    let mut want = vec![b'V'; MASK_B64_MAX - 1];
    let n = want.len();
    want[n - 4..].copy_from_slice(b"VVU=");

    assert_eq!(MASK_B64_MAX, 173);
    assert_eq!(mask_of(&[APPLIED; MASK_OPS]), want);
    assert_eq!(
        mask(&[APPLIED; MASK_OPS + 1], &mut [0u8; MASK_B64_MAX]),
        -EINVAL
    );
}

#[test]
fn mask_refuses_a_code_past_two_bits() {
    assert_eq!(mask(&[APPLIED, 4], &mut [0u8; MASK_B64_MAX]), -EINVAL);
}

#[test]
fn mask_refuses_a_buffer_too_small() {
    let codes = [APPLIED; 5];
    let mut b64 = [0xffu8; 5];

    assert_eq!(mask(&codes[..0], &mut b64[..0]), -E2BIG);
    assert_eq!(mask(&codes[..0], &mut b64[..1]), 0);
    assert_eq!(cstr(&b64), b"");
    assert_eq!(mask(&codes[..1], &mut b64[..4]), -E2BIG);
    assert_eq!(mask(&codes, &mut b64[..4]), -E2BIG);
    assert_eq!(mask(&codes, &mut b64), 0);
    assert_eq!(cstr(&b64), b"VUA=");
}

/// Conditions of the named kinds and statuses.
fn conds(named: &[(&'static CStr, &'static CStr)]) -> Vec<Condition> {
    named
        .iter()
        .map(|(kind, status)| Condition {
            kind: kind.as_ptr(),
            status: status.as_ptr(),
            detail: [0; 192],
        })
        .collect()
}

const ALL: [&CStr; 7] = [
    c"LsmAttached",
    c"KeyringSealed",
    c"ChainIntact",
    c"UpatchesMeasured",
    c"TpmMeasured",
    c"ConfigActive",
    c"XdpCovered",
];

#[test]
fn cond_of_all_ok() {
    let ok: Vec<_> = ALL.iter().map(|k| (*k, c"OK")).collect();
    let mut reordered = ok.clone();
    reordered.reverse();

    assert_eq!(cond(&conds(&ok)), ALL_OK);
    assert_eq!(cond(&conds(&reordered)), ALL_OK);
}

#[test]
fn cond_of_a_config_warning() {
    let warn: Vec<_> = ALL
        .iter()
        .map(|k| {
            (
                *k,
                if *k == c"ConfigActive" {
                    c"WARN"
                } else {
                    c"OK"
                },
            )
        })
        .collect();
    let mut reordered = warn.clone();
    reordered.rotate_left(3);

    assert_eq!(cond(&conds(&warn)), 6485);
    assert_eq!(cond(&conds(&reordered)), 6485);
}

#[test]
fn cond_leaves_a_missing_condition_at_zero() {
    let without_chain: Vec<_> = ALL
        .iter()
        .filter(|k| **k != c"ChainIntact")
        .map(|k| (*k, c"OK"))
        .collect();

    assert_eq!(cond(&conds(&without_chain)), ALL_OK & !(3 << 4));
    assert_eq!(cond(&[]), 0);
}

#[test]
fn cond_places_each_status_by_name() {
    let c = conds(&[
        (c"XdpCovered", c"ALERT"),
        (c"Unknown", c"ALERT"),
        (c"LsmAttached", c"ALERT"),
        (c"KeyringSealed", c"WARN"),
    ]);
    assert_eq!(cond(&c), (3 << 12) | (2 << 2) | 3);
}

#[test]
fn cond_follows_the_order_conditions_returns() {
    // SAFETY: an input of flags, counts and NULL strings, for which
    // zeros are a value.
    let mut i: ConditionsInput = unsafe { core::mem::zeroed() };
    i.reachable = true;
    i.parsed = true;
    i.lsm_attached = 1;
    // SAFETY: conditions of NULL strings and empty details.
    let mut c: [Condition; CONDITIONS_MAX] = unsafe { core::mem::zeroed() };
    let n = conditions(&i, &mut c);
    let word = cond(&c[..n]);

    assert_eq!(n, CONDITIONS_MAX);
    for i in 0..n {
        assert_ne!((word >> (2 * i)) & 3, 0, "{i}");
    }
    assert_eq!(word & 3, 1);
}

fn node_a() -> Input<'static> {
    Input {
        boot_id: Some(b"168d20a1-5011-4e1b-9924-d8b73c85aa4e"),
        version_id: Some(VERSION_ID),
        config_root: Some(CONFIG_ROOT_A),
        kernel_release: Some(b"7.4.2"),
        image_id: Some(b"fleet-os"),
        image_version: Some(b"2026.11.1"),
        image_root: Some(IMAGE_ROOT),
        verdict: Some(b"ok"),
        cond: ALL_OK,
        flags: 0,
        tamper: Some(&NO_TAMPER),
        integrity: Some(&NO_INTEGRITY),
        tree: Some(Tree {
            tree_id: Some(b"fleet-base"),
            generation: 0,
            base_seq: 0,
            last_seq: 0,
            base_root: Some(ZEROS),
            projection_root: None,
            mask: None,
        }),
        set_sha256: None,
        count: 0,
        not_ok: 0,
    }
}

fn node_b() -> Input<'static> {
    let mut i = node_a();
    i.boot_id = Some(b"9a6f14ea-0cc2-45e1-8e23-7b887120cf54");
    i.config_root = Some(CONFIG_ROOT_B);
    i.image_root = Some(b"");
    i.tree.as_mut().unwrap().projection_root = Some(ZEROS);
    i.set_sha256 = Some(SET_EMPTY);
    i
}

/// `i` after a release of `generation` operations, whose mask is `mask`.
fn at_release<'a>(i: &mut Input<'a>, generation: u64, mask: &'a [u8]) {
    let t = i.tree.as_mut().unwrap();
    t.generation = generation;
    t.last_seq = generation;
    t.mask = Some(mask);
}

/// The mask of a release of `generation` operations, each `outcome`.
fn release_mask(generation: usize, outcome: u8) -> Vec<u8> {
    mask_of(&vec![outcome; generation])
}

fn fixture(name: &str) -> Vec<u8> {
    let want = std::fs::read(testing_path(&format!("fixtures/keepalive/{name}"))).unwrap();
    assert!(want.len() <= FIXTURE_BODY_MAX);
    want
}

fn emitted(i: &Input<'_>) -> Vec<u8> {
    body(i).unwrap()
}

fn has(body: &[u8], part: &str) -> bool {
    crate::text::find(body, part.as_bytes()).is_some()
}

#[test]
fn body_of_node_a_after_release_1_0_0() {
    let mask = release_mask(1, APPLIED);
    let mut i: Input<'_> = node_a();
    at_release(&mut i, 1, &mask);
    i.tree.as_mut().unwrap().projection_root = Some(ROOT_AFTER_1);
    i.set_sha256 = Some(SET_1_0_0);
    i.count = 1;
    assert_eq!(emitted(&i), fixture("node-a-1.0.0.json"));
}

#[test]
fn body_of_node_a_after_release_1_1_0() {
    let mask = release_mask(3, APPLIED);
    let mut i: Input<'_> = node_a();
    at_release(&mut i, 3, &mask);
    i.tree.as_mut().unwrap().projection_root = Some(ROOT_AFTER_3);
    i.set_sha256 = Some(SET_1_1_0);
    i.count = 1;
    assert_eq!(emitted(&i), fixture("node-a-1.1.0.json"));
}

#[test]
fn body_of_node_b_after_release_1_0_0() {
    let mask = release_mask(1, PASSED_OVER);
    let mut i: Input<'_> = node_b();
    at_release(&mut i, 1, &mask);
    assert_eq!(emitted(&i), fixture("node-b-1.0.0.json"));
}

#[test]
fn body_of_node_b_after_release_1_1_0() {
    let mask = release_mask(3, PASSED_OVER);
    let mut i: Input<'_> = node_b();
    at_release(&mut i, 3, &mask);
    assert_eq!(emitted(&i), fixture("node-b-1.1.0.json"));
}

#[test]
fn body_of_sixteen_operations() {
    let mut i = node_a();
    i.boot_id = Some(b"d5140906-4eab-4983-a62c-29e49d449ea3");
    i.config_root = Some(b"1fbdff17ad8d50404772901df54d5aa2c698eddbb413e286fc654f80931c688a");
    i.kernel_release = Some(b"7.4.0-shirudo");
    let t = i.tree.as_mut().unwrap();
    t.generation = 42;
    t.last_seq = 12;
    t.projection_root = Some(b"f59301708fc8e150c5d2abb1009b4f13fc0dcc1304b708f77dc14b1541679e28");
    t.mask = Some(b"WdlZAA==");
    i.set_sha256 = Some(b"ac1af1d44b5c1fe3f616384db421138aa4d296595797b5864908a89276e17e6d");
    i.count = 7;
    assert_eq!(emitted(&i), fixture("ops-16.json"));
}

fn all_null() -> Input<'static> {
    Input {
        boot_id: Some(b"b"),
        version_id: Some(VERSION_ID),
        config_root: None,
        kernel_release: Some(b"k"),
        image_id: None,
        image_version: None,
        image_root: None,
        verdict: Some(b"init-pending"),
        cond: 0,
        flags: 72,
        tamper: None,
        integrity: None,
        tree: None,
        set_sha256: Some(SET_EMPTY),
        count: 0,
        not_ok: 0,
    }
}

#[test]
fn body_with_every_nullable_key_null() {
    let want = format!(
        concat!(
            r#"{{"schema":"shirudo.keepalive/1","boot_id":"b","version_id":"{v}","config_root":null,"#,
            r#""kernel_release":"k","image_id":null,"image_version":null,"image_root":null,"#,
            r#""verdict":"init-pending","cond":0,"flags":72,"tamper":null,"integrity":null,"#,
            r#""tree_id":null,"generation":null,"base_seq":null,"last_seq":null,"base_root":null,"#,
            r#""projection_root":null,"mask":null,"set_sha256":"{s}","count":0,"not_ok":0}}"#
        ),
        v = String::from_utf8_lossy(VERSION_ID),
        s = String::from_utf8_lossy(SET_EMPTY)
    );
    assert_eq!(emitted(&all_null()), want.as_bytes());
}

#[test]
fn body_without_a_tree_gives_null_tree_keys() {
    let mut i = node_a_at_1_0_0();
    i.tree = None;
    assert!(has(
        &emitted(&i),
        r#",0],"tree_id":null,"generation":null,"base_seq":null,"last_seq":null,"base_root":null,"projection_root":null,"mask":null,"set_sha256":"#
    ));
}

fn node_a_at_1_0_0() -> Input<'static> {
    let mut i = node_a();
    let t = i.tree.as_mut().unwrap();
    t.generation = 1;
    t.last_seq = 1;
    t.projection_root = Some(ROOT_AFTER_1);
    t.mask = Some(b"QA==");
    i.set_sha256 = Some(SET_1_0_0);
    i.count = 1;
    i
}

#[test]
fn body_gives_each_nullable_key_as_null() {
    fn tree<'a, 'b>(i: &'a mut Input<'b>) -> &'a mut Tree<'b> {
        i.tree.as_mut().unwrap()
    }
    let mut i = node_a_at_1_0_0();
    let check = |i: &Input<'_>, want: &str| assert!(has(&emitted(i), want), "{want}");

    for v in [None, Some(&b""[..])] {
        i.config_root = v;
        check(&i, r#","config_root":null,"kernel_release":"#);
    }
    for v in [None, Some(&b""[..])] {
        i.image_id = v;
        check(&i, r#","image_id":null,"image_version":""#);
    }
    for v in [None, Some(&b""[..])] {
        i.image_version = v;
        check(&i, r#","image_version":null,"image_root":""#);
    }
    for v in [None, Some(&b""[..])] {
        i.image_root = v;
        check(&i, r#","image_root":null,"verdict":"#);
    }
    i.tamper = None;
    check(&i, r#","tamper":null,"integrity":[0,"#);
    i.integrity = None;
    check(&i, r#","integrity":null,"tree_id":"fleet-base","#);
    for v in [None, Some(&b""[..])] {
        tree(&mut i).base_root = v;
        check(&i, r#","base_root":null,"projection_root":""#);
    }
    tree(&mut i).mask = None;
    check(&i, r#","mask":null,"set_sha256":"#);
    check(
        &i,
        &format!(
            r#","tree_id":"fleet-base","generation":1,"base_seq":0,"last_seq":1,"base_root":null,"projection_root":"{}","mask":null,"#,
            String::from_utf8_lossy(ROOT_AFTER_1)
        ),
    );
}

#[test]
fn body_tells_an_empty_mask_from_none() {
    let mask = mask_of(&[]);
    let mut i: Input<'_> = node_a_at_1_0_0();
    i.tree.as_mut().unwrap().mask = Some(&mask);
    assert!(has(&emitted(&i), r#","mask":"","set_sha256":"#));
}

/// The keys of the body's top level, and whether each stood there.
#[derive(Default)]
struct Keys {
    depth: usize,
    keys: Vec<Vec<u8>>,
    nested: bool,
}

impl Visit for Keys {
    fn open(&mut self, _: bool) -> core::result::Result<(), c_int> {
        self.depth += 1;
        Ok(())
    }
    fn close(&mut self, _: bool) -> core::result::Result<(), c_int> {
        self.depth -= 1;
        Ok(())
    }
    fn key(&mut self, key: &CStr) -> core::result::Result<(), c_int> {
        self.nested |= self.depth != 1;
        self.keys.push(key.to_bytes().to_vec());
        Ok(())
    }
    fn string(&mut self, _: &CStr) -> core::result::Result<(), c_int> {
        Ok(())
    }
    fn number(&mut self, _: &[u8], _: bool) -> core::result::Result<(), c_int> {
        Ok(())
    }
    fn literal(&mut self, _: c_int) -> core::result::Result<(), c_int> {
        Ok(())
    }
}

#[test]
fn body_has_every_key_in_order() {
    let order = [
        "schema",
        "boot_id",
        "version_id",
        "config_root",
        "kernel_release",
        "image_id",
        "image_version",
        "image_root",
        "verdict",
        "cond",
        "flags",
        "tamper",
        "integrity",
        "tree_id",
        "generation",
        "base_seq",
        "last_seq",
        "base_root",
        "projection_root",
        "mask",
        "set_sha256",
        "count",
        "not_ok",
    ];

    for i in [node_a_at_1_0_0(), all_null()] {
        let mut keys = Keys::default();
        assert_eq!(walk(&emitted(&i), &mut keys), Ok(()));
        assert!(!keys.nested);
        assert_eq!(keys.keys, order.map(|k| k.as_bytes().to_vec()));
    }
}

#[test]
fn body_lists_the_counters_in_enum_order() {
    const SEAL_SIGNAL: usize = 36;
    const KCORE: usize = 19;
    let mut tamper: [u64; TAMPER_MAX] = core::array::from_fn(|i| i as u64 + 1);
    let mut integrity: [u64; INTEGRITY_MAX] = core::array::from_fn(|i| 100 + i as u64);
    tamper[SEAL_SIGNAL] = u64::MAX;
    integrity[KCORE] = u64::MAX;
    let mut i: Input<'_> = node_a_at_1_0_0();
    i.tamper = Some(&tamper);
    i.integrity = Some(&integrity);

    assert!(has(
        &emitted(&i),
        concat!(
            r#","tamper":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,"#,
            r#"34,35,36,18446744073709551615,38,39,40,41,42,43],"integrity":[100,101,102,103,104,105,106,107,108,109,"#,
            r#"110,111,112,113,114,115,116,117,118,18446744073709551615,120,121],"tree_id":"#
        )
    ));
}

fn refused(i: &Input<'_>) -> c_int {
    body(i).unwrap_err()
}

#[test]
fn body_refuses_a_missing_string() {
    let unset: [fn(&mut Input<'static>); 4] = [
        |i: &mut Input<'static>| i.boot_id = None,
        |i: &mut Input<'static>| i.kernel_release = None,
        |i: &mut Input<'static>| i.verdict = None,
        |i: &mut Input<'static>| i.tree.as_mut().unwrap().tree_id = None,
    ];
    for f in unset {
        let mut i = node_a_at_1_0_0();
        f(&mut i);
        assert_eq!(refused(&i), -EINVAL);
    }
}

#[test]
fn body_refuses_what_is_no_hash() {
    let prefixed = [&b"sha256:"[..], VERSION_ID].concat();
    let longer = [VERSION_ID, b"0"].concat();
    let upper = VERSION_ID.to_ascii_uppercase();
    let g = [&b"g"[..], VERSION_ID].concat();
    let mut i: Input<'_> = node_a_at_1_0_0();

    for bad in [
        None,
        Some(&b""[..]),
        Some(&prefixed[..]),
        Some(&longer[..]),
        Some(&upper[..]),
    ] {
        i.version_id = bad;
        assert_eq!(refused(&i), -EINVAL, "{bad:?}");
    }
    let mut i = node_a_at_1_0_0();
    i.config_root = Some(b"1d8465c5");
    assert_eq!(refused(&i), -EINVAL);
    let mut i: Input<'_> = node_a_at_1_0_0();
    i.image_root = Some(&g);
    assert_eq!(refused(&i), -EINVAL);
    let mut i = node_a_at_1_0_0();
    i.tree.as_mut().unwrap().base_root = Some(b"0");
    assert_eq!(refused(&i), -EINVAL);
    let mut i = node_a_at_1_0_0();
    for bad in [Some(&b""[..]), None] {
        i.tree.as_mut().unwrap().projection_root = bad;
        assert_eq!(refused(&i), -EINVAL);
    }
    let mut i = node_a_at_1_0_0();
    i.set_sha256 = None;
    assert_eq!(refused(&i), -EINVAL);
}

#[test]
fn body_refuses_a_string_that_is_not_utf8() {
    let mut i = node_a_at_1_0_0();
    i.kernel_release = Some(b"7.4.2\xff");
    assert_eq!(refused(&i), -crate::errno::EILSEQ);
}

/// emit() of `i` into a buffer of `cap` bytes.
fn emit_into(i: &Input<'_>, cap: usize) -> (c_int, usize) {
    let mut buf = vec![0u8; cap];
    let mut e = JsonEmit::fixed(buf.as_mut_ptr().cast(), cap);
    let ret = emit(i, &mut e);
    (ret, e.written())
}

#[test]
fn body_refuses_a_buffer_one_byte_short() {
    let i = node_a_at_1_0_0();
    let whole = emitted(&i).len();

    assert_eq!(emit_into(&i, whole).0, -crate::errno::ENOSPC);
    assert_eq!(emit_into(&i, 1).0, -crate::errno::ENOSPC);
    assert_eq!(emit_into(&i, whole + 1), (0, whole));
}

#[test]
fn body_of_the_largest_values_fits() {
    let text = vec![b'x'; STRING_MAX];
    let mask = mask_of(&[NOT_ATTACHED; MASK_OPS]);
    let (tamper, integrity) = ([u64::MAX; TAMPER_MAX], [u64::MAX; INTEGRITY_MAX]);
    let i = Input {
        boot_id: Some(&text),
        version_id: Some(ONES),
        config_root: Some(ONES),
        kernel_release: Some(&text),
        image_id: Some(&text),
        image_version: Some(&text),
        image_root: Some(ONES),
        verdict: Some(&text),
        cond: u16::MAX,
        flags: u32::MAX,
        tamper: Some(&tamper),
        integrity: Some(&integrity),
        tree: Some(Tree {
            tree_id: Some(&text),
            generation: u64::MAX,
            base_seq: u64::MAX,
            last_seq: u64::MAX,
            base_root: Some(ONES),
            projection_root: Some(ONES),
            mask: Some(&mask),
        }),
        set_sha256: Some(ONES),
        count: u64::MAX,
        not_ok: u64::MAX,
    };
    let whole = emitted(&i).len();

    assert_eq!(whole, 3900);
    assert!(whole < BODY_MAX);
    assert_eq!(emit_into(&i, whole).0, -crate::errno::ENOSPC);
    assert_eq!(emit_into(&i, whole + 1).0, 0);
}

/// A node read by a snapshot. Each state read gives the next of seqs as
/// last_seq and the last one past the end, or with no seqs a last_seq
/// that moves on every read; each pending() call gives the next of
/// pending, false past the end.
#[derive(Default)]
struct FakeNode {
    seqs: Vec<i64>,
    pending: Vec<bool>,
    state_rc: c_int,
    collect_ret: c_int,
    reads: usize,
    pending_calls: usize,
    collects: usize,
}

const MOVING_FROM: i64 = 100;

impl SnapshotOps for FakeNode {
    fn read_state(&mut self, state: &mut TreeState) -> c_int {
        let read = self.reads;
        self.reads += 1;
        *state = TreeState::zeroed();
        state.schema = 1;
        state.generation = 1;
        state.head_seq = MASK_OPS as i64;
        state.tree_id[..10].copy_from_slice(b"fleet-base");
        state.last_seq = match self.seqs.last() {
            None => MOVING_FROM + read as i64,
            Some(last) => *self.seqs.get(read).unwrap_or(last),
        };
        self.state_rc
    }

    fn pending(&mut self) -> bool {
        let call = self.pending_calls;
        self.pending_calls += 1;
        self.pending.get(call).copied().unwrap_or(false)
    }

    fn collect(&mut self, _: &TreeState, _: c_int) -> c_int {
        self.collects += 1;
        self.collect_ret
    }
}

/// A snapshot of `node`: its flags and the state it gives.
fn snapshot_of(node: &mut FakeNode) -> (u32, Box<TreeState>) {
    let mut state = Box::new(TreeState::zeroed());
    let (mut state_rc, mut flags) = (1, 0);
    assert_eq!(snapshot(node, &mut state, &mut state_rc, &mut flags), 0);
    assert_eq!(state_rc, node.state_rc);
    (flags, state)
}

fn node(seqs: &[i64], pending: &[bool]) -> FakeNode {
    FakeNode {
        seqs: seqs.to_vec(),
        pending: pending.to_vec(),
        ..FakeNode::default()
    }
}

#[test]
fn snapshot_of_a_still_tree_reads_it_twice() {
    let mut n = node(&[7], &[]);
    let (flags, state) = snapshot_of(&mut n);

    assert_eq!((flags, n.reads, n.collects, state.last_seq), (0, 2, 1, 7));
}

#[test]
fn snapshot_tries_again_after_a_state_that_moved() {
    let mut n = node(&[7, 8], &[]);
    let (flags, state) = snapshot_of(&mut n);

    assert_eq!((flags, n.reads, n.collects, state.last_seq), (0, 4, 2, 8));
}

#[test]
fn snapshot_gives_up_on_a_state_that_keeps_moving() {
    let mut n = node(&[], &[]);
    let (flags, state) = snapshot_of(&mut n);

    assert_eq!(flags, SNAPSHOT_UNSETTLED);
    assert_eq!((n.reads, n.collects), (2 * SNAPSHOT_TRIES, SNAPSHOT_TRIES));
    // The first read of the last try is what the body sends.
    assert_eq!(
        state.last_seq,
        MOVING_FROM + 2 * (SNAPSHOT_TRIES as i64 - 1)
    );
}

#[test]
fn snapshot_sees_a_pending_operation_before_it_reads() {
    assert_eq!(
        snapshot_of(&mut node(&[7], &[true, false])).0,
        TREE_OP_PENDING
    );
}

#[test]
fn snapshot_sees_a_pending_operation_after_it_reads() {
    assert_eq!(
        snapshot_of(&mut node(&[7], &[false, true])).0,
        TREE_OP_PENDING
    );
}

#[test]
fn snapshot_tells_the_pending_operation_of_its_last_try() {
    let mut n = node(&[7, 8], &[true, true]);

    assert_eq!(snapshot_of(&mut n).0, 0);
    assert_eq!(n.pending_calls, 4);
}

#[test]
fn snapshot_of_no_tree_settles() {
    let mut n = FakeNode {
        state_rc: -crate::errno::ENOENT,
        ..FakeNode::default()
    };

    assert_eq!(snapshot_of(&mut n).0, 0);
    assert_eq!(n.collects, 1);
}

#[test]
fn snapshot_stops_at_a_failed_collect() {
    let mut n = FakeNode {
        seqs: vec![7],
        collect_ret: -crate::errno::ENOMEM,
        ..FakeNode::default()
    };
    let mut state = Box::new(TreeState::zeroed());
    let (mut state_rc, mut flags) = (0, 0);

    assert_eq!(
        snapshot(&mut n, &mut state, &mut state_rc, &mut flags),
        -crate::errno::ENOMEM
    );
    assert_eq!((n.reads, flags), (1, 0));
}
