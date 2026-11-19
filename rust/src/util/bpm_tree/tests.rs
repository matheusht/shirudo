// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::errno::{E2BIG, EINVAL, EIO, EKEYREJECTED, ERANGE};
use crate::util::chain::history_step;

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SEALED: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ROOT: &str = "0123456789abcdef0123456789abcdef0123456789ABCDEF0123456789abcdef";

/// `value` into the text `t`, terminated.
fn set(t: &mut [u8], value: &str) {
    t.fill(0);
    t[..value.len()].copy_from_slice(value.as_bytes());
}

/// An operation of upatch "t" at seq 1, of label site "a b".
struct Op(TreeOperation);

impl Op {
    fn new() -> Self {
        let mut op = TreeOperation {
            seq: 1,
            ..TreeOperation::default()
        };

        set(&mut op.op, "add");
        set(&mut op.id, "t");
        set(&mut op.artifact.repository, "oci://registry.example/t");
        set(&mut op.artifact.manifest_digest, DIGEST);
        set(&mut op.artifact.layer_digest, DIGEST);
        set(&mut op.artifact.payload_sha256, DIGEST);
        op.selector
            .pair_add(SelectorMap::Labels, b"site", vec![b"a b".to_vec()])
            .unwrap();
        Op(op)
    }

    fn digest(&self) -> Result<[u8; 72], c_int> {
        operation_digest(&self.0)
    }

    /// The operation's digest, recorded in it.
    fn seal(&mut self) {
        let d = self.digest().unwrap();
        self.0.operation_digest[..72].copy_from_slice(&d);
    }

    fn label(&mut self) -> &mut TreeSelectorKv {
        &mut self.0.selector.labels[0]
    }
}

/// A publication of tree "t".
struct Pub(TreePublication);

impl Pub {
    fn new(generation: i64) -> Self {
        let mut p = TreePublication {
            schema: 1,
            generation,
            ..TreePublication::default()
        };
        set(&mut p.tree_id, "t");
        Pub(p)
    }

    fn append(&mut self, op: &Op) {
        assert_eq!(self.0.append(op.0.clone()), Ok(()));
    }

    fn operations(&self) -> &[TreeOperation] {
        &self.0.operations
    }

    /// The document emit_publication() writes, with `extra`.
    fn emit(&self, extra: Option<Extra<'_>>) -> Result<Vec<u8>, c_int> {
        emit_publication(&self.0, extra)
    }

    fn parse(doc: &[u8]) -> Result<Self, c_int> {
        TreePublication::parse(doc).map(Pub)
    }

    fn check(&self) -> Result<(), c_int> {
        publication_check(&self.0)
    }
}

fn has(doc: &[u8], part: &str) -> bool {
    crate::text::find(doc, part.as_bytes()).is_some()
}

fn validate(op: &TreeOperation) -> Result<(), c_int> {
    operation_validate(op)
}

/// The node's parser refuses a control character, so a publication
/// holding one would go out, signed, and fail every node's sync.
#[test]
fn operation_takes_no_control_character() {
    let mut op = Op::new();

    assert!(op.digest().is_ok());
    op.label().values[0][1] = b'\t';
    assert_eq!(op.digest(), Err(-EINVAL));
    op.label().values[0][1] = b' ';
    op.label().key[0] = b'\n';
    assert_eq!(op.digest(), Err(-EINVAL));
    op.label().key[0] = b's';
    op.0.artifact.repository[0] = b'\r';
    assert_eq!(op.digest(), Err(-EINVAL));
}

/// A publication of the one operation, sealed, at head 1.
fn publication_of(op: &mut Op) -> Pub {
    let mut p = Pub::new(1);
    op.seal();
    p.append(op);
    p.0.head_seq = 1;
    p
}

/// What the publisher writes, the node reads back to the same digest.
#[test]
fn publication_reads_back() {
    let mut op = Op::new();
    let p = publication_of(&mut op);
    let back = Pub::parse(&p.emit(None).unwrap()).unwrap();

    assert_eq!(back.0.schema, 1);
    assert_eq!(back.operations().len(), 1);
    let digest = operation_digest(&back.operations()[0]).unwrap();
    assert_eq!(cstr(&digest), cstr(&op.0.operation_digest));
    let label = &back.operations()[0].selector.labels[0];
    assert_eq!(label.values[0], b"a b");
}

/// Keys past the emitter's bound, as a publisher's fixes can be.
#[test]
fn publication_carries_keys_outside_the_digest() {
    let mut op = Op::new();
    let p = publication_of(&mut op);
    let mut fixes = |e: &mut JsonEmit, index: usize| {
        let id = vec![b'A' + index as u8; 200];
        e.arr_open(b"fixes");
        for _ in 0..64 {
            e.str(&id);
        }
        e.arr_close();
        0
    };
    let doc = p.emit(Some(&mut fixes)).unwrap();

    assert!(doc.len() > 64 * 200);
    let (fixes_at, digest_at) = (
        crate::text::find(&doc, b"},\"fixes\":[\"AAAA"),
        crate::text::find(&doc, b"\"],\"operation_digest\":"),
    );
    assert!(matches!((fixes_at, digest_at), (Some(f), Some(d)) if f < d));
    let back = Pub::parse(&doc).unwrap();
    assert_eq!(back.operations().len(), 1);
    let digest = operation_digest(&back.operations()[0]).unwrap();
    assert_eq!(cstr(&digest), cstr(&op.0.operation_digest));
    assert_eq!(
        cstr(&back.operations()[0].operation_digest),
        cstr(&op.0.operation_digest)
    );
    let mut failing = |_: &mut JsonEmit, _: usize| -EIO;
    assert_eq!(p.emit(Some(&mut failing)), Err(-EIO));
}

#[test]
fn publication_reads_past_malformed_fixes() {
    let mut op = Op::new();
    let p = publication_of(&mut op);
    let mut malformed = |e: &mut JsonEmit, _: usize| {
        e.obj_open_key(b"fixes");
        e.arr_open(b"n");
        e.raw_value(b"null");
        e.str(b"\x07");
        e.arr_close();
        e.obj_close();
        e.arr_open(b"fixes");
        e.str(b"");
        e.arr_close();
        0
    };
    let doc = p.emit(Some(&mut malformed)).unwrap();

    assert!(has(&doc, r#""fixes":{"n":[null,"\u0007"]}"#));
    let back = Pub::parse(&doc).unwrap();
    assert_eq!(back.check(), Ok(()));
    assert_eq!(back.operations().len(), 1);
    assert_eq!(validate(&back.operations()[0]), Ok(()));
}

/// A later segment names its sealed predecessor and the history before it.
#[test]
fn segment_reads_back() {
    let mut op = Op::new();
    let mut p = Pub::new(4);
    p.0.base_seq = 2;
    p.0.head_seq = 3;
    set(&mut p.0.parent_manifest_digest, SEALED);
    set(&mut p.0.segment_manifest_digest, SEALED);
    set(&mut p.0.history_root, ROOT);
    op.0.seq = 3;
    op.seal();
    p.append(&op);
    let doc = p.emit(None).unwrap();

    assert!(has(
        &doc,
        &format!(
            r#""base":{{"seq":2,"segment_manifest_digest":"{SEALED}","history_root":"{ROOT}"}},"#
        )
    ));
    let back = Pub::parse(&doc).unwrap();
    assert_eq!(back.0.base_seq, 2);
    assert_eq!(cstr(&back.0.segment_manifest_digest), SEALED.as_bytes());
    assert_eq!(cstr(&back.0.history_root), ROOT.as_bytes());
    assert_eq!(back.check(), Ok(()));
    assert_eq!(back.operations().len(), 1);
    assert_eq!(validate(&back.operations()[0]), Ok(()));
    p.0.history_root[0] = 0;
    assert!(!has(&p.emit(None).unwrap(), "history_root"));
}

/// A root too long for its key, or a digest that is no string, does not
/// parse.
#[test]
fn segment_refuses_malformed_keys() {
    for doc in [
        format!(r#"{{"schema":1,"tree_id":"t","generation":1,"base":{{"seq":0,"history_root":"{ROOT}0"}},"operations":[],"head":{{"seq":0}}}}"#),
        r#"{"schema":1,"tree_id":"t","generation":1,"base":{"seq":0,"segment_manifest_digest":3},"operations":[],"head":{"seq":0}}"#.to_string(),
    ] {
        assert!(Pub::parse(doc.as_bytes()).is_err(), "{doc}");
    }
}

/// What sync checks of an operation before it applies one.
#[test]
fn operation_validates_against_its_digest() {
    let mut op = Op::new();

    op.seal();
    assert_eq!(validate(&op.0), Ok(()));
    op.0.seq = 2;
    assert_eq!(validate(&op.0), Err(-EKEYREJECTED));
    op.0.seq = 0;
    assert_eq!(validate(&op.0), Err(-EINVAL));
    op.0.seq = 1;
    set(&mut op.0.op, "replace");
    assert_eq!(validate(&op.0), Err(-EINVAL));
    set(&mut op.0.op, "add");
    set(&mut op.0.id, "../t");
    assert_eq!(validate(&op.0), Err(-EINVAL));
    set(&mut op.0.id, "t");
    set(&mut op.0.artifact.layer_digest, "sha256:aa");
    assert_eq!(validate(&op.0), Err(-EINVAL));
}

/// A publication from `base_seq` to `head_seq` of operations of `seqs`,
/// of no pairs.
fn over(seqs: &[i64], base_seq: i64, head_seq: i64) -> TreePublication {
    let operations = seqs
        .iter()
        .map(|&seq| TreeOperation {
            seq,
            ..TreeOperation::default()
        })
        .collect();

    TreePublication {
        operations,
        base_seq,
        head_seq,
        ..TreePublication::default()
    }
}

fn check(p: &TreePublication) -> Result<(), c_int> {
    publication_check(p)
}

#[test]
fn publication_runs_from_base_to_head() {
    let mut p = over(&[1, 2], 0, 2);

    assert_eq!(check(&p), Ok(()));
    p.head_seq = 3;
    assert_eq!(check(&p), Err(-EINVAL));
    p.head_seq = 2;
    p.operations[0].seq = 2;
    assert_eq!(check(&p), Err(-EINVAL));
    p.operations[0].seq = 1;
    set(&mut p.parent_manifest_digest, "sha256:aa");
    assert_eq!(check(&p), Err(-EINVAL));
    set(&mut p.parent_manifest_digest, DIGEST);
    assert_eq!(check(&p), Ok(()));
    p.operations.clear();
    assert_eq!(check(&p), Err(-EINVAL));
    p.head_seq = 0;
    assert_eq!(check(&p), Ok(()));
    p.base_seq = -1;
    p.head_seq = -1;
    assert_eq!(check(&p), Err(-EINVAL));
}

/// What sync checks of a publication: a tree ID its state can record,
/// the numbers and each operation's digests, naming the operation that
/// fails.
#[test]
fn publication_verifies_as_sync_does() {
    let mut op = Op::new();
    let mut p = Pub::new(1);
    let verify = |p: &Pub| publication_verify(&p.0);

    p.0.head_seq = 2;
    for seq in 1..=2 {
        op.0.seq = seq;
        op.seal();
        p.append(&op);
    }
    assert_eq!(verify(&p), Ok(()));
    set(&mut p.0.tree_id, "../t");
    assert_eq!(verify(&p), Err((-EINVAL, None)));
    set(&mut p.0.tree_id, "t");
    p.0.head_seq = 3;
    assert_eq!(verify(&p), Err((-EINVAL, None)));
    p.0.head_seq = 2;
    p.0.operations[1].operation_digest[7] ^= 1;
    p.0.operations[0].id[0] = b'.';
    assert_eq!(verify(&p), Err((-EINVAL, Some(0))));
    p.0.operations[0].id[0] = b't';
    assert_eq!(verify(&p), Err((-EKEYREJECTED, Some(1))));
}

/// A segment past the first names its sealed predecessor and the
/// history root at its base and holds an operation; the first names
/// neither.
#[test]
fn segment_names_its_base() {
    let mut p = over(&[3, 4], 2, 4);

    assert_eq!(check(&p), Err(-EINVAL));
    set(&mut p.segment_manifest_digest, SEALED);
    assert_eq!(check(&p), Err(-EINVAL));
    set(&mut p.history_root, ROOT);
    assert_eq!(check(&p), Ok(()));
    for bad in [
        "",
        "sha256:bb",
        "sha512:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ] {
        set(&mut p.segment_manifest_digest, bad);
        assert_eq!(check(&p), Err(-EINVAL), "{bad}");
    }
    set(&mut p.segment_manifest_digest, SEALED);
    for bad in [
        &ROOT[..63],
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
    ] {
        set(&mut p.history_root, bad);
        assert_eq!(check(&p), Err(-EINVAL), "{bad}");
    }
    set(&mut p.history_root, ROOT);
    assert_eq!(check(&p), Ok(()));
    p.operations.clear();
    p.head_seq = 2;
    assert_eq!(check(&p), Err(-EINVAL));

    let mut p = over(&[1, 2], 0, 2);
    set(&mut p.segment_manifest_digest, SEALED);
    assert_eq!(check(&p), Err(-EINVAL));
    p.segment_manifest_digest[0] = 0;
    set(&mut p.history_root, ROOT);
    assert_eq!(check(&p), Err(-EINVAL));
    set(&mut p.history_root, &"0".repeat(64));
    assert_eq!(check(&p), Err(-EINVAL));
    p.history_root[0] = 0;
    assert_eq!(check(&p), Ok(()));
}

fn state(generation: i64, last_seq: i64, head_seq: i64) -> TreeState {
    let mut s = TreeState::zeroed();
    s.generation = generation;
    s.last_seq = last_seq;
    s.head_seq = head_seq;
    set(&mut s.tree_id, "t");
    set(&mut s.manifest_digest, "m5");
    s
}

fn publication(generation: i64, base_seq: i64, head_seq: i64) -> TreePublication {
    let mut p = TreePublication {
        generation,
        base_seq,
        head_seq,
        ..TreePublication::default()
    };
    set(&mut p.tree_id, "t");
    p
}

/// A node never goes back to an older tree, or skips past its cursor.
#[test]
fn publication_follows_the_recorded_state() {
    let mut s = state(5, 3, 0);
    let mut p = publication(6, 0, 4);

    assert_eq!(publication_follows(&p, Some(&s), b"m6"), 0);
    assert_eq!(publication_follows(&p, None, b"m6"), 0);
    set(&mut p.parent_manifest_digest, "m5");
    assert_eq!(publication_follows(&p, Some(&s), b"m6"), 0);
    set(&mut p.parent_manifest_digest, "m4");
    assert_eq!(publication_follows(&p, Some(&s), b"m6"), -ERANGE);
    p.generation = 7;
    assert_eq!(publication_follows(&p, Some(&s), b"m7"), 0);
    p.generation = 5;
    assert_eq!(publication_follows(&p, Some(&s), b"m5"), 0);
    assert_eq!(publication_follows(&p, Some(&s), b"other"), -ERANGE);
    p.generation = 7;
    p.head_seq = 2;
    assert_eq!(publication_follows(&p, Some(&s), b"m7"), -ERANGE);
    p.head_seq = 4;
    set(&mut p.tree_id, "u");
    assert_eq!(publication_follows(&p, Some(&s), b"m7"), -EINVAL);
    s.generation = i64::MAX;
    set(&mut p.tree_id, "t");
    assert_eq!(publication_follows(&p, Some(&s), b"m7"), -ERANGE);
}

/// A node behind a segment's base walks back to it, once the publication
/// would otherwise follow; a node at or past the base does not.
#[test]
fn segment_asks_for_a_walk() {
    let mut s = state(5, 3, 4);
    let mut p = publication(8, 4, 6);

    assert_eq!(publication_follows(&p, None, b"m8"), FOLLOWS_WALK);
    assert_eq!(publication_follows(&p, Some(&s), b"m8"), FOLLOWS_WALK);
    for (last, want) in [(4, 0), (5, 0), (6, 0), (7, -ERANGE)] {
        s.last_seq = last;
        assert_eq!(publication_follows(&p, Some(&s), b"m8"), want, "{last}");
    }
    s.last_seq = 3;
    p.generation = 6;
    set(&mut p.parent_manifest_digest, "m5");
    assert_eq!(publication_follows(&p, Some(&s), b"m6"), FOLLOWS_WALK);
    set(&mut p.parent_manifest_digest, "m4");
    assert_eq!(publication_follows(&p, Some(&s), b"m6"), -ERANGE);
    p.generation = 5;
    assert_eq!(publication_follows(&p, Some(&s), b"m6"), -ERANGE);
    p.generation = 8;
    set(&mut p.tree_id, "u");
    assert_eq!(publication_follows(&p, Some(&s), b"m8"), -EINVAL);
}

/// One step back: the sealed segment the successor names, right before
/// it.
#[test]
fn segment_precedes_its_successor() {
    let mut pred = publication(3, 0, 2);
    let mut succ = publication(4, 2, 4);
    let precedes = |pred: &TreePublication, digest: &str, succ: &TreePublication| {
        segment_precedes(pred, digest.as_bytes(), succ)
    };

    set(&mut succ.segment_manifest_digest, SEALED);
    assert_eq!(precedes(&pred, SEALED, &succ), 0);
    assert_eq!(precedes(&pred, DIGEST, &succ), -ERANGE);
    set(&mut pred.tree_id, "u");
    assert_eq!(precedes(&pred, SEALED, &succ), -ERANGE);
    set(&mut pred.tree_id, "t");
    for head in [1, 3] {
        pred.head_seq = head;
        assert_eq!(precedes(&pred, SEALED, &succ), -ERANGE, "{head}");
    }
    pred.head_seq = 2;
    for generation in [4, 5] {
        pred.generation = generation;
        assert_eq!(precedes(&pred, SEALED, &succ), -ERANGE, "{generation}");
    }
    pred.generation = 1;
    assert_eq!(precedes(&pred, SEALED, &succ), 0);
    succ.base_seq = 0;
    pred.head_seq = 0;
    assert_eq!(precedes(&pred, SEALED, &succ), -ERANGE);
    succ.segment_manifest_digest[0] = 0;
    assert_eq!(precedes(&pred, "", &succ), -ERANGE);
}

/// A joining node may walk further back than one that holds upatches of
/// the tree, and neither past its limit.
#[test]
fn walk_stays_within_its_limit() {
    assert_eq!(walk_within(0, 0), 0);
    assert_eq!(walk_within(MAX_JOIN_OPS, 0), 0);
    assert_eq!(walk_within(MAX_JOIN_OPS + 1, 0), -E2BIG);
    assert_eq!(walk_within(1 + MAX_WALK_OPS, 1), 0);
    assert_eq!(walk_within(2 + MAX_WALK_OPS, 1), -E2BIG);
    assert_eq!(walk_within(i64::MAX, 1), -E2BIG);
    assert_eq!(walk_within(3, 7), 0);
    assert_eq!(walk_within(-1, 0), -EINVAL);
    assert_eq!(walk_within(i64::MAX, -1), -EINVAL);
}

fn digest_of(text: &str) -> [u8; 32] {
    digest_bytes(text.as_bytes()).unwrap()
}

/// The history root at any seq of a segment, folded from its base.
#[test]
fn history_folds_from_the_base() {
    let mut p = over(&[5, 6], 4, 6);
    set(&mut p.operations[0].operation_digest, DIGEST);
    set(&mut p.operations[1].operation_digest, SEALED);
    set(&mut p.history_root, ROOT);
    let at = history_at;
    let mut base = [0u8; 32];
    crate::util::hex::decode(ROOT.as_bytes(), &mut base).unwrap();
    let one = history_step(&base, &digest_of(DIGEST)).unwrap();
    let two = history_step(&one, &digest_of(SEALED)).unwrap();

    assert_eq!(at(&p, 4), Ok(base));
    assert_eq!(at(&p, 5), Ok(one));
    assert_eq!(at(&p, 6), Ok(two));
    assert_eq!(at(&p, 3), Err(-EINVAL));
    assert_eq!(at(&p, 7), Err(-EINVAL));
    // The first segment starts from 32 zero bytes, whatever it holds.
    p.operations[0].seq = 1;
    p.operations[1].seq = 2;
    p.base_seq = 0;
    p.head_seq = 2;
    assert_eq!(at(&p, 0), Ok([0; 32]));
    assert_eq!(
        at(&p, 1),
        Ok(history_step(&[0; 32], &digest_of(DIGEST)).unwrap())
    );
    p.base_seq = 4;
    set(&mut p.history_root, "00");
    assert_eq!(at(&p, 4), Err(-EINVAL));
    set(&mut p.history_root, ROOT);
    p.operations[0].seq = 5;
    p.operations[1].seq = 6;
    p.head_seq = 6;
    p.operations[1].operation_digest[7] = b'x';
    assert_eq!(at(&p, 5), Ok(one));
    assert_eq!(at(&p, 6), Err(-EINVAL));
}
