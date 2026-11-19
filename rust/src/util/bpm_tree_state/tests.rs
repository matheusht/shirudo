// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::testutil::TempDir;
use crate::util::bpm_tree::SelectorMap;
use crate::util::gzip::crc32;

/// `text` as one gzip member of stored blocks, as gzip -0 writes it.
fn gzipped(text: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    let mut chunks = text.chunks(0xffff).peekable();

    if text.is_empty() {
        out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    }
    while let Some(chunk) = chunks.next() {
        let len = chunk.len() as u16;
        out.push(u8::from(chunks.peek().is_none()));
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&crc32(0, text).to_le_bytes());
    out.extend_from_slice(&(text.len() as u32).to_le_bytes());
    out
}

/// A selector of the one kconfig pair CONFIG_MODULES.
struct Modules(TreeSelector);

impl Modules {
    fn new() -> Self {
        let mut s = TreeSelector::default();

        assert_eq!(
            s.pair_add(SelectorMap::Kconfig, b"CONFIG_MODULES", Vec::new()),
            Ok(())
        );
        Modules(s)
    }

    /// kconfig_read() of the config at `path`: the value of
    /// CONFIG_MODULES, None where it is not set, or the error.
    fn read(&self, path: &CStr, gz: bool) -> Result<Option<Vec<u8>>, c_int> {
        let mut values = kconfig_read(path, &self.0, gz)?;

        Ok(values.swap_remove(0))
    }
}

/// CONFIG_MODULES of the config `text`, written gzip'd or not.
fn modules_in(text: &[u8], gz: bool) -> Result<Option<Vec<u8>>, c_int> {
    let dir = TempDir::new();
    std::fs::write(
        dir.join("config"),
        if gz { gzipped(text) } else { text.to_vec() },
    )
    .unwrap();
    Modules::new().read(&dir.cpath("config"), gz)
}

/// A line longer than the read buffer came in parts, and the part from
/// the middle of a long string read as an option of its own.
#[test]
fn long_line_is_one_line() {
    let text = [
        &b"# CONFIG_MODULES is not set\nCONFIG_CMDLINE=\""[..],
        &[b' '; 2014],
        b"CONFIG_MODULES=y\"\nCONFIG_X=y\n",
    ]
    .concat();

    assert_eq!(modules_in(&text, false), Ok(Some(b"n".to_vec())));
    assert_eq!(modules_in(&text, true), Ok(Some(b"n".to_vec())));
    assert_eq!(
        modules_in(b"CONFIG_MODULES=y\n", false),
        Ok(Some(b"y".to_vec()))
    );
    assert_eq!(
        modules_in(b"CONFIG_MODULES=m", true),
        Ok(Some(b"m".to_vec()))
    );
}

/// A config written gzip'd or not, cut by `cut` bytes and `extra`
/// appended, read as gzip'd: Ok where it reads CONFIG_MODULES=y.
fn read_gz(gz: bool, cut: usize, extra: &[u8]) -> Result<(), c_int> {
    let text = b"CONFIG_MODULES=y\n";
    let mut bytes = if gz { gzipped(text) } else { text.to_vec() };
    bytes.truncate(bytes.len() - cut);
    bytes.extend_from_slice(extra);
    let dir = TempDir::new();
    std::fs::write(dir.join("config"), bytes).unwrap();
    match Modules::new().read(&dir.cpath("config"), true)? {
        Some(v) if v == b"y" => Ok(()),
        _ => Err(1),
    }
}

#[test]
fn gzip_config_is_one_whole_member() {
    assert_eq!(read_gz(true, 0, b""), Ok(()));
    assert_eq!(read_gz(true, 1, b""), Err(-EINVAL));
    assert_eq!(read_gz(true, 8, b""), Err(-EINVAL));
    assert_eq!(read_gz(true, 0, b"x"), Err(-EINVAL));
    assert_eq!(read_gz(false, 0, b""), Err(-EINVAL));
}

const PENDING_DIGEST: &str =
    "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn pending(doc: &str) -> Result<TreePending, c_int> {
    pending_parse(doc.as_bytes())
}

#[test]
fn pending_is_an_operation_in_flight() {
    let p = pending(&format!(
        r#"{{"schema":1,"seq":3,"id":"fix","operation_digest":"{PENDING_DIGEST}"}}"#
    ))
    .unwrap();

    assert_eq!((p.seq, cstr(&p.id)), (3, &b"fix"[..]));
    for bad in [
        format!(r#"{{"schema":2,"seq":3,"id":"fix","operation_digest":"{PENDING_DIGEST}"}}"#),
        format!(r#"{{"schema":1,"seq":0,"id":"fix","operation_digest":"{PENDING_DIGEST}"}}"#),
        format!(r#"{{"schema":1,"seq":3,"id":"../fix","operation_digest":"{PENDING_DIGEST}"}}"#),
        r#"{"schema":1,"seq":3,"id":"fix","operation_digest":"sha256:00"}"#.to_string(),
    ] {
        assert_eq!(pending(&bad).err(), Some(-EINVAL), "{bad}");
    }
}

/// read_config_file() of `path` into four pairs: their keys and values,
/// or the error.
/// A key and its value.
type Pair = (Vec<u8>, Vec<u8>);

fn labels_of(path: &CStr) -> Result<Vec<Pair>, (c_int, c_int)> {
    // SAFETY: pairs of texts, for which zeros are a value.
    let mut labels: [TreeKv; 4] = unsafe { core::mem::zeroed() };
    let mut n = -1;
    // SAFETY: a C string and room for four pairs and their count.
    match unsafe { read_config_file(path.as_ptr(), labels.as_mut_ptr(), &mut n, 4) } {
        0 => Ok(labels[..n as usize]
            .iter()
            .map(|kv| (cstr(&kv.key).to_vec(), cstr(&kv.value).to_vec()))
            .collect()),
        err => Err((err, n)),
    }
}

/// As the format has it: blanks go but for those between a key and its =.
#[test]
fn labels_are_cut_at_the_first_equals() {
    let dir = TempDir::new();
    std::fs::write(
        dir.join("labels"),
        "# site=x\n  site = a \t\nzone=b=c\njunk\nempty=\t\n",
    )
    .unwrap();
    let pair = |k: &str, v: &str| (k.as_bytes().to_vec(), v.as_bytes().to_vec());

    assert_eq!(
        labels_of(&dir.cpath("labels")),
        Ok(vec![
            pair("site ", "a"),
            pair("zone", "b=c"),
            pair("empty", "")
        ])
    );
    assert_eq!(labels_of(c"/nonexistent/node.labels"), Err((-ENOENT, 0)));
}

/// The tree's directory of this test's thread, in `dir`.
fn use_tree(dir: &TempDir) {
    TEST_DIR.set(Some(dir.cpath("upatch-tree")));
}

fn tree_file(name: &[u8]) -> std::path::PathBuf {
    std::path::PathBuf::from(tree_path(name).into_string().unwrap())
}

/// `text` written to the tree's file `name`, appended or in place of
/// what it held.
fn write_text(name: &[u8], text: &[u8], append: bool) {
    use std::io::Write;
    let path = tree_file(name);
    let parent = path.parent().unwrap();
    if !parent.exists() {
        std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700)
            .create(parent)
            .unwrap();
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append)
        .open(path)
        .unwrap();
    f.write_all(text).unwrap();
}

fn outcomes_size() -> u64 {
    std::fs::metadata(tree_file(OUTCOMES)).unwrap().len()
}

/// The roots a test gives the line of seq: every byte seq, or seq + 100.
fn roots_of(seq: i64) -> ([u8; 32], [u8; 32]) {
    if seq == 0 {
        return ([0; 32], [0; 32]);
    }
    ([seq as u8; 32], [seq as u8 + 100; 32])
}

fn append_outcome(seq: i64, outcome: i64) {
    let (projection, history) = roots_of(seq);
    assert_eq!(outcome_append(seq, outcome, &projection, &history), 0);
}

/// outcomes_read() from `from` to `to`: the codes and the roots of
/// `from`, or the error.
fn outcomes(from: i64, to: i64) -> Result<(Vec<u8>, Roots), c_int> {
    outcomes_read(from, to)
}

fn outcome_line(seq: i64, outcome: i64) -> String {
    format!(
        r#"{{"schema":1,"seq":{seq},"outcome":{outcome},"projection_root":"{}","history_root":"{}"}}"#,
        "01".repeat(32),
        "65".repeat(32)
    ) + "\n"
}

#[test]
fn outcomes_append_and_read_back() {
    let dir = TempDir::new();
    use_tree(&dir);

    append_outcome(1, OUTCOME_APPLIED);
    assert_eq!(
        std::fs::read(tree_file(OUTCOMES)).unwrap(),
        outcome_line(1, 1).as_bytes()
    );
    append_outcome(2, OUTCOME_UNMATCHED);
    append_outcome(3, OUTCOME_MODULE_ABSENT);
    assert_eq!(outcomes(0, 3), Ok((vec![1, 2, 3], roots_of(0))));
    assert_eq!(outcomes(1, 3), Ok((vec![2, 3], roots_of(1))));
    assert_eq!(outcomes(3, 3), Ok((vec![], roots_of(3))));
    assert_eq!(outcomes(0, 0), Ok((vec![], roots_of(0))));
    assert_eq!(outcomes(2, 1).err(), Some(-EINVAL));
    assert_eq!(outcomes(-1, 1).err(), Some(-EINVAL));
    let (projection, history) = roots_of(4);
    assert_eq!(
        outcome_append(0, OUTCOME_APPLIED, &projection, &history),
        -EINVAL
    );
    assert_eq!(outcome_append(4, 0, &projection, &history), -EINVAL);
    assert_eq!(outcome_append(4, 4, &projection, &history), -EINVAL);
}

const TORN: &[u8] = br#"{"schema":1,"seq":3,"outc"#;

#[test]
fn outcomes_torn_last_line_is_dropped() {
    let dir = TempDir::new();
    use_tree(&dir);

    append_outcome(1, OUTCOME_APPLIED);
    append_outcome(2, OUTCOME_UNMATCHED);
    let whole = outcomes_size();
    write_text(OUTCOMES, TORN, true);
    assert!(outcomes(0, 2).is_ok());
    assert_eq!(outcomes(0, 3).err(), Some(-EBADMSG));
    assert_eq!(outcomes_resume(3), Err(-EBADMSG));
    assert!(outcomes_resume(2).is_ok());
    assert_eq!(outcomes_size(), whole);
    write_text(OUTCOMES, TORN, true);
    append_outcome(3, OUTCOME_APPLIED);
    assert_eq!(outcomes(0, 3).unwrap().0[2], 1);
}

#[test]
fn outcomes_resume_cuts_past_last_seq() {
    let dir = TempDir::new();
    use_tree(&dir);

    assert_eq!(outcomes_resume(0), Ok([0; 32]));
    assert!(!tree_file(OUTCOMES).exists());
    assert_eq!(outcomes_resume(2), Err(-ENOENT));
    assert_eq!(outcomes_resume(-1), Err(-EINVAL));
    append_outcome(1, OUTCOME_APPLIED);
    append_outcome(2, OUTCOME_UNMATCHED);
    let two = outcomes_size();
    append_outcome(3, OUTCOME_MODULE_ABSENT);
    append_outcome(4, OUTCOME_APPLIED);
    assert_eq!(outcomes_resume(2), Ok([2 + 100; 32]));
    assert_eq!(outcomes_size(), two);
    assert_eq!(outcomes(0, 2).unwrap().0, [1, 2]);
    assert_eq!(outcomes(0, 3).err(), Some(-EBADMSG));
    assert_eq!(outcomes_resume(5), Err(-EBADMSG));
    assert_eq!(outcomes_size(), two);
    // What follows last_seq goes unread: it need not be a line.
    write_text(
        OUTCOMES,
        ("not a line\n".to_string() + &outcome_line(9, 1)).as_bytes(),
        true,
    );
    assert!(outcomes_resume(2).is_ok());
    assert_eq!(outcomes_size(), two);
    assert_eq!(outcomes_resume(0), Ok([0; 32]));
    assert_eq!(outcomes_size(), 0);
}

fn read_outcomes(text: &str, to: i64) -> Result<(), c_int> {
    write_text(OUTCOMES, text.as_bytes(), false);
    outcomes(0, to).map(|_| ())
}

#[test]
fn outcomes_gap_and_missing_line() {
    let dir = TempDir::new();
    use_tree(&dir);
    let (l1, l3) = (outcome_line(1, 1), outcome_line(3, 1));

    assert_eq!(outcomes(0, 1).err(), Some(-ENOENT));
    assert_eq!(read_outcomes(&l1, 1), Ok(()));
    assert_eq!(read_outcomes(&l1, 2), Err(-EBADMSG));
    assert_eq!(read_outcomes("", 1), Err(-EBADMSG));
    assert_eq!(read_outcomes(&(l1.clone() + &l3), 3), Err(-EBADMSG));
    assert_eq!(read_outcomes(&(l1.clone() + &l3), 1), Ok(()));
    assert_eq!(read_outcomes(&outcome_line(2, 1), 2), Err(-EBADMSG));
    assert_eq!(read_outcomes(&(l1.clone() + &l1), 2), Err(-EBADMSG));
    assert_eq!(outcomes_resume(2), Err(-EBADMSG));
    for bad in [
        outcome_line(1, 0),
        outcome_line(1, 4),
        outcome_line(0, 1),
        "\n".to_string() + &l1,
        "not a line\n".to_string(),
        "{\"schema\":2,\"seq\":1,\"outcome\":1,\"projection_root\":\"\",\"history_root\":\"\"}\n".to_string(),
        "{\"schema\":1,\"seq\":1,\"outcome\":1,\"projection_root\":\"01\",\"history_root\":\"65\"}\n".to_string(),
        "{\"schema\":1,\"seq\":1,\"outcome\":1}\n".to_string(),
    ] {
        assert_eq!(read_outcomes(&bad, 1), Err(-EBADMSG), "{bad:?}");
    }
}

#[test]
fn outcomes_longer_line_is_malformed() {
    let dir = TempDir::new();
    use_tree(&dir);
    let mut text = " ".repeat(2 * OUTCOME_LINE_MAX - 2) + "\n";

    assert_eq!(read_outcomes(&text, 1), Err(-EBADMSG));
    text.pop();
    text.push(' ');
    assert_eq!(read_outcomes(&text, 1), Err(-EBADMSG));
}

#[test]
fn outcomes_cover_the_state() {
    let dir = TempDir::new();
    use_tree(&dir);

    assert_eq!(outcomes_resume(1), Err(-ENOENT));
    write_text(
        OUTCOMES,
        (outcome_line(1, 1) + &outcome_line(2, 2)).as_bytes(),
        false,
    );
    assert_eq!(outcomes_resume(3), Err(-EBADMSG));
    assert_ne!(outcomes_resume(2), Ok([0; 32]));
    assert!(outcomes_resume(2).is_ok());
    write_text(
        OUTCOMES,
        (outcome_line(1, 1) + &outcome_line(3, 2)).as_bytes(),
        false,
    );
    assert_eq!(outcomes_resume(3), Err(-EBADMSG));
    assert!(outcomes_resume(1).is_ok());
    write_text(OUTCOMES, b"", false);
    assert_eq!(outcomes_resume(1), Err(-EBADMSG));
}

const STATE_ROOT: &str = "5c7761b120a9cf59e79e5a078227b450b7a39294db74bb3ba28e28c6ae196d27";

fn state_head() -> String {
    format!(
        r#"{{"schema":1,"tree_id":"prod","generation":3,"last_seq":5,"projection_root":"{STATE_ROOT}","projection_root_tpm":"{STATE_ROOT}","manifest_digest":"{PENDING_DIGEST}""#
    )
}

fn read_state() -> Result<TreeState, c_int> {
    state_read()
}

fn state_of(text: &str) -> Result<TreeState, c_int> {
    write_text(STATE, text.as_bytes(), false);
    read_state()
}

#[test]
fn state_names_its_publication_head_and_base() {
    let dir = TempDir::new();
    use_tree(&dir);

    assert_eq!(read_state().err(), Some(-ENOENT));
    assert_eq!(state_of(&(state_head() + "}")).err(), Some(-EINVAL));
    assert_eq!(
        state_of(&(state_head() + r#","head_seq":7}"#)).err(),
        Some(-EINVAL)
    );
    assert_eq!(
        state_of(&(state_head() + r#","segment_base_seq":0}"#)).err(),
        Some(-EINVAL)
    );
    let mut s = state_of(&(state_head() + r#","head_seq":7,"segment_base_seq":2}"#)).unwrap();
    assert_eq!((s.last_seq, s.head_seq, s.segment_base_seq), (5, 7, 2));
    s.head_seq = 9;
    s.segment_base_seq = 4;
    assert_eq!(state_write(&s), Ok(()));
    let back = read_state().unwrap();
    assert_eq!(cstr(&back.tree_id), b"prod");
    assert_eq!(
        (
            back.generation,
            back.last_seq,
            back.head_seq,
            back.segment_base_seq
        ),
        (3, 5, 9, 4)
    );
    assert_eq!(cstr(&back.projection_root), STATE_ROOT.as_bytes());
    assert_eq!(cstr(&back.projection_root_tpm), STATE_ROOT.as_bytes());
    assert_eq!(cstr(&back.manifest_digest), PENDING_DIGEST.as_bytes());
}

#[test]
fn state_needs_both_projection_roots() {
    let dir = TempDir::new();
    use_tree(&dir);
    let head = format!(
        r#"{{"schema":1,"tree_id":"prod","generation":3,"last_seq":5,"projection_root":"{STATE_ROOT}","#
    );
    let tail =
        format!(r#""manifest_digest":"{PENDING_DIGEST}","head_seq":7,"segment_base_seq":0}}"#);

    assert_eq!(state_of(&format!("{head}{tail}")).err(), Some(-EINVAL));
    assert_eq!(
        state_of(&format!(r#"{head}"projection_root_tpm":"",{tail}"#)).err(),
        Some(-EINVAL)
    );
    assert_eq!(
        state_of(&format!(r#"{head}"projection_root_tpm":"5c",{tail}"#)).err(),
        Some(-EINVAL)
    );
    let s = state_of(&format!(
        r#"{head}"projection_root_tpm":"{STATE_ROOT}",{tail}"#
    ))
    .unwrap();
    assert_eq!(cstr(&s.projection_root_tpm), STATE_ROOT.as_bytes());
}

/// The tree eventlog matches a state that was read and holds its replay,
/// and no state that could not be read; a log that does not replay
/// leaves the answer unset.
#[test]
fn eventlog_matches_only_a_state_read() {
    let dir = TempDir::new();
    use_tree(&dir);
    let mut s = TreeState::default();

    assert_eq!(eventlog_matches(Some(&s)), Err(-ENOENT));
    let mut next = [0u8; 64];
    crate::util::hex::decode(&PENDING_DIGEST.as_bytes()[7..], &mut next[32..]).unwrap();
    let root = crate::util::crypto_openssl::sha256(&next).unwrap();
    assert_eq!(event_append(1, PENDING_DIGEST.as_bytes(), &root), Ok(()));
    s.projection_root[..64].copy_from_slice(&crate::util::hex::encode(&root));
    assert_eq!(eventlog_matches(Some(&s)), Ok((root, true)));
    assert_eq!(eventlog_matches(None).map(|r| r.1), Ok(false));
    s.projection_root[0] = if s.projection_root[0] == b'0' {
        b'1'
    } else {
        b'0'
    };
    assert_eq!(eventlog_matches(Some(&s)).map(|r| r.1), Ok(false));
    s.projection_root[0] = 0;
    assert_eq!(eventlog_matches(Some(&s)).map(|r| r.1), Ok(false));
}
