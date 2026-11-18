// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::testutil::TempDir;
use core::ffi::{c_char, c_void};

/// This thread's log, in `dir`.
fn use_log(dir: &TempDir) {
    let leak = |name| -> &'static CStr { Box::leak(dir.cpath(name).into_boxed_c_str()) };

    TEST_PATHS.set(Some((leak("eventlog"), leak("pending"))));
}

/// A record of `ty` and a digest of `fill` bytes, whose fields `body`
/// adds.
fn record(ty: &[u8], fill: u8, body: impl FnOnce(&mut JsonEmit)) -> Vec<u8> {
    let mut buf = [0u8; 1024];
    let mut e = JsonEmit::fixed(&mut buf);

    record_open(&mut e, ty, &[fill; 32]);
    body(&mut e);
    e.obj_close();
    assert_eq!(e.err(), 0);
    let n = e.written();
    buf[..n].to_vec()
}

fn plain(ty: &[u8], fill: u8) -> Vec<u8> {
    record(ty, fill, |_| {})
}

fn write_log(text: &[u8]) {
    std::fs::write(path().to_str().unwrap(), text).unwrap();
}

/// The register the log replays to.
fn replayed() -> Result<[u8; 32], c_int> {
    let mut out = [0u8; 32];
    match records::replay(&mut out) {
        0 => Ok(out),
        err => Err(err),
    }
}

/// The lines, each with its newline.
fn lines(lines: &[&[u8]]) -> Vec<u8> {
    lines.iter().flat_map(|l| [*l, b"\n"].concat()).collect()
}

/// A record killed before its newline is no record yet: readers skip it,
/// and the next append drops it rather than run on from it.
#[test]
fn unfinished_append_is_no_record() {
    let dir = TempDir::new();
    use_log(&dir);
    let (init, load, unload) = (
        plain(b"init", 1),
        plain(b"upatch_load", 2),
        plain(b"upatch_unload", 3),
    );

    write_log(&lines(&[&init]));
    let alone = replayed().unwrap();
    write_log(&lines(&[&init, &unload]));
    let both = replayed().unwrap();
    write_log(&[lines(&[&init]), load[..load.len() - 1].to_vec()].concat());
    assert_eq!(replayed(), Ok(alone));
    write_log(&[lines(&[&init]), load].concat());
    assert_eq!(replayed(), Ok(alone));
    assert_eq!(append_to(path(), &unload), 0);
    assert_eq!(replayed(), Ok(both));
}

/// A NUL would end the walk early and hide the records after it.
#[test]
fn nul_in_the_log_is_refused() {
    let dir = TempDir::new();
    use_log(&dir);
    let (init, unload) = (plain(b"init", 1), plain(b"upatch_unload", 3));

    write_log(&lines(&[&init, &[b"\0", &unload[..]].concat()]));
    assert_eq!(replayed(), Err(-EINVAL));
}

const DIGEST_HEX: &[u8] = b"abababababababababababababababababababababababababababababababab";

fn operation() -> Vec<u8> {
    [&b"sha256:"[..], DIGEST_HEX].concat()
}

fn tree_record(seq: i64, op: &[u8]) -> Vec<u8> {
    record(b"tree_op", 7, |e| {
        e.obj_open_key(b"tree");
        e.kv_int(b"seq", seq);
        e.kv_string(b"operation_digest", op);
        e.obj_close();
    })
}

/// Tree recovery asks whether an operation was measured this boot before
/// it applies the operation again, which would measure it twice.
#[test]
fn tree_op_measured_this_boot() {
    let dir = TempDir::new();
    use_log(&dir);
    let (init, tree) = (plain(b"init", 1), tree_record(3, &operation()));

    assert_eq!(records::tree_op_measured(3, &operation()), 0);
    write_log(&lines(&[&init, &tree]));
    assert_eq!(records::tree_op_measured(3, &operation()), 1);
    assert_eq!(records::tree_op_measured(4, &operation()), 0);
    assert_eq!(
        records::tree_op_measured(3, &[&operation()[..], b"0"].concat()),
        0
    );
    write_log(&lines(&[&tree]));
    assert_eq!(records::tree_op_measured(3, &operation()), 0);
}

#[derive(Default)]
struct Seen {
    inits: i32,
    loads: i32,
    last: Vec<u8>,
}

/// # Safety
///
/// `ctx` is a `Seen`, and `name` a C string for an event other than init.
unsafe extern "C" fn count_upatch(
    event: c_int,
    name: *const c_char,
    _payload_hex: *const c_char,
    ctx: *mut c_void,
) -> c_int {
    // SAFETY: the Seen the test passes.
    let s = unsafe { &mut *ctx.cast::<Seen>() };

    if event == UPATCH_INIT {
        s.inits += 1;
        return 0;
    }
    s.loads += c_int::from(event == records::UPATCH_LOAD);
    // SAFETY: the record's name, a C string for the call.
    s.last = unsafe { CStr::from_ptr(name) }.to_bytes().to_vec();
    0
}

fn set_record(ty: &[u8], name: &[u8]) -> Vec<u8> {
    record(ty, 2, |e| {
        e.arr_open(b"set");
        e.obj_open();
        e.kv_string(b"name", name);
        e.kv_string(b"payload_sha256", DIGEST_HEX);
        e.obj_close();
        e.arr_close();
    })
}

/// Only an init record's set says what boot restore loaded.
#[test]
fn set_counts_in_an_init_record_alone() {
    let dir = TempDir::new();
    use_log(&dir);
    let mut s = Seen::default();
    let ctx = (&raw mut s).cast::<c_void>();

    write_log(&lines(&[
        &set_record(b"init", b"fix"),
        &set_record(b"key_revoke", b"ghost"),
    ]));
    assert_eq!(records::upatches(false, Some(count_upatch), ctx), 0);
    assert_eq!((s.inits, s.loads, s.last.as_slice()), (1, 1, &b"fix"[..]));
    write_log(&lines(&[&set_record(b"init", b"../fix")]));
    assert_eq!(records::upatches(false, Some(count_upatch), ctx), -EINVAL);
}
