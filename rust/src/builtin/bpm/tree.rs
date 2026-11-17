// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo bpm tree sync`: the signed upatch tree applied on a target,
//! each operation measured into the register and logged in the tree
//! eventlog before the cursor moves past it.

use core::ffi::c_int;

use super::{
    Result, TREE_PENDING_PATH, TREE_STATUS_DIR, TREE_USAGE, curl_ready, eprint, error, fail,
    finish, lock, message, path, print, remove, status, warn,
};
use crate::errno::{EINVAL, EIO, EKEYREJECTED, ENOENT, ERANGE};
use crate::sys::upatch::UPATCH_INSTALL_TARGET_MISSING;
use crate::text::{cstr, strscpy};
use crate::util::bpm_oci::{MAX_DIGEST, package_name_ok};
use crate::util::bpm_tree::{
    Publication, TreeOperation, TreePending, TreePublication, TreeState, digest_bytes,
    operation_validate, publication_check, publication_follows,
};
use crate::util::bpm_tree_state::{
    tree_configured, tree_event_append, tree_event_replay, tree_pending_read, tree_pending_write,
    tree_selector_matches, tree_state_read, tree_state_write,
};
use crate::util::chain::{chain_bound, chain_extend, chain_tree_event, memneq_explicit, sha256_2};
use crate::util::eventlog::{
    eventlog_append, eventlog_lock, eventlog_record_open, eventlog_tree_op_measured,
    eventlog_unlock,
};
use crate::util::help::is_help;
use crate::util::json::JsonEmit;
use crate::util::seal::{
    SealOutput, seal_mkdir_p, seal_output_commit, seal_output_create, seal_write_file,
};
use crate::util::upatch;

/// The lowercase hex of `bytes` into `out`, NUL-terminated.
fn hex_into(bytes: &[u8; 32], out: &mut [u8; 65]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    for (i, b) in bytes.iter().enumerate() {
        out[2 * i] = HEX[usize::from(b >> 4)];
        out[2 * i + 1] = HEX[usize::from(b & 0xf)];
    }
    out[64] = 0;
}

/// The 32 bytes 64 hex digits of either case spell.
fn hex32(text: &[u8]) -> Option<[u8; 32]> {
    let hex = cstr(text);
    let mut out = [0; 32];

    if hex.len() != 64 {
        return None;
    }
    for (b, pair) in out.iter_mut().zip(hex.chunks_exact(2)) {
        let digit = |c: u8| char::from(c).to_digit(16);
        *b = (digit(pair[0])? << 4 | digit(pair[1])?) as u8;
    }
    Some(out)
}

/// SHA-256 over `a` and then `b`.
fn hash2(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32]> {
    let mut out = [0; 32];

    // SAFETY: two digests and room for one.
    status(unsafe {
        sha256_2(
            a.as_ptr().cast(),
            32,
            b.as_ptr().cast(),
            32,
            out.as_mut_ptr(),
        )
    })?;
    Ok(out)
}

/// A sync's failure in its log, with the operation it was at.
fn report_error(phase: &[u8], op: Option<&TreeOperation>, ret: c_int) {
    let rc = ret.to_string();
    let at = op.map_or_else(Vec::new, |op| {
        [
            b" seq=",
            op.seq.to_string().as_bytes(),
            b" id=",
            cstr(&op.id),
        ]
        .concat()
    });

    if ret > 0 {
        error(&[
            b"bpm tree sync: phase=",
            phase,
            &at,
            b" rc=",
            rc.as_bytes(),
            b" (command status)",
        ]);
        return;
    }
    let why: &[u8] = if ret < 0 {
        super::strerr(-ret)
    } else {
        b"success"
    };
    error(&[
        b"bpm tree sync: phase=",
        phase,
        &at,
        b" rc=",
        rc.as_bytes(),
        b" (",
        why,
        b")",
    ]);
}

/// Event = SHA256("shirudo-tree\0" || seq || operation_digest), extended
/// into the register and recorded in the eventlog with the chain. The
/// tree's own projection stays a file chain; the register is what an
/// operator attests.
fn measure(op: &TreeOperation, digest: &[u8; 32]) -> Result {
    let lock = eventlog_lock();

    if lock < 0 {
        return Err(lock);
    }
    let ret = measure_locked(op, digest);
    eventlog_unlock(lock);
    ret
}

fn measure_locked(op: &TreeOperation, digest: &[u8; 32]) -> Result {
    let mut event = [0; 32];
    let mut chain = [0; 32];
    let mut chain_hex = [0; 65];
    let mut line = [0u8; 4096];

    // SAFETY: digests and room for them.
    unsafe {
        status(chain_tree_event(
            op.seq,
            digest.as_ptr(),
            event.as_mut_ptr(),
        ))?;
        status(chain_extend(event.as_ptr(), chain.as_mut_ptr()))?;
    }
    hex_into(&chain, &mut chain_hex);
    let mut e = JsonEmit::fixed(line.as_mut_ptr().cast(), line.len());
    // SAFETY: the emitter, a C string and the event.
    unsafe { eventlog_record_open(&mut e, c"tree_op".as_ptr(), event.as_ptr()) };
    e.obj_open_key(b"tree");
    e.kv_int(b"seq", op.seq);
    e.kv_string(b"op", cstr(&op.op));
    e.kv_string(b"id", cstr(&op.id));
    e.kv_string(b"operation_digest", cstr(&op.operation_digest));
    e.obj_close();
    e.kv_string(b"chain", cstr(&chain_hex));
    e.obj_close();
    if e.err() != 0 {
        return Err(e.err());
    }
    // SAFETY: the emitter's NUL-terminated line.
    status(unsafe { eventlog_append(line.as_ptr().cast()) })
}

fn status_write(id: &[u8], text: &[u8]) -> Result {
    if !upatch::name_valid(Some(id)) || text.is_empty() {
        return Err(-EINVAL);
    }
    // SAFETY: a C string.
    status(unsafe { seal_mkdir_p(message(&[TREE_STATUS_DIR.as_bytes()]).as_ptr(), 0o700) })?;
    let p = path(&[TREE_STATUS_DIR.as_bytes(), b"/", id])?;
    // SAFETY: a C string and the status's bytes.
    status(unsafe { seal_write_file(p.as_ptr(), text.as_ptr().cast(), text.len(), 0o600) })
}

fn status_clear(id: &[u8]) {
    if upatch::name_valid(Some(id)) {
        if let Ok(p) = path(&[TREE_STATUS_DIR.as_bytes(), b"/", id]) {
            remove(&p);
        }
    }
}

/// Completes the only non-idempotent window: the process may have
/// measured the operation, or appended its tree event too, before the
/// sealed cursor was committed. Applying it again would extend the
/// register with it a second time this boot.
fn recover_pending(p: &TreePublication, state: &mut TreeState) -> Result {
    // SAFETY: an all-zero record is an empty one.
    let mut pending: TreePending = unsafe { core::mem::zeroed() };

    // SAFETY: room for the record.
    match unsafe { tree_pending_read(&mut pending) } {
        0 => {}
        err if err == -ENOENT => return Ok(()),
        err => return Err(err),
    }
    // SAFETY: the publication the parse filled.
    let ops = unsafe { p.operations() };
    let Some(op) = ops.iter().find(|op| {
        op.seq == pending.seq
            && cstr(&op.id) == cstr(&pending.id)
            && cstr(&op.operation_digest) == cstr(&pending.operation_digest)
    }) else {
        return Err(-ERANGE);
    };
    if pending.seq <= state.last_seq {
        remove(TREE_PENDING_PATH);
        return Ok(());
    }
    let (Some(digest), Some(previous)) = (
        digest_bytes(&pending.operation_digest),
        hex32(&state.projection_root),
    ) else {
        return Err(-EINVAL);
    };
    let next = hash2(&previous, &digest)?;
    let mut replay = [0; 32];
    let (mut applied, mut event_present) = (false, false);
    // SAFETY: room for the replayed root.
    match unsafe { tree_event_replay(replay.as_mut_ptr()) } {
        0 if !memneq_explicit(&replay, &next) => {
            applied = true;
            event_present = true;
        }
        0 if memneq_explicit(&replay, &previous) => return Err(-EKEYREJECTED),
        0 => {}
        err if err == -ENOENT => {}
        _ => return Err(-EKEYREJECTED),
    }
    if !applied {
        // SAFETY: the operation's NUL-terminated digest.
        match unsafe { eventlog_tree_op_measured(op.seq, op.operation_digest.as_ptr().cast()) } {
            r if r < 0 => return Err(-EKEYREJECTED),
            // Still pre-operation; retry normally.
            0 => return Ok(()),
            _ => {}
        }
    }
    if !event_present {
        // SAFETY: the operation's NUL-terminated digest and the root.
        status(unsafe {
            tree_event_append(op.seq, op.operation_digest.as_ptr().cast(), next.as_ptr())
        })?;
    }
    hex_into(&next, &mut state.projection_root);
    hex_into(&next, &mut state.projection_root_tpm);
    state.last_seq = op.seq;
    // SAFETY: the state.
    status(unsafe { tree_state_write(state) })?;
    remove(TREE_PENDING_PATH);
    Ok(())
}

/// What a sync counts.
#[derive(Default)]
struct Counts {
    selected: i64,
    skipped: i64,
    applied: i64,
    module_skipped: i64,
}

/// Applies one selected operation: recorded as pending, its artifact
/// fetched and checked, installed or removed, measured, logged in the
/// tree eventlog, and the cursor committed past it.
fn apply(op: &TreeOperation, state: &mut TreeState, counts: &mut Counts) -> Result {
    let failed = |phase: &[u8], ret: c_int| {
        report_error(phase, Some(op), ret);
        Err(ret)
    };
    let id = cstr(&op.id);

    let Some(digest) = digest_bytes(&op.operation_digest) else {
        report_error(b"operation_digest_parse", Some(op), -EINVAL);
        return Err(-EINVAL);
    };
    // SAFETY: the operation.
    let ret = unsafe { tree_pending_write(op) };
    if ret != 0 {
        return failed(b"pending_write", ret);
    }
    let artifact = match super::fetch::tree_artifact(op) {
        Ok(artifact) => artifact,
        Err(err) => return failed(b"artifact_fetch_or_verify", err),
    };
    let add = cstr(&op.op) == b"add";
    let mut ret = match cstr(&op.op) {
        b"add" => crate::builtin::upatch::install(&artifact),
        b"delete" => crate::builtin::upatch::remove(&artifact),
        _ => return Err(-EINVAL),
    };
    let skipped_module = add && ret == UPATCH_INSTALL_TARGET_MISSING;
    if skipped_module {
        ret = 0;
        counts.module_skipped += 1;
        warn(&[b"bpm tree: skipped ", id, b": module not loaded"]);
    }
    if ret != 0 {
        return failed(b"upatch_install", ret);
    }
    let Some(previous) = hex32(&state.projection_root) else {
        return failed(b"projection_root_decode", -EINVAL);
    };
    let next = match hash2(&previous, &digest) {
        Ok(next) => next,
        Err(err) => return failed(b"projection_root_hash", err),
    };
    if let Err(err) = measure(op, &digest) {
        return failed(b"register_extend", err);
    }
    hex_into(&next, &mut state.projection_root);
    hex_into(&next, &mut state.projection_root_tpm);
    // SAFETY: the operation's NUL-terminated digest and the root.
    let ret =
        unsafe { tree_event_append(op.seq, op.operation_digest.as_ptr().cast(), next.as_ptr()) };
    if ret != 0 {
        return failed(b"tree_event_append", ret);
    }
    state.last_seq = op.seq;
    counts.applied += 1;
    // SAFETY: the state.
    let ret = unsafe { tree_state_write(state) };
    if ret != 0 {
        return failed(b"tree_state_commit", ret);
    }
    let written = if skipped_module {
        status_write(id, b"skipped: module not loaded")
    } else {
        status_clear(id);
        Ok(())
    };
    if let Err(err) = written {
        return failed(b"tree_status_write", err);
    }
    remove(TREE_PENDING_PATH);
    Ok(())
}

/// The sync's report: to `path`, sealed, or else to stdout.
fn write_report(
    path: Option<&[u8]>,
    s: &TreeState,
    counts: &Counts,
    dry_run: bool,
    tpm: bool,
) -> Result {
    let mut buf = [0u8; 4096];
    let mut e = JsonEmit::fixed(buf.as_mut_ptr().cast(), buf.len());

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_bool(b"dry_run", dry_run);
    e.kv_int(b"selected", counts.selected);
    e.kv_int(b"skipped", counts.skipped);
    e.kv_int(b"applied", counts.applied);
    e.kv_int(b"module_skipped", counts.module_skipped);
    e.kv_bool(b"tpm_available", tpm);
    e.kv_int(b"last_seq", s.last_seq);
    if tpm {
        e.kv_string(b"projection_root_tpm", cstr(&s.projection_root_tpm));
    } else {
        e.kv_null(b"projection_root_tpm");
    }
    e.obj_close();
    if e.err() != 0 {
        return Err(e.err());
    }
    let body = &buf[..e.written()];
    let Some(path) = path else {
        print(&[body, b"\n"].concat());
        return Ok(());
    };
    let path = message(&[path]);
    let mut out = SealOutput::closed();
    // SAFETY: the output to create, a C string and the report's bytes.
    unsafe {
        status(seal_output_create(&mut out, path.as_ptr(), 0o600))?;
        status(seal_output_commit(
            &mut out,
            body.as_ptr().cast(),
            body.len(),
        ))
    }
}

/// The sync, `args` from "tree" on: `tree sync [--dry-run]
/// [--report=<path>]`.
fn sync(args: &[&[u8]]) -> Result {
    let mut dry_run = false;
    let mut report: &[u8] = b"";
    let mut i = 2;

    if args.len() < 2 || args[1] != b"sync" {
        return Err(-EINVAL);
    }
    while i < args.len() {
        let a = args[i];

        if a == b"--dry-run" {
            dry_run = true;
        } else if a.starts_with(b"--report=") || (a == b"--report" && i + 1 < args.len()) {
            let p = if a.get(8) == Some(&b'=') {
                &a[9..]
            } else {
                i += 1;
                args[i]
            };
            if p.len() >= crate::sys::libc::PATH_MAX {
                error(&[b"bpm tree sync: report path too long"]);
                return Err(2);
            }
            report = p;
        } else if is_help(Some(a)) {
            eprint(b"usage: shirudo bpm tree sync [--dry-run] [--report=<path>]\n");
            return Ok(());
        } else {
            return Err(-EINVAL);
        }
        i += 1;
    }
    // Optional integration: manual `shirudo upatch` remains valid.
    let cfg = match super::source::load_tree() {
        Err(err) if err == -ENOENT => return Ok(()),
        cfg => cfg?,
    };
    // SAFETY: an all-zero state is an empty one.
    let mut state: TreeState = unsafe { core::mem::zeroed() };
    // SAFETY: room for the state.
    let have_state = match unsafe { tree_state_read(&mut state) } {
        0 => true,
        err if err == -ENOENT => false,
        err => return Err(err),
    };
    let mut publication = Publication::new();
    let mut manifest_digest = [0u8; MAX_DIGEST];
    super::fetch::tree_publication(&cfg, publication.get_mut(), &mut manifest_digest)?;
    let p = publication.get();
    // The node records the tree ID in its state, which takes names
    // alone: one that is not would be applied, measured and logged and
    // then never recorded, failing every later sync.
    if !package_name_ok(cstr(&p.tree_id)) {
        return Err(-EINVAL);
    }
    // SAFETY: the publication the parse filled.
    let ops = unsafe { p.operations() };
    // SAFETY: as above.
    status(unsafe { publication_check(p) })?;
    for op in ops {
        // SAFETY: an operation the parse filled.
        let ret = unsafe { operation_validate(op) };
        if ret != 0 {
            report_error(b"operation_validate", Some(op), ret);
            return Err(ret);
        }
    }
    status(publication_follows(
        p,
        have_state.then_some(&state),
        cstr(&manifest_digest),
    ))?;
    if !have_state {
        state.schema = 1;
        let _ = strscpy(&mut state.tree_id, cstr(&p.tree_id));
        state.projection_root[..64].fill(b'0');
        state.projection_root[64] = 0;
        state.projection_root_tpm[..64].fill(b'0');
        state.projection_root_tpm[64] = 0;
    }
    if let Err(err) = recover_pending(p, &mut state) {
        report_error(b"pending_recovery", None, err);
        return Err(err);
    }
    let tpm = chain_bound();
    let mut counts = Counts::default();
    for op in ops {
        if op.seq <= state.last_seq {
            continue;
        }
        // SAFETY: the selector the parse filled.
        let matched = unsafe { tree_selector_matches(&op.selector) };
        if matched < 0 {
            report_error(b"selector_evaluate", Some(op), matched);
            return Err(matched);
        }
        if matched == 0 {
            counts.skipped += 1;
            if !dry_run {
                state.last_seq = op.seq;
            }
            continue;
        }
        counts.selected += 1;
        if !dry_run {
            apply(op, &mut state, &mut counts)?;
        }
    }
    if !dry_run {
        state.generation = p.generation;
        let _ = strscpy(&mut state.manifest_digest, cstr(&manifest_digest));
        if state.tree_id[0] == 0 {
            let _ = strscpy(&mut state.tree_id, cstr(&p.tree_id));
        }
        // SAFETY: the state.
        let ret = unsafe { tree_state_write(&state) };
        if ret != 0 {
            report_error(b"tree_state_commit_final", None, ret);
            return Err(ret);
        }
    }
    // "-" is standard output, where the report goes without --report.
    let to = (!report.is_empty() && report != b"-").then_some(report);
    write_report(to, &state, &counts, dry_run, tpm)
}

/// `shirudo bpm tree sync`, which takes the bpm lock only once a tree is
/// configured, so that a node without one needs no writable state.
pub(super) fn tree(args: &[&[u8]]) -> c_int {
    let n = args.len();

    if n > 6 {
        return 2;
    }
    if n == 4 && is_help(Some(args[3])) {
        eprint(TREE_USAGE);
        return 0;
    }
    if !tree_configured() {
        return 0;
    }
    if !curl_ready() {
        return fail(b"initialize curl", -EIO);
    }
    let held = match lock() {
        Ok(held) => held,
        Err(err) => return finish(None, Err(err), b"lock"),
    };
    finish(Some(held), sync(&args[1..]), b"tree sync")
}
