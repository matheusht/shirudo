// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-tree: a tree publication parsed. One that checks is consistent
//! about its segment; its verification names the operation it fails on;
//! and what it emits, with a publisher's fixes or without, parses back
//! to the same publication.

use core::ffi::c_int;

use super::{
    Extra, MAX_BYTES, Publication, TreeOperation, TreePublication, emit_publication,
    operation_digest, operation_validate, parse, publication_check, publication_verify,
    segment_precedes,
};
use crate::fuzzing::fuzz_target;
use crate::heap::xfree;
use crate::text::cstr;
use crate::util::json::JsonEmit;

fn abort() -> ! {
    std::process::abort()
}

/// The publication `data` describes, read as a tree file is.
fn parsed(data: &[u8]) -> Option<Publication> {
    if data.len() > MAX_BYTES {
        return None;
    }
    let mut p = Publication::new();
    // SAFETY: room for a publication, which the parse owns.
    (unsafe { parse(data, p.get_mut()) } == 0).then_some(p)
}

fn operations(p: &TreePublication) -> &[TreeOperation] {
    // SAFETY: a parsed publication's operations, of its count.
    unsafe { p.operations() }
}

fn check(p: &TreePublication) -> c_int {
    // SAFETY: a parsed publication.
    unsafe { publication_check(p) }
}

/// The digest of an operation, as text, or why not.
fn digest(op: &TreeOperation) -> Result<Vec<u8>, c_int> {
    // SAFETY: an operation of a parsed publication.
    unsafe { operation_digest(op) }.map(|d| cstr(&d).to_vec())
}

/// The fixes a publisher adds to every other operation.
fn emit_fixes(e: &mut JsonEmit, index: usize, p: &TreePublication) -> c_int {
    if index % 2 == 0 {
        e.arr_open(b"fixes");
        e.str(b"EXAMPLE-0101");
        e.str(cstr(&p.tree_id));
        e.arr_close();
    }
    0
}

fn read_back(p: &TreePublication, extra: Option<Extra<'_>>) {
    // SAFETY: a parsed publication.
    let Ok((body, cap, len)) = (unsafe { emit_publication(p, extra) }) else {
        return;
    };
    // SAFETY: the document emitted, `len` bytes at `body`.
    let again = parsed(unsafe { core::slice::from_raw_parts(body.cast::<u8>(), len) });
    let Some(again) = again else {
        abort();
    };
    let again = again.get();
    if again.n_operations != p.n_operations
        || cstr(&again.tree_id) != cstr(&p.tree_id)
        || again.generation != p.generation
        || again.base_seq != p.base_seq
        || cstr(&again.segment_manifest_digest) != cstr(&p.segment_manifest_digest)
        || cstr(&again.history_root) != cstr(&p.history_root)
        || again.head_seq != p.head_seq
        || (check(again) == 0) != (check(p) == 0)
    {
        abort();
    }
    for (a, b) in operations(p).iter().zip(operations(again)) {
        if digest(a) != digest(b) || cstr(&b.operation_digest) != cstr(&a.operation_digest) {
            abort();
        }
    }
    // SAFETY: the emitter's buffer, of its capacity, freed once.
    unsafe { xfree(body.cast(), cap) };
}

fn verify_names_its_failure(p: &TreePublication) {
    // SAFETY: a parsed publication.
    let (ret, bad) = match unsafe { publication_verify(p) } {
        Ok(()) => (0, None),
        Err((err, bad)) => (err, bad),
    };
    let ops = operations(p);
    let fails_alike = |i: usize| {
        // SAFETY: an operation of the publication's.
        unsafe { operation_validate(&ops[i]) == ret }
    };
    if bad.is_some_and(|i| i >= ops.len())
        || (ret == 0 && (bad.is_some() || check(p) != 0))
        || bad.is_some_and(|i| !fails_alike(i))
    {
        abort();
    }
}

fuzz_target!(shirudo_fuzz_tree, shirudo_fuzz_tree_init, |data| {
    let Some(p) = parsed(data) else {
        return;
    };
    let p = p.get();
    if check(p) == 0 {
        let empty = |s: &[u8]| s.first().is_none_or(|&c| c == 0);
        if empty(&p.segment_manifest_digest) != (p.base_seq == 0)
            || empty(&p.history_root) != (p.base_seq == 0)
            || (p.base_seq != 0 && p.n_operations == 0)
            || segment_precedes(p, cstr(&p.segment_manifest_digest), p) == 0
        {
            abort();
        }
    }
    verify_names_its_failure(p);
    read_back(p, None);
    read_back(
        p,
        Some(&mut |e: &mut JsonEmit, index: usize| emit_fixes(e, index, p)),
    );
});
