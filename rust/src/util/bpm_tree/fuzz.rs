// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-tree: a tree publication parsed. One that checks is consistent
//! about its segment; its verification names the operation it fails on;
//! and what it emits, with a publisher's fixes or without, parses back
//! to the same publication.

use core::ffi::c_int;

use super::{
    Extra, MAX_BYTES, TreeOperation, TreePublication, emit_publication, operation_digest,
    operation_validate, publication_check, publication_verify, segment_precedes,
};
use crate::fuzzing::fuzz_target;
use crate::text::cstr;
use crate::util::json::JsonEmit;

fn abort() -> ! {
    std::process::abort()
}

/// The publication `data` describes, read as a tree file is.
fn parsed(data: &[u8]) -> Option<TreePublication> {
    if data.len() > MAX_BYTES {
        return None;
    }
    TreePublication::parse(data).ok()
}

/// The digest of an operation, as text, or why not.
fn digest(op: &TreeOperation) -> Result<Vec<u8>, c_int> {
    operation_digest(op).map(|d| cstr(&d).to_vec())
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
    let Ok(doc) = emit_publication(p, extra) else {
        return;
    };
    let Some(again) = parsed(&doc) else {
        abort();
    };
    if again.operations.len() != p.operations.len()
        || cstr(&again.tree_id) != cstr(&p.tree_id)
        || again.generation != p.generation
        || again.base_seq != p.base_seq
        || cstr(&again.segment_manifest_digest) != cstr(&p.segment_manifest_digest)
        || cstr(&again.history_root) != cstr(&p.history_root)
        || again.head_seq != p.head_seq
        || publication_check(&again).is_ok() != publication_check(p).is_ok()
    {
        abort();
    }
    for (a, b) in p.operations.iter().zip(&again.operations) {
        if digest(a) != digest(b) || cstr(&b.operation_digest) != cstr(&a.operation_digest) {
            abort();
        }
    }
}

fn verify_names_its_failure(p: &TreePublication) {
    let (ret, bad) = match publication_verify(p) {
        Ok(()) => (0, None),
        Err((err, bad)) => (err, bad),
    };
    let fails_alike = |i: usize| {
        p.operations
            .get(i)
            .is_some_and(|op| operation_validate(op) == Err(ret))
    };
    if (ret == 0 && (bad.is_some() || publication_check(p).is_err()))
        || bad.is_some_and(|i| !fails_alike(i))
    {
        abort();
    }
}

fuzz_target!(shirudo_fuzz_tree, shirudo_fuzz_tree_init, |data| {
    let Some(p) = parsed(data) else {
        return;
    };
    if publication_check(&p).is_ok() {
        let empty = |s: &[u8]| s.first().is_none_or(|&c| c == 0);
        if empty(&p.segment_manifest_digest) != (p.base_seq == 0)
            || empty(&p.history_root) != (p.base_seq == 0)
            || (p.base_seq != 0 && p.operations.is_empty())
            || segment_precedes(&p, cstr(&p.segment_manifest_digest), &p) == 0
        {
            abort();
        }
    }
    verify_names_its_failure(&p);
    read_back(&p, None);
    read_back(
        &p,
        Some(&mut |e: &mut JsonEmit, index: usize| emit_fixes(e, index, &p)),
    );
});
