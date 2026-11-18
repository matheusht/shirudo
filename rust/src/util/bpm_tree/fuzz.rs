// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-tree: a tree publication parsed. One that checks is consistent
//! about its segment; its verification names the operation it fails on;
//! and what it emits, with a publisher's fixes or without, parses back
//! to the same publication.

use core::ffi::{c_char, c_int, c_void};

use super::capi::{
    tree_emit_publication, tree_operation_digest, tree_operation_validate, tree_parse,
    tree_publication_check, tree_publication_free, tree_publication_verify, tree_segment_precedes,
};
use super::{TreeEmitExtra, TreeOperation, TreePublication};
use crate::fuzzing::fuzz_target;
use crate::heap::xfree;
use crate::text::cstr;
use crate::util::json::JsonEmit;

fn abort() -> ! {
    std::process::abort()
}

fn zeroed() -> Box<TreePublication> {
    // SAFETY: a publication of nothing, for which zeros are the value.
    Box::new(unsafe { core::mem::zeroed() })
}

fn operations(p: &TreePublication) -> &[TreeOperation] {
    // SAFETY: the publication's operations, of its count.
    unsafe { crate::ffi::slice(p.operations, p.n_operations.max(0) as usize) }
}

fn check(p: &TreePublication) -> c_int {
    // SAFETY: a parsed publication.
    unsafe { tree_publication_check(p) }
}

/// # Safety
///
/// `e` is the emitter, `ctx` the publication the fixes name.
unsafe extern "C" fn emit_fixes(e: *mut JsonEmit, index: c_int, ctx: *mut c_void) -> c_int {
    if index % 2 != 0 {
        return 0;
    }
    // SAFETY: the caller's emitter and publication.
    let (e, p) = unsafe { (&mut *e, &*ctx.cast::<TreePublication>()) };
    e.arr_open(b"fixes");
    e.str(b"EXAMPLE-0101");
    e.str(cstr(&p.tree_id));
    e.arr_close();
    0
}

fn digest(op: &TreeOperation) -> (c_int, [u8; 72]) {
    let mut out = [0u8; 72];
    // SAFETY: an operation and room for its digest.
    let ret = unsafe { tree_operation_digest(op, &mut out) };
    (ret, out)
}

fn read_back(p: &TreePublication, extra: Option<&TreeEmitExtra>) {
    let (mut out, mut len): (*mut c_char, usize) = (core::ptr::null_mut(), 0);
    let extra = extra.map_or(core::ptr::null(), |e| e as *const TreeEmitExtra);
    // SAFETY: the publication, the extra or NULL, and rooms for the
    // document, freed after.
    if unsafe { tree_emit_publication(p, extra, &mut out, &mut len) } != 0 {
        return;
    }
    let mut again = zeroed();
    // SAFETY: the document emitted, and room for the publication.
    if unsafe { tree_parse(out, len, &mut *again) } != 0
        || again.n_operations != p.n_operations
        || cstr(&again.tree_id) != cstr(&p.tree_id)
        || again.generation != p.generation
        || again.base_seq != p.base_seq
        || cstr(&again.segment_manifest_digest) != cstr(&p.segment_manifest_digest)
        || cstr(&again.history_root) != cstr(&p.history_root)
        || again.head_seq != p.head_seq
        || (check(&again) == 0) != (check(p) == 0)
    {
        abort();
    }
    for (a, b) in operations(p).iter().zip(operations(&again)) {
        let ((ra, da), (rb, db)) = (digest(a), digest(b));
        if ra != rb
            || cstr(&da) != cstr(&db)
            || cstr(&b.operation_digest) != cstr(&a.operation_digest)
        {
            abort();
        }
    }
    // SAFETY: the publication parsed, and the document, freed once.
    unsafe {
        tree_publication_free(&mut *again);
        xfree(out.cast(), len);
    }
}

fn verify_names_its_failure(p: &TreePublication) {
    let mut bad = 0;
    // SAFETY: the publication and room for the operation it fails on.
    let ret = unsafe { tree_publication_verify(p, &mut bad) };
    let ops = operations(p);
    // SAFETY: an operation of the publication's.
    let validate = |i: usize| unsafe { tree_operation_validate(&ops[i]) };
    if bad < -1
        || bad >= p.n_operations
        || (ret == 0 && (bad != -1 || check(p) != 0))
        || (bad >= 0 && validate(bad as usize) != ret)
    {
        abort();
    }
}

fuzz_target!(shirudo_fuzz_tree, shirudo_fuzz_tree_init, |data| {
    let mut p = zeroed();
    // SAFETY: the input and room for the publication.
    if unsafe { tree_parse(data.as_ptr().cast(), data.len(), &mut *p) } != 0 {
        return;
    }
    if check(&p) == 0 {
        let empty = |s: &[u8]| s.first().is_none_or(|&c| c == 0);
        // SAFETY: the publication and its own predecessor digest.
        let precedes =
            unsafe { tree_segment_precedes(&*p, p.segment_manifest_digest.as_ptr().cast(), &*p) };
        if empty(&p.segment_manifest_digest) != (p.base_seq == 0)
            || empty(&p.history_root) != (p.base_seq == 0)
            || (p.base_seq != 0 && p.n_operations == 0)
            || precedes == 0
        {
            abort();
        }
    }
    verify_names_its_failure(&p);
    read_back(&p, None);
    let extra = TreeEmitExtra {
        operation: Some(emit_fixes),
        ctx: (&raw const *p).cast_mut().cast(),
    };
    read_back(&p, Some(&extra));
    // SAFETY: the publication parsed, freed once.
    unsafe { tree_publication_free(&mut *p) };
});
