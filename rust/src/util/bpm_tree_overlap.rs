// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Which operations of an upatch tree can meet on one node, from their
//! selectors alone: the checks `bpm tree append` makes before it signs a
//! publication.

use crate::text::cstr;
use crate::util::bpm_tree::{
    MAX_KCONFIG, MAX_LABELS, MAX_VALUES, Text, TreeOperation, TreePublication, TreeSelector,
    TreeSelectorKv, count, pairs,
};
use crate::util::kernel_release::prefix_matches;

/// The values of a selector list, as many as its count says.
fn values(list: &[Text], n: i32) -> impl Iterator<Item = &[u8]> + Clone {
    list[..count(n, MAX_VALUES)].iter().map(|v| cstr(v))
}

fn lists_share(a: &[Text], na: i32, b: &[Text], nb: i32) -> bool {
    values(a, na).any(|v| values(b, nb).any(|w| v == w))
}

fn list_within(inner: &[Text], n_inner: i32, outer: &[Text], n_outer: i32) -> bool {
    values(inner, n_inner).all(|v| values(outer, n_outer).any(|w| v == w))
}

/// Two prefixes take a common release exactly when one takes the other
/// read as a release: every release the longer takes continues it.
fn prefixes_share(a: &[Text], na: i32, b: &[Text], nb: i32) -> bool {
    values(a, na).any(|v| values(b, nb).any(|w| prefix_matches(v, w) || prefix_matches(w, v)))
}

fn prefixes_within(inner: &[Text], n_inner: i32, outer: &[Text], n_outer: i32) -> bool {
    values(inner, n_inner).all(|v| values(outer, n_outer).any(|w| prefix_matches(v, w)))
}

/// A selector's pairs.
///
/// # Safety
///
/// `kvs` holds as many pairs as `n` says up to `max`.
unsafe fn kvs<'a>(kvs: *const TreeSelectorKv, n: i32, max: usize) -> &'a [TreeSelectorKv] {
    // SAFETY: the caller's pairs.
    unsafe { pairs(kvs, n, max) }
}

/// A node has one value for a key.
fn kvs_exclude(a: &[TreeSelectorKv], b: &[TreeSelectorKv]) -> bool {
    a.iter().any(|x| {
        b.iter().any(|y| {
            cstr(&x.key) == cstr(&y.key)
                && !lists_share(&x.values, x.n_values, &y.values, y.n_values)
        })
    })
}

fn kvs_within(inner: &[TreeSelectorKv], outer: &[TreeSelectorKv]) -> bool {
    outer.iter().all(|o| {
        inner.iter().any(|i| {
            cstr(&i.key) == cstr(&o.key)
                && list_within(&i.values, i.n_values, &o.values, o.n_values)
        })
    })
}

/// Whether no node matches both selectors: they name different
/// architectures, kernel builds or releases, or different values for one
/// label or kernel option. False is no proof of a shared node.
///
/// # Safety
///
/// The selectors' pairs are as their counts say.
pub(crate) unsafe fn selectors_disjoint(a: &TreeSelector, b: &TreeSelector) -> bool {
    if a.n_architecture > 0
        && b.n_architecture > 0
        && !lists_share(
            &a.architecture,
            a.n_architecture,
            &b.architecture,
            b.n_architecture,
        )
    {
        return true;
    }
    if a.n_kernel_build_id > 0
        && b.n_kernel_build_id > 0
        && !lists_share(
            &a.kernel_build_id,
            a.n_kernel_build_id,
            &b.kernel_build_id,
            b.n_kernel_build_id,
        )
    {
        return true;
    }
    if a.n_kernel_release_prefix > 0
        && b.n_kernel_release_prefix > 0
        && !prefixes_share(
            &a.kernel_release_prefix,
            a.n_kernel_release_prefix,
            &b.kernel_release_prefix,
            b.n_kernel_release_prefix,
        )
    {
        return true;
    }
    // SAFETY: the caller's pairs.
    unsafe {
        kvs_exclude(
            kvs(a.kconfig, a.n_kconfig, MAX_KCONFIG),
            kvs(b.kconfig, b.n_kconfig, MAX_KCONFIG),
        ) || kvs_exclude(
            kvs(a.labels, a.n_labels, MAX_LABELS),
            kvs(b.labels, b.n_labels, MAX_LABELS),
        )
    }
}

/// Whether `outer` takes every node `inner` takes: an empty list of
/// `outer` constrains nothing, one of `inner` everything.
///
/// # Safety
///
/// The selectors' pairs are as their counts say.
unsafe fn selector_covers(outer: &TreeSelector, inner: &TreeSelector) -> bool {
    if outer.n_architecture > 0
        && (inner.n_architecture <= 0
            || !list_within(
                &inner.architecture,
                inner.n_architecture,
                &outer.architecture,
                outer.n_architecture,
            ))
    {
        return false;
    }
    if outer.n_kernel_build_id > 0
        && (inner.n_kernel_build_id <= 0
            || !list_within(
                &inner.kernel_build_id,
                inner.n_kernel_build_id,
                &outer.kernel_build_id,
                outer.n_kernel_build_id,
            ))
    {
        return false;
    }
    if outer.n_kernel_release_prefix > 0
        && (inner.n_kernel_release_prefix <= 0
            || !prefixes_within(
                &inner.kernel_release_prefix,
                inner.n_kernel_release_prefix,
                &outer.kernel_release_prefix,
                outer.n_kernel_release_prefix,
            ))
    {
        return false;
    }
    // SAFETY: the caller's pairs.
    unsafe {
        kvs_within(
            kvs(inner.kconfig, inner.n_kconfig, MAX_KCONFIG),
            kvs(outer.kconfig, outer.n_kconfig, MAX_KCONFIG),
        ) && kvs_within(
            kvs(inner.labels, inner.n_labels, MAX_LABELS),
            kvs(outer.labels, outer.n_labels, MAX_LABELS),
        )
    }
}

/// Whether a delete of `later`, which all come after `add`, reaches
/// every node `add` reaches.
///
/// # Safety
///
/// The operations' selectors' pairs are as their counts say.
pub(crate) unsafe fn add_withdrawn(add: &TreeOperation, later: &[TreeOperation]) -> bool {
    later.iter().any(|op| {
        cstr(&op.op) == b"delete"
            && cstr(&op.id) == cstr(&add.id)
            // SAFETY: the caller's selectors.
            && unsafe { selector_covers(&op.selector, &add.selector) }
    })
}

/// Whether the add at `index` may still be loaded somewhere: no later
/// delete of its upatch reaches every node it reaches.
///
/// # Safety
///
/// The publication's operations and their pairs are as its counts say,
/// and `index` one of them.
pub(crate) unsafe fn add_live(p: &TreePublication, index: usize) -> bool {
    // SAFETY: the caller's publication.
    let ops = unsafe { p.operations() };
    // SAFETY: as above.
    !unsafe { add_withdrawn(&ops[index], &ops[index + 1..]) }
}

#[cfg(test)]
mod tests;
