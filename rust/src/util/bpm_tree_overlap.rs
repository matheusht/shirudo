// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Which operations of an upatch tree can meet on one node, from their
//! selectors alone: the checks `bpm tree append` makes before it signs a
//! publication.

use crate::text::cstr;
use crate::util::bpm_tree::{TreeOperation, TreePublication, TreeSelector, TreeSelectorKv};
use crate::util::kernel_release::prefix_matches;

/// A test of two lists of selector values.
type ListTest = fn(&[Vec<u8>], &[Vec<u8>]) -> bool;

fn lists_share(a: &[Vec<u8>], b: &[Vec<u8>]) -> bool {
    a.iter().any(|v| b.contains(v))
}

fn list_within(inner: &[Vec<u8>], outer: &[Vec<u8>]) -> bool {
    inner.iter().all(|v| outer.contains(v))
}

/// Two prefixes take a common release exactly when one takes the other
/// read as a release: every release the longer takes continues it.
fn prefixes_share(a: &[Vec<u8>], b: &[Vec<u8>]) -> bool {
    a.iter().any(|v| {
        b.iter()
            .any(|w| prefix_matches(v, w) || prefix_matches(w, v))
    })
}

fn prefixes_within(inner: &[Vec<u8>], outer: &[Vec<u8>]) -> bool {
    inner
        .iter()
        .all(|v| outer.iter().any(|w| prefix_matches(v, w)))
}

/// A node has one value for a key.
fn kvs_exclude(a: &[TreeSelectorKv], b: &[TreeSelectorKv]) -> bool {
    a.iter().any(|x| {
        b.iter()
            .any(|y| x.key == y.key && !lists_share(&x.values, &y.values))
    })
}

fn kvs_within(inner: &[TreeSelectorKv], outer: &[TreeSelectorKv]) -> bool {
    outer.iter().all(|o| {
        inner
            .iter()
            .any(|i| i.key == o.key && list_within(&i.values, &o.values))
    })
}

/// Whether no node matches both selectors: they name different
/// architectures, kernel builds or releases, or different values for one
/// label or kernel option. False is no proof of a shared node.
pub(crate) fn selectors_disjoint(a: &TreeSelector, b: &TreeSelector) -> bool {
    let both = |a: &[Vec<u8>], b: &[Vec<u8>]| !a.is_empty() && !b.is_empty();

    (both(&a.architecture, &b.architecture) && !lists_share(&a.architecture, &b.architecture))
        || (both(&a.kernel_build_id, &b.kernel_build_id)
            && !lists_share(&a.kernel_build_id, &b.kernel_build_id))
        || (both(&a.kernel_release_prefix, &b.kernel_release_prefix)
            && !prefixes_share(&a.kernel_release_prefix, &b.kernel_release_prefix))
        || kvs_exclude(&a.kconfig, &b.kconfig)
        || kvs_exclude(&a.labels, &b.labels)
}

/// Whether `outer` takes every node `inner` takes: an empty list of
/// `outer` constrains nothing, one of `inner` everything.
fn selector_covers(outer: &TreeSelector, inner: &TreeSelector) -> bool {
    let covers = |outer: &[Vec<u8>], inner: &[Vec<u8>], within: ListTest| {
        outer.is_empty() || (!inner.is_empty() && within(inner, outer))
    };

    covers(&outer.architecture, &inner.architecture, list_within)
        && covers(&outer.kernel_build_id, &inner.kernel_build_id, list_within)
        && covers(
            &outer.kernel_release_prefix,
            &inner.kernel_release_prefix,
            prefixes_within,
        )
        && kvs_within(&inner.kconfig, &outer.kconfig)
        && kvs_within(&inner.labels, &outer.labels)
}

/// Whether a delete of `later`, which all come after `add`, reaches
/// every node `add` reaches.
pub(crate) fn add_withdrawn(add: &TreeOperation, later: &[TreeOperation]) -> bool {
    later.iter().any(|op| {
        cstr(&op.op) == b"delete"
            && cstr(&op.id) == cstr(&add.id)
            && selector_covers(&op.selector, &add.selector)
    })
}

/// Whether the add at `index` of the publication may still be loaded
/// somewhere: no later delete of its upatch reaches every node it
/// reaches.
pub(crate) fn add_live(p: &TreePublication, index: usize) -> bool {
    match p.operations.get(index..) {
        Some([add, later @ ..]) => !add_withdrawn(add, later),
        _ => false,
    }
}

#[cfg(test)]
mod tests;
