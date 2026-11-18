// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::util::bpm_tree::{
    publication_free, tree_publication_append, tree_selector_free, tree_selector_kv_add,
};

/// `value` into the text `t`.
fn set(t: &mut [u8], value: &str) {
    t.fill(0);
    t[..value.len()].copy_from_slice(value.as_bytes());
}

/// A selector that names nothing, which takes every node.
fn any() -> Box<TreeSelector> {
    // SAFETY: a selector of texts, counts and pointers, for which zeros
    // are no pairs and no value.
    Box::new(unsafe { core::mem::zeroed() })
}

/// The value `v` added to the list `list` of `n` values.
fn push(list: &mut [Text], n: &mut i32, v: &str) {
    set(&mut list[*n as usize], v);
    *n += 1;
}

/// A pair of `key` and one or two values added to the pairs at `kvs`.
fn pair(kvs: &mut *mut TreeSelectorKv, n: &mut i32, key: &str, values: &[&str]) {
    let mut kv = core::ptr::null_mut();
    // SAFETY: the selector's pairs and their count, and room for the new
    // one, which it hands back.
    let kv = unsafe {
        assert_eq!(tree_selector_kv_add(kvs, n, MAX_LABELS as i32, &mut kv), 0);
        &mut *kv
    };
    set(&mut kv.key, key);
    for v in values {
        push(&mut kv.values, &mut kv.n_values, v);
    }
}

fn label(s: &mut TreeSelector, key: &str, values: &[&str]) {
    pair(&mut s.labels, &mut s.n_labels, key, values);
}

fn disjoint(a: &TreeSelector, b: &TreeSelector) -> bool {
    // SAFETY: two selectors whose pairs are as their counts say.
    unsafe { selectors_disjoint(a, b) }
}

fn free(s: &mut TreeSelector) {
    // SAFETY: a selector whose pairs came from tree_selector_kv_add().
    unsafe { tree_selector_free(s) };
}

#[test]
fn an_unconstrained_selector_shares_every_node() {
    let (unset, mut some) = (any(), any());

    push(&mut some.architecture, &mut some.n_architecture, "x86_64");
    label(&mut some, "site", &["a"]);
    assert!(!disjoint(&unset, &unset));
    assert!(!disjoint(&unset, &some));
    assert!(!disjoint(&some, &unset));
    free(&mut some);
}

#[test]
fn lists_without_a_common_value_are_disjoint() {
    let (mut a, mut b) = (any(), any());

    push(&mut a.architecture, &mut a.n_architecture, "x86_64");
    push(&mut b.architecture, &mut b.n_architecture, "aarch64");
    assert!(disjoint(&a, &b));
    push(&mut b.architecture, &mut b.n_architecture, "x86_64");
    assert!(!disjoint(&a, &b));
    push(&mut a.kernel_build_id, &mut a.n_kernel_build_id, "aa");
    assert!(!disjoint(&a, &b));
    push(&mut b.kernel_build_id, &mut b.n_kernel_build_id, "bb");
    assert!(disjoint(&a, &b));
}

/// 7.1 takes 7.1.3 and not 7.10.0, as the node reads a prefix.
#[test]
fn release_prefixes_meet_where_one_continues_the_other() {
    let (mut a, mut b) = (any(), any());

    push(
        &mut a.kernel_release_prefix,
        &mut a.n_kernel_release_prefix,
        "7.1",
    );
    push(
        &mut b.kernel_release_prefix,
        &mut b.n_kernel_release_prefix,
        "7.10",
    );
    assert!(disjoint(&a, &b));
    assert!(disjoint(&b, &a));
    set(&mut b.kernel_release_prefix[0], "7.1.3");
    assert!(!disjoint(&a, &b));
    assert!(!disjoint(&b, &a));
    set(&mut b.kernel_release_prefix[0], "7");
    assert!(!disjoint(&a, &b));
}

#[test]
fn a_key_with_other_values_is_disjoint() {
    let (mut a, mut b, mut other_key, mut both) = (any(), any(), any(), any());

    label(&mut a, "site", &["a"]);
    label(&mut b, "site", &["b"]);
    label(&mut other_key, "env", &["b"]);
    label(&mut both, "site", &["b", "a"]);
    assert!(disjoint(&a, &b));
    assert!(!disjoint(&a, &other_key));
    assert!(!disjoint(&a, &both));
    pair(&mut a.kconfig, &mut a.n_kconfig, "CONFIG_PREEMPT", &["y"]);
    pair(
        &mut both.kconfig,
        &mut both.n_kconfig,
        "CONFIG_PREEMPT",
        &["n"],
    );
    assert!(disjoint(&a, &both));
    for s in [&mut a, &mut b, &mut other_key, &mut both] {
        free(s);
    }
}

/// A publication of no operation, freed when it goes.
struct Publication(Box<TreePublication>);

impl Publication {
    fn new() -> Self {
        // SAFETY: a publication of no operation, for which zeros are a
        // value.
        Publication(Box::new(unsafe { core::mem::zeroed() }))
    }

    /// The operation `op` of `id` appended, which the caller may then
    /// select with.
    fn append(&mut self, op: &str, id: &str) -> &mut TreeOperation {
        // SAFETY: an operation of no pairs, for which zeros are a value.
        let mut blank: Box<TreeOperation> = Box::new(unsafe { core::mem::zeroed() });
        set(&mut blank.op, op);
        set(&mut blank.id, id);
        // SAFETY: the publication and an operation of no pairs.
        assert_eq!(unsafe { tree_publication_append(&mut *self.0, &*blank) }, 0);
        let n = self.0.n_operations as usize;
        // SAFETY: the operation just appended.
        unsafe { &mut *self.0.operations.add(n - 1) }
    }

    fn operations(&self) -> &[TreeOperation] {
        if self.0.operations.is_null() {
            return &[];
        }
        // SAFETY: the publication's operations, as many as it counts.
        unsafe { core::slice::from_raw_parts(self.0.operations, self.0.n_operations as usize) }
    }

    fn live(&self, index: usize) -> bool {
        // SAFETY: the publication, whose pairs are as their counts say.
        unsafe { add_live(&self.0, index) }
    }
}

impl Drop for Publication {
    fn drop(&mut self) {
        publication_free(&mut self.0);
    }
}

/// A delete that leaves the upatch on some node the add reached keeps it.
#[test]
fn an_add_lives_until_a_delete_reaches_all_its_nodes() {
    let mut p = Publication::new();

    p.append("delete", "x");
    label(&mut p.append("add", "x").selector, "site", &["a", "b"]);
    assert!(p.live(1));
    p.append("delete", "y");
    assert!(p.live(1));
    p.append("add", "x");
    assert!(p.live(1));
    label(&mut p.append("delete", "x").selector, "site", &["a"]);
    assert!(p.live(1));
    let op = p.append("delete", "x");
    label(&mut op.selector, "site", &["a", "b"]);
    push(
        &mut op.selector.architecture,
        &mut op.selector.n_architecture,
        "x86_64",
    );
    assert!(p.live(1));
    label(&mut p.append("delete", "x").selector, "site", &["b", "a"]);
    assert!(!p.live(1));
    assert!(p.live(3));
    // The last delete taken back, its pairs freed with the rest.
    p.0.n_operations -= 1;
    // SAFETY: the operation past the count, freed once, here.
    unsafe { free(&mut (*p.0.operations.add(p.0.n_operations as usize)).selector) };
    assert!(p.live(1));
    p.append("delete", "x");
    assert!(!p.live(1));
    assert!(!p.live(3));
}

/// The operations of the segments after the add's, held apart from it.
#[test]
fn a_later_segment_withdraws_an_add_as_its_own_does() {
    let (mut sealed, mut later) = (Publication::new(), Publication::new());
    let withdrawn = |sealed: &Publication, later: &[TreeOperation]| {
        // SAFETY: an operation and later ones, whose pairs are as their
        // counts say.
        unsafe { add_withdrawn(&sealed.operations()[0], later) }
    };

    label(&mut sealed.append("add", "x").selector, "site", &["a", "b"]);
    assert!(!withdrawn(&sealed, later.operations()));
    later.append("add", "x");
    later.append("delete", "y");
    label(&mut later.append("delete", "x").selector, "site", &["a"]);
    assert!(!withdrawn(&sealed, later.operations()));
    label(
        &mut later.append("delete", "x").selector,
        "site",
        &["b", "a"],
    );
    let n = later.operations().len();
    assert!(withdrawn(&sealed, later.operations()));
    assert!(!withdrawn(&sealed, &later.operations()[..n - 1]));
    assert!(sealed.live(0));
}
