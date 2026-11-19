// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::util::bpm_tree::SelectorMap;

/// `value` into the text `t`.
fn set(t: &mut [u8], value: &str) {
    t.fill(0);
    t[..value.len()].copy_from_slice(value.as_bytes());
}

/// A selector that names nothing, which takes every node.
fn any() -> TreeSelector {
    TreeSelector::default()
}

/// The value `v` added to the list `list`.
fn push(list: &mut Vec<Vec<u8>>, v: &str) {
    list.push(v.as_bytes().to_vec());
}

/// A pair of `key` and its values added to the map `map` of `s`.
fn pair(s: &mut TreeSelector, map: SelectorMap, key: &str, values: &[&str]) {
    let values = values.iter().map(|v| v.as_bytes().to_vec()).collect();

    assert_eq!(s.pair_add(map, key.as_bytes(), values), Ok(()));
}

fn label(s: &mut TreeSelector, key: &str, values: &[&str]) {
    pair(s, SelectorMap::Labels, key, values);
}

fn disjoint(a: &TreeSelector, b: &TreeSelector) -> bool {
    selectors_disjoint(a, b)
}

#[test]
fn an_unconstrained_selector_shares_every_node() {
    let (unset, mut some) = (any(), any());

    push(&mut some.architecture, "x86_64");
    label(&mut some, "site", &["a"]);
    assert!(!disjoint(&unset, &unset));
    assert!(!disjoint(&unset, &some));
    assert!(!disjoint(&some, &unset));
}

#[test]
fn lists_without_a_common_value_are_disjoint() {
    let (mut a, mut b) = (any(), any());

    push(&mut a.architecture, "x86_64");
    push(&mut b.architecture, "aarch64");
    assert!(disjoint(&a, &b));
    push(&mut b.architecture, "x86_64");
    assert!(!disjoint(&a, &b));
    push(&mut a.kernel_build_id, "aa");
    assert!(!disjoint(&a, &b));
    push(&mut b.kernel_build_id, "bb");
    assert!(disjoint(&a, &b));
}

/// 7.1 takes 7.1.3 and not 7.10.0, as the node reads a prefix.
#[test]
fn release_prefixes_meet_where_one_continues_the_other() {
    let (mut a, mut b) = (any(), any());

    push(&mut a.kernel_release_prefix, "7.1");
    push(&mut b.kernel_release_prefix, "7.10");
    assert!(disjoint(&a, &b));
    assert!(disjoint(&b, &a));
    b.kernel_release_prefix[0] = b"7.1.3".to_vec();
    assert!(!disjoint(&a, &b));
    assert!(!disjoint(&b, &a));
    b.kernel_release_prefix[0] = b"7".to_vec();
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
    pair(&mut a, SelectorMap::Kconfig, "CONFIG_PREEMPT", &["y"]);
    pair(&mut both, SelectorMap::Kconfig, "CONFIG_PREEMPT", &["n"]);
    assert!(disjoint(&a, &both));
}

/// A publication of operations without a selector, until the caller
/// gives one.
struct Publication(TreePublication);

impl Publication {
    fn new() -> Self {
        Publication(TreePublication::default())
    }

    /// The operation `op` of `id` appended, which the caller may then
    /// select with.
    fn append(&mut self, op: &str, id: &str) -> &mut TreeOperation {
        let mut blank = TreeOperation::default();
        set(&mut blank.op, op);
        set(&mut blank.id, id);
        assert_eq!(self.0.append(blank), Ok(()));
        let ops = &mut self.0.operations;
        let n = ops.len();
        &mut ops[n - 1]
    }

    fn operations(&self) -> &[TreeOperation] {
        &self.0.operations
    }

    fn live(&self, index: usize) -> bool {
        add_live(&self.0, index)
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
    push(&mut op.selector.architecture, "x86_64");
    assert!(p.live(1));
    label(&mut p.append("delete", "x").selector, "site", &["b", "a"]);
    assert!(!p.live(1));
    assert!(p.live(3));
    // The last delete taken back.
    p.0.operations.pop();
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
        add_withdrawn(&sealed.operations()[0], later)
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
