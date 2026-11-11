// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The tree publications of `util/bpm_tree.h`.

use core::ffi::{c_char, c_int};

/// A `struct tree_publication`, which only `util/bpm_tree.c` looks into.
pub enum TreePublication {}

unsafe extern "C" {
    /// The publication the `len` bytes of JSON at `body` describe.
    pub fn tree_parse(body: *const c_char, len: usize, out: *mut TreePublication) -> c_int;
}
