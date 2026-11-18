// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The Rust half of shirudo: modules that replace the C ones, exporting
//! the C interface their headers declare while C still calls them.

extern crate alloc;

mod bpf;
#[cfg(any(test, feature = "test-helpers"))]
mod btf_builder;
mod builtin;
mod errno;
mod ffi;
mod heap;
#[cfg(feature = "test-helpers")]
mod helpers;
mod log;
#[cfg(not(test))]
mod panic;
mod quote_check;
mod shirudo_build;
mod skel;
mod sys;
#[cfg(test)]
mod testutil;
mod text;
mod util;
