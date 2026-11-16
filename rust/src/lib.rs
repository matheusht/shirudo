// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The Rust half of shirudo: modules that replace the C ones, exporting
//! the C interface their headers declare while C still calls them.

extern crate alloc;

mod builtin;
mod errno;
mod ffi;
mod heap;
mod panic;
mod shirudo_build;
mod sys;
mod text;
mod util;
