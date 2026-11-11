// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The Rust half of shirudo: modules that replace the C ones one at a
//! time, exporting the C interface their headers declare. It takes core
//! and alloc alone, and the C library for the rest, as the C does.

#![no_std]

extern crate alloc;

mod errno;
mod ffi;
mod heap;
mod panic;
mod sys;
mod text;
mod util;
