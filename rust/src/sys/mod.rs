// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Declarations of what the Rust modules call in C: the C library,
//! libcurl, zlib, OpenSSL, libelf, and the util/ modules not ported yet, one
//! module for each header, each to go when what it declares is Rust.

pub mod btf;
pub mod curl;
pub mod elf;
pub mod hex;
pub mod identity;
pub mod image_guards;
pub mod image_runtime;
pub mod libc;
pub mod loader;
pub mod log;
pub mod malloc;
pub mod openssl;
pub mod paths;
pub mod seal;
pub mod ssl;
pub mod string;
pub mod tss2;
pub mod upatch;
pub mod version;
pub mod zlib;
