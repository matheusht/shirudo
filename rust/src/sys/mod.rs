// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Declarations of what the Rust modules call in C: the C library,
//! libcurl, zlib, OpenSSL, libelf, and the util/ modules not ported yet, one
//! module for each header, each to go when what it declares is Rust.

pub mod bpf;
pub mod btf;
pub mod curl;
pub mod elf;
pub mod identity;
pub mod libbpf;
pub mod libc;
pub mod loader;
pub mod log;
pub mod luajit;
pub mod openssl;
pub mod ssl;
pub mod string;
pub mod tss2;
pub mod upatch;
pub mod upatch_maps;
pub mod version;
pub mod zlib;
