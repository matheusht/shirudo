// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! A library to preload, whose constructor creates the file
//! SHIRUDO_PRELOAD_MARKER names, so that t1003 sees whether a binary ran
//! preloaded constructors. Built by the test itself:
//!
//!   rustc --edition 2024 --crate-type cdylib -C panic=abort test-preload.rs

use std::os::unix::fs::OpenOptionsExt;

/// Run by the loader when it maps the library, before main().
#[used]
#[unsafe(link_section = ".init_array")]
static MARK: extern "C" fn() = mark_preload;

extern "C" fn mark_preload() {
    if let Some(path) = std::env::var_os("SHIRUDO_PRELOAD_MARKER") {
        let _ = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path);
    }
}
