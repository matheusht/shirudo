// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The embedded BPF objects of `util/loader.h`: the light skeletons of
//! bpf2 and the seal, and the unload template.

use core::ffi::{c_char, c_void};

/// `struct embedded_bpf`: an object or skeleton built into the binary.
#[repr(C)]
pub struct EmbeddedBpf {
    pub name: *const c_char,
    pub data: *const c_void,
    pub size: usize,
}

unsafe extern "C" {
    /// The light skeleton of bpf2.
    pub fn bpf2_blob() -> *const EmbeddedBpf;
    /// The unload directive's template.
    pub fn unload_blob() -> *const EmbeddedBpf;
    /// The light skeleton of the seal.
    pub fn seal_blob() -> *const EmbeddedBpf;
}
