// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The bpf() syscall wrappers of libbpf's `bpf/bpf.h` that userspace
//! calls.

use core::ffi::{c_char, c_int};

unsafe extern "C" {
    /// Opens the BPF object pinned at `pathname`: a descriptor, or a
    /// negative error.
    pub fn bpf_obj_get(pathname: *const c_char) -> c_int;
}
