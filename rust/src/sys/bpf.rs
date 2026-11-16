// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The bpf() syscall wrappers of libbpf's `bpf/bpf.h` that userspace
//! calls.

use core::ffi::{c_char, c_int, c_void};

/// `BPF_ANY`: create or update.
pub const BPF_ANY: u64 = 0;

unsafe extern "C" {
    /// Opens the BPF object pinned at `pathname`: a descriptor, or a
    /// negative error.
    pub fn bpf_obj_get(pathname: *const c_char) -> c_int;
    /// The kernel's `struct bpf_*_info` of object `fd`, at most `*len`
    /// bytes of it into `info`, the bytes into `*len`: 0 or -errno.
    pub fn bpf_obj_get_info_by_fd(fd: c_int, info: *mut c_void, len: *mut u32) -> c_int;
    /// Program `id`, opened: a descriptor or -errno.
    pub fn bpf_prog_get_fd_by_id(id: u32) -> c_int;
    /// Pins the object at `fd` at `pathname`: 0, or a negative error
    /// with errno set.
    pub fn bpf_obj_pin(fd: c_int, pathname: *const c_char) -> c_int;
    pub fn bpf_map_lookup_elem(fd: c_int, key: *const c_void, value: *mut c_void) -> c_int;
    /// The key after `key` into `next`, the first with NULL: 0, or an
    /// error at the end.
    pub fn bpf_map_get_next_key(fd: c_int, key: *const c_void, next: *mut c_void) -> c_int;
    pub fn bpf_map_update_elem(
        fd: c_int,
        key: *const c_void,
        value: *const c_void,
        flags: u64,
    ) -> c_int;
    /// Freezes the map at `fd` against writes from userspace.
    pub fn bpf_map_freeze(fd: c_int) -> c_int;
}
