// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The object, program, map and link calls of libbpf's `bpf/libbpf.h`
//! that bring the enforcement up from an embedded object.

use core::ffi::{c_char, c_int, c_void};

/// `struct bpf_object`: libbpf's, opaque.
pub enum BpfObject {}
/// `struct bpf_program`: libbpf's, opaque.
pub enum BpfProgram {}
/// `struct bpf_map`: libbpf's, opaque.
pub enum BpfMap {}
/// `struct bpf_link`: libbpf's, opaque.
pub enum BpfLink {}

unsafe extern "C" {
    /// The object in the `size` bytes at `buf`, opened but not loaded;
    /// NULL with errno set on failure. `opts` NULL for the defaults.
    pub fn bpf_object__open_mem(
        buf: *const c_void,
        size: usize,
        opts: *const c_void,
    ) -> *mut BpfObject;
    pub fn bpf_object__load(obj: *mut BpfObject) -> c_int;
    /// Closes an object, NULL for none.
    pub fn bpf_object__close(obj: *mut BpfObject);
    pub fn bpf_object__find_program_by_name(
        obj: *const BpfObject,
        name: *const c_char,
    ) -> *mut BpfProgram;
    pub fn bpf_object__find_map_by_name(obj: *const BpfObject, name: *const c_char) -> *mut BpfMap;
    /// The program attached where its section says; NULL with errno set
    /// on failure.
    pub fn bpf_program__attach(prog: *const BpfProgram) -> *mut BpfLink;
    pub fn bpf_link__pin(link: *mut BpfLink, path: *const c_char) -> c_int;
    pub fn bpf_link__unpin(link: *mut BpfLink) -> c_int;
    /// Lets go of a link, detaching it unless pinned; NULL for none.
    pub fn bpf_link__destroy(link: *mut BpfLink) -> c_int;
    pub fn bpf_map__fd(map: *const BpfMap) -> c_int;
    /// Has the unloaded object's map use the map at `fd` instead.
    pub fn bpf_map__reuse_fd(map: *mut BpfMap, fd: c_int) -> c_int;
}
