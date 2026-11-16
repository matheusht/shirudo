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

/// `struct gen_loader_opts` of the vendored libbpf: what
/// bpf_object__gen_loader() fills, the loader program and its data, and
/// the shirudo options it takes.
#[repr(C)]
pub struct GenLoaderOpts {
    pub sz: usize,
    pub data: *const c_char,
    pub insns: *const c_char,
    pub data_sz: u32,
    pub insns_sz: u32,
    pub gen_hash: bool,
    pub reuse_map_mask: u64,
}

const _: () = assert!(size_of::<GenLoaderOpts>() == 48);

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
    /// The object in the ELF file at `path`, opened but not loaded; NULL
    /// with errno set on failure.
    pub fn bpf_object__open_file(path: *const c_char, opts: *const c_void) -> *mut BpfObject;
    /// The map after `prev`, NULL for the first; NULL after the last.
    pub fn bpf_object__next_map(obj: *const BpfObject, prev: *const BpfMap) -> *mut BpfMap;
    /// The program after `prev`, NULL for the first; NULL after the last.
    pub fn bpf_object__next_program(
        obj: *const BpfObject,
        prev: *mut BpfProgram,
    ) -> *mut BpfProgram;
    /// Has the object's next load record a loader program instead.
    pub fn bpf_object__gen_loader(obj: *mut BpfObject, opts: *mut GenLoaderOpts) -> c_int;
    pub fn bpf_map__name(map: *const BpfMap) -> *const c_char;
    pub fn bpf_map__type(map: *const BpfMap) -> u32;
    pub fn bpf_map__key_size(map: *const BpfMap) -> u32;
    pub fn bpf_map__value_size(map: *const BpfMap) -> u32;
    pub fn bpf_map__max_entries(map: *const BpfMap) -> u32;
    pub fn bpf_map__map_flags(map: *const BpfMap) -> u32;
    /// The map's initial value and its size into `psize`; NULL for none.
    pub fn bpf_map__initial_value(map: *const BpfMap, psize: *mut usize) -> *mut c_void;
    pub fn bpf_map__set_initial_value(map: *mut BpfMap, data: *const c_void, size: usize) -> c_int;
    pub fn bpf_program__name(prog: *const BpfProgram) -> *const c_char;
    pub fn bpf_program__section_name(prog: *const BpfProgram) -> *const c_char;
    pub fn bpf_program__set_expected_attach_type(prog: *mut BpfProgram, ty: u32) -> c_int;
    /// Has `sec` name programs of `prog_type` and `exp_attach_type`: the
    /// handler's id, or a negative error.
    pub fn libbpf_register_prog_handler(
        sec: *const c_char,
        prog_type: u32,
        exp_attach_type: u32,
        opts: *const c_void,
    ) -> c_int;
    pub fn libbpf_unregister_prog_handler(handler_id: c_int) -> c_int;
}
