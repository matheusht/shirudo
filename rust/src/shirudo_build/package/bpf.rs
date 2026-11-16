// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The libbpf object a package is made from: its maps and programs in
//! the order libbpf iterates them, which is the order the generated
//! loader's descriptor arrays have.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::marker::PhantomData;
use core::ptr;

use crate::ffi;
use crate::sys::btf::libbpf_get_error;
use crate::sys::libbpf::{
    BpfMap, BpfObject, BpfProgram, GenLoaderOpts, bpf_map__initial_value, bpf_map__key_size,
    bpf_map__map_flags, bpf_map__max_entries, bpf_map__name, bpf_map__set_initial_value,
    bpf_map__type, bpf_map__value_size, bpf_object__close, bpf_object__gen_loader,
    bpf_object__load, bpf_object__next_map, bpf_object__next_program, bpf_object__open_file,
    bpf_object__open_mem, bpf_program__name, bpf_program__section_name,
    bpf_program__set_expected_attach_type,
};

/// An object libbpf opened, closed when it goes.
pub(super) struct Object(*mut BpfObject);

impl Drop for Object {
    fn drop(&mut self) {
        // SAFETY: the object opened, closed once.
        unsafe { bpf_object__close(self.0) };
    }
}

fn opened(obj: *mut BpfObject) -> Result<Object, c_int> {
    // SAFETY: what libbpf returned.
    match unsafe { libbpf_get_error(obj.cast_const().cast()) } {
        0 => Ok(Object(obj)),
        err => Err(err as c_int),
    }
}

impl Object {
    pub(super) fn open_file(path: &CStr) -> Result<Self, c_int> {
        // SAFETY: a C string and the default options.
        opened(unsafe { bpf_object__open_file(path.as_ptr(), ptr::null()) })
    }

    pub(super) fn open_mem(data: *const c_void, size: usize) -> Result<Self, c_int> {
        // SAFETY: the caller's static object of `size` bytes.
        opened(unsafe { bpf_object__open_mem(data, size, ptr::null()) })
    }

    pub(super) fn maps(&self) -> impl Iterator<Item = Map<'_>> {
        let obj = self.0;
        let mut prev: *mut BpfMap = ptr::null_mut();

        core::iter::from_fn(move || {
            // SAFETY: the object and the map last returned, or NULL.
            prev = unsafe { bpf_object__next_map(obj, prev) };
            (!prev.is_null()).then_some(Map(prev, PhantomData))
        })
    }

    pub(super) fn programs(&self) -> impl Iterator<Item = Prog<'_>> {
        let obj = self.0;
        let mut prev: *mut BpfProgram = ptr::null_mut();

        core::iter::from_fn(move || {
            // SAFETY: the object and the program last returned, or NULL.
            prev = unsafe { bpf_object__next_program(obj, prev) };
            (!prev.is_null()).then_some(Prog(prev, PhantomData))
        })
    }

    pub(super) fn has_map(&self, name: &[u8]) -> bool {
        self.maps().any(|m| m.name() == name)
    }

    /// The .rodata map: libbpf names it "<objname>.rodata".
    pub(super) fn rodata(&self) -> Option<Map<'_>> {
        self.maps().find(|m| m.name().ends_with(b".rodata"))
    }

    pub(super) fn gen_loader(&self, opts: &mut GenLoaderOpts) -> c_int {
        // SAFETY: the object and its options.
        unsafe { bpf_object__gen_loader(self.0, opts) }
    }

    pub(super) fn load(&self) -> c_int {
        // SAFETY: the object.
        unsafe { bpf_object__load(self.0) }
    }
}

fn text<'a>(p: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: NULL or a C string of the object's.
    (!p.is_null()).then(|| unsafe { ffi::c_str(p) })
}

/// A map of an object.
#[derive(Clone, Copy, PartialEq)]
pub(super) struct Map<'a>(*mut BpfMap, PhantomData<&'a Object>);

impl<'a> Map<'a> {
    pub(super) fn name(&self) -> &'a [u8] {
        // SAFETY: a map of a live object.
        text(unsafe { bpf_map__name(self.0) }).unwrap_or_default()
    }

    pub(super) fn ty(&self) -> u32 {
        // SAFETY: a map of a live object.
        unsafe { bpf_map__type(self.0) }
    }

    pub(super) fn key_size(&self) -> u32 {
        // SAFETY: a map of a live object.
        unsafe { bpf_map__key_size(self.0) }
    }

    pub(super) fn value_size(&self) -> u32 {
        // SAFETY: a map of a live object.
        unsafe { bpf_map__value_size(self.0) }
    }

    pub(super) fn max_entries(&self) -> u32 {
        // SAFETY: a map of a live object.
        unsafe { bpf_map__max_entries(self.0) }
    }

    pub(super) fn flags(&self) -> u32 {
        // SAFETY: a map of a live object.
        unsafe { bpf_map__map_flags(self.0) }
    }

    /// The map's initial value, empty for none.
    pub(super) fn initial_value(&self) -> &'a [u8] {
        let mut size = 0;
        // SAFETY: a map of a live object and room for the size.
        let data = unsafe { bpf_map__initial_value(self.0, &mut size) };
        if data.is_null() {
            return &[];
        }
        // SAFETY: the object's `size` bytes.
        unsafe { ffi::slice(data.cast::<u8>(), size) }
    }

    pub(super) fn set_initial_value(&self, value: &[u8]) -> c_int {
        // SAFETY: a map of a live object and the value's bytes.
        unsafe { bpf_map__set_initial_value(self.0, value.as_ptr().cast(), value.len()) }
    }
}

/// A program of an object.
#[derive(Clone, Copy)]
pub(super) struct Prog<'a>(*mut BpfProgram, PhantomData<&'a Object>);

impl<'a> Prog<'a> {
    pub(super) fn name(&self) -> Option<&'a [u8]> {
        // SAFETY: a program of a live object.
        text(unsafe { bpf_program__name(self.0) })
    }

    pub(super) fn section(&self) -> Option<&'a [u8]> {
        // SAFETY: a program of a live object.
        text(unsafe { bpf_program__section_name(self.0) })
    }

    pub(super) fn set_expected_attach_type(&self, ty: u32) -> c_int {
        // SAFETY: a program of a live, unloaded object.
        unsafe { bpf_program__set_expected_attach_type(self.0, ty) }
    }
}
