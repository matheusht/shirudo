// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The BTF reading of libbpf's `bpf/btf.h`: the functions that load a
//! `struct btf` and find its types, and the inline helpers of the header
//! and of `linux/btf.h` that decode a type.

use core::ffi::{c_char, c_long, c_void};

/// `struct btf`: libbpf's, opaque.
#[repr(C)]
pub struct Btf {
    _opaque: [u8; 0],
}

/// `struct btf_type`. A type of some kinds is followed by more: an
/// integer by its encoding, an array by a `struct btf_array`, a struct by
/// its `vlen()` members.
#[repr(C)]
pub struct BtfType {
    pub name_off: u32,
    pub info: u32,
    /// The union of `size` and `type`.
    pub size_type: u32,
}

/// `struct btf_member`.
#[repr(C)]
pub struct BtfMember {
    pub name_off: u32,
    pub ty: u32,
    pub offset: u32,
}

/// `struct btf_array`.
#[repr(C)]
pub struct BtfArray {
    pub ty: u32,
    pub index_type: u32,
    pub nelems: u32,
}

pub const KIND_INT: u16 = 1;
pub const KIND_PTR: u16 = 2;
pub const KIND_ARRAY: u16 = 3;
pub const KIND_STRUCT: u16 = 4;
pub const KIND_TYPEDEF: u16 = 8;
pub const KIND_VOLATILE: u16 = 9;
pub const KIND_CONST: u16 = 10;
pub const KIND_RESTRICT: u16 = 11;
pub const KIND_TYPE_TAG: u16 = 18;
/// `BTF_INT_SIGNED`.
pub const INT_SIGNED: u8 = 1;

unsafe extern "C" {
    /// The running kernel's BTF, or NULL with errno set.
    pub fn btf__load_vmlinux_btf() -> *mut Btf;
    pub fn btf__free(btf: *mut Btf);
    /// The ID of the type of `kind` named `name`, or a negative errno.
    pub fn btf__find_by_name_kind(btf: *const Btf, name: *const c_char, kind: u32) -> i32;
    /// The type of `id`, or NULL.
    pub fn btf__type_by_id(btf: *const Btf, id: u32) -> *const BtfType;
    /// The string at `offset` of the string section, or NULL.
    pub fn btf__name_by_offset(btf: *const Btf, offset: u32) -> *const c_char;
    /// The negative errno a pointer libbpf returned stands for, or 0.
    pub fn libbpf_get_error(ptr: *const c_void) -> c_long;
}

impl BtfType {
    /// btf_kind(): `BTF_INFO_KIND()` of the info.
    pub fn kind(&self) -> u16 {
        ((self.info >> 24) & 0x7f) as u16
    }

    /// btf_vlen(): `BTF_INFO_VLEN()` of the info.
    pub fn vlen(&self) -> u32 {
        self.info & 0x00ff_ffff
    }

    /// btf_kflag(): `BTF_INFO_KFLAG()` of the info.
    pub fn kflag(&self) -> bool {
        self.info >> 31 != 0
    }

    /// btf_is_mod(): a volatile, const, restrict or type tag.
    pub fn is_mod(&self) -> bool {
        matches!(
            self.kind(),
            KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG
        )
    }
}

/// The word that follows an integer type, which `BTF_INT_*()` decode.
///
/// # Safety
///
/// `t` is a type of kind `BTF_KIND_INT` of a BTF.
unsafe fn int_word(t: *const BtfType) -> u32 {
    // SAFETY: the caller's integer type, followed by its encoding.
    unsafe { t.add(1).cast::<u32>().read_unaligned() }
}

/// btf_int_encoding().
///
/// # Safety
///
/// As int_word().
pub unsafe fn int_encoding(t: *const BtfType) -> u8 {
    // SAFETY: the caller's integer type.
    ((unsafe { int_word(t) } & 0x0f00_0000) >> 24) as u8
}

/// btf_int_offset().
///
/// # Safety
///
/// As int_word().
pub unsafe fn int_offset(t: *const BtfType) -> u8 {
    // SAFETY: the caller's integer type.
    ((unsafe { int_word(t) } & 0x00ff_0000) >> 16) as u8
}

/// btf_int_bits().
///
/// # Safety
///
/// As int_word().
pub unsafe fn int_bits(t: *const BtfType) -> u8 {
    // SAFETY: the caller's integer type.
    (unsafe { int_word(t) } & 0x0000_00ff) as u8
}

/// btf_array(): the array an array type describes.
///
/// # Safety
///
/// `t` is a type of kind `BTF_KIND_ARRAY` of a BTF.
pub unsafe fn array(t: *const BtfType) -> *const BtfArray {
    // SAFETY: the caller's array type, followed by its array.
    unsafe { t.add(1).cast() }
}

/// btf_members(): the members a struct type has, `vlen()` of them.
///
/// # Safety
///
/// `t` is a type of kind `BTF_KIND_STRUCT` or `BTF_KIND_UNION` of a BTF.
pub unsafe fn members(t: *const BtfType) -> *const BtfMember {
    // SAFETY: the caller's struct type, followed by its members.
    unsafe { t.add(1).cast() }
}

/// btf_member_bitfield_size(): the bits of member `idx` of a struct
/// with `kflag()` set, `BTF_MEMBER_BITFIELD_SIZE()` of its offset, or 0.
///
/// # Safety
///
/// `t` is a struct type of a BTF with more than `idx` members.
pub unsafe fn member_bitfield_size(t: *const BtfType, idx: u32) -> u32 {
    // SAFETY: the caller's struct type and a member of it.
    unsafe {
        if !(*t).kflag() {
            return 0;
        }
        (*members(t).add(idx as usize)).offset >> 24
    }
}
