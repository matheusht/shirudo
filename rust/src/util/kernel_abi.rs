// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The kernel ABI check behind `util/kernel_abi.h`. The signed loader
//! requires map hashing, exclusive-map binding and signed program
//! metadata. Stock kernels can expose BPF and the BPF LSM while still
//! lacking this contract, so those kernels are rejected before
//! BPF_PROG_LOAD.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use crate::errno::EOPNOTSUPP;
use crate::sys::btf::{
    Btf, BtfMember, BtfType, INT_SIGNED, KIND_ARRAY, KIND_INT, KIND_PTR, KIND_STRUCT, KIND_TYPEDEF,
    array, btf__find_by_name_kind, btf__free, btf__load_vmlinux_btf, btf__name_by_offset,
    btf__type_by_id, int_bits, int_encoding, int_offset, libbpf_get_error, member_bitfield_size,
    members,
};
use crate::sys::libc::strerror;
use crate::text::capi::strscpy;

const MAP_SHA_SIZE: u32 = 32;
const BTF_MAX_UNWRAP: usize = 32;

/// abi_fail(): why the check failed, which strsprintf() formats from
/// the C's format and the string `arg` it converts, unless NULL, into the
/// `detail_sz` bytes at `detail`, or "?" when that does not fit; and
/// -EOPNOTSUPP.
///
/// # Safety
///
/// `detail` is NULL or room for `detail_sz` bytes, `arg` NULL or a C
/// string, and `fmt` converts one string when `arg` is not NULL.
unsafe fn fail(detail: *mut c_char, detail_sz: usize, fmt: &CStr, arg: *const c_char) -> c_int {
    if !detail.is_null() && detail_sz != 0 {
        // SAFETY: the caller's room, and the format with what it converts.
        let n = unsafe {
            if arg.is_null() {
                crate::text::csprintf!(detail, detail_sz, fmt.as_ptr())
            } else {
                crate::text::csprintf!(detail, detail_sz, fmt.as_ptr(), arg)
            }
        };
        if n < 0 {
            // SAFETY: the caller's room, and a C string.
            unsafe { strscpy(detail, c"?".as_ptr(), detail_sz) };
        }
    }
    -EOPNOTSUPP
}

/// The type `t` is, or NULL.
///
/// # Safety
///
/// `t` is NULL or a type of a BTF.
unsafe fn type_of<'a>(t: *const BtfType) -> Option<&'a BtfType> {
    // SAFETY: the caller's type, or NULL.
    unsafe { t.as_ref() }
}

/// The type `id` names past typedefs and modifiers, or NULL for one
/// that does not resolve within BTF_MAX_UNWRAP steps.
///
/// # Safety
///
/// `btf` is a BTF.
unsafe fn unwrap_type(btf: *const Btf, mut id: u32) -> *const BtfType {
    for _ in 0..BTF_MAX_UNWRAP {
        // SAFETY: the caller's BTF.
        let t = unsafe { btf__type_by_id(btf, id) };
        // SAFETY: a type of the BTF, or NULL.
        let Some(ty) = (unsafe { type_of(t) }) else {
            return ptr::null();
        };
        if ty.kind() != KIND_TYPEDEF && !ty.is_mod() {
            return t;
        }
        id = ty.size_type;
    }
    ptr::null()
}

/// The member of the struct `t` named `name`, and its index into
/// `*index`, or NULL.
///
/// # Safety
///
/// `btf` is a BTF and `t` a struct type of it.
unsafe fn find_member(
    btf: *const Btf,
    t: *const BtfType,
    name: &CStr,
    index: &mut u32,
) -> *const BtfMember {
    // SAFETY: the caller's struct type, and its vlen() members.
    unsafe {
        let m = members(t);

        for i in 0..(*t).vlen() {
            let member = m.add(i as usize);
            let member_name = btf__name_by_offset(btf, (*member).name_off);

            if !member_name.is_null() && CStr::from_ptr(member_name) == name {
                *index = i;
                return member;
            }
        }
    }
    ptr::null()
}

/// Whether `t` is an integer of `bytes` bytes, all bits its value, and
/// signed or not as `signed` says.
///
/// # Safety
///
/// `t` is NULL or a type of a BTF.
unsafe fn is_int(t: *const BtfType, bytes: u32, signed: bool) -> bool {
    // SAFETY: the caller's type or NULL; an integer type is followed by
    // its encoding.
    unsafe {
        type_of(t).is_some_and(|ty| {
            ty.kind() == KIND_INT
                && ty.size_type == bytes
                && int_offset(t) == 0
                && u32::from(int_bits(t)) == bytes * 8
                && (int_encoding(t) & INT_SIGNED != 0) == signed
        })
    }
}

/// is_unsigned_int().
///
/// # Safety
///
/// As is_int().
unsafe fn is_unsigned_int(t: *const BtfType, bytes: u32) -> bool {
    // SAFETY: the caller's type or NULL.
    unsafe { is_int(t, bytes, false) }
}

/// is_signed_int().
///
/// # Safety
///
/// As is_int().
unsafe fn is_signed_int(t: *const BtfType, bytes: u32) -> bool {
    // SAFETY: the caller's type or NULL.
    unsafe { is_int(t, bytes, true) }
}

/// is_byte_int(): an integer of a byte, signed or not.
///
/// # Safety
///
/// As is_int().
unsafe fn is_byte_int(t: *const BtfType) -> bool {
    // SAFETY: the caller's type or NULL; an integer type is followed by
    // its encoding.
    unsafe {
        type_of(t).is_some_and(|ty| {
            ty.kind() == KIND_INT && ty.size_type == 1 && int_offset(t) == 0 && int_bits(t) == 8
        })
    }
}

/// Whether `t` is a type, of `kind`.
///
/// # Safety
///
/// As is_int().
unsafe fn is_kind(t: *const BtfType, kind: u16) -> bool {
    // SAFETY: the caller's type or NULL.
    unsafe { type_of(t) }.is_some_and(|ty| ty.kind() == kind)
}

/// The type of the member `m`, past typedefs and modifiers, or NULL for
/// no member.
///
/// # Safety
///
/// `btf` is a BTF and `m` NULL or a member of a struct type of it.
unsafe fn member_type(btf: *const Btf, m: *const BtfMember) -> *const BtfType {
    // SAFETY: the caller's BTF and member, or NULL.
    match unsafe { m.as_ref() } {
        // SAFETY: as above.
        Some(m) => unsafe { unwrap_type(btf, m.ty) },
        None => ptr::null(),
    }
}

/// kernel_abi_validate_btf(): whether `btf` has the members the signed
/// loader needs, of the types it needs: 0, or -EOPNOTSUPP with what is
/// missing into the `detail_sz` bytes at `detail`.
///
/// # Safety
///
/// `btf` is NULL or a BTF, and `detail` NULL or room for `detail_sz`
/// bytes.
unsafe fn validate_btf(btf: *const Btf, detail: *mut c_char, detail_sz: usize) -> c_int {
    let mut member_idx = 0u32;

    if !detail.is_null() && detail_sz != 0 {
        // SAFETY: the caller's room.
        unsafe { *detail = 0 };
    }
    if btf.is_null() {
        // SAFETY: the caller's room, and a format that converts nothing.
        return unsafe {
            fail(
                detail,
                detail_sz,
                c"kernel BTF is unavailable; boot a shirudo-patched kernel",
                ptr::null(),
            )
        };
    }

    // SAFETY: the caller's BTF, a C string, and the types it holds,
    // whose kinds are checked before what follows them is read.
    unsafe {
        let map_id = btf__find_by_name_kind(btf, c"bpf_map".as_ptr(), u32::from(KIND_STRUCT));
        if map_id < 0 {
            return fail(
                detail,
                detail_sz,
                c"kernel BTF has no struct bpf_map; boot a shirudo-patched kernel",
                ptr::null(),
            );
        }
        let map = btf__type_by_id(btf, map_id as u32);
        if map.is_null() {
            return fail(
                detail,
                detail_sz,
                c"kernel BTF cannot resolve struct bpf_map",
                ptr::null(),
            );
        }

        let sha = find_member(btf, map, c"sha", &mut member_idx);
        if sha.is_null() {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_map.sha is missing; boot a shirudo-patched kernel",
                ptr::null(),
            );
        }
        if member_bitfield_size(map, member_idx) != 0 {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_map.sha must be a non-bitfield",
                ptr::null(),
            );
        }
        let sha_type = unwrap_type(btf, (*sha).ty);
        if !is_kind(sha_type, KIND_ARRAY) {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_map.sha must have type u8[32]",
                ptr::null(),
            );
        }
        let sha_array = array(sha_type);
        let elem_type = unwrap_type(btf, (*sha_array).ty);
        if (*sha_array).nelems != MAP_SHA_SIZE || !is_unsigned_int(elem_type, 1) {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_map.sha must have type u8[32]",
                ptr::null(),
            );
        }

        let excl_prog_sha = find_member(btf, map, c"excl_prog_sha", &mut member_idx);
        if excl_prog_sha.is_null() {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_map.excl_prog_sha is missing; boot a shirudo-patched kernel",
                ptr::null(),
            );
        }
        if member_bitfield_size(map, member_idx) != 0 {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_map.excl_prog_sha must be a non-bitfield",
                ptr::null(),
            );
        }
        let excl_type = unwrap_type(btf, (*excl_prog_sha).ty);
        if !is_kind(excl_type, KIND_PTR) {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_map.excl_prog_sha must have pointer type",
                ptr::null(),
            );
        }
        let elem_type = unwrap_type(btf, (*excl_type).size_type);
        if !is_byte_int(elem_type) {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_map.excl_prog_sha must point to a byte",
                ptr::null(),
            );
        }

        let aux_id = btf__find_by_name_kind(btf, c"bpf_prog_aux".as_ptr(), u32::from(KIND_STRUCT));
        if aux_id < 0 {
            return fail(
                detail,
                detail_sz,
                c"kernel BTF has no struct bpf_prog_aux; boot a shirudo-patched kernel",
                ptr::null(),
            );
        }
        let aux = btf__type_by_id(btf, aux_id as u32);
        if aux.is_null() {
            return fail(
                detail,
                detail_sz,
                c"kernel BTF cannot resolve struct bpf_prog_aux",
                ptr::null(),
            );
        }

        let sig = find_member(btf, aux, c"sig", &mut member_idx);
        if sig.is_null() {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_prog_aux.sig is missing; boot a shirudo-patched kernel",
                ptr::null(),
            );
        }
        let sig_type = unwrap_type(btf, (*sig).ty);
        if !is_kind(sig_type, KIND_STRUCT) {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_prog_aux.sig must have struct type",
                ptr::null(),
            );
        }

        let keyring_serial = find_member(btf, sig_type, c"keyring_serial", &mut member_idx);
        if keyring_serial.is_null() || !is_signed_int(member_type(btf, keyring_serial), 4) {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_prog_aux.sig.keyring_serial must have type s32",
                ptr::null(),
            );
        }
        let keyring_type = find_member(btf, sig_type, c"keyring_type", &mut member_idx);
        if keyring_type.is_null() || !is_unsigned_int(member_type(btf, keyring_type), 1) {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_prog_aux.sig.keyring_type must have type u8",
                ptr::null(),
            );
        }
        let verdict = find_member(btf, sig_type, c"verdict", &mut member_idx);
        if verdict.is_null() || !is_unsigned_int(member_type(btf, verdict), 1) {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_prog_aux.sig.verdict must have type u8",
                ptr::null(),
            );
        }
    }
    0
}

/// kernel_abi_check(): kernel_abi_validate_btf() of the running kernel's
/// BTF.
///
/// # Safety
///
/// `detail` is NULL or room for `detail_sz` bytes.
unsafe fn check(detail: *mut c_char, detail_sz: usize) -> c_int {
    if !detail.is_null() && detail_sz != 0 {
        // SAFETY: the caller's room.
        unsafe { *detail = 0 };
    }
    // SAFETY: what libbpf returns, a BTF or what stands for an error.
    let btf = unsafe { btf__load_vmlinux_btf() };
    // SAFETY: as above.
    let err = unsafe { libbpf_get_error(btf.cast()) };
    if err != 0 {
        // SAFETY: the caller's room, the C's format, and the string it
        // converts.
        return unsafe {
            fail(
                detail,
                detail_sz,
                c"cannot read target kernel BTF: %s; boot a shirudo-patched kernel",
                strerror(err.wrapping_neg() as c_int),
            )
        };
    }
    // SAFETY: the BTF libbpf loaded, freed once, and the caller's room.
    unsafe {
        let ret = validate_btf(btf, detail, detail_sz);

        btf__free(btf);
        ret
    }
}

pub(crate) use capi::kernel_abi_check;

mod capi {
    use core::ffi::{c_char, c_int};

    use crate::sys::btf::Btf;

    /// # Safety
    ///
    /// `btf` is NULL or a BTF, and `detail` NULL or room for
    /// `detail_sz` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn kernel_abi_validate_btf(
        btf: *const Btf,
        detail: *mut c_char,
        detail_sz: usize,
    ) -> c_int {
        // SAFETY: the caller passes a BTF or NULL, and the room.
        unsafe { super::validate_btf(btf, detail, detail_sz) }
    }

    /// # Safety
    ///
    /// `detail` is NULL or room for `detail_sz` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn kernel_abi_check(detail: *mut c_char, detail_sz: usize) -> c_int {
        // SAFETY: the caller passes the room.
        unsafe { super::check(detail, detail_sz) }
    }
}
