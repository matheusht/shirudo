// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The kernel ABI check behind `util/kernel_abi.h`. The signed loader
//! requires map hashing, exclusive-map binding and signed program
//! metadata. Stock kernels can expose BPF and the BPF LSM while still
//! lacking this contract, so those kernels are rejected before
//! BPF_PROG_LOAD.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use crate::bpf::btf::{
    Btf, INT_SIGNED, KIND_ARRAY, KIND_CONST, KIND_FUNC, KIND_INT, KIND_PTR, KIND_RESTRICT,
    KIND_STRUCT, KIND_TYPE_TAG, KIND_TYPEDEF, KIND_VOLATILE, Member,
};
use crate::errno::{E2BIG, EINVAL, EOPNOTSUPP};
use crate::skel::EmbeddedBpf;
use crate::sys::libc::strerror;
use crate::text::capi::strscpy;
use crate::util::kernel_btf;

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

/// The type `id` names past typedefs and modifiers, or none for one
/// that does not resolve within BTF_MAX_UNWRAP steps.
fn unwrap_type(btf: &Btf, mut id: u32) -> Option<u32> {
    for _ in 0..BTF_MAX_UNWRAP {
        if !btf.has(id) {
            return None;
        }
        if !matches!(
            btf.kind(id),
            KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG
        ) {
            return Some(id);
        }
        id = btf.size_or_type(id);
    }
    None
}

/// The member of the struct `t` named `name`.
fn find_member(btf: &Btf, t: u32, name: &[u8]) -> Option<Member> {
    btf.members(t)
        .find(|m| btf.str_at(m.name_off) == Some(name))
}

/// Whether `t` is an integer of `bytes` bytes, all bits its value, and
/// signed or not as `signed` says.
fn is_int(btf: &Btf, t: Option<u32>, bytes: u32, signed: bool) -> bool {
    t.is_some_and(|t| {
        btf.kind(t) == KIND_INT
            && btf.size_or_type(t) == bytes
            && btf.int_offset(t) == 0
            && u32::from(btf.int_bits(t)) == bytes * 8
            && (btf.int_encoding(t) & INT_SIGNED != 0) == signed
    })
}

/// is_byte_int(): an integer of a byte, signed or not.
fn is_byte_int(btf: &Btf, t: Option<u32>) -> bool {
    t.is_some_and(|t| {
        btf.kind(t) == KIND_INT
            && btf.size_or_type(t) == 1
            && btf.int_offset(t) == 0
            && btf.int_bits(t) == 8
    })
}

/// Whether `t` is a type, of `kind`.
fn is_kind(btf: &Btf, t: Option<u32>, kind: u32) -> bool {
    t.is_some_and(|t| btf.kind(t) == kind)
}

/// The type of the member `m`, past typedefs and modifiers.
fn member_type(btf: &Btf, m: Option<Member>) -> Option<u32> {
    unwrap_type(btf, m?.ty)
}

/// kernel_abi_validate_btf(): whether `btf` has the members the signed
/// loader needs, of the types it needs: 0, or -EOPNOTSUPP with what is
/// missing into the `detail_sz` bytes at `detail`.
///
/// # Safety
///
/// `detail` is NULL or room for `detail_sz` bytes.
unsafe fn validate_btf(btf: Option<&Btf>, detail: *mut c_char, detail_sz: usize) -> c_int {
    if !detail.is_null() && detail_sz != 0 {
        // SAFETY: the caller's room.
        unsafe { *detail = 0 };
    }
    let Some(btf) = btf else {
        // SAFETY: the caller's room, and a format that converts nothing.
        return unsafe {
            fail(
                detail,
                detail_sz,
                c"kernel BTF is unavailable; boot a shirudo-patched kernel",
                ptr::null(),
            )
        };
    };

    // SAFETY: the caller's room, and the formats, which convert nothing.
    unsafe {
        let Some(map) = btf.find_by_name_kind(b"bpf_map", KIND_STRUCT) else {
            return fail(
                detail,
                detail_sz,
                c"kernel BTF has no struct bpf_map; boot a shirudo-patched kernel",
                ptr::null(),
            );
        };
        if !btf.has(map) {
            return fail(
                detail,
                detail_sz,
                c"kernel BTF cannot resolve struct bpf_map",
                ptr::null(),
            );
        }

        let Some(sha) = find_member(btf, map, b"sha") else {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_map.sha is missing; boot a shirudo-patched kernel",
                ptr::null(),
            );
        };
        if sha.bitfield_size() != 0 {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_map.sha must be a non-bitfield",
                ptr::null(),
            );
        }
        let sha_type = unwrap_type(btf, sha.ty);
        if !is_kind(btf, sha_type, KIND_ARRAY) {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_map.sha must have type u8[32]",
                ptr::null(),
            );
        }
        let sha_array = btf.array(sha_type.unwrap_or(0));
        let elem_type = unwrap_type(btf, sha_array.ty);
        if sha_array.nelems != MAP_SHA_SIZE || !is_int(btf, elem_type, 1, false) {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_map.sha must have type u8[32]",
                ptr::null(),
            );
        }

        let Some(excl_prog_sha) = find_member(btf, map, b"excl_prog_sha") else {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_map.excl_prog_sha is missing; boot a shirudo-patched kernel",
                ptr::null(),
            );
        };
        if excl_prog_sha.bitfield_size() != 0 {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_map.excl_prog_sha must be a non-bitfield",
                ptr::null(),
            );
        }
        let excl_type = unwrap_type(btf, excl_prog_sha.ty);
        if !is_kind(btf, excl_type, KIND_PTR) {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_map.excl_prog_sha must have pointer type",
                ptr::null(),
            );
        }
        let elem_type = unwrap_type(btf, btf.size_or_type(excl_type.unwrap_or(0)));
        if !is_byte_int(btf, elem_type) {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_map.excl_prog_sha must point to a byte",
                ptr::null(),
            );
        }

        let Some(aux) = btf.find_by_name_kind(b"bpf_prog_aux", KIND_STRUCT) else {
            return fail(
                detail,
                detail_sz,
                c"kernel BTF has no struct bpf_prog_aux; boot a shirudo-patched kernel",
                ptr::null(),
            );
        };
        if !btf.has(aux) {
            return fail(
                detail,
                detail_sz,
                c"kernel BTF cannot resolve struct bpf_prog_aux",
                ptr::null(),
            );
        }

        let Some(sig) = find_member(btf, aux, b"sig") else {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_prog_aux.sig is missing; boot a shirudo-patched kernel",
                ptr::null(),
            );
        };
        let sig_type = unwrap_type(btf, sig.ty);
        if !is_kind(btf, sig_type, KIND_STRUCT) {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_prog_aux.sig must have struct type",
                ptr::null(),
            );
        }

        let sig_type = sig_type.unwrap_or(0);
        let keyring_serial = find_member(btf, sig_type, b"keyring_serial");
        if !is_int(btf, member_type(btf, keyring_serial), 4, true) {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_prog_aux.sig.keyring_serial must have type s32",
                ptr::null(),
            );
        }
        let keyring_type = find_member(btf, sig_type, b"keyring_type");
        if !is_int(btf, member_type(btf, keyring_type), 1, false) {
            return fail(
                detail,
                detail_sz,
                c"struct bpf_prog_aux.sig.keyring_type must have type u8",
                ptr::null(),
            );
        }
        let verdict = find_member(btf, sig_type, b"verdict");
        if !is_int(btf, member_type(btf, verdict), 1, false) {
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
    match kernel_btf::load_vmlinux() {
        // SAFETY: the caller's room.
        Ok(btf) => unsafe { validate_btf(Some(&btf), detail, detail_sz) },
        // SAFETY: the caller's room, the C's format, and the string it
        // converts.
        Err(err) => unsafe {
            fail(
                detail,
                detail_sz,
                c"cannot read target kernel BTF: %s; boot a shirudo-patched kernel",
                strerror(-err),
            )
        },
    }
}

/// `LSM_HOOKS_MAX` and `LSM_HOOK_NAME_MAX`.
const LSM_HOOKS_MAX: usize = 128;
const LSM_HOOK_NAME_MAX: usize = 64;
/// `KERNEL_ABI_DETAIL_MAX`.
const DETAIL_MAX: usize = 256;

/// `struct lsm_hooks`: the hooks programs attach to, each once.
#[repr(C)]
pub struct LsmHooks {
    name: [[u8; LSM_HOOK_NAME_MAX]; LSM_HOOKS_MAX],
    n: usize,
}

const _: () = assert!(size_of::<LsmHooks>() == 8200);

impl LsmHooks {
    pub(crate) fn new() -> Box<Self> {
        Box::new(LsmHooks {
            name: [[0; LSM_HOOK_NAME_MAX]; LSM_HOOKS_MAX],
            n: 0,
        })
    }

    fn names(&self) -> impl Iterator<Item = &[u8]> {
        self.name[..self.n.min(LSM_HOOKS_MAX)]
            .iter()
            .map(|n| crate::text::cstr(n))
    }

    /// Adds `hook` unless it is there: -E2BIG when it does not fit.
    fn add(&mut self, hook: &[u8]) -> Result<(), c_int> {
        if self.names().any(|h| h == hook) {
            return Ok(());
        }
        if self.n >= LSM_HOOKS_MAX || hook.len() >= LSM_HOOK_NAME_MAX {
            return Err(-E2BIG);
        }
        let slot = &mut self.name[self.n];
        slot[..hook.len()].copy_from_slice(hook);
        slot[hook.len()] = 0;
        self.n += 1;
        Ok(())
    }
}

/// Adds the hooks the lsm and lsm.s programs of `obj` attach to, which
/// the skeleton generator read from the object: -EINVAL for an object
/// this build does not embed, -E2BIG when they do not fit.
pub(crate) fn lsm_hooks(obj: &EmbeddedBpf, hooks: &mut LsmHooks) -> Result<(), c_int> {
    obj.lsm_hooks()
        .ok_or(-EINVAL)?
        .iter()
        .try_for_each(|h| hooks.add(h.as_bytes()))
}

/// Whether `btf` has a bpf_lsm_<hook> function for every hook, or why
/// not, naming the hooks it lacks as far as the detail holds them.
pub(crate) fn validate_lsm_hooks(btf: Option<&Btf>, hooks: &LsmHooks) -> Result<(), Vec<u8>> {
    let Some(btf) = btf else {
        return Err(b"kernel BTF is unavailable; boot a shirudo-patched kernel".to_vec());
    };
    let mut missing: Vec<u8> = Vec::new();
    let mut n_missing = 0;
    for hook in hooks.names() {
        if btf
            .find_by_name_kind(&[b"bpf_lsm_", hook].concat(), KIND_FUNC)
            .is_some()
        {
            continue;
        }
        let sep: &[u8] = if n_missing > 0 { b", " } else { b"" };
        if missing.len() + sep.len() + hook.len() < DETAIL_MAX {
            missing.extend_from_slice(sep);
            missing.extend_from_slice(hook);
        }
        n_missing += 1;
    }
    if n_missing == 0 {
        return Ok(());
    }
    let plural: &[u8] = if n_missing > 1 { b"s" } else { b"" };
    Err([
        &b"kernel has no LSM hook"[..],
        plural,
        b" ",
        &missing,
        b"; boot a shirudo-patched kernel",
    ]
    .concat())
}

/// validate_lsm_hooks() on the running kernel's BTF.
pub(crate) fn check_lsm_hooks(hooks: &LsmHooks) -> Result<(), Vec<u8>> {
    match kernel_btf::load_vmlinux() {
        Ok(btf) => validate_lsm_hooks(Some(&btf), hooks),
        Err(err) => Err([
            &b"cannot read target kernel BTF: "[..],
            // SAFETY: strerror() gives a C string.
            unsafe { crate::ffi::c_str(strerror(-err)) },
            b"; boot a shirudo-patched kernel",
        ]
        .concat()),
    }
}

/// A detail into the caller's room: -EOPNOTSUPP, the detail "?" when it
/// does not fit.
///
/// # Safety
///
/// `detail` is NULL or room for `detail_sz` bytes.
unsafe fn fail_with(detail: *mut c_char, detail_sz: usize, text: &[u8]) -> c_int {
    if !detail.is_null() && detail_sz != 0 {
        // SAFETY: the caller's room.
        let room = unsafe { core::slice::from_raw_parts_mut(detail.cast::<u8>(), detail_sz) };
        if crate::text::strscpy(room, text).is_err() {
            let _ = crate::text::strscpy(room, b"?");
        }
    }
    -EOPNOTSUPP
}

/// The result of a hook check into the caller's room.
///
/// # Safety
///
/// `detail` is NULL or room for `detail_sz` bytes.
unsafe fn report_hooks(r: Result<(), Vec<u8>>, detail: *mut c_char, detail_sz: usize) -> c_int {
    if !detail.is_null() && detail_sz != 0 {
        // SAFETY: the caller's room.
        unsafe { *detail = 0 };
    }
    match r {
        Ok(()) => 0,
        // SAFETY: the caller's room.
        Err(text) => unsafe { fail_with(detail, detail_sz, &text) },
    }
}

pub(crate) use capi::kernel_abi_check;

mod capi {
    use core::ffi::{c_char, c_int};

    use crate::bpf::btf::Btf;

    /// # Safety
    ///
    /// `btf` is NULL or a BTF shirudo_btf_new() made, and `detail` NULL
    /// or room for `detail_sz` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn kernel_abi_validate_btf(
        btf: *const Btf,
        detail: *mut c_char,
        detail_sz: usize,
    ) -> c_int {
        // SAFETY: the caller passes a BTF or NULL, and the room.
        unsafe { super::validate_btf(btf.as_ref(), detail, detail_sz) }
    }

    /// # Safety
    ///
    /// `detail` is NULL or room for `detail_sz` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn kernel_abi_check(detail: *mut c_char, detail_sz: usize) -> c_int {
        // SAFETY: the caller passes the room.
        unsafe { super::check(detail, detail_sz) }
    }

    /// # Safety
    ///
    /// `obj` is an embedded object and `hooks` a hook list.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn kernel_abi_lsm_hooks(
        obj: *const super::EmbeddedBpf,
        hooks: *mut super::LsmHooks,
    ) -> c_int {
        // SAFETY: the caller passes an object and a list.
        unsafe { super::lsm_hooks(&*obj, &mut *hooks) }
            .err()
            .unwrap_or(0)
    }

    /// # Safety
    ///
    /// `btf` is NULL or a BTF shirudo_btf_new() made, `hooks` a hook
    /// list, and `detail` NULL or room for `detail_sz` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn kernel_abi_validate_lsm_hooks(
        btf: *const Btf,
        hooks: *const super::LsmHooks,
        detail: *mut c_char,
        detail_sz: usize,
    ) -> c_int {
        // SAFETY: the caller passes a BTF or NULL, a list and the room.
        unsafe {
            super::report_hooks(
                super::validate_lsm_hooks(btf.as_ref(), &*hooks),
                detail,
                detail_sz,
            )
        }
    }

    /// # Safety
    ///
    /// `hooks` is a hook list, and `detail` NULL or room for `detail_sz`
    /// bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn kernel_abi_check_lsm_hooks(
        hooks: *const super::LsmHooks,
        detail: *mut c_char,
        detail_sz: usize,
    ) -> c_int {
        // SAFETY: the caller passes a list and the room.
        unsafe { super::report_hooks(super::check_lsm_hooks(&*hooks), detail, detail_sz) }
    }
}
