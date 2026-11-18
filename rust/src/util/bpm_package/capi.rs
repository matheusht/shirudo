// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C-shaped interface the crate still calls.

use core::ffi::{CStr, c_char, c_int, c_void};

use super::archive::{self, Found};
use super::publication;
use super::{PackageInfo, info, semver};
use crate::ffi;

type MemberFn = unsafe extern "C" fn(ctx: *mut c_void, member: *const c_char, ty: c_char) -> c_int;

/// A C string the caller may pass as NULL.
///
/// # Safety
///
/// `s` is NULL or a C string valid for `'a`.
unsafe fn opt_bytes<'a>(s: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller passes NULL or a C string.
    (!s.is_null()).then(|| unsafe { ffi::c_str(s) })
}

/// # Safety
///
/// `s` is NULL or a C string.
pub unsafe extern "C" fn bpm_semver_valid(s: *const c_char) -> bool {
    // SAFETY: the caller passes NULL or a C string.
    unsafe { opt_bytes(s) }.is_some_and(semver::valid)
}

/// # Safety
///
/// `archive` and `member` are NULL or C strings, and `out` and `out_len`
/// take the member.
pub unsafe extern "C" fn bpm_pkg_read_member(
    archive: *const c_char,
    member: *const c_char,
    out: *mut *mut u8,
    out_len: *mut usize,
    max: usize,
) -> c_int {
    // SAFETY: the caller passes NULL or C strings and the two outputs.
    unsafe {
        let mut found = Found {
            out: &mut *out,
            out_len: &mut *out_len,
            dir: None,
        };

        archive::read_member_in(archive, opt_bytes(member), None, &mut found, max)
    }
}

/// # Safety
///
/// `archive` is NULL or a C string and `info` a package info, its cert
/// NULL or one `xfree()` may release.
pub unsafe extern "C" fn bpm_pkg_load_info(
    archive: *const c_char,
    info: *mut PackageInfo,
) -> c_int {
    // SAFETY: the caller passes its info.
    info::load_info(archive, unsafe { &mut *info })
}

/// The manifest of a tree publication whose layers are `payload` and
/// `sig`, as bpm tree append writes it, into `out` of `cap` bytes with
/// its length in `*len`: 0 or -errno.
///
/// # Safety
///
/// `payload` and `sig` are descriptors, `out` has room for `cap` bytes
/// and `len` for a size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_tree_manifest(
    payload: *const crate::util::bpm_oci::Descriptor,
    sig: *const crate::util::bpm_oci::Descriptor,
    out: *mut c_char,
    cap: usize,
    len: *mut usize,
) -> c_int {
    // SAFETY: the caller's descriptors, room and size.
    unsafe {
        *len = 0;
        let room = ffi::bytes_mut(out.cast(), cap);
        match publication::emit_tree_manifest(&*payload, &*sig, room) {
            Ok(n) => {
                *len = n;
                0
            }
            Err(err) => err,
        }
    }
}

/// # Safety
///
/// fd is an open archive descriptor, package_dir is NULL or a C string,
/// and visit is NULL or a function that takes ctx.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_pkg_visit_members_fd(
    fd: c_int,
    package_dir: *const c_char,
    visit: Option<MemberFn>,
    ctx: *mut c_void,
) -> c_int {
    // SAFETY: the caller passes NULL or a C string.
    let package_dir = unsafe { opt_bytes(package_dir) };
    // SAFETY: the caller lends an open descriptor for this call.
    let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };

    match visit {
        Some(visit) => {
            let mut call = |member: &CStr, ty: c_char| {
                // SAFETY: the caller's function, with its context and the
                // member's terminated name, which lives for the call.
                unsafe { visit(ctx, member.as_ptr(), ty) }
            };
            archive::visit_members_fd(fd, package_dir, Some(&mut call))
        }
        None => archive::visit_members_fd(fd, package_dir, None),
    }
}

/// # Safety
///
/// fd is an open archive descriptor, member and package_dir are NULL or
/// C strings, found_dir is NULL or has found_dir_sz bytes of room, and
/// out and out_len take the member.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_pkg_read_member_fd(
    fd: c_int,
    member: *const c_char,
    package_dir: *const c_char,
    found_dir: *mut c_char,
    found_dir_sz: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
    max: usize,
) -> c_int {
    // SAFETY: the caller passes NULL or C strings, NULL or the room at
    // found_dir, and the two outputs.
    unsafe {
        let mut found = Found {
            out: &mut *out,
            out_len: &mut *out_len,
            dir: (!found_dir.is_null()).then(|| ffi::bytes_mut(found_dir.cast(), found_dir_sz)),
        };

        // SAFETY: the caller lends an open descriptor for this call.
        let fd = std::os::fd::BorrowedFd::borrow_raw(fd);
        archive::read_member_fd(
            fd,
            opt_bytes(member),
            opt_bytes(package_dir),
            &mut found,
            max,
        )
    }
}
