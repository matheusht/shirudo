// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C interface of `util/bpm_package.h`.

use core::ffi::{CStr, c_char, c_int, c_void};

use super::archive::{self, Found};
use super::publication::{self, Signed};
use super::{IndexEntry, PackageInfo, UpatchMember, index, info, semver, tar};
use crate::ffi;
use crate::util::bpm_oci::{BpmBuffer, Descriptor, OciClient};
use crate::util::bpm_tree::TreePublication;

/// The `bpm_pkg_member_fn` a member walk calls.
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
/// `body` holds `len` bytes, `entries` has room for `BPM_MAX_ENTRIES`
/// entries and `n_entries` is an int.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_index_parse(
    body: *const u8,
    len: usize,
    entries: *mut IndexEntry,
    n_entries: *mut c_int,
) -> c_int {
    // SAFETY: the caller passes the body, room for the entries and the
    // count.
    unsafe { index::index_parse(ffi::slice(body, len), entries, &mut *n_entries) }
}

/// # Safety
///
/// `a` and `b` are C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_semver_compare(a: *const c_char, b: *const c_char) -> c_int {
    // SAFETY: the caller passes two C strings.
    unsafe { semver::compare(ffi::c_str(a), ffi::c_str(b)) }
}

/// # Safety
///
/// `s` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_semver_valid(s: *const c_char) -> bool {
    // SAFETY: the caller passes NULL or a C string.
    unsafe { opt_bytes(s) }.is_some_and(semver::valid)
}

/// # Safety
///
/// `payload` and `sig` are NULL or hold their lengths' bytes, and
/// `cert_path` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_verify_cms(
    payload: *const u8,
    payload_len: usize,
    sig: *const u8,
    sig_len: usize,
    cert_path: *const c_char,
) -> c_int {
    let signed = Signed {
        payload,
        payload_len,
        sig,
        sig_len,
    };

    publication::verify_cms(&signed, cert_path)
}

/// # Safety
///
/// `payload` and `sig` are NULL or hold their lengths' bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_verify_cms_fd(
    payload: *const u8,
    payload_len: usize,
    sig: *const u8,
    sig_len: usize,
    cert_fd: c_int,
) -> c_int {
    let signed = Signed {
        payload,
        payload_len,
        sig,
        sig_len,
    };

    publication::verify_cms_fd(&signed, cert_fd)
}

/// # Safety
///
/// `name` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_archive_rel_ok(name: *const c_char) -> bool {
    // SAFETY: the caller passes NULL or a C string.
    unsafe { opt_bytes(name) }.is_some_and(tar::archive_rel_ok)
}

/// # Safety
///
/// `name` holds `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_upatch_member(name: *const c_char, len: usize) -> UpatchMember {
    // SAFETY: the caller passes len bytes at name.
    tar::upatch_member(unsafe { ffi::slice(name.cast(), len) })
}

/// # Safety
///
/// `name` holds `len` bytes and `out` has room for `cap`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_upatch_pair(
    name: *const c_char,
    len: usize,
    out: *mut c_char,
    cap: usize,
) -> c_int {
    // SAFETY: the caller passes len bytes at name and the room at out.
    unsafe {
        tar::upatch_pair(
            ffi::slice(name.cast(), len),
            ffi::bytes_mut(out.cast(), cap),
        )
    }
}

/// # Safety
///
/// `archive` and `package_dir` are NULL or C strings, and `visit` NULL
/// or a function that takes `ctx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_pkg_visit_members(
    archive: *const c_char,
    package_dir: *const c_char,
    visit: Option<MemberFn>,
    ctx: *mut c_void,
) -> c_int {
    // SAFETY: the caller passes NULL or a C string.
    let package_dir = unsafe { opt_bytes(package_dir) };

    match visit {
        Some(visit) => {
            let mut call = |member: &CStr, ty: c_char| {
                // SAFETY: the caller's function, with its context and the
                // member's terminated name, which lives for the call.
                unsafe { visit(ctx, member.as_ptr(), ty) }
            };
            archive::visit_members(archive, package_dir, Some(&mut call))
        }
        None => archive::visit_members(archive, package_dir, None),
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
/// `archive`, `member` and `package_dir` are NULL or C strings,
/// `found_dir` is NULL or has room for `found_dir_sz`, and `out` and
/// `out_len` take the member.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_pkg_read_member_in(
    archive: *const c_char,
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

        archive::read_member_in(
            archive,
            opt_bytes(member),
            opt_bytes(package_dir),
            &mut found,
            max,
        )
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

        archive::read_member_fd(
            fd,
            opt_bytes(member),
            opt_bytes(package_dir),
            &mut found,
            max,
        )
    }
}

/// # Safety
///
/// `archive` and `member` are NULL or C strings, and `out` and `out_len`
/// take the member.
#[unsafe(no_mangle)]
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
/// `archive` is NULL or a C string and `dest` a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_pkg_extract(archive: *const c_char, dest: *const c_char) -> c_int {
    // SAFETY: the caller passes a C string.
    archive::extract(archive, unsafe { CStr::from_ptr(dest) })
}

/// # Safety
///
/// `archive` is NULL or a C string and `info` a package info, its cert
/// NULL or one `xfree()` may release.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_pkg_load_info(
    archive: *const c_char,
    info: *mut PackageInfo,
) -> c_int {
    // SAFETY: the caller passes its info.
    info::load_info(archive, unsafe { &mut *info })
}

/// # Safety
///
/// payload and sig point to descriptors, out has cap bytes and len is
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_tree_manifest(
    payload: *const Descriptor,
    sig: *const Descriptor,
    out: *mut c_char,
    cap: usize,
    len: *mut usize,
) -> c_int {
    // SAFETY: the caller passes a writable length.
    let len = unsafe { &mut *len };
    *len = 0;
    // SAFETY: the caller passes a descriptor.
    let payload = unsafe { &*payload };
    // SAFETY: the caller passes a descriptor.
    let sig = unsafe { &*sig };
    // SAFETY: the caller passes cap output bytes.
    let out = unsafe { ffi::bytes_mut(out.cast(), cap) };
    match publication::tree_manifest(payload, sig, out) {
        Ok(n) => {
            *len = n;
            0
        }
        Err(err) => err,
    }
}

/// # Safety
///
/// c points to a client, repository and reference are C strings,
/// cert_path is NULL or a C string, trusted is NULL or a trusted set,
/// payload is writable and manifest_digest has digest_sz bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_tree_fetch_document(
    c: *mut OciClient,
    repository: *const c_char,
    reference: *const c_char,
    cert_path: *const c_char,
    trusted: *const c_void,
    payload: *mut BpmBuffer,
    manifest_digest: *mut c_char,
    digest_sz: usize,
) -> c_int {
    // SAFETY: the caller lends its client, strings, payload and digest.
    unsafe {
        publication::fetch_document(
            &mut *c,
            ffi::c_str(repository),
            ffi::c_str(reference),
            cert_path,
            trusted,
            &mut *payload,
            ffi::bytes_mut(manifest_digest.cast(), digest_sz),
        )
    }
}

/// # Safety
///
/// `c` is a client, `repository` and `reference` are C strings,
/// `cert_path` NULL or one, `publication` a publication to fill and
/// `manifest_digest` has room for `digest_sz`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_tree_fetch_publication(
    c: *mut OciClient,
    repository: *const c_char,
    reference: *const c_char,
    cert_path: *const c_char,
    trusted: *const c_void,
    publication: *mut TreePublication,
    manifest_digest: *mut c_char,
    digest_sz: usize,
) -> c_int {
    // SAFETY: the caller passes its client, C strings, its publication
    // and room for the digest.
    unsafe {
        publication::fetch_publication(
            &mut *c,
            ffi::c_str(repository),
            ffi::c_str(reference),
            cert_path,
            trusted,
            publication,
            ffi::bytes_mut(manifest_digest.cast(), digest_sz),
        )
    }
}
