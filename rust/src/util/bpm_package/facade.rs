// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The package reader as Rust code calls it, with what it reads owned.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use super::archive::{self, Found};
use super::publication::{self, Signed};
use super::{IndexEntry, index};
use crate::errno::EINVAL;
use crate::heap::xfree;
use crate::util::bpm_oci::{Client, MAX_ENTRIES};
use crate::util::bpm_tree::TreePublication;

/// A negative errno.
type Result<T> = core::result::Result<T, c_int>;

/// A member's bytes, which the xmalloc family holds with a NUL after
/// them.
pub(crate) struct Member {
    data: *mut u8,
    len: usize,
}

impl Member {
    pub(crate) fn bytes(&self) -> &[u8] {
        if self.data.is_null() {
            return &[];
        }
        // SAFETY: a member read holds len bytes at data.
        unsafe { core::slice::from_raw_parts(self.data, self.len) }
    }

    /// The bytes, writable, as text_sanitize() takes them.
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        if self.data.is_null() {
            return &mut [];
        }
        // SAFETY: a member read holds len bytes at data, this one's own.
        unsafe { core::slice::from_raw_parts_mut(self.data, self.len) }
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        // SAFETY: the reader's allocation of len + 1 bytes, or NULL.
        unsafe { xfree(self.data.cast(), self.len + 1) };
    }
}

/// `member` of the package `archive`, in its directory `package_dir`
/// when given, at most `max` bytes; `found_dir` takes the directory it
/// was found in.
pub(crate) fn read_member_in(
    archive: &CStr,
    member: &[u8],
    package_dir: Option<&[u8]>,
    found_dir: Option<&mut [u8]>,
    max: usize,
) -> Result<Member> {
    let mut read = Member {
        data: ptr::null_mut(),
        len: 0,
    };
    let mut found = Found {
        out: &mut read.data,
        out_len: &mut read.len,
        dir: found_dir,
    };

    match archive::read_member_in(archive.as_ptr(), Some(member), package_dir, &mut found, max) {
        0 => Ok(read),
        err => Err(err),
    }
}

/// Calls `visit` with the name and tar type of each member of the
/// package in `package_dir`.
pub(crate) fn visit_members(
    archive: &CStr,
    package_dir: Option<&[u8]>,
    visit: &mut dyn FnMut(&CStr, c_char) -> c_int,
) -> c_int {
    archive::visit_members(archive.as_ptr(), package_dir, Some(visit))
}

pub(crate) fn extract(archive: &CStr, dest: &CStr) -> c_int {
    archive::extract(archive.as_ptr(), dest)
}

fn signed(payload: &[u8], sig: &[u8]) -> Signed {
    let at = |b: &[u8]| {
        if b.is_empty() {
            ptr::null()
        } else {
            b.as_ptr()
        }
    };

    Signed {
        payload: at(payload),
        payload_len: payload.len(),
        sig: at(sig),
        sig_len: sig.len(),
    }
}

/// Whether `sig` is a CMS signature over `payload` by the certificate
/// at `cert_path`: 0 or -errno.
pub(crate) fn verify_cms(payload: &[u8], sig: &[u8], cert_path: &CStr) -> c_int {
    publication::verify_cms(&signed(payload, sig), cert_path.as_ptr())
}

/// As [`verify_cms`], with the certificate open on `cert_fd`.
pub(crate) fn verify_cms_fd(payload: &[u8], sig: &[u8], cert_fd: c_int) -> c_int {
    publication::verify_cms_fd(&signed(payload, sig), cert_fd)
}

/// The entries of a signed repository index.
pub(crate) fn index_parse(body: &[u8]) -> Result<Vec<IndexEntry>> {
    let mut entries = vec![IndexEntry::new(); MAX_ENTRIES];
    let mut n = 0;

    match index::index_parse(body, entries.as_mut_ptr(), &mut n) {
        0 => {
            entries.truncate(usize::try_from(n).map_err(|_| -EINVAL)?);
            Ok(entries)
        }
        err => Err(err),
    }
}

/// The tree publication at `reference` of `repository`, verified against
/// the certificate at `cert_path`, into `out`, with the digest of its
/// manifest into `manifest_digest`.
/// The checked bytes of the tree publication at `repository:reference`,
/// against `trusted`, or the certificate at `cert_path` without one, and
/// its manifest's digest.
pub(crate) fn fetch_document(
    client: &mut Client,
    repository: &[u8],
    reference: &[u8],
    cert_path: Option<&CStr>,
    trusted: Option<&crate::util::keys::TrustedSet>,
) -> core::result::Result<(Vec<u8>, Vec<u8>), c_int> {
    let mut payload = crate::util::bpm_oci::BpmBuffer::new();
    let mut digest = [0u8; 128];
    let ret = publication::fetch_document(
        client.as_mut(),
        repository,
        reference,
        cert_path.map_or(core::ptr::null(), CStr::as_ptr),
        trusted,
        &mut payload,
        &mut digest,
    );
    if ret != 0 {
        return Err(ret);
    }
    // SAFETY: the payload's len bytes, copied before it is freed.
    let document = unsafe { crate::ffi::slice(payload.data, payload.len) }.to_vec();
    crate::util::bpm_oci::buffer_free(&mut payload);
    Ok((document, crate::text::cstr(&digest).to_vec()))
}

pub(crate) fn fetch_publication(
    client: &mut Client,
    repository: &[u8],
    reference: &[u8],
    cert_path: &CStr,
    trusted: Option<&crate::util::keys::TrustedSet>,
    out: &mut TreePublication,
    manifest_digest: &mut [u8],
) -> c_int {
    publication::fetch_publication(
        client.as_mut(),
        repository,
        reference,
        cert_path.as_ptr(),
        trusted,
        out,
        manifest_digest,
    )
}
