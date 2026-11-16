// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `.bee` archives, signed repository indexes and tree publications,
//! behind `util/bpm_package.h`: the index a target picks a package from,
//! the order of versions, the ustar members of a package, and the signed
//! tree it fetches.

mod archive;
mod capi;
mod facade;
mod index;
mod info;
mod publication;
mod semver;
mod tar;

pub(crate) use facade::{
    Member, extract, fetch_publication, index_parse, read_member_in, verify_cms, verify_cms_fd,
    visit_members,
};
pub(crate) use semver::compare as semver_compare;
pub(crate) use tar::{archive_rel_ok, upatch_member, upatch_pair};

use super::bpm_oci::{MAX_DIGEST, MAX_ENDPOINT, MAX_NAME};

/// `struct bpm_index_entry`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IndexEntry {
    pub(crate) name: [u8; MAX_NAME],
    pub(crate) version: [u8; MAX_NAME],
    pub(crate) repository: [u8; MAX_ENDPOINT],
    pub(crate) manifest_digest: [u8; MAX_DIGEST],
    pub(crate) package_digest: [u8; MAX_DIGEST],
    signer: [u8; MAX_DIGEST],
    pub(crate) package_size: i64,
}

/// `struct bpm_package_info`: a package's identity, and its signer's
/// certificate in an allocation of `cert_len + 1` bytes, which `xfree()`
/// releases.
#[repr(C)]
pub struct PackageInfo {
    name: [u8; MAX_NAME],
    version: [u8; MAX_NAME],
    signer: [u8; MAX_DIGEST],
    cert: *mut u8,
    cert_len: usize,
}

/// `enum bpm_upatch_member`: what a file of a package's upatches/ is.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UpatchMember {
    Other = 0,
    Load = 1,
    Unload = 2,
}

const _: () = assert!(size_of::<IndexEntry>() == 1160);
const _: () = assert!(size_of::<PackageInfo>() == 400);
const _: () = assert!(size_of::<UpatchMember>() == size_of::<core::ffi::c_int>());

impl IndexEntry {
    pub(crate) const fn new() -> Self {
        IndexEntry {
            name: [0; MAX_NAME],
            version: [0; MAX_NAME],
            repository: [0; MAX_ENDPOINT],
            manifest_digest: [0; MAX_DIGEST],
            package_digest: [0; MAX_DIGEST],
            signer: [0; MAX_DIGEST],
            package_size: 0,
        }
    }
}
