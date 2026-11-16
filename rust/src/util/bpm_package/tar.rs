// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The ustar headers of a `.bee`, and the names of its members.

use core::ffi::c_int;

use super::UpatchMember;
use crate::errno::{EINVAL, ENAMETOOLONG, EOVERFLOW};
use crate::text::name_has_suffix;

/// A ustar block: a header, or a piece of a member's data.
pub(super) const BLOCK: usize = 512;

/// The fields of a header.
pub(super) const NAME: core::ops::Range<usize> = 0..100;
pub(super) const SIZE: core::ops::Range<usize> = 124..136;
const CHKSUM: core::ops::Range<usize> = 148..156;
pub(super) const TYPEFLAG: usize = 156;
pub(super) const PREFIX: usize = 345;

/// Digits and nothing but blanks or NULs around them: a field read up to
/// its first stray byte, or a base-256 size read as zero, put the next
/// member where no other tar reader would.
pub(super) fn octal(field: &[u8]) -> Result<u64, c_int> {
    let n = field.len();
    let mut i = 0;
    let mut v = 0u64;

    while i < n && (field[i] == b' ' || field[i] == 0) {
        i += 1;
    }
    let first = i;
    while i < n && (b'0'..=b'7').contains(&field[i]) {
        v = v.checked_mul(8).ok_or(-EOVERFLOW)? | u64::from(field[i] - b'0');
        i += 1;
    }
    if i == first || field[i..].iter().any(|&c| c != b' ' && c != 0) {
        return Err(-EINVAL);
    }
    Ok(v)
}

/// The checksum is the header's byte sum with its own field as blanks.
pub(super) fn header_ok(h: &[u8; BLOCK]) -> bool {
    let Ok(want) = octal(&h[CHKSUM]) else {
        return false;
    };
    let sum: u64 = h
        .iter()
        .enumerate()
        .map(|(i, &c)| u64::from(if CHKSUM.contains(&i) { b' ' } else { c }))
        .sum();

    sum == want
}

/// The size of a member's data, read up to the block its last byte ends.
pub(super) fn padding(size: u64) -> u64 {
    (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64
}

/// A relative path of components that are neither empty nor `.` nor
/// `..`, which may end in a slash.
pub(crate) fn archive_rel_ok(name: &[u8]) -> bool {
    if name.first().is_none_or(|&c| c == b'/') {
        return false;
    }
    let mut rest = name;
    while !rest.is_empty() {
        let n = rest.iter().position(|&c| c == b'/').unwrap_or(rest.len());

        if matches!(&rest[..n], b"" | b"." | b"..") {
            return false;
        }
        rest = &rest[(n + 1).min(rest.len())..];
    }
    true
}

/// What a file of a package's upatches/ is by its name:
/// `<x>.unload.upatch` an unload directive, any other `<x>.upatch` a
/// load, and a hidden name neither.
pub(crate) fn upatch_member(name: &[u8]) -> UpatchMember {
    if name.first().is_none_or(|&c| c == b'.') || name.contains(&0) {
        return UpatchMember::Other;
    }
    if name_has_suffix(name, b".unload.upatch") {
        return UpatchMember::Unload;
    }
    if name_has_suffix(name, b".upatch") {
        return UpatchMember::Load;
    }
    UpatchMember::Other
}

/// The other half of a load or unload name into `out`, terminated.
pub(crate) fn upatch_pair(name: &[u8], out: &mut [u8]) -> c_int {
    let (from, to): (&[u8], &[u8]) = match upatch_member(name) {
        UpatchMember::Load => (b".upatch", b".unload.upatch"),
        UpatchMember::Unload => (b".unload.upatch", b".upatch"),
        UpatchMember::Other => return -EINVAL,
    };
    let base = name.len() - from.len();

    if base >= out.len() || to.len() >= out.len() - base {
        return -ENAMETOOLONG;
    }
    out[..base].copy_from_slice(&name[..base]);
    out[base..base + to.len()].copy_from_slice(to);
    out[base + to.len()] = 0;
    0
}

/// `<dir>/<member>` for a `dir` other than `.`.
pub(super) fn package_member_name_ok(name: &[u8], member: Option<&[u8]>) -> bool {
    let Some(member) = member else {
        return false;
    };
    if !archive_rel_ok(name) {
        return false;
    }
    let Some(slash) = name.iter().position(|&c| c == b'/') else {
        return false;
    };
    slash != 0 && !name.starts_with(b"./") && archive_rel_ok(member) && &name[slash + 1..] == member
}
