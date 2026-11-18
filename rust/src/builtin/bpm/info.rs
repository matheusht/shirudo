// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo bpm info`: a package's README, its upatches, and the
//! `.rodata` initial data of one of them, from a local file or an OCI
//! reference.

use core::ffi::c_char;
use std::os::fd::{AsFd, OwnedFd};

use super::{Result, error, message, status};
use crate::errno::{E2BIG, EINVAL, ENODATA, ENOENT, EOPNOTSUPP};
use crate::sys::libc::STDOUT_FILENO;
use crate::text::{cstr, sanitize};
use crate::util::bpm_package::{
    Member, UpatchMember, archive_rel_ok, read_member_fd, upatch_member, visit_members_fd,
};
use crate::util::io::write_complete;
use crate::util::json::MAX_BYTES;
use crate::util::upatch::{
    FILE_MAX as UPATCH_FILE_MAX, Upatch, is_unload, upatch_close, upatch_open_memory,
};
use crate::util::upatch_rodata::upatch_rodata_print;

/// The most a Beefile takes.
const BEEFILE_MAX: usize = 4 << 20;

/// A package to read: a local file, or an OCI reference downloaded into
/// memory.
struct Archive(OwnedFd);

impl Archive {
    fn open(source: &[u8]) -> Result<Archive> {
        super::fetch::package_source_open(source).map(Archive)
    }

    /// The package's Beefile, which says that it is one, and the
    /// directory it is in.
    fn beefile(&self, dir: &mut [u8; 101]) -> Result<crate::util::bpm_package::Member> {
        read_member_fd(self.0.as_fd(), b"Beefile", None, Some(dir), BEEFILE_MAX)
    }

    fn member(&self, member: &[u8], dir: &[u8; 101], max: usize) -> Result<Member> {
        read_member_fd(self.0.as_fd(), member, Some(cstr(dir)), None, max)
    }
}

fn stdout_write(bytes: &[u8]) -> Result {
    // SAFETY: the bytes, to stdout.
    status(unsafe { write_complete(STDOUT_FILENO, bytes.as_ptr().cast(), bytes.len()) })
}

pub(super) fn readme(source: &[u8]) -> Result {
    let archive = Archive::open(source)?;
    let mut dir = [0; 101];

    if let Err(err) = archive.beefile(&mut dir) {
        if err == -ENOENT {
            error(&[b"bpm info: package ", source, b" does not include Beefile"]);
        }
        return Err(err);
    }
    let mut readme = match archive.member(b"README.md", &dir, BEEFILE_MAX) {
        Ok(readme) => readme,
        Err(err) => {
            if err == -ENOENT {
                error(&[
                    b"bpm info: package ",
                    source,
                    b" does not include README.md",
                ]);
            }
            return Err(err);
        }
    };
    let text = readme.bytes_mut();
    sanitize(text, true);
    stdout_write(readme.bytes())
}

/// A member of the package that names an upatch, loads only unless
/// `all`, one line of the list.
fn listed(list: &mut Vec<u8>, member: &[u8], ty: c_char, all: bool) -> Result {
    let Some(base) = member.strip_prefix(b"upatches/") else {
        return Ok(());
    };

    if ty != b'0' as c_char || base.contains(&b'/') {
        return Ok(());
    }
    match upatch_member(base) {
        UpatchMember::Other => return Ok(()),
        UpatchMember::Unload if !all => return Ok(()),
        _ => {}
    }
    if list.len() + member.len() + 1 > MAX_BYTES {
        return Err(-E2BIG);
    }
    let start = list.len();
    list.extend_from_slice(member);
    sanitize(&mut list[start..], false);
    list.push(b'\n');
    Ok(())
}

pub(super) fn upatches(source: &[u8], all: bool) -> Result {
    let archive = Archive::open(source)?;
    let mut dir = [0; 101];
    let mut list = Vec::new();
    let ret = archive.beefile(&mut dir).and_then(|_beefile| {
        status(visit_members_fd(
            archive.0.as_fd(),
            Some(cstr(&dir)),
            &mut |member, ty| match listed(&mut list, member.to_bytes(), ty, all) {
                Ok(()) => 0,
                Err(err) => err,
            },
        ))
    });
    let ret = ret.and_then(|()| {
        if list.is_empty() {
            Ok(())
        } else {
            stdout_write(&list)
        }
    });

    if ret == Err(-ENOENT) {
        error(&[
            b"bpm info upatches: package ",
            source,
            b" does not include Beefile",
        ]);
    }
    ret
}

pub(super) fn data(source: &[u8], member: &[u8], json: bool) -> Result {
    let Some(base) = member.strip_prefix(b"upatches/") else {
        return Err(-EINVAL);
    };

    if !archive_rel_ok(member) || base.contains(&b'/') || upatch_member(base) == UpatchMember::Other
    {
        return Err(-EINVAL);
    }
    let archive = Archive::open(source)?;
    let mut dir = [0; 101];
    if let Err(err) = archive.beefile(&mut dir) {
        if err == -ENOENT {
            error(&[
                b"bpm info data: package ",
                source,
                b" does not include Beefile",
            ]);
        }
        return Err(err);
    }
    let bytes = match archive.member(member, &dir, UPATCH_FILE_MAX) {
        Ok(bytes) => bytes,
        Err(err) => {
            if err == -ENOENT {
                error(&[
                    b"bpm info data: package ",
                    source,
                    b" has no member ",
                    member,
                ]);
            }
            return Err(err);
        }
    };
    let member_path = message(&[member]);
    // SAFETY: an all-zero container is a closed one.
    let mut u: Upatch = unsafe { core::mem::zeroed() };
    let data = bytes.bytes();
    // SAFETY: the member's bytes, which outlive the container, and the
    // container to fill.
    let ret = match unsafe { upatch_open_memory(data.as_ptr().cast(), data.len(), &mut u) } {
        0 if is_unload(&u) => {
            error(&[b"bpm info data: ", member, b" is an unload directive"]);
            Err(-EINVAL)
        }
        0 => {
            // SAFETY: the open container and a C string.
            let ret = unsafe { upatch_rodata_print(&u, member_path.as_ptr(), json) };
            match ret {
                r if r == -ENODATA => error(&[
                    b"bpm info data: ",
                    member,
                    b" has no loader .rodata map data",
                ]),
                r if r == -ENOENT || r == -EOPNOTSUPP => error(&[
                    b"bpm info data: ",
                    member,
                    b" has no supported BTF .rodata data",
                ]),
                r if r == -EINVAL => error(&[b"bpm info data: cannot decode .rodata in ", member]),
                _ => {}
            }
            status(ret)
        }
        err => {
            error(&[b"bpm info data: ", member, b" is not a valid upatch"]);
            Err(err)
        }
    };
    // SAFETY: the container, open or zeroed.
    unsafe { upatch_close(&mut u) };
    ret
}
