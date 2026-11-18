// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-xfs-attrmulti: XFS_IOC_ATTRMULTI_BY_HANDLE with no operations on
//! the file named, and the errno it fails with printed, or 0. XFS itself
//! refuses the empty handle with EINVAL, so EACCES comes from an LSM.
//!
//!   test-xfs-attrmulti <file on XFS>

use core::ffi::{CStr, c_int, c_void};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;

use super::{err, helper_main, out, strerror};

helper_main!(shirudo_helper_test_xfs_attrmulti, run);

/// `xfs_fsop_handlereq_t`.
#[repr(C)]
struct HandleReq {
    fd: u32,
    path: *mut c_void,
    oflags: u32,
    ihandle: *mut c_void,
    ihandlen: u32,
    ohandle: *mut c_void,
    ohandlen: *mut u32,
}

/// `xfs_fsop_attrmulti_handlereq_t`.
#[repr(C)]
struct AttrmultiReq {
    hreq: HandleReq,
    opcount: u32,
    ops: *mut c_void,
}

/// _IOW('X', 123, struct attrmulti_req).
const XFS_IOC_ATTRMULTI_BY_HANDLE: libc::c_ulong = (1 << 30)
    | ((size_of::<AttrmultiReq>() as libc::c_ulong) << 16)
    | ((b'X' as libc::c_ulong) << 8)
    | 123;

fn run(args: &[&CStr]) -> c_int {
    let [_, path] = args else {
        err(&format!(
            "usage: {} <file on XFS>\n",
            args.first()
                .map_or("test-xfs-attrmulti".into(), |a| a.to_string_lossy())
        ));
        return 2;
    };
    let file = match std::fs::File::open(std::ffi::OsStr::from_bytes(path.to_bytes())) {
        Ok(f) => f,
        Err(e) => {
            err(&format!(
                "open {}: {}\n",
                path.to_string_lossy(),
                strerror(e.raw_os_error().unwrap_or(0))
            ));
            return 2;
        }
    };
    // SAFETY: a request of no handle and no operation, for which zeros
    // are the value.
    let mut req: AttrmultiReq = unsafe { core::mem::zeroed() };
    // SAFETY: the file and the request, which the ioctl reads.
    let ret = unsafe { libc::ioctl(file.as_raw_fd(), XFS_IOC_ATTRMULTI_BY_HANDLE, &mut req) };
    let errno = if ret < 0 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    } else {
        0
    };
    out(&format!("{errno}\n"));
    0
}
