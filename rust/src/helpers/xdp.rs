// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-xdp: the driver-mode XDP program of a device, by its id, or
//! that an untrusted caller can neither take hold of it nor replace or
//! detach it, and that it stays.
//!
//!   test-xdp query|denied <device>

use core::ffi::{CStr, c_int};

use super::{err, helper_main, out};
use crate::util::bpf_sys::{Attr, BPF_LINK_CREATE, bpf_prog_get_fd_by_id};
use crate::util::xdp::{drv_detach, drv_prog_id};

helper_main!(shirudo_helper_test_xdp, run);

const BPF_LINK_DETACH: core::ffi::c_long = 34;
const BPF_XDP: u32 = 37;
const XDP_FLAGS_DRV_MODE: u32 = 4;

/// What an untrusted caller gets trying: the program's descriptor, a
/// link of no program in its place, a detach of no link, and the
/// netlink detach, which the program's link holds against.
fn denied(ifindex: u32, id: u32) -> bool {
    let fd = bpf_prog_get_fd_by_id(id);
    if fd >= 0 {
        // SAFETY: the descriptor just opened, closed once.
        unsafe { libc::close(fd) };
        err("XDP program descriptor acquisition was allowed\n");
        return false;
    }
    let link = Attr::new()
        .u32(0, u32::MAX)
        .u32(4, ifindex)
        .u32(8, BPF_XDP)
        .u32(12, XDP_FLAGS_DRV_MODE)
        .fd(BPF_LINK_CREATE);
    let detach = Attr::new().u32(0, u32::MAX).run(BPF_LINK_DETACH);
    fd == -libc::EACCES
        && link.err() == Some(libc::EACCES)
        && detach.err() == Some(libc::EACCES)
        && drv_detach(ifindex) == -libc::EBUSY
}

fn run(args: &[&CStr]) -> c_int {
    let [_, how, device] = args else {
        return 2;
    };
    // SAFETY: a C string.
    let ifindex = unsafe { libc::if_nametoindex(device.as_ptr()) };
    if ifindex == 0 {
        return 2;
    }
    let Ok(id) = drv_prog_id(ifindex) else {
        return 2;
    };
    match how.to_bytes() {
        b"query" => {
            out(&format!("{id}\n"));
            0
        }
        b"denied" if id != 0 => {
            if !denied(ifindex, id) {
                return 1;
            }
            match drv_prog_id(ifindex) {
                Ok(after) if after == id => 0,
                _ => 1,
            }
        }
        _ => 2,
    }
}
