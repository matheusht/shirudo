// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-perf-attach: a loaded kprobe-type program attached to a perf
//! event of the caller's own through PERF_EVENT_IOC_SET_BPF, the legacy
//! attach that never passes through bpf(). The event is a uprobe on this
//! executable, which needs no kprobe support; whether it fires is beside
//! the point. Prints "attached prog_id=<id>" or "errno=<n>".
//! With `--kprobe-multi`, creates a kprobe multi link instead.
//!
//!   test-perf-attach [<program name>]
//!   test-perf-attach --kprobe-multi <program name>

use core::ffi::{CStr, c_int, c_long};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;

use super::{err, helper_main, out, strerror};
use crate::util::bpf_info::{Info, PROG_INFO_SIZE};
use crate::util::bpf_sys::{Attr, bpf_prog_get_fd_by_id, link_create};

helper_main!(shirudo_helper_test_perf_attach, run);

const BPF_PROG_GET_NEXT_ID: c_long = 11;
const BPF_PROG_TYPE_KPROBE: u32 = 2;
/// The offsets of type and name in struct bpf_prog_info.
const PROG_INFO_TYPE: usize = 0;
const PROG_INFO_NAME: usize = 64;
/// PERF_ATTR_SIZE_VER7, and _IOW('$', 8, __u32).
const PERF_ATTR_SIZE: usize = 128;
const PERF_EVENT_IOC_SET_BPF: libc::c_ulong =
    (1 << 30) | (4 << 16) | ((b'$' as libc::c_ulong) << 8) | 8;
const PERF_FLAG_FD_CLOEXEC: c_long = 8;
const BPF_TRACE_KPROBE_MULTI: u32 = 42;

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn uprobe_type() -> Option<u32> {
    std::fs::read_to_string("/sys/bus/event_source/devices/uprobe/type")
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// The file offset of the first executable segment, where a probe may
/// sit.
fn exec_offset(path: &std::path::Path) -> Option<u64> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut eh = [0u8; 64];
    f.read_exact(&mut eh).ok()?;
    let phoff = u64::from_ne_bytes(eh[32..40].try_into().ok()?);
    let phentsize = u64::from(u16::from_ne_bytes(eh[54..56].try_into().ok()?));
    let phnum = u16::from_ne_bytes(eh[56..58].try_into().ok()?);
    for i in 0..u64::from(phnum) {
        let mut ph = [0u8; 56];
        f.read_exact_at(&mut ph, phoff + i * phentsize).ok()?;
        let (ty, flags) = (
            u32::from_ne_bytes(ph[0..4].try_into().ok()?),
            u32::from_ne_bytes(ph[4..8].try_into().ok()?),
        );
        if ty == libc::PT_LOAD && flags & libc::PF_X != 0 {
            return Some(u64::from_ne_bytes(ph[8..16].try_into().ok()?) + 64);
        }
    }
    None
}

/// The first loaded kprobe-type program, of the name wanted if one is,
/// open, with its id.
fn find_prog(want: Option<&[u8]>) -> Option<(OwnedFd, u32)> {
    let mut id = 0u32;
    loop {
        let mut next = Attr::new().u32(0, id);
        next.call(BPF_PROG_GET_NEXT_ID).ok()?;
        id = next.u32_at(4);
        let fd = bpf_prog_get_fd_by_id(id);
        if fd < 0 {
            continue;
        }
        // SAFETY: the descriptor just opened, owned here.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut info = Info::<PROG_INFO_SIZE>::new();
        if info.read(fd.as_raw_fd()).is_err() || info.u32_at(PROG_INFO_TYPE) != BPF_PROG_TYPE_KPROBE
        {
            continue;
        }
        let name = &info.bytes()[PROG_INFO_NAME..PROG_INFO_NAME + 16];
        if want.is_none_or(|w| crate::text::cstr(name) == &w[..w.len().min(16)]) {
            return Some((fd, id));
        }
    }
}

fn link_kprobe_multi(want: &[u8]) -> c_int {
    let Some((prog, id)) = find_prog(Some(want)) else {
        err("no loaded kprobe-type program\n");
        return 2;
    };
    let sym = c"vfs_read".as_ptr();
    let syms = [sym];
    let link = link_create(prog.as_raw_fd(), 0, BPF_TRACE_KPROBE_MULTI, |a| {
        a.u32(20, 1).ptr(24, syms.as_ptr())
    });
    match link {
        Ok(_) => out(&format!("attached prog_id={id}\n")),
        Err(e) => out(&format!("errno={e}\n")),
    }
    0
}

fn run(args: &[&CStr]) -> c_int {
    if args.len() == 3 && args[1].to_bytes() == b"--kprobe-multi" {
        return link_kprobe_multi(args[2].to_bytes());
    }
    let Some(ty) = uprobe_type() else {
        err("no uprobe PMU\n");
        return 2;
    };
    let me = match std::fs::read_link("/proc/self/exe") {
        Ok(p) => p,
        Err(e) => {
            err(&format!(
                "readlink: {}\n",
                strerror(e.raw_os_error().unwrap_or(0))
            ));
            return 2;
        }
    };
    let Some(off) = exec_offset(&me) else {
        err(&format!("no executable segment in {}\n", me.display()));
        return 2;
    };
    let Some((prog, id)) = find_prog(args.get(1).map(|a| a.to_bytes())) else {
        err("no loaded kprobe-type program\n");
        return 2;
    };
    let Ok(path) = std::ffi::CString::new(me.as_os_str().as_bytes()) else {
        return 2;
    };
    let mut pe = [0u8; PERF_ATTR_SIZE];
    pe[0..4].copy_from_slice(&ty.to_ne_bytes());
    pe[4..8].copy_from_slice(&(PERF_ATTR_SIZE as u32).to_ne_bytes());
    pe[56..64].copy_from_slice(&(path.as_ptr() as u64).to_ne_bytes());
    pe[64..72].copy_from_slice(&off.to_ne_bytes());
    // SAFETY: the attribute, whose path outlives the call, for this
    // process on CPU 0, in no group.
    let perf = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            pe.as_ptr(),
            -1 as c_long,
            0 as c_long,
            -1 as c_long,
            PERF_FLAG_FD_CLOEXEC,
        )
    };
    if perf < 0 {
        err(&format!("perf_event_open: {}\n", strerror(errno())));
        return 2;
    }
    // SAFETY: the event's descriptor, owned here, and the program's;
    // the errno read before the event closes.
    let ret = unsafe {
        let perf = OwnedFd::from_raw_fd(perf as c_int);
        match libc::ioctl(perf.as_raw_fd(), PERF_EVENT_IOC_SET_BPF, prog.as_raw_fd()) {
            0 => 0,
            _ => errno(),
        }
    };
    if ret == 0 {
        out(&format!("attached prog_id={id}\n"));
    } else {
        out(&format!("errno={ret}\n"));
    }
    0
}
