// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The bpf() syscall: `union bpf_attr`, filled by hand, and the commands
//! shirudo issues, among them those of libbpf's `bpf/bpf.h` it called,
//! with their contract: a descriptor, never 0, 1 or 2, or 0; else -errno,
//! errno set.

use core::ffi::{c_char, c_int, c_long, c_void};
use std::os::fd::{FromRawFd, OwnedFd};

use crate::sys::libc::{close, errno, fcntl, set_errno, syscall};

#[cfg(target_arch = "x86_64")]
const SYS_BPF: c_long = 321;
#[cfg(target_arch = "aarch64")]
const SYS_BPF: c_long = 280;

/// The bpf() commands shirudo issues.
pub(crate) const BPF_MAP_CREATE: c_long = 0;
const BPF_MAP_LOOKUP_ELEM: c_long = 1;
pub(crate) const BPF_MAP_UPDATE_ELEM: c_long = 2;
const BPF_MAP_GET_NEXT_KEY: c_long = 4;
pub(crate) const BPF_PROG_LOAD: c_long = 5;
pub(crate) const BPF_OBJ_PIN: c_long = 6;
const BPF_OBJ_GET: c_long = 7;
const BPF_PROG_TEST_RUN: c_long = 10;
const BPF_PROG_GET_FD_BY_ID: c_long = 13;
const BPF_MAP_GET_FD_BY_ID: c_long = 14;
const BPF_OBJ_GET_INFO_BY_FD: c_long = 15;
pub(crate) const BPF_RAW_TRACEPOINT_OPEN: c_long = 17;
const BPF_BTF_GET_FD_BY_ID: c_long = 19;
pub(crate) const BPF_MAP_FREEZE: c_long = 22;
pub(crate) const BPF_LINK_CREATE: c_long = 28;

/// `BPF_ANY`: create or update.
pub(crate) const BPF_ANY: u64 = 0;
const F_DUPFD_CLOEXEC: c_int = 1030;

/// `union bpf_attr`, filled by hand.
#[repr(C, align(8))]
pub(crate) struct Attr([u8; Attr::SIZE]);

impl Attr {
    const SIZE: usize = 168;

    pub(crate) fn new() -> Self {
        Attr([0; Self::SIZE])
    }

    pub(crate) fn put(mut self, off: usize, v: &[u8]) -> Self {
        self.0[off..off + v.len()].copy_from_slice(v);
        self
    }

    pub(crate) fn u32(self, off: usize, v: u32) -> Self {
        self.put(off, &v.to_ne_bytes())
    }

    pub(crate) fn u64(self, off: usize, v: u64) -> Self {
        self.put(off, &v.to_ne_bytes())
    }

    pub(crate) fn ptr<T>(self, off: usize, p: *const T) -> Self {
        self.u64(off, p as u64)
    }

    pub(crate) fn u32_at(&self, off: usize) -> u32 {
        let mut v = [0; 4];
        v.copy_from_slice(&self.0[off..off + 4]);
        u32::from_ne_bytes(v)
    }

    /// bpf() command `cmd` on the attribute, which the kernel may write
    /// back into, whose pointers the caller keeps live: what it returns,
    /// or the errno.
    pub(crate) fn call(&mut self, cmd: c_long) -> Result<c_int, c_int> {
        // SAFETY: an attribute of the size the kernel takes, its
        // pointers to what the caller keeps live across the call.
        let ret = unsafe { syscall(SYS_BPF, cmd, self.0.as_mut_ptr(), Self::SIZE as c_long) };
        if ret < 0 {
            Err(errno())
        } else {
            Ok(ret as c_int)
        }
    }

    /// bpf() command `cmd` on the attribute, whose pointers the caller
    /// keeps live: what it returns, or the errno.
    pub(crate) fn run(mut self, cmd: c_long) -> Result<c_int, c_int> {
        self.call(cmd)
    }

    /// As run(), for a command that makes a descriptor.
    pub(crate) fn fd(self, cmd: c_long) -> Result<OwnedFd, c_int> {
        let fd = self.run(cmd)?;
        // SAFETY: a descriptor the kernel just made, owned here alone.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

/// The link program `prog` makes with BPF_LINK_CREATE at `target` as
/// attach type `ty`, what `with` puts in the union besides.
pub(crate) fn link_create(
    prog: c_int,
    target: c_int,
    ty: u32,
    with: impl FnOnce(Attr) -> Attr,
) -> Result<OwnedFd, c_int> {
    with(
        Attr::new()
            .u32(0, prog as u32)
            .u32(4, target as u32)
            .u32(8, ty),
    )
    .fd(BPF_LINK_CREATE)
}

/// What a command returns: -errno for an error, errno still set.
fn ret(r: Result<c_int, c_int>) -> c_int {
    r.unwrap_or_else(|e| -e)
}

/// The descriptor a command made, moved past 0, 1 and 2 as libbpf's
/// ensure_good_fd() moves it, so that no standard stream is taken for
/// it; or -errno.
fn good_fd(r: Result<c_int, c_int>) -> c_int {
    let fd = match r {
        Ok(fd) if fd >= 3 => return fd,
        Ok(fd) => fd,
        Err(e) => return -e,
    };
    // SAFETY: the descriptor the kernel just made, duplicated past 2.
    let dup = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, 3 as c_int) };
    let saved = errno();
    // SAFETY: the descriptor the duplicate replaces.
    unsafe { close(fd) };
    set_errno(saved);
    if dup < 0 { -saved } else { dup }
}

/// Opens the BPF object pinned at `pathname`.
///
/// # Safety
///
/// `pathname` is a C string.
pub(crate) unsafe fn bpf_obj_get(pathname: *const c_char) -> c_int {
    good_fd(Attr::new().ptr(0, pathname).run(BPF_OBJ_GET))
}

/// Pins the object at `fd` at `pathname`.
///
/// # Safety
///
/// `pathname` is a C string.
pub(crate) unsafe fn bpf_obj_pin(fd: c_int, pathname: *const c_char) -> c_int {
    ret(Attr::new()
        .ptr(0, pathname)
        .u32(8, fd as u32)
        .run(BPF_OBJ_PIN))
}

/// Program `id`, opened.
pub(crate) fn bpf_prog_get_fd_by_id(id: u32) -> c_int {
    good_fd(Attr::new().u32(0, id).run(BPF_PROG_GET_FD_BY_ID))
}

/// Map `id`, opened.
pub(crate) fn bpf_map_get_fd_by_id(id: u32) -> c_int {
    good_fd(Attr::new().u32(0, id).run(BPF_MAP_GET_FD_BY_ID))
}

/// BTF object `id`, opened.
pub(crate) fn bpf_btf_get_fd_by_id(id: u32) -> c_int {
    good_fd(Attr::new().u32(0, id).run(BPF_BTF_GET_FD_BY_ID))
}

/// The kernel's `struct bpf_*_info` of object `fd`, at most `*len` bytes
/// of it into `info`, and into `*len` the bytes it wrote.
///
/// # Safety
///
/// `info` has room for `*len` bytes.
pub(crate) unsafe fn bpf_obj_get_info_by_fd(fd: c_int, info: *mut c_void, len: *mut u32) -> c_int {
    // SAFETY: the caller's length.
    let mut attr = Attr::new()
        .u32(0, fd as u32)
        .u32(4, unsafe { *len })
        .ptr(8, info);
    let r = attr.call(BPF_OBJ_GET_INFO_BY_FD);
    if r.is_ok() {
        // SAFETY: as above.
        unsafe { *len = attr.u32_at(4) };
    }
    ret(r)
}

/// The value of `key` in the map at `fd`, into `value`.
///
/// # Safety
///
/// `key` and `value` have the map's key and value sizes.
pub(crate) unsafe fn bpf_map_lookup_elem(
    fd: c_int,
    key: *const c_void,
    value: *mut c_void,
) -> c_int {
    ret(Attr::new()
        .u32(0, fd as u32)
        .ptr(8, key)
        .ptr(16, value)
        .run(BPF_MAP_LOOKUP_ELEM))
}

/// The key after `key` in the map at `fd` into `next`, the first for a
/// NULL `key`: -ENOENT after the last.
///
/// # Safety
///
/// `key`, NULL or not, and `next` have the map's key size.
pub(crate) unsafe fn bpf_map_get_next_key(
    fd: c_int,
    key: *const c_void,
    next: *mut c_void,
) -> c_int {
    ret(Attr::new()
        .u32(0, fd as u32)
        .ptr(8, key)
        .ptr(16, next)
        .run(BPF_MAP_GET_NEXT_KEY))
}

/// Sets `key` of the map at `fd` to `value`, as BPF_* `flags` say.
///
/// # Safety
///
/// `key` and `value` have the map's key and value sizes.
pub(crate) unsafe fn bpf_map_update_elem(
    fd: c_int,
    key: *const c_void,
    value: *const c_void,
    flags: u64,
) -> c_int {
    ret(Attr::new()
        .u32(0, fd as u32)
        .ptr(8, key)
        .ptr(16, value)
        .u64(24, flags)
        .run(BPF_MAP_UPDATE_ELEM))
}

/// Freezes the map at `fd` against writes from userspace.
pub(crate) fn bpf_map_freeze(fd: c_int) -> c_int {
    ret(Attr::new().u32(0, fd as u32).run(BPF_MAP_FREEZE))
}

/// One BPF_PROG_TEST_RUN of `prog_fd` over `ctx`: its return value, or
/// -errno.
pub(crate) fn prog_test_run(prog_fd: c_int, ctx: *mut c_void, ctx_size: u32) -> Result<u32, c_int> {
    let mut attr = Attr::new()
        .u32(0, prog_fd as u32)
        .u32(40, ctx_size)
        .ptr(48, ctx);
    attr.call(BPF_PROG_TEST_RUN).map_err(|e| -e)?;
    Ok(attr.u32_at(4))
}

/// libbpf's name of BPF_PROG_TYPE_* `t`.
pub(crate) fn prog_type_name(t: u32) -> Option<&'static [u8]> {
    const NAMES: [&[u8]; 33] = [
        b"unspec",
        b"socket_filter",
        b"kprobe",
        b"sched_cls",
        b"sched_act",
        b"tracepoint",
        b"xdp",
        b"perf_event",
        b"cgroup_skb",
        b"cgroup_sock",
        b"lwt_in",
        b"lwt_out",
        b"lwt_xmit",
        b"sock_ops",
        b"sk_skb",
        b"cgroup_device",
        b"sk_msg",
        b"raw_tracepoint",
        b"cgroup_sock_addr",
        b"lwt_seg6local",
        b"lirc_mode2",
        b"sk_reuseport",
        b"flow_dissector",
        b"cgroup_sysctl",
        b"raw_tracepoint_writable",
        b"cgroup_sockopt",
        b"tracing",
        b"struct_ops",
        b"ext",
        b"lsm",
        b"sk_lookup",
        b"syscall",
        b"netfilter",
    ];
    NAMES.get(t as usize).copied()
}
