// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! What the pins of a loaded upatch say about it: its link, the hook it
//! attaches to as a SEC()-style string, when it was loaded and the
//! payload digest bpf2's xattr guard keeps on them.

use core::ffi::{CStr, c_char, c_int};
use std::ffi::{CString, OsStr};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use crate::errno::{EINVAL, ENAMETOOLONG, ENOENT};
use crate::sys::bpf::{bpf_obj_get, bpf_prog_get_fd_by_id, libbpf_bpf_prog_type_str};
use crate::sys::btf::{Btf, btf__name_by_offset, btf__type_by_id, btf__type_cnt};
use crate::sys::libc::{close, errno, getxattr};
use crate::text::{strscpy, strsprintf};
use crate::util::bpf_info::{Info, LINK_INFO_SIZE, PROG_INFO_SIZE};
use crate::util::timefmt::iso8601;
use crate::util::upatch::{NAME_MAX, pin_name};

/// BPFFS_UPATCHES_DIR and XATTR_PAYLOAD of util/paths.h.
pub(crate) const BPFFS_UPATCHES_DIR: &str = "/run/shirudo/bpffs/upatches";
pub(crate) const XATTR_PAYLOAD: &CStr = c"security.bpf.shirudo.payload";
const PATH_MAX: usize = 4096;

/// Where `struct bpf_link_info` and `struct bpf_prog_info` keep the
/// fields read here.
const LINK_TYPE: usize = 0;
const LINK_PROG_ID: usize = 8;
const LINK_TRACING_ATTACH_TYPE: usize = 16;
const LINK_UPROBE_PATH: usize = 16;
const LINK_UPROBE_PATH_SIZE: usize = 48;
const LINK_UPROBE_COUNT: usize = 52;
const LINK_NETFILTER_PF: usize = 16;
const LINK_NETFILTER_HOOKNUM: usize = 20;
const LINK_NETFILTER_PRIORITY: usize = 24;
const PROG_TYPE: usize = 0;
const PROG_ATTACH_BTF_ID: usize = 224;

const BPF_LINK_TYPE_TRACING: u32 = 2;
const BPF_LINK_TYPE_NETFILTER: u32 = 10;
const BPF_LINK_TYPE_UPROBE_MULTI: u32 = 12;
const BPF_PROG_TYPE_TRACING: u32 = 26;
const BPF_PROG_TYPE_LSM: u32 = 29;
const BPF_PROG_TYPE_NETFILTER: u32 = 32;
const BPF_TRACE_RAW_TP: u32 = 23;
const BPF_TRACE_FENTRY: u32 = 24;
const BPF_TRACE_FEXIT: u32 = 25;
const BPF_MODIFY_RETURN: u32 = 26;
const BPF_TRACE_ITER: u32 = 28;
/// NFPROTO_IPV6, NF_INET_PRE_ROUTING and NF_IP6_PRI_RAW_BEFORE_DEFRAG.
const NFPROTO_IPV6: u32 = 10;
const NF_INET_PRE_ROUTING: u32 = 0;
const NF_IP6_PRI_RAW_BEFORE_DEFRAG: i32 = -450;

/// The pin directory of upatch `name`, and below it each of `parts`, as
/// upatch_pin_path() of util/paths.h makes it; -ENAMETOOLONG for a name
/// or a path too long.
pub(crate) fn pin_path(name: &[u8], parts: &[&[u8]]) -> Result<CString, c_int> {
    if name.len() > NAME_MAX {
        return Err(-ENAMETOOLONG);
    }
    let mut path = [BPFFS_UPATCHES_DIR.as_bytes(), b"/", &pin_name(name)].concat();
    for p in parts {
        path.extend_from_slice(b"/");
        path.extend_from_slice(p);
    }
    if path.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    CString::new(path).map_err(|_| -EINVAL)
}

/// The first link pinned for upatch `name`: "link" for one program,
/// "link_0" of "link_0", "link_1", ... for more. A descriptor, or -errno,
/// the first pin's when neither is there.
pub(crate) fn open_first_link(name: &[u8]) -> c_int {
    let open = |link: &[u8]| -> Result<c_int, c_int> {
        let pin = pin_path(name, &[link])?;
        // SAFETY: a C string.
        match unsafe { bpf_obj_get(pin.as_ptr()) } {
            fd if fd >= 0 => Ok(fd),
            _ => Err(errno()),
        }
    };
    let first = match open(b"link") {
        Ok(fd) => return fd,
        Err(e) if e < 0 => return e,
        Err(e) => e,
    };
    match open(b"link_0") {
        Ok(fd) => fd,
        Err(e) if e < 0 => e,
        Err(ENOENT) => -first,
        Err(e) => -e,
    }
}

/// The SEC() prefix of a program of `prog_type` attached as
/// `attach_type`, where its type alone does not say it.
fn sec_prefix(prog_type: u32, attach_type: u32) -> Option<&'static [u8]> {
    match (prog_type, attach_type) {
        (BPF_PROG_TYPE_LSM, _) => Some(b"lsm"),
        (BPF_PROG_TYPE_NETFILTER, _) => Some(b"netfilter"),
        (BPF_PROG_TYPE_TRACING, BPF_TRACE_FENTRY) => Some(b"fentry"),
        (BPF_PROG_TYPE_TRACING, BPF_TRACE_FEXIT) => Some(b"fexit"),
        (BPF_PROG_TYPE_TRACING, BPF_MODIFY_RETURN) => Some(b"fmod_ret"),
        (BPF_PROG_TYPE_TRACING, BPF_TRACE_RAW_TP) => Some(b"tp_btf"),
        (BPF_PROG_TYPE_TRACING, BPF_TRACE_ITER) => Some(b"iter"),
        _ => None,
    }
}

/// A uprobe-multi link's location: its binary and how many functions.
fn uprobe_multi(link: c_int, first: &Info<LINK_INFO_SIZE>, out: &mut [u8]) -> c_int {
    let count = first.u32_at(LINK_UPROBE_COUNT);
    let path_size = first.u32_at(LINK_UPROBE_PATH_SIZE);
    if path_size == 0 || path_size as usize > PATH_MAX {
        return -EINVAL;
    }
    let mut path = vec![0u8; path_size as usize];
    let mut detail = Info::<LINK_INFO_SIZE>::new();
    detail.set(LINK_UPROBE_PATH, &(path.as_mut_ptr() as u64).to_ne_bytes());
    detail.set(LINK_UPROBE_PATH_SIZE, &path_size.to_ne_bytes());
    let ret = detail.read(link).err().unwrap_or(0);
    if ret != 0 {
        return ret;
    }
    let Some(end) = path.iter().position(|&c| c == 0) else {
        return -EINVAL;
    };
    strsprintf(
        out,
        &[
            b"uprobe.multi/",
            &path[..end],
            b" (",
            count.to_string().as_bytes(),
            b" funcs)",
        ],
    )
    .map_or_else(|e| e, |_| 0)
}

/// Where upatch `name` attaches, as a C string into `out`: the SEC()-style
/// hook, its attach target named from `vbtf`, the vmlinux BTF or NULL,
/// when there is one. 0, or -errno and as the C left it.
pub(crate) fn resolve_location(vbtf: *const Btf, name: &[u8], out: &mut [u8]) -> c_int {
    if let Some(first) = out.first_mut() {
        *first = 0;
    }
    let link = open_first_link(name);
    if link < 0 {
        return link;
    }
    let mut linfo = Info::<LINK_INFO_SIZE>::new();
    let ret = linfo.read(link).err().unwrap_or(0);
    let prog_id = linfo.u32_at(LINK_PROG_ID);
    if ret != 0 || prog_id == 0 {
        // SAFETY: the link opened above.
        unsafe { close(link) };
        return if ret != 0 { ret } else { -EINVAL };
    }
    let link_type = linfo.u32_at(LINK_TYPE);
    if link_type == BPF_LINK_TYPE_UPROBE_MULTI {
        let ret = uprobe_multi(link, &linfo, out);
        // SAFETY: the link opened above.
        unsafe { close(link) };
        return ret;
    }
    // SAFETY: the link opened above.
    unsafe { close(link) };
    let attach_type = if link_type == BPF_LINK_TYPE_TRACING {
        linfo.u32_at(LINK_TRACING_ATTACH_TYPE)
    } else {
        0
    };
    if link_type == BPF_LINK_TYPE_NETFILTER
        && linfo.u32_at(LINK_NETFILTER_PF) == NFPROTO_IPV6
        && linfo.u32_at(LINK_NETFILTER_HOOKNUM) == NF_INET_PRE_ROUTING
        && linfo.u32_at(LINK_NETFILTER_PRIORITY) as i32 == NF_IP6_PRI_RAW_BEFORE_DEFRAG
    {
        let _ = strscpy(out, b"netfilter/ipv6-pre-routing");
        return 0;
    }

    // SAFETY: a call that takes no pointer.
    let prog = unsafe { bpf_prog_get_fd_by_id(prog_id) };
    if prog < 0 {
        return -errno();
    }
    let mut info = Info::<PROG_INFO_SIZE>::new();
    let ret = info.read(prog).err().unwrap_or(0);
    // SAFETY: the program opened above.
    unsafe { close(prog) };
    if ret != 0 {
        return ret;
    }
    let prog_type = info.u32_at(PROG_TYPE);
    let btf_id = info.u32_at(PROG_ATTACH_BTF_ID);

    // SAFETY: the BTF, which bounds the ID checked against its count and
    // the offset of the type's name; a C string in it or NULL.
    let mut attach: &[u8] = unsafe {
        if vbtf.is_null() || btf_id == 0 || btf_id >= btf__type_cnt(vbtf) {
            b""
        } else {
            let t = btf__type_by_id(vbtf, btf_id);
            let n = if t.is_null() {
                core::ptr::null()
            } else {
                btf__name_by_offset(vbtf, (*t).name_off)
            };
            if n.is_null() {
                b""
            } else {
                crate::ffi::c_str(n)
            }
        }
    };
    let prefix = sec_prefix(prog_type, attach_type).unwrap_or_else(|| {
        // SAFETY: libbpf's static name of the type, or NULL.
        let s: *const c_char = unsafe { libbpf_bpf_prog_type_str(prog_type) };
        if s.is_null() {
            b"?"
        } else {
            // SAFETY: as above.
            unsafe { crate::ffi::c_str(s) }
        }
    });
    // The kernel names an LSM hook's attach point bpf_lsm_<hook>.
    if prog_type == BPF_PROG_TYPE_LSM {
        attach = attach.strip_prefix(b"bpf_lsm_").unwrap_or(attach);
    }
    if attach.is_empty() {
        let _ = strscpy(out, prefix);
        return 0;
    }
    strsprintf(out, &[prefix, b"/", attach]).map_or_else(|e| e, |_| 0)
}

/// When upatch `name` was loaded, its pin directory's change time, into
/// `out`; empty when unknown.
pub(crate) fn loaded_at(name: &[u8], out: &mut [u8]) {
    if let Some(first) = out.first_mut() {
        *first = 0;
    }
    let Ok(dir) = pin_path(name, &[]) else {
        return;
    };
    if let Ok(st) = fs::metadata(OsStr::from_bytes(dir.as_bytes())) {
        iso8601(st.ctime(), out);
    }
}

/// The hex payload digest recorded on the pins of upatch `name` into
/// `out`, which holds 65 bytes; empty on any failure.
pub(crate) fn payload_sha256(name: &[u8], out: &mut [u8]) {
    if let Some(first) = out.first_mut() {
        *first = 0;
    }
    if out.len() < 65 {
        return;
    }
    let Ok(dir) = pin_path(name, &[]) else {
        return;
    };
    let mut raw = [0u8; 32];
    // SAFETY: two C strings and room for the digest.
    let n = unsafe {
        getxattr(
            dir.as_ptr(),
            XATTR_PAYLOAD.as_ptr(),
            raw.as_mut_ptr().cast(),
            raw.len(),
        )
    };
    if n != 32 {
        return;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in raw.iter().enumerate() {
        out[2 * i] = HEX[usize::from(b >> 4)];
        out[2 * i + 1] = HEX[usize::from(b & 0xf)];
    }
    out[64] = 0;
}
