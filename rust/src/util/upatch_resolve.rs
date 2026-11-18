// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! What the pins of a loaded upatch say about it: its link, the hook it
//! attaches to as a SEC()-style string, when it was loaded and the
//! payload digest bpf2's xattr guard keeps on them.

use core::ffi::{CStr, c_int};
use std::ffi::{CString, OsStr};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use crate::bpf::btf::Btf;
use crate::errno::{EINVAL, ENAMETOOLONG, ENOENT};
use crate::sys::libc::{close, errno, if_indextoname};
use crate::text::{strscpy, strsprintf};
use crate::util::bpf_info::{Info, LINK_INFO_SIZE, PROG_INFO_SIZE};
use crate::util::bpf_sys::{bpf_obj_get, bpf_prog_get_fd_by_id, prog_type_name};
use crate::util::timefmt::iso8601;
use crate::util::upatch::{NAME_MAX, pin_name};
use crate::util::upatch_pins::{
    PAYLOAD_HASH_LEN, Pins, each_link, pin_payload, xdp_prog_open, xdp_prog_pin,
};

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
const LINK_UPROBE_FLAGS: usize = 56;
const LINK_XDP_IFINDEX: usize = 16;
const LINK_PERF_EVENT_TYPE: usize = 16;
const LINK_PERF_UPROBE_FILE_NAME: usize = 24;
const LINK_PERF_UPROBE_NAME_LEN: usize = 32;
const LINK_PERF_UPROBE_OFFSET: usize = 36;
const PROG_TYPE: usize = 0;
const PROG_ATTACH_BTF_ID: usize = 224;

const BPF_LINK_TYPE_TRACING: u32 = 2;
const BPF_LINK_TYPE_NETFILTER: u32 = 10;
const BPF_LINK_TYPE_UPROBE_MULTI: u32 = 12;
const BPF_LINK_TYPE_XDP: u32 = 6;
const BPF_LINK_TYPE_PERF_EVENT: u32 = 7;
const BPF_PERF_EVENT_UPROBE: u32 = 1;
const BPF_PERF_EVENT_URETPROBE: u32 = 2;
const BPF_F_UPROBE_MULTI_RETURN: u32 = 1;
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

/// The pin directory of upatch `name`, and below it each of `parts`;
/// -ENAMETOOLONG for a name or a path too long.
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
    let kind: &[u8] = if first.u32_at(LINK_UPROBE_FLAGS) & BPF_F_UPROBE_MULTI_RETURN != 0 {
        b"uretprobe.multi/"
    } else {
        b"uprobe.multi/"
    };
    strsprintf(
        out,
        &[
            kind,
            &path[..end],
            b" (",
            count.to_string().as_bytes(),
            b" funcs)",
        ],
    )
    .map_or_else(|e| e, |_| 0)
}

/// Calls `cb` with each link of upatch `name`, its index, its pin and what
/// the kernel says of it; a link whose pin cannot be opened or read ends
/// the walk with its -errno.
pub(crate) fn each_link_info(
    name: &[u8],
    cb: &mut dyn FnMut(u32, &CStr, &Info<LINK_INFO_SIZE>) -> c_int,
) -> c_int {
    each_link(name, &mut |index, pin| {
        // SAFETY: a C string.
        let fd = unsafe { bpf_obj_get(pin.as_ptr()) };
        if fd < 0 {
            return -errno();
        }
        let mut info = Info::<LINK_INFO_SIZE>::new();
        let ret = info.read(fd).err().unwrap_or(0);
        // SAFETY: the link opened above.
        unsafe { close(fd) };
        if ret != 0 { ret } else { cb(index, pin, &info) }
    })
}

/// The program id of upatch `name`: its first link's, or with no link an
/// XDP program pin's.
pub(crate) fn first_prog_id(name: &[u8]) -> Result<u32, c_int> {
    let fd = open_first_link(name);
    if fd >= 0 {
        let mut linfo = Info::<LINK_INFO_SIZE>::new();
        let ret = linfo.read(fd);
        // SAFETY: the link opened above.
        unsafe { close(fd) };
        ret?;
        let id = linfo.u32_at(LINK_PROG_ID);
        return if id != 0 { Ok(id) } else { Err(-EINVAL) };
    }
    if fd != -ENOENT {
        return Err(fd);
    }
    let pins = Pins::read(name)?;
    if pins.nr_xdp_progs == 0 {
        return Err(-ENOENT);
    }
    let (_, id) = xdp_prog_open(name, pins.first_xdp_prog)?;
    if id != 0 { Ok(id) } else { Err(-EINVAL) }
}

/// Where an XDP upatch runs: the device of its lowest live link, and how
/// many more; the kernel clears a link's ifindex when its device goes.
fn xdp_location(name: &[u8], out: &mut [u8]) -> c_int {
    let (mut lowest, mut live, mut device) = (0u32, 0u32, Vec::new());
    let ret = each_link_info(name, &mut |index, _, info| {
        let ifindex = info.u32_at(LINK_XDP_IFINDEX);
        if info.u32_at(LINK_TYPE) != BPF_LINK_TYPE_XDP || ifindex == 0 {
            return 0;
        }
        if live == 0 || index < lowest {
            lowest = index;
            let mut buf = [0u8; 16];
            // SAFETY: an ifindex and room for a name.
            let named = unsafe { if_indextoname(ifindex, buf.as_mut_ptr().cast()) };
            device = if named.is_null() {
                format!("ifindex:{ifindex}").into_bytes()
            } else {
                crate::text::cstr(&buf).to_vec()
            };
        }
        live += 1;
        0
    });
    if ret != 0 {
        return ret;
    }
    let text = match live {
        0 => b"xdp (waiting for a device)".to_vec(),
        1 => [&b"xdp/"[..], &device].concat(),
        n => format!("xdp/{} (+{})", String::from_utf8_lossy(&device), n - 1).into_bytes(),
    };
    strsprintf(out, &[&text]).map_or_else(|e| e, |_| 0)
}

fn link_is_uprobe(linfo: &Info<LINK_INFO_SIZE>) -> bool {
    linfo.u32_at(LINK_TYPE) == BPF_LINK_TYPE_PERF_EVENT
        && matches!(
            linfo.u32_at(LINK_PERF_EVENT_TYPE),
            BPF_PERF_EVENT_UPROBE | BPF_PERF_EVENT_URETPROBE
        )
}

/// A uprobe or uretprobe link's location: its binary and offset.
fn uprobe_location(link: c_int, out: &mut [u8]) -> c_int {
    let mut path = vec![0u8; PATH_MAX];
    let mut linfo = Info::<LINK_INFO_SIZE>::new();
    linfo.set(
        LINK_PERF_UPROBE_FILE_NAME,
        &(path.as_mut_ptr() as u64).to_ne_bytes(),
    );
    linfo.set(LINK_PERF_UPROBE_NAME_LEN, &(PATH_MAX as u32).to_ne_bytes());
    if let Err(err) = linfo.read(link) {
        return err;
    }
    let Some(end) = path.iter().position(|&c| c == 0) else {
        return -EINVAL;
    };
    if !link_is_uprobe(&linfo) {
        return -EINVAL;
    }
    let kind: &[u8] = if linfo.u32_at(LINK_PERF_EVENT_TYPE) == BPF_PERF_EVENT_URETPROBE {
        b"uretprobe/"
    } else {
        b"uprobe/"
    };
    let offset = format!("+0x{:x}", linfo.u32_at(LINK_PERF_UPROBE_OFFSET));
    strsprintf(out, &[kind, &path[..end], offset.as_bytes()]).map_or_else(|e| e, |_| 0)
}

/// Where upatch `name` attaches, as a C string into `out`: the SEC()-style
/// hook, its attach target named from `vbtf`, the vmlinux BTF, when there
/// is one. 0, or -errno and as the C left it.
pub(crate) fn resolve_location(vbtf: Option<&Btf>, name: &[u8], out: &mut [u8]) -> c_int {
    if let Some(first) = out.first_mut() {
        *first = 0;
    }
    if Pins::read(name).is_ok_and(|p| p.nr_xdp_progs != 0) {
        return xdp_location(name, out);
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
    if link_is_uprobe(&linfo) {
        let ret = uprobe_location(link, out);
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

    let prog = bpf_prog_get_fd_by_id(prog_id);
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

    let mut attach: &[u8] = vbtf
        .filter(|b| btf_id != 0 && b.has(btf_id))
        .and_then(|b| b.str_at(b.name_off(btf_id)))
        .unwrap_or_default();
    let prefix = sec_prefix(prog_type, attach_type)
        .unwrap_or_else(|| prog_type_name(prog_type).unwrap_or(b"?"));
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
/// `out`; empty when unknown. Later XDP links change the directory's
/// ctime, so an XDP upatch's is its first program pin's.
pub(crate) fn loaded_at(name: &[u8], out: &mut [u8]) {
    if let Some(first) = out.first_mut() {
        *first = 0;
    }
    let dir = match Pins::read(name) {
        Ok(p) if p.nr_xdp_progs != 0 => xdp_prog_pin(name, p.first_xdp_prog),
        _ => pin_path(name, &[]),
    };
    let Ok(dir) = dir else {
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
    if out.len() < 2 * PAYLOAD_HASH_LEN + 1 {
        return;
    }
    let Ok(raw) = pin_payload(name) else {
        return;
    };
    let hex = crate::util::hex::encode(&raw);
    out[..hex.len()].copy_from_slice(&hex);
    out[hex.len()] = 0;
}

mod capi {
    use core::ffi::{CStr, c_char, c_int, c_void};

    use crate::errno::ENAMETOOLONG;

    /// As upatch_each_link(), with what the kernel says of each link.
    ///
    /// # Safety
    ///
    /// `name` is a C string and `cb` takes the index, the pin, the link's
    /// `struct bpf_link_info` and `ctx`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_each_link_info(
        name: *const c_char,
        cb: unsafe extern "C" fn(u32, *const c_char, *const c_void, *mut c_void) -> c_int,
        ctx: *mut c_void,
    ) -> c_int {
        // SAFETY: the caller's C string.
        let name = unsafe { CStr::from_ptr(name) }.to_bytes();
        super::each_link_info(name, &mut |index, pin, info| {
            // SAFETY: the caller's callback and context, with the link's
            // info, which outlives the call.
            unsafe { cb(index, pin.as_ptr(), info.bytes().as_ptr().cast(), ctx) }
        })
    }

    /// From the first link, or from an XDP program pin when it has none.
    ///
    /// # Safety
    ///
    /// `name` is a C string and `out` room for an id.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_first_prog_id(name: *const c_char, out: *mut u32) -> c_int {
        // SAFETY: the caller's C string and room.
        unsafe {
            *out = 0;
            match super::first_prog_id(CStr::from_ptr(name).to_bytes()) {
                Ok(id) => {
                    *out = id;
                    0
                }
                Err(err) => err,
            }
        }
    }

    /// upatch_pin_path(): the pin directory of upatch `name` and below it
    /// each component of `parts`, an array a NULL ends or NULL for none,
    /// into the `cap` bytes at `out`: 0, or -ENAMETOOLONG with `out` left
    /// empty.
    ///
    /// # Safety
    ///
    /// `out` is room for `cap` bytes, `name` NULL or a C string, and
    /// `parts` NULL or an array of C strings a NULL ends.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_pin_path(
        out: *mut c_char,
        cap: usize,
        name: *const c_char,
        parts: *const *const c_char,
    ) -> c_int {
        let mut comps: Vec<&[u8]> = Vec::new();
        let mut p = parts;
        // SAFETY: the caller's array, read up to its NULL.
        unsafe {
            while !p.is_null() && !(*p).is_null() {
                comps.push(CStr::from_ptr(*p).to_bytes());
                p = p.add(1);
            }
        }
        // SAFETY: the caller's C string.
        let path = (!name.is_null())
            .then(|| super::pin_path(unsafe { CStr::from_ptr(name) }.to_bytes(), &comps));
        // SAFETY: the caller's room.
        let out = unsafe { core::slice::from_raw_parts_mut(out.cast::<u8>(), cap) };
        match path {
            Some(Ok(path)) if path.as_bytes().len() < cap => {
                let path = path.as_bytes_with_nul();
                out[..path.len()].copy_from_slice(path);
                0
            }
            _ => {
                if let Some(first) = out.first_mut() {
                    *first = 0;
                }
                -ENAMETOOLONG
            }
        }
    }
}
