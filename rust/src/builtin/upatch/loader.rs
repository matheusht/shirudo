// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The signed loader, which `upatch load`, `upatch unload` and boot
//! restore share: one signature-verified path into the kernel.
//!
//! The kernel checks the loader program's signature against the BPF
//! keyring init froze, over the instructions and the frozen map of
//! metadata they are bound to. The program, run once, creates the
//! payload's maps and programs from kernel context. It can neither attach
//! nor pin them, so they are attached here, at the sites the signed
//! metadata names, checked to be there, and pinned so that they outlive
//! this process. The pins then carry the payload's digest, which unload
//! and every undo compare with the records.

use crate::util::paths::{POLICY_PIN, SOCKET_POLICY_PIN, XATTR_POLICY};
use core::ffi::{CStr, c_int, c_long};
use std::ffi::{CString, OsStr};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixDatagram;

use super::ops::{fail, remove_pins};
use super::{log_audit, log_err, log_info, log_warn, strerr};
use crate::errno::{
    E2BIG, EACCES, EBUSY, EEXIST, EINVAL, EIO, ENAMETOOLONG, ENODATA, ENOENT, ENOKEY, ENOPKG,
    ENOTDIR, EOPNOTSUPP, EOVERFLOW, EPERM, ERANGE, ESTALE, EXDEV,
};
use crate::sys::libc::{close, errno, fcntl, fgetxattr, fsetxattr, getsockopt, setxattr, syscall};
use crate::text::{digits, parse_u64};
use crate::util::bpf_info::{Info, LINK_INFO_SIZE, MAP_INFO_SIZE, PROG_INFO_SIZE};
use crate::util::bpf_sys::{
    Attr, BPF_MAP_CREATE, BPF_MAP_FREEZE, BPF_MAP_UPDATE_ELEM, BPF_OBJ_PIN, BPF_PROG_LOAD,
    BPF_RAW_TRACEPOINT_OPEN, bpf_obj_get, link_create, prog_test_run,
};
use crate::util::chain::{memneq_explicit, sha256_2};
use crate::util::crypto_openssl::sha256_into;
use crate::util::elf_target;
use crate::util::identity;
use crate::util::kernel_btf;
use crate::util::keyring;
use crate::util::lskel::{Ctx, F_SLEEPABLE, MAP_TYPE_ARRAY, PROG_TYPE_SYSCALL, VERIFIER_LOG_MAX};
use crate::util::report::{OpReport, report_set_log};
use crate::util::upatch::{
    self, ATTACH_CGROUP_SKB_EGRESS, ATTACH_CGROUP_SKB_INGRESS, ATTACH_FMOD_RET, ATTACH_KPROBE,
    ATTACH_KRETPROBE, ATTACH_NETFILTER_IPV6_PRE_ROUTING, ATTACH_RAW_TRACEPOINT, ATTACH_UPROBE,
    ATTACH_UPROBE_MULTI, ATTACH_URETPROBE, ATTACH_URETPROBE_MULTI, ATTACH_XDP, MAPS_MAX, NAME_MAX,
    Opened, POLICY_LABEL_ENTRY, POLICY_LABEL_HEADER, ProgSpec, ROLE_ATTACH, ROLE_SERIALIZER,
    ROLE_TEST_RUN, Upatch, kind_has_uprobe_target,
};
use crate::util::upatch_pins::{LINK_PIN_PREFIX, xdp_prog_pin};
use crate::util::upatch_resolve::{BPFFS_UPATCHES_DIR, XATTR_PAYLOAD, pin_path};
use crate::util::xdp::{self, XdpDevice};

/// SIG_KEYRING_BPF: the kind of keyring init froze for signed loads.
const SIG_KEYRING_BPF: u32 = 5;
const POLICY_NAME_MAX: usize = 64;

#[cfg(target_arch = "x86_64")]
const SYS_PERF_EVENT_OPEN: c_long = 298;
#[cfg(target_arch = "aarch64")]
const SYS_PERF_EVENT_OPEN: c_long = 241;

const MAP_TYPE_SK_STORAGE: u32 = 24;
const MAP_TYPE_TASK_STORAGE: u32 = 29;
const F_NO_PREALLOC: u32 = 1;
const F_CLONE: u32 = 512;
const PROG_TYPE_CGROUP_SKB: u32 = 8;
const PROG_TYPE_LSM: u32 = 29;

/// BPF_* attach types.
const CGROUP_INET_INGRESS: u32 = 0;
const CGROUP_INET_EGRESS: u32 = 1;
const MODIFY_RETURN: u32 = 26;
const LSM_MAC: u32 = 27;
const PERF_EVENT: u32 = 41;
const NETFILTER: u32 = 45;
const TRACE_UPROBE_MULTI: u32 = 48;
const F_UPROBE_MULTI_RETURN: u32 = 1;
const F_UPROBE_MULTI_PATH_FD: u32 = 2;
/// BPF_XDP and XDP_FLAGS_DRV_MODE: shirudo attaches in driver mode only.
const ATTACH_TYPE_XDP: u32 = 37;
const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;

/// BPF_LINK_TYPE_*, and the perf event kinds a kprobe link reports.
const LINK_RAW_TRACEPOINT: u32 = 1;
const LINK_TRACING: u32 = 2;
const LINK_CGROUP: u32 = 3;
const LINK_PERF_EVENT: u32 = 7;
const LINK_NETFILTER: u32 = 10;
const LINK_UPROBE_MULTI: u32 = 12;
const LINK_XDP: u32 = 6;
const PERF_EVENT_UPROBE: u32 = 1;
const PERF_EVENT_URETPROBE: u32 = 2;
const PERF_EVENT_KPROBE: u32 = 3;
const PERF_EVENT_KRETPROBE: u32 = 4;

/// The hook a netfilter program takes: IPv6 before defragmentation.
const NFPROTO_IPV6: u32 = 10;
const NF_INET_PRE_ROUTING: u32 = 0;
const NF_IP6_PRI_RAW_BEFORE_DEFRAG: i32 = -450;
/// The initial network namespace's cookie, NET_NS_INIT_ID in linux/nsfs.h.
const NET_NS_INIT_COOKIE: u64 = 7;
/// The root of the unified cgroup hierarchy.
const ROOT_CGROUP_ID: u64 = 1;
const SOL_SOCKET: c_int = 1;
const SO_NETNS_COOKIE: c_int = 71;
const PERF_FLAG_FD_CLOEXEC: c_long = 8;
const F_DUPFD_CLOEXEC: c_int = 1030;
const O_DIRECTORY: c_int = 0o200000;
const O_PATH: c_int = 0o10000000;

/// Where the fields read sit in `struct bpf_prog_info`, `bpf_map_info`
/// and `bpf_link_info`.
const PROG_TYPE: usize = 0;
const PROG_BTF_ID: usize = 128;
const PROG_FUNC_INFO_REC_SIZE: usize = 132;
const PROG_FUNC_INFO: usize = 136;
const PROG_NR_FUNC_INFO: usize = 144;
const MAP_TYPE: usize = 0;
const MAP_KEY_SIZE: usize = 8;
const MAP_VALUE_SIZE: usize = 12;
const MAP_FLAGS: usize = 20;
const MAP_NAME: usize = 24;
const LINK_TYPE: usize = 0;
const LINK_U: usize = 16;

/// The report the caller asked for, if any.
struct Rep<'a>(Option<&'a mut OpReport>);

impl Rep<'_> {
    fn fail(&mut self, phase: &'static CStr, category: &'static CStr, err: c_int, message: &[u8]) {
        if let Some(r) = self.0.as_deref_mut() {
            fail(r, phase, category, err, message);
        }
    }

    /// Keeps the verifier's log in the report.
    fn log(&mut self, vlog: &[u8]) {
        if let Some(r) = self.0.as_deref_mut() {
            // SAFETY: a NUL-terminated log, and the report's own or none.
            unsafe { report_set_log(r, vlog.as_ptr().cast()) };
        }
    }

    fn loader_return(&mut self, ret: i32) {
        if let Some(r) = self.0.as_deref_mut() {
            r.loader_return = ret;
        }
    }
}

/// ENOPKG is the kernel's X.509 parser meeting an algorithm it was not
/// built with: an ML-DSA signature without CONFIG_CRYPTO_MLDSA.
fn load_category(e: c_int) -> &'static CStr {
    match e {
        crate::errno::EKEYREJECTED => c"signature_rejected",
        ENOKEY => c"keyring_missing",
        ENOPKG => c"signature_unsupported",
        EACCES | EPERM => c"lsm_denied",
        _ => c"verifier_rejected",
    }
}

fn target_category(e: c_int) -> &'static CStr {
    match e {
        ENOENT | ENOTDIR => c"attach_target_missing",
        ESTALE => c"binary_mismatch",
        EACCES | EPERM => c"lsm_denied",
        ERANGE | EINVAL | E2BIG => c"parser_rejected",
        _ => c"unknown",
    }
}

fn link_category(e: c_int) -> &'static CStr {
    match e {
        ENOENT | ENOTDIR => c"attach_target_missing",
        ESTALE => c"binary_mismatch",
        EXDEV => c"attach_scope_mismatch",
        EOPNOTSUPP => c"kernel_abi_unsupported",
        EACCES | EPERM => c"lsm_denied",
        _ => c"unknown",
    }
}

/// Why attaching and pinning failed: an errno, or shirudo's own verdict
/// on an XDP device, one of `xdp::ERR_*`.
#[derive(Clone, Copy)]
pub(super) enum AttachError {
    Errno(c_int),
    Xdp(c_int),
}

impl AttachError {
    fn category(self) -> &'static CStr {
        match self {
            AttachError::Xdp(xdp::ERR_NO_MULTIBUF) => c"xdp_multibuf_unsupported",
            AttachError::Xdp(xdp::ERR_DRIVER_SETTINGS) => c"xdp_driver_refused",
            AttachError::Xdp(xdp::ERR_OCCUPIED) => c"xdp_device_occupied",
            AttachError::Xdp(xdp::ERR_LINK_SCOPE) | AttachError::Errno(EXDEV) => {
                c"attach_scope_mismatch"
            }
            AttachError::Errno(e) => link_category(e),
            AttachError::Xdp(_) => c"unknown",
        }
    }

    /// The errno a report carries.
    fn errno(self) -> c_int {
        match self {
            AttachError::Errno(e) => e,
            AttachError::Xdp(x) => -xdp::attach_errno(x),
        }
    }
}

impl From<c_int> for AttachError {
    fn from(e: c_int) -> Self {
        AttachError::Errno(e)
    }
}

fn kind_name(kind: u32) -> &'static [u8] {
    match kind {
        ATTACH_RAW_TRACEPOINT => b"raw_tracepoint",
        ATTACH_KPROBE => b"kprobe",
        ATTACH_KRETPROBE => b"kretprobe",
        ATTACH_CGROUP_SKB_INGRESS => b"cgroup_skb/ingress",
        ATTACH_CGROUP_SKB_EGRESS => b"cgroup_skb/egress",
        ATTACH_FMOD_RET => b"fmod_ret",
        ATTACH_NETFILTER_IPV6_PRE_ROUTING => b"netfilter/ipv6-pre-routing",
        ATTACH_UPROBE_MULTI => b"uprobe.multi",
        ATTACH_XDP => b"xdp",
        ATTACH_URETPROBE_MULTI => b"uretprobe.multi",
        ATTACH_UPROBE => b"uprobe",
        ATTACH_URETPROBE => b"uretprobe",
        _ => b"unknown",
    }
}

/// The bytes of `b` up to its first NUL.
fn till_nul(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

fn os(b: &[u8]) -> &OsStr {
    OsStr::from_bytes(b)
}

fn io_errno(e: &std::io::Error) -> c_int {
    e.raw_os_error().unwrap_or(EIO)
}

fn num(n: impl ToString) -> String {
    n.to_string()
}

/// The program specs of the signed attach metadata, freed when dropped
/// with the targets they hold open.
struct Specs {
    ptr: *mut ProgSpec,
    n: u32,
}

impl Specs {
    fn parse(meta: &[u8], nr_maps: u32, nr_progs: u32) -> Result<Self, c_int> {
        let mut ptr = core::ptr::null_mut();
        // SAFETY: the metadata, and room for the array it gives.
        let ret = unsafe {
            upatch::specs_parse(
                meta.as_ptr().cast(),
                meta.len() as u32,
                nr_maps,
                nr_progs,
                &mut ptr,
            )
        };
        if ret != 0 {
            Err(ret)
        } else {
            Ok(Specs { ptr, n: nr_progs })
        }
    }

    fn get(&self) -> &[ProgSpec] {
        // SAFETY: the n specs parsed, or none.
        unsafe { crate::ffi::slice(self.ptr, self.n as usize) }
    }

    fn get_mut(&mut self) -> &mut [ProgSpec] {
        if self.ptr.is_null() {
            return &mut [];
        }
        // SAFETY: the n specs parsed, owned here.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.n as usize) }
    }
}

impl Drop for Specs {
    fn drop(&mut self) {
        // SAFETY: the specs parsed, freed once.
        unsafe { upatch::specs_free(self.ptr, self.n) };
    }
}

/// The name the BTF of `prog` gives its first function.
fn prog_func_name(prog: c_int, base: &Info<PROG_INFO_SIZE>) -> Result<Vec<u8>, c_int> {
    let (nr, rec_size, btf_id) = (
        base.u32_at(PROG_NR_FUNC_INFO),
        base.u32_at(PROG_FUNC_INFO_REC_SIZE),
        base.u32_at(PROG_BTF_ID),
    );
    if nr == 0 || rec_size == 0 || btf_id == 0 {
        return Err(ENOENT);
    }
    if rec_size < 8 {
        return Err(EINVAL);
    }
    let mut recs = vec![0u8; nr as usize * rec_size as usize];
    let mut info = Info::<PROG_INFO_SIZE>::new();
    info.set(PROG_NR_FUNC_INFO, &nr.to_ne_bytes());
    info.set(PROG_FUNC_INFO_REC_SIZE, &rec_size.to_ne_bytes());
    info.set(PROG_FUNC_INFO, &(recs.as_mut_ptr() as u64).to_ne_bytes());
    info.read(prog).map_err(|e| -e)?;
    let type_id = u32::from_ne_bytes([recs[4], recs[5], recs[6], recs[7]]);
    let btf = kernel_btf::by_id(btf_id).map_err(|e| -e)?;
    let name = if btf.has(type_id) {
        btf.str_at(btf.name_off(type_id))
            .unwrap_or_default()
            .to_vec()
    } else {
        Vec::new()
    };
    match name.len() {
        0 => Err(ENOENT),
        n if n >= 128 => Err(ENAMETOOLONG),
        _ => Ok(name),
    }
}

/// A raw_tracepoint program the kernel loaded as cgroup_skb: its
/// direction inferred from its function's name.
fn attach_cgroup_skb_fallback(prog: c_int, info: &Info<PROG_INFO_SIZE>) -> Result<OwnedFd, c_int> {
    let func = prog_func_name(prog, info).inspect_err(|_| {
        log_err(b"program metadata says raw_tracepoint, but loaded program type is cgroup_skb and function name is unavailable; rebuild the upatch with cgroup_skb metadata");
    })?;
    let has = |s: &[u8]| func.windows(s.len()).any(|w| w == s);
    let ty = if [&b"egress"[..], b"query", b"send"].iter().any(|s| has(s)) {
        CGROUP_INET_EGRESS
    } else if [&b"ingress"[..], b"response", b"recv", b"receive"]
        .iter()
        .any(|s| has(s))
    {
        CGROUP_INET_INGRESS
    } else {
        log_err(&[&b"program metadata says raw_tracepoint, but loaded program type is cgroup_skb and function '"[..], func.as_slice(), b"' does not identify ingress or egress; rebuild the upatch with cgroup_skb metadata"].concat());
        return Err(EINVAL);
    };
    let dir: &[u8] = if ty == CGROUP_INET_EGRESS {
        b"egress"
    } else {
        b"ingress"
    };
    log_warn(&[&b"program metadata says raw_tracepoint, but loaded program type is cgroup_skb; inferring "[..], dir, b" from function '", func.as_slice(), b"'"].concat());
    let link = attach_cgroup_skb(prog, ty)?;
    log_info(&[&b"attached cgroup_skb fallback as "[..], dir].concat());
    Ok(link)
}

/// A raw_tracepoint spec: an LSM program by its BTF link, a cgroup_skb
/// one by the fallback, any other at the attach_btf_id it carries.
fn attach_default(prog: c_int) -> Result<OwnedFd, c_int> {
    let mut info = Info::<PROG_INFO_SIZE>::new();
    info.read(prog).map_err(|e| -e)?;
    match info.u32_at(PROG_TYPE) {
        PROG_TYPE_LSM => link_create(prog, 0, LSM_MAC, |a| a),
        PROG_TYPE_CGROUP_SKB => attach_cgroup_skb_fallback(prog, &info),
        _ => Attr::new()
            .u64(0, 0)
            .u32(8, prog as u32)
            .fd(BPF_RAW_TRACEPOINT_OPEN),
    }
}

fn attach_cgroup_skb(prog: c_int, ty: u32) -> Result<OwnedFd, c_int> {
    let cgroup = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY)
        .open("/sys/fs/cgroup")
        .map_err(|e| io_errno(&e))?;
    link_create(prog, cgroup.as_raw_fd(), ty, |a| a)
}

/// The number after `prefix` in the sysfs file at `path`, up to INT_MAX.
fn read_int_file(path: &str, prefix: &[u8]) -> Result<u32, c_int> {
    let mut buf = [0u8; 63];
    let n = File::open(path)
        .and_then(|mut f| f.read(&mut buf))
        .map_err(|e| io_errno(&e))?;
    let rest = buf[..n]
        .strip_prefix(prefix)
        .filter(|_| n != 0)
        .ok_or(EINVAL)?;
    parse_u64(&rest[..digits(rest)], i32::MAX as u64)
        .map(|v| v as u32)
        .map_err(|_| EINVAL)
}

/// The perf event of a kprobe at `target` plus `offset`, or a kretprobe.
/// A kprobe or uprobe event of the PMU `pmu` names in sysfs at `name`, a
/// function or a path, and `offset`.
fn perf_event_open_probe(
    pmu: &str,
    name: &[u8],
    offset: u64,
    retprobe: bool,
) -> Result<OwnedFd, c_int> {
    const SIZE: usize = 144;
    #[repr(C, align(8))]
    struct PerfAttr([u8; SIZE]);

    let devices = format!("/sys/bus/event_source/devices/{pmu}");
    let ty = read_int_file(&format!("{devices}/type"), b"")?;
    let mut config = 0u64;
    if retprobe {
        let bit = read_int_file(&format!("{devices}/format/retprobe"), b"config:")?;
        if bit >= 64 {
            return Err(EINVAL);
        }
        config |= 1 << bit;
    }
    let name = CString::new(till_nul(name)).map_err(|_| EINVAL)?;
    let mut a = PerfAttr([0; SIZE]);
    a.0[0..4].copy_from_slice(&ty.to_ne_bytes());
    a.0[4..8].copy_from_slice(&(SIZE as u32).to_ne_bytes());
    a.0[8..16].copy_from_slice(&config.to_ne_bytes());
    a.0[56..64].copy_from_slice(&(name.as_ptr() as u64).to_ne_bytes());
    a.0[64..72].copy_from_slice(&offset.to_ne_bytes());
    // SAFETY: the attribute, of its size, and the name it points to.
    let fd = unsafe {
        syscall(
            SYS_PERF_EVENT_OPEN,
            a.0.as_mut_ptr(),
            -1 as c_long,
            0 as c_long,
            -1 as c_long,
            PERF_FLAG_FD_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(errno());
    }
    // SAFETY: the event just opened, owned here alone.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as c_int) })
}

/// The kernel resolves the binary from a path, so name the descriptor
/// prepare_uprobe_targets() checked: the probe lands in that inode, not
/// in whatever the spec's path names by now.
fn perf_event_open_uprobe(spec: &ProgSpec) -> Result<OwnedFd, c_int> {
    if spec.target_fd < 0 || spec.uprobe_offsets.is_null() || spec.nr_uprobe_offsets != 1 {
        return Err(EINVAL);
    }
    let path = format!("/proc/self/fd/{}", spec.target_fd);
    // SAFETY: the spec's one offset.
    let offset = unsafe { *spec.uprobe_offsets };
    perf_event_open_probe(
        "uprobe",
        path.as_bytes(),
        offset,
        spec.kind == ATTACH_URETPROBE,
    )
}

/// Each uprobe target opened and bound to its recorded GNU build ID
/// before any program loads. The descriptor stays open in its spec
/// through the link's creation, so that the path cannot be replaced in
/// between.
fn prepare_uprobe_targets(specs: &mut [ProgSpec]) -> Result<(), c_int> {
    for spec in specs.iter_mut().filter(|s| kind_has_uprobe_target(s.kind)) {
        // SAFETY: the spec's C string.
        let path = unsafe { CStr::from_ptr(spec.uprobe_path) };
        let at = OpenOptions::new()
            .read(true)
            .custom_flags(O_PATH)
            .open(os(path.to_bytes()))
            .map_err(|e| io_errno(&e))?;
        let st = at.metadata().map_err(|e| io_errno(&e))?;
        if !st.file_type().is_file() {
            return Err(ESTALE);
        }
        let file =
            File::open(format!("/proc/self/fd/{}", at.as_raw_fd())).map_err(|e| io_errno(&e))?;
        drop(at);
        let opened = file.metadata().map_err(|e| io_errno(&e))?;
        if opened.dev() != st.dev() || opened.ino() != st.ino() {
            return Err(ESTALE);
        }
        // SAFETY: the spec's offsets, by their count.
        let offsets =
            unsafe { crate::ffi::slice(spec.uprobe_offsets, spec.nr_uprobe_offsets as usize) };
        if offsets.iter().any(|&o| o >= opened.size()) {
            return Err(ERANGE);
        }
        let id = match elf_target::build_id(&file) {
            Ok(id) => id,
            Err(r) if r == -EACCES || r == -EPERM => return Err(-r),
            Err(_) => return Err(ESTALE),
        };
        if id.len() != spec.build_id_len as usize || id[..] != spec.build_id[..id.len()] {
            return Err(ESTALE);
        }
        spec.target_fd = file.into_raw_fd();
    }
    Ok(())
}

fn attach_uprobe_multi(prog: c_int, spec: &ProgSpec) -> Result<OwnedFd, c_int> {
    if spec.target_fd < 0
        || spec.uprobe_path.is_null()
        || spec.uprobe_offsets.is_null()
        || spec.nr_uprobe_offsets == 0
    {
        return Err(EINVAL);
    }
    let mut flags = F_UPROBE_MULTI_PATH_FD;
    if spec.kind == ATTACH_URETPROBE_MULTI {
        flags |= F_UPROBE_MULTI_RETURN;
    }
    link_create(prog, 0, TRACE_UPROBE_MULTI, |a| {
        a.ptr(24, spec.uprobe_offsets)
            .u32(48, spec.nr_uprobe_offsets)
            .u32(52, flags)
            .u32(60, spec.target_fd as u32)
    })
}

fn attach(prog: c_int, spec: &ProgSpec) -> Result<OwnedFd, c_int> {
    match spec.kind {
        ATTACH_RAW_TRACEPOINT => attach_default(prog),
        ATTACH_CGROUP_SKB_INGRESS => attach_cgroup_skb(prog, CGROUP_INET_INGRESS),
        ATTACH_CGROUP_SKB_EGRESS => attach_cgroup_skb(prog, CGROUP_INET_EGRESS),
        ATTACH_FMOD_RET => link_create(prog, 0, MODIFY_RETURN, |a| a),
        ATTACH_NETFILTER_IPV6_PRE_ROUTING => link_create(prog, 0, NETFILTER, |a| {
            a.u32(16, NFPROTO_IPV6)
                .u32(20, NF_INET_PRE_ROUTING)
                .u32(24, NF_IP6_PRI_RAW_BEFORE_DEFRAG as u32)
        }),
        ATTACH_UPROBE_MULTI | ATTACH_URETPROBE_MULTI => attach_uprobe_multi(prog, spec),
        ATTACH_KPROBE | ATTACH_KRETPROBE => {
            let perf = perf_event_open_probe(
                "kprobe",
                &spec.target,
                spec.offset,
                spec.kind == ATTACH_KRETPROBE,
            )?;
            link_create(prog, perf.as_raw_fd(), PERF_EVENT, |a| a)
        }
        ATTACH_UPROBE | ATTACH_URETPROBE => {
            let perf = perf_event_open_uprobe(spec)?;
            link_create(prog, perf.as_raw_fd(), PERF_EVENT, |a| a)
        }
        _ => Err(EINVAL),
    }
}

/// Whether this process runs in the initial network namespace, which a
/// netfilter link hooks when it hooks the caller's: EXDEV when not.
fn netns_initial() -> Result<(), c_int> {
    let sock = UnixDatagram::unbound().map_err(|e| io_errno(&e))?;
    let mut cookie = 0u64;
    let mut len = size_of::<u64>() as u32;
    // SAFETY: the socket, and room for the cookie and its length.
    if unsafe {
        getsockopt(
            sock.as_raw_fd(),
            SOL_SOCKET,
            SO_NETNS_COOKIE,
            (&raw mut cookie).cast(),
            &mut len,
        )
    } != 0
    {
        return Err(errno());
    }
    if cookie == NET_NS_INIT_COOKIE {
        Ok(())
    } else {
        Err(EXDEV)
    }
}

/// The site a kprobe, uprobe, cgroup or netfilter program attaches at is
/// named by the caller, and the caller's cgroup namespace and mount of
/// the cgroup tree, network namespace and sysfs are root's to arrange: a
/// cgroup_skb program attached under a namespace root or a bind mount of
/// a subtree guards a corner, a netfilter program in a namespace of its
/// own guards nothing, a kprobe opened through a sysfs that names another
/// PMU lands elsewhere, and each is measured as loaded. What the kernel
/// reports about the link is compared with the spec before the link is
/// pinned: EXDEV when they differ. A uprobe's file name is not: the
/// descriptor it was opened through fixes the inode, and the name the
/// kernel reports can differ from the signed path by a symlink.
fn link_matches_spec(link: c_int, spec: &ProgSpec, ifindex: u32) -> Result<(), c_int> {
    let mut func = [0u8; 128];
    let mut info = Info::<LINK_INFO_SIZE>::new();
    let kprobe = spec.kind == ATTACH_KPROBE || spec.kind == ATTACH_KRETPROBE;
    if kprobe {
        info.set(24, &(func.as_mut_ptr() as u64).to_ne_bytes());
        info.set(32, &(func.len() as u32).to_ne_bytes());
    }
    info.read(link).map_err(|e| -e)?;
    let ty = info.u32_at(LINK_TYPE);
    if ty == LINK_CGROUP {
        let b = info.bytes();
        let id = u64::from_ne_bytes(b[LINK_U..LINK_U + 8].try_into().unwrap_or_default());
        return if id == ROOT_CGROUP_ID {
            Ok(())
        } else {
            Err(EXDEV)
        };
    }
    let ok = match spec.kind {
        // The caller's namespace was checked before the devices were read.
        ATTACH_XDP => ty == LINK_XDP && ifindex != 0 && info.u32_at(LINK_U) == ifindex,
        ATTACH_CGROUP_SKB_INGRESS | ATTACH_CGROUP_SKB_EGRESS => false,
        ATTACH_NETFILTER_IPV6_PRE_ROUTING => {
            if ty == LINK_NETFILTER
                && info.u32_at(LINK_U) == NFPROTO_IPV6
                && info.u32_at(LINK_U + 4) == NF_INET_PRE_ROUTING
                && info.u32_at(LINK_U + 8) as i32 == NF_IP6_PRI_RAW_BEFORE_DEFRAG
            {
                return netns_initial();
            }
            false
        }
        ATTACH_KPROBE | ATTACH_KRETPROBE => {
            let want = if spec.kind == ATTACH_KRETPROBE {
                PERF_EVENT_KRETPROBE
            } else {
                PERF_EVENT_KPROBE
            };
            ty == LINK_PERF_EVENT
                && info.u32_at(LINK_U) == want
                && info.u32_at(32) as usize <= func.len()
                && u64::from(info.u32_at(36)) == spec.offset
                && till_nul(&func) == till_nul(&spec.target)
        }
        ATTACH_UPROBE | ATTACH_URETPROBE => {
            let want = if spec.kind == ATTACH_URETPROBE {
                PERF_EVENT_URETPROBE
            } else {
                PERF_EVENT_UPROBE
            };
            let b = info.bytes();
            let ref_ctr = u64::from_ne_bytes(b[48..56].try_into().unwrap_or_default());
            spec.nr_uprobe_offsets == 1
                && ty == LINK_PERF_EVENT
                && info.u32_at(LINK_U) == want
                // SAFETY: the spec's one offset.
                && u64::from(info.u32_at(36)) == unsafe { *spec.uprobe_offsets }
                && ref_ctr == 0
        }
        ATTACH_UPROBE_MULTI | ATTACH_URETPROBE_MULTI => {
            let ret = spec.kind == ATTACH_URETPROBE_MULTI;
            ty == LINK_UPROBE_MULTI
                && info.u32_at(52) == spec.nr_uprobe_offsets
                && (info.u32_at(56) & F_UPROBE_MULTI_RETURN != 0) == ret
        }
        ATTACH_FMOD_RET => ty == LINK_TRACING && info.u32_at(LINK_U) == MODIFY_RETURN,
        _ => ty == LINK_RAW_TRACEPOINT || ty == LINK_TRACING,
    };
    if ok { Ok(()) } else { Err(EXDEV) }
}

fn obj_pin(fd: c_int, path: &CStr) -> Result<(), c_int> {
    Attr::new()
        .ptr(0, path.as_ptr())
        .u32(8, fd as u32)
        .run(BPF_OBJ_PIN)
        .map(|_| ())
}

/// Makes directory `path` unless it exists: whether it was made, or the
/// errno.
fn mkdir_if_absent(path: &[u8]) -> Result<bool, c_int> {
    match DirBuilder::new().mode(0o700).create(os(path)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(io_errno(&e)),
    }
}

/// Removes the pin a load that died before its link left at `pin`,
/// bound to maps nothing reaches any more.
fn unlink_stale(pin: &CStr) -> Result<(), c_int> {
    if fs::metadata(os(pin.to_bytes())).is_ok() {
        fs::remove_file(os(pin.to_bytes())).map_err(|e| io_errno(&e))?;
    }
    Ok(())
}

fn cpath(parts: &[&[u8]]) -> Result<CString, c_int> {
    CString::new(parts.concat()).map_err(|_| EINVAL)
}

/// A pin a load that died before its link left: bound to maps nothing
/// reaches any more, so it is replaced.
fn obj_repin(fd: c_int, pin: &CStr) -> Result<(), c_int> {
    unlink_stale(pin)?;
    obj_pin(fd, pin)
}

impl AttachError {
    /// As C has it: a negative errno, or the verdict.
    pub(super) fn code(self) -> c_int {
        match self {
            AttachError::Errno(e) => -e,
            AttachError::Xdp(x) => x,
        }
    }
}

/// Links exist only per device, so with none attached the pin is what
/// keeps the program loaded, and its index is what ties it to its signed
/// classes.
fn pin_xdp_prog(prog: c_int, name: &[u8], index: u32) -> Result<CString, c_int> {
    let pin = xdp_prog_pin(name, index).map_err(|_| ENAMETOOLONG)?;
    obj_repin(prog, &pin).inspect_err(|&e| {
        log_err(&[&b"pin XDP program "[..], pin.to_bytes(), b": ", strerr(e)].concat());
    })?;
    Ok(pin)
}

/// The link of `prog` on `dev`, pinned at `pin`. Unpinned, a closed link
/// detaches, so a failure leaves the device as it was.
pub(super) fn xdp_attach_one(
    prog: c_int,
    spec: &ProgSpec,
    dev: &XdpDevice,
    pin: &CStr,
) -> Result<(), AttachError> {
    let errno_of = |e: c_int| AttachError::Errno(-e);

    match xdp::device_verify(dev) {
        0 => {}
        e => return Err(errno_of(e)),
    }
    // Before the attach: it can reconfigure a NIC, and reconcile retries.
    let features = xdp::device_features(dev.ifindex).map_err(errno_of)?;
    if xdp::multibuf_refused(features) {
        return Err(AttachError::Xdp(xdp::ERR_NO_MULTIBUF));
    }
    let link = match link_create(prog, dev.ifindex as c_int, ATTACH_TYPE_XDP, |a| {
        a.u32(12, XDP_FLAGS_DRV_MODE)
    }) {
        Ok(l) => l,
        Err(e) => {
            if xdp::attach_unsupported(-e, features) {
                return Err(AttachError::Xdp(xdp::ERR_NO_NATIVE));
            }
            if e == EBUSY || e == EEXIST {
                return Err(AttachError::Xdp(xdp::ERR_OCCUPIED));
            }
            // Not a kernel without the link type: EOPNOTSUPP would read as
            // one.
            if xdp::driver_refused(-e) {
                log_info(
                    &[
                        &b"XDP: the driver of "[..],
                        dev.name(),
                        b" refused the program: ",
                        strerr(e),
                    ]
                    .concat(),
                );
                return Err(AttachError::Xdp(xdp::ERR_DRIVER_SETTINGS));
            }
            return Err(AttachError::Errno(e));
        }
    };
    // Not to be read as device_verify()'s "the device changed".
    link_matches_spec(link.as_raw_fd(), spec, dev.ifindex).map_err(|e| {
        if e == EXDEV {
            AttachError::Xdp(xdp::ERR_LINK_SCOPE)
        } else {
            AttachError::Errno(e)
        }
    })?;
    match xdp::device_verify(dev) {
        0 => {}
        e => return Err(errno_of(e)),
    }
    obj_pin(link.as_raw_fd(), pin).map_err(AttachError::Errno)
}

/// `prog` attached to every device of `devices` its signed classes
/// select, each link pinned at the next link number of `dir`, counted in
/// `numbered` and kept in `pinned`. A device that cannot run it, or has
/// gone, is passed over; any other failure fails the load.
fn attach_xdp_devices(
    prog: c_int,
    spec: &ProgSpec,
    devices: &[XdpDevice],
    dir: &[u8],
    numbered: &mut u32,
    pinned: &mut Vec<CString>,
) -> Result<(), AttachError> {
    let mut attached = 0;

    for (i, dev) in devices.iter().enumerate() {
        if !xdp::selected(devices, i, spec.device_classes) {
            continue;
        }
        if *numbered == u32::MAX {
            return Err(AttachError::Errno(EOVERFLOW));
        }
        let pin = cpath(&[dir, b"/", LINK_PIN_PREFIX, num(*numbered).as_bytes()])?;
        let ifindex = num(dev.ifindex);
        match xdp_attach_one(prog, spec, dev, &pin) {
            Ok(()) => {}
            Err(AttachError::Xdp(xdp::ERR_NO_NATIVE)) => {
                log_warn(
                    &[
                        &b"XDP: skipping "[..],
                        dev.name(),
                        b" (ifindex ",
                        ifindex.as_bytes(),
                        b", class ",
                        num(dev.class()).as_bytes(),
                        b"): native XDP unsupported",
                    ]
                    .concat(),
                );
                continue;
            }
            Err(e) if xdp::attach_skippable(e.code(), dev) => {
                log_warn(
                    &[
                        &b"XDP: skipping "[..],
                        dev.name(),
                        b" (ifindex ",
                        ifindex.as_bytes(),
                        b"): ",
                        xdp::attach_strerror(e.code()).to_bytes(),
                    ]
                    .concat(),
                );
                continue;
            }
            Err(e) => {
                log_err(
                    &[
                        &b"XDP: attach "[..],
                        dev.name(),
                        b" (ifindex ",
                        ifindex.as_bytes(),
                        b"): ",
                        xdp::attach_strerror(e.code()).to_bytes(),
                    ]
                    .concat(),
                );
                return Err(e);
            }
        }
        *numbered += 1;
        attached += 1;
        log_info(
            &[
                &b"XDP: attached "[..],
                dev.name(),
                b" (ifindex ",
                ifindex.as_bytes(),
                b", class ",
                num(dev.class()).as_bytes(),
                b") at ",
                pin.to_bytes(),
            ]
            .concat(),
        );
        pinned.push(pin);
    }
    if attached == 0 {
        log_info(
            &[
                &b"XDP: no attachable interface matches signed class mask "[..],
                num(spec.device_classes).as_bytes(),
                b" yet",
            ]
            .concat(),
        );
    }
    Ok(())
}

/// The programs the loader made, attached and pinned: serializers as
/// programs for `upatch map`, the test-run program as one, an XDP program
/// as one and a link on each device it selects, the rest as links. With
/// an XDP program the links of every attach program share one count of
/// link numbers, as devices come and go. A failure unpins what this call
/// pinned: the upatch is then neither archived nor measured, so none of
/// its programs may stay attached.
fn attach_and_pin(cx: &Ctx, name: &[u8], specs: &[ProgSpec]) -> Result<(), AttachError> {
    if specs.is_empty() {
        log_warn(b"upatch carries no programs to attach");
        return Ok(());
    }
    let dir = pin_path(name, &[]).map_err(|_| ENAMETOOLONG)?;
    let dir = dir.as_bytes();
    let has_xdp = specs.iter().any(|s| s.kind == ATTACH_XDP);
    if let Err(e) = mkdir_if_absent(BPFFS_UPATCHES_DIR.as_bytes()) {
        log_err(
            &[
                &b"mkdir "[..],
                BPFFS_UPATCHES_DIR.as_bytes(),
                b": ",
                strerr(e),
            ]
            .concat(),
        );
        return Err(e.into());
    }
    let serializers = [dir, b"/serializers"].concat();
    let mut pinned: Vec<CString> = Vec::new();
    let (mut made_dir, mut made_serializers) = (false, false);
    let ret = (|| -> Result<(), AttachError> {
        let devices = if has_xdp {
            netns_initial()?;
            let devices = xdp::devices_read().map_err(|e| AttachError::Errno(-e))?;
            xdp::warn_unclassified(&devices);
            devices
        } else {
            Vec::new()
        };
        made_dir = mkdir_if_absent(dir).inspect_err(|&e| {
            log_err(&[&b"mkdir "[..], dir, b": ", strerr(e)].concat());
        })?;
        let attach_count = specs.iter().filter(|s| s.role == ROLE_ATTACH).count();
        let (mut attach_seen, mut numbered) = (0u32, 0u32);
        let mut test = None;
        for (i, spec) in specs.iter().enumerate() {
            let i = i as u32;
            let fd = cx.prog_fd(i);
            if fd <= 0 {
                log_err(&[&b"loader produced no fd for prog "[..], num(i).as_bytes()].concat());
                return Err(EINVAL.into());
            }
            match spec.role {
                ROLE_SERIALIZER => {
                    let pin = cpath(&[serializers.as_slice(), b"/", till_nul(&spec.map)])?;
                    made_serializers |= mkdir_if_absent(&serializers).inspect_err(|&e| {
                        log_err(
                            &[&b"mkdir "[..], serializers.as_slice(), b": ", strerr(e)].concat(),
                        );
                    })?;
                    obj_repin(fd, &pin).inspect_err(|&e| {
                        log_err(
                            &[&b"pin serializer "[..], pin.to_bytes(), b": ", strerr(e)].concat(),
                        );
                    })?;
                    log_info(
                        &[
                            &b"upatch load: serializer program "[..],
                            num(i).as_bytes(),
                            b" pinned at ",
                            pin.to_bytes(),
                        ]
                        .concat(),
                    );
                    pinned.push(pin);
                }
                ROLE_TEST_RUN => {
                    let pin = cpath(&[dir, b"/test"])?;
                    test = Some(fd);
                    obj_repin(fd, &pin).inspect_err(|&e| {
                        log_err(
                            &[
                                &b"pin test-run program "[..],
                                pin.to_bytes(),
                                b": ",
                                strerr(e),
                            ]
                            .concat(),
                        );
                    })?;
                    log_info(
                        &[
                            &b"upatch load: test-run program "[..],
                            num(i).as_bytes(),
                            b" pinned at ",
                            pin.to_bytes(),
                        ]
                        .concat(),
                    );
                    pinned.push(pin);
                }
                _ => {
                    let pin = if has_xdp {
                        if numbered == u32::MAX {
                            return Err(EOVERFLOW.into());
                        }
                        cpath(&[dir, b"/", LINK_PIN_PREFIX, num(numbered).as_bytes()])?
                    } else if attach_count == 1 {
                        cpath(&[dir, b"/link"])?
                    } else {
                        cpath(&[dir, b"/", LINK_PIN_PREFIX, num(attach_seen).as_bytes()])?
                    };
                    attach_seen += 1;
                    if spec.kind == ATTACH_XDP {
                        pinned.push(pin_xdp_prog(fd, name, i)?);
                        attach_xdp_devices(fd, spec, &devices, dir, &mut numbered, &mut pinned)?;
                        continue;
                    }
                    let kind = kind_name(spec.kind);
                    let target = till_nul(&spec.target);
                    let link = attach(fd, spec).inspect_err(|&e| {
                        let site: Vec<u8> = if kind_has_uprobe_target(spec.kind) {
                            // SAFETY: the spec's C string.
                            let path = unsafe { CStr::from_ptr(spec.uprobe_path) }.to_bytes();
                            [&b" "[..], path, b":", target].concat()
                        } else if !target.is_empty() {
                            [&b" "[..], target].concat()
                        } else {
                            Vec::new()
                        };
                        log_err(
                            &[
                                &b"attach prog "[..],
                                num(i).as_bytes(),
                                b" (",
                                kind,
                                site.as_slice(),
                                b"): ",
                                strerr(e),
                            ]
                            .concat(),
                        );
                    })?;
                    // Unpinned, a closed link detaches.
                    link_matches_spec(link.as_raw_fd(), spec, 0).inspect_err(|&e| {
                        log_err(
                            &[
                                &b"attach prog "[..],
                                num(i).as_bytes(),
                                b" (",
                                kind,
                                b" ",
                                target,
                                b"): the link is not at the site the metadata names: ",
                                strerr(e),
                            ]
                            .concat(),
                        );
                    })?;
                    obj_pin(link.as_raw_fd(), &pin).inspect_err(|&e| {
                        log_err(&[&b"pin "[..], pin.to_bytes(), b": ", strerr(e)].concat());
                    })?;
                    if has_xdp {
                        numbered += 1;
                    }
                    log_info(
                        &[
                            &b"upatch load: program "[..],
                            num(i).as_bytes(),
                            b" (",
                            kind,
                            b") pinned at ",
                            pin.to_bytes(),
                        ]
                        .concat(),
                    );
                    pinned.push(pin);
                }
            }
        }
        if let Some(fd) = test {
            // A zero context is the load-time arena initialization call.
            let mut init = [0u64; 2];
            let ret = match prog_test_run(fd, init.as_mut_ptr().cast(), 16) {
                Ok(r) if (r as i32) < 0 => r as i32,
                Ok(_) => 0,
                Err(e) => e,
            };
            if ret < 0 {
                log_err(&[&b"initialize test-run arena: "[..], strerr(-ret)].concat());
                return Err((-ret).into());
            }
        }
        Ok(())
    })();
    if ret.is_err() {
        for pin in &pinned {
            let _ = fs::remove_file(os(pin.to_bytes()));
        }
        if made_serializers {
            let _ = fs::remove_dir(os(&serializers));
        }
        if made_dir {
            let _ = fs::remove_dir(os(dir));
        }
    }
    ret
}

/// The maps the loader made, pinned for `upatch map`. Best effort: the
/// upatch is loaded, so a map that cannot be pinned is logged and left
/// unobservable until the next load. bpffs reserves dots in path
/// components, so libbpf's .bss, .data and .rodata are skipped, and
/// upatch-private maps are not the operator's to see.
fn pin_maps(cx: &Ctx, skip: [u32; 2], name: &[u8]) {
    if cx.nr_maps == 0 {
        return;
    }
    let Ok(dir) = pin_path(name, &[b"maps"]) else {
        return;
    };
    let dir = dir.as_bytes();
    if let Err(e) = mkdir_if_absent(dir) {
        log_warn(
            &[
                &b"upatch maps: mkdir "[..],
                dir,
                b": ",
                strerr(e),
                b" (continuing without map pins)",
            ]
            .concat(),
        );
        return;
    }
    for i in 0..cx.nr_maps {
        let fd = cx.map_fd(i);
        if skip.contains(&i) || fd <= 0 {
            continue;
        }
        let mut info = Info::<MAP_INFO_SIZE>::new();
        if let Err(e) = info.read(fd) {
            log_warn(
                &[
                    &b"upatch load: map "[..],
                    num(i).as_bytes(),
                    b" info: ",
                    strerr(-e),
                ]
                .concat(),
            );
            continue;
        }
        let map = till_nul(&info.bytes()[MAP_NAME..MAP_NAME + 16]).to_vec();
        if map.is_empty() || map.contains(&b'.') || map.starts_with(b"obs_i_") {
            continue;
        }
        let Ok(pin) = cpath(&[dir, b"/", map.as_slice()]) else {
            continue;
        };
        if fs::metadata(os(pin.to_bytes())).is_ok() {
            continue;
        }
        if let Err(e) = obj_pin(fd, &pin) {
            log_warn(&[&b"upatch load: pin "[..], pin.to_bytes(), b": ", strerr(e)].concat());
            continue;
        }
        log_info(
            &[
                &b"upatch load: map "[..],
                num(i).as_bytes(),
                b" (",
                map.as_slice(),
                b") pinned at ",
                pin.to_bytes(),
            ]
            .concat(),
        );
    }
}

/// The policy map init pinned at `pin`, of the shape the loader binds: a
/// descriptor above stdin's, which the loader would take for none.
fn open_shared_policy_map(
    pin: &CStr,
    ty: u32,
    value_size: u32,
    flags: u32,
) -> Result<OwnedFd, c_int> {
    // SAFETY: a C string.
    let fd = unsafe { bpf_obj_get(pin.as_ptr()) };
    if fd < 0 {
        return Err(errno());
    }
    // SAFETY: the pin opened above, owned here alone.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut info = Info::<MAP_INFO_SIZE>::new();
    info.read(fd.as_raw_fd()).map_err(|e| -e)?;
    if info.u32_at(MAP_TYPE) != ty
        || info.u32_at(MAP_KEY_SIZE) != 4
        || info.u32_at(MAP_VALUE_SIZE) != value_size
        || info.u32_at(MAP_FLAGS) != flags
    {
        return Err(EINVAL);
    }
    if fd.as_raw_fd() != 0 {
        return Ok(fd);
    }
    // SAFETY: the descriptor, duplicated above 2.
    let copy = unsafe { fcntl(fd.as_raw_fd(), F_DUPFD_CLOEXEC, 3) };
    if copy < 0 {
        return Err(errno());
    }
    // SAFETY: the copy just made, owned here alone.
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}

/// The payload's digest on the pin directory: the value `upatch unload`
/// checks and every undo compares with the records, unforgeable behind
/// bpf2's xattr guard. Pins without it are ones no record covers, which
/// the next upatch command would take out after this load's own record,
/// so the load is taken out here, before it.
fn set_pin_payload(name: &[u8], payload: &[u8; 32]) -> Result<(), c_int> {
    let dir = pin_path(name, &[]).map_err(|_| ENAMETOOLONG)?;
    // SAFETY: two C strings and the digest.
    if unsafe {
        setxattr(
            dir.as_ptr(),
            XATTR_PAYLOAD.as_ptr(),
            payload.as_ptr().cast(),
            32,
            0,
        )
    } == 0
    {
        return Ok(());
    }
    let e = errno();
    log_err(
        &[
            &b"upatch: cannot record the payload on "[..],
            dir.as_bytes(),
            b": ",
            strerr(e),
            b"; undoing the load",
        ]
        .concat(),
    );
    if remove_pins(name) != 0 {
        log_err(
            &[
                &b"upatch: "[..],
                name,
                b" could not be undone; the next upatch command takes it out",
            ]
            .concat(),
        );
    }
    Err(e)
}

/// The policy labels the signature covered, set on their files: from
/// the copy the kernel checked, not from the file again, which may hold
/// other labels by now.
fn apply_policy_labels(u: &Upatch) {
    if u.map.is_null() || u.signed_policy_labels.is_null() {
        return;
    }
    // SAFETY: the signed section within the container, of its length.
    let labels = unsafe {
        crate::ffi::slice(
            u.signed_policy_labels.cast::<u8>(),
            u.signed_policy_labels_len as usize,
        )
    };
    let count = u32::from_le_bytes([labels[8], labels[9], labels[10], labels[11]]) as usize;
    for e in labels[POLICY_LABEL_HEADER..]
        .chunks_exact(POLICY_LABEL_ENTRY)
        .take(count)
    {
        let bit = u64::from_le_bytes(e[..8].try_into().unwrap_or_default());
        let policy = till_nul(&e[8..8 + POLICY_NAME_MAX]);
        let path = till_nul(&e[8 + POLICY_NAME_MAX..]);
        let file = match File::open(os(path)) {
            Ok(f) => f,
            Err(err) => {
                log_warn(
                    &[
                        &b"upatch: cannot label "[..],
                        path,
                        b" for policy ",
                        policy,
                        b": ",
                        strerr(io_errno(&err)),
                    ]
                    .concat(),
                );
                continue;
            }
        };
        let mut current = 0u64;
        // SAFETY: the file, a C string and room for the value.
        let n = unsafe {
            fgetxattr(
                file.as_raw_fd(),
                XATTR_POLICY.as_ptr(),
                (&raw mut current).cast(),
                8,
            )
        };
        if n < 0 && matches!(errno(), ENODATA | EOPNOTSUPP) {
            current = 0;
        } else if n != 8 {
            let why = if n < 0 {
                strerr(errno())
            } else {
                b"invalid length"
            };
            log_warn(
                &[
                    &b"upatch: cannot read policy label on "[..],
                    path,
                    b": ",
                    why,
                ]
                .concat(),
            );
            continue;
        }
        current |= bit;
        // SAFETY: the file, a C string and the value.
        if unsafe {
            fsetxattr(
                file.as_raw_fd(),
                XATTR_POLICY.as_ptr(),
                (&raw const current).cast(),
                8,
                0,
            )
        } != 0
        {
            log_warn(
                &[
                    &b"upatch: cannot set policy label on "[..],
                    path,
                    b": ",
                    strerr(errno()),
                ]
                .concat(),
            );
        }
    }
}

/// The kernel's BPF keyring, checked against the anchor init froze:
/// the keyring a signed load names and its serial.
pub(crate) fn trust_anchor(rep: Option<&mut OpReport>) -> Result<(i32, i32), ()> {
    let mut rep = Rep(rep);
    let mut id = crate::sys::identity::Identity::zeroed();
    let ret = identity::read(&mut id);
    if ret != 0 {
        log_err(
            &[
                &b"no trust anchor frozen this boot: "[..],
                strerr(-ret),
                b" (run `shirudo init`)",
            ]
            .concat(),
        );
        rep.fail(
            c"pre_flight",
            c"keyring_missing",
            -ret,
            b"no trust anchor frozen this boot",
        );
        return Err(());
    }
    let ring = keyring::bpf_serial();
    if id.keyring_type != SIG_KEYRING_BPF || ring <= 0 || ring != id.keyring_serial {
        log_err(b"the kernel BPF keyring differs from the frozen anchor");
        rep.fail(
            c"pre_flight",
            c"tampered",
            0,
            b"BPF keyring is not the frozen anchor",
        );
        return Err(());
    }
    Ok((keyring::KEY_SPEC_BPF_KEYRING, ring))
}

/// The section of the container at `off`, `len` bytes long, which the
/// parser bounded.
fn section(u: &Upatch, off: u32, len: u32) -> &[u8] {
    if u.map.is_null() {
        return &[];
    }
    // SAFETY: a section within the container, which the parser checked.
    unsafe { core::slice::from_raw_parts(u.map.add(off as usize), len as usize) }
}

/// Opens the upatch at `path` and applies it: boot restore's way in.
pub(crate) fn apply_path(
    path: &CStr,
    verify_only: bool,
    rep: Option<&mut OpReport>,
) -> Result<(), ()> {
    let mut rep = Rep(rep);
    let u = match Opened::open(path) {
        Ok(u) => u,
        Err(e) => {
            log_err(&[&b"open "[..], path.to_bytes(), b": ", strerr(-e)].concat());
            rep.fail(c"parse", c"parser_rejected", -e, b"cannot open .upatch");
            return Err(());
        }
    };
    apply(&u, path, verify_only, rep.0)
}

/// Loads `u`, which the caller read once and closes: the name the
/// signature covers, the loader the kernel verifies and what the caller
/// then measures and archives are all those bytes, which `label` names
/// in messages. With `verify_only` the kernel checks the signature
/// alone: the unload directive's gate, which accepts an UNLOAD directive
/// and stops before the loader runs. What failed goes in `rep`.
pub(crate) fn apply(
    u: &Upatch,
    label: &CStr,
    verify_only: bool,
    rep: Option<&mut OpReport>,
) -> Result<(), ()> {
    let mut rep = Rep(rep);
    if !verify_only && upatch::is_unload(u) {
        log_err(
            &[
                &b"upatch load: "[..],
                label.to_bytes(),
                b" is an UNLOAD directive; use `shirudo upatch unload`",
            ]
            .concat(),
        );
        rep.fail(c"parse", c"parser_rejected", 0, b"is an UNLOAD directive");
        return Err(());
    }
    let (keyring, serial) = trust_anchor(rep.0.as_deref_mut())?;
    let h = &u.hdr;
    let insns = section(u, h.loader_insns_off, h.loader_insns_len);
    let sig = section(u, h.signature_off, h.signature_len);
    let data = section(u, h.data_off, h.data_len);
    let insn_cnt = h.loader_insns_len as usize / 8;
    let mut prog_name = [0u8; 16];
    upatch::prog_name(u, &mut prog_name);

    // The pin directory, the archive and unload share the raw name. Boot
    // restore reaches here without the command's check, so it is checked
    // again; and the header's copy, which everything else reads, must be
    // the one the signature covers.
    let mut name = [0u8; NAME_MAX + 1];
    upatch::header_name(u, &mut name);
    let name = till_nul(&name);
    if !upatch::name_valid(Some(name)) {
        log_err(&[&b"upatch: refusing unsafe upatch name '"[..], name, b"'"].concat());
        rep.fail(c"parse", c"parser_rejected", 0, b"unsafe upatch name");
        return Err(());
    }
    if !upatch::name_signed(u) {
        log_err(
            &[
                &b"upatch: the name of '"[..],
                name,
                b"' is not signature-covered or differs from the signed one; rebuild the artifact",
            ]
            .concat(),
        );
        rep.fail(c"parse", c"parser_rejected", 0, b"name not signed");
        return Err(());
    }

    // The signature authorises the load, but payload_sha256 is what the
    // pin xattr, the register event and the unload match record, so a
    // header value that is not SHA-256(insns || data) is refused even
    // when signed.
    let mut digest = [0u8; 32];
    // SAFETY: the two sections, and room for the digest.
    let err = unsafe {
        sha256_2(
            insns.as_ptr().cast(),
            insns.len(),
            data.as_ptr().cast(),
            data.len(),
            digest.as_mut_ptr(),
        )
    };
    if err != 0 {
        log_err(
            &[
                &b"upatch: cannot hash the payload of '"[..],
                name,
                b"': ",
                strerr(-err),
            ]
            .concat(),
        );
        rep.fail(c"parse", c"unknown", -err, b"payload hash failed");
        return Err(());
    }
    if memneq_explicit(&digest, &h.payload_sha256) {
        log_err(b"upatch: payload_sha256 does not match signed content (insns || data); refusing");
        rep.fail(c"parse", c"parser_rejected", 0, b"payload_sha256 mismatch");
        return Err(());
    }

    // The attach metadata is signed with the data, which the kernel has
    // not verified yet: parsing it strictly here keeps a malformed
    // artifact from the keyring, and the load that follows keeps a forged
    // one from the sites it names.
    let mut specs = None;
    if !verify_only {
        if u.map.is_null() || u.signed_attach.is_null() {
            log_err(
                &[
                    &b"upatch: the attach metadata of '"[..],
                    name,
                    b"' is not signature-covered; rebuild the artifact",
                ]
                .concat(),
            );
            rep.fail(
                c"parse",
                c"parser_rejected",
                0,
                b"attach metadata not signed",
            );
            return Err(());
        }
        // SAFETY: the signed section within the container, of its length.
        let meta = unsafe { crate::ffi::slice(u.signed_attach, u.signed_attach_len as usize) };
        let mut parsed = match Specs::parse(meta, h.nr_maps, h.nr_progs) {
            Ok(s) => s,
            Err(e) => {
                log_err(&[&b"upatch program metadata rejected: "[..], strerr(-e)].concat());
                rep.fail(
                    c"parse",
                    c"parser_rejected",
                    -e,
                    b"invalid program attach metadata",
                );
                return Err(());
            }
        };
        if let Err(e) = prepare_uprobe_targets(parsed.get_mut()) {
            let cat = target_category(e);
            log_err(
                &[
                    &b"uprobe target verification failed ("[..],
                    cat.to_bytes(),
                    b"): ",
                    strerr(e),
                ]
                .concat(),
            );
            rep.fail(
                c"target_verify",
                cat,
                e,
                b"uprobe target verification failed",
            );
            return Err(());
        }
        specs = Some(parsed);
    }

    // The metadata map is exclusive to the loader by the digest of its
    // instructions alone, which the verifier enforces, and frozen: the
    // kernel refuses a signed load whose bound map is not.
    let mut loader_digest = [0u8; 32];
    if sha256_into(insns, &mut loader_digest) != 0 {
        log_err(b"__loader.map: cannot hash the loader");
        rep.fail(
            c"signed_loader_load",
            c"unknown",
            EIO,
            b"loader digest failed",
        );
        return Err(());
    }
    let map_name = *b"__loader.map\0\0\0\0";
    let map = Attr::new()
        .u32(0, MAP_TYPE_ARRAY)
        .u32(4, 4)
        .u32(
            8,
            if data.is_empty() {
                4
            } else {
                data.len() as u32
            },
        )
        .u32(12, 1)
        .put(28, &map_name)
        .ptr(80, loader_digest.as_ptr())
        .u32(88, 32)
        .fd(BPF_MAP_CREATE);
    let map = match map {
        Ok(fd) => fd,
        Err(e) => {
            log_err(&[&b"__loader.map create: "[..], strerr(e)].concat());
            rep.fail(
                c"signed_loader_load",
                load_category(e),
                e,
                b"__loader.map create failed",
            );
            return Err(());
        }
    };
    let (key, zero) = (0u32, [0u8; 4]);
    let value = if data.is_empty() {
        zero.as_ptr()
    } else {
        data.as_ptr()
    };
    if let Err(e) = Attr::new()
        .u32(0, map.as_raw_fd() as u32)
        .ptr(8, &raw const key)
        .ptr(16, value)
        .run(BPF_MAP_UPDATE_ELEM)
    {
        log_err(&[&b"__loader.map update: "[..], strerr(e)].concat());
        rep.fail(
            c"signed_loader_load",
            load_category(e),
            e,
            b"__loader.map update failed",
        );
        return Err(());
    }
    if let Err(e) = Attr::new()
        .u32(0, map.as_raw_fd() as u32)
        .run(BPF_MAP_FREEZE)
    {
        log_err(&[&b"__loader.map freeze: "[..], strerr(e)].concat());
        rep.fail(
            c"signed_loader_load",
            load_category(e),
            e,
            b"__loader.map freeze failed",
        );
        return Err(());
    }

    // The verifier resolves the exclusive metadata map up front through
    // fd_array_cnt and folds its frozen contents into the signed buffer
    // (insns || metadata): the kernel refuses to bind a map to a signed
    // load through the sparse fd_array path.
    let mut vlog = vec![0u8; VERIFIER_LOG_MAX];
    let fd_array = [map.as_raw_fd()];
    let n = prog_name.iter().position(|&c| c == 0).unwrap_or(16);
    let prog = Attr::new()
        .u32(0, PROG_TYPE_SYSCALL)
        .u32(4, insn_cnt as u32)
        .ptr(8, insns.as_ptr())
        .ptr(16, c"Dual BSD/GPL".as_ptr())
        .u32(24, 1)
        .u32(28, VERIFIER_LOG_MAX as u32)
        .ptr(32, vlog.as_ptr())
        .u32(44, F_SLEEPABLE)
        .put(48, &prog_name[..n])
        .ptr(120, fd_array.as_ptr())
        .u32(148, 1)
        .ptr(152, sig.as_ptr())
        .u32(160, h.signature_len)
        .u32(164, keyring as u32)
        .fd(BPF_PROG_LOAD);
    let prog = match prog {
        Ok(fd) => fd,
        Err(e) => {
            log_err(&[&b"BPF_PROG_LOAD (signed loader): "[..], strerr(e)].concat());
            if vlog[0] != 0 {
                let _ = std::io::stderr()
                    .write_all(&[&b"loader verifier log:\n"[..], till_nul(&vlog), b"\n"].concat());
            }
            rep.fail(
                c"signed_loader_load",
                load_category(e),
                e,
                b"BPF_PROG_LOAD of signed loader failed",
            );
            rep.log(&vlog);
            return Err(());
        }
    };
    let op: &[u8] = if verify_only {
        b"upatch unload"
    } else {
        b"upatch load"
    };
    log_info(
        &[
            op,
            b": signed loader accepted, keyring ",
            num(serial).as_bytes(),
            b", ",
            num(insn_cnt).as_bytes(),
            b" instructions",
        ]
        .concat(),
    );
    if verify_only {
        return Ok(());
    }

    // The loader creates the programs and maps from kernel context but
    // can neither attach nor pin: gen_loader emits no link-create and
    // bpf_sys_bpf() cannot BPF_OBJ_PIN. Its descriptors trail the
    // context, sized from the header's counts.
    vlog[0] = 0;
    let Some(mut cx) = Ctx::new(h.nr_maps, h.nr_progs, &mut vlog) else {
        log_err(
            &[
                &b"upatch: "[..],
                num(h.nr_maps).as_bytes(),
                b" maps and ",
                num(h.nr_progs).as_bytes(),
                b" programs do not fit the loader context",
            ]
            .concat(),
        );
        rep.fail(
            c"payload_load",
            c"unknown",
            E2BIG,
            b"loader context too large",
        );
        return Err(());
    };
    let mut skip = [MAPS_MAX; 2];
    let mut policy: Option<[c_int; 2]> = None;
    if !u.signed_policy_labels.is_null() {
        skip = [u.signed_policy_map_idx, u.signed_socket_policy_map_idx];
        let task =
            match open_shared_policy_map(POLICY_PIN, MAP_TYPE_TASK_STORAGE, 16, F_NO_PREALLOC) {
                Ok(fd) => fd,
                Err(e) => {
                    log_err(&[&b"upatch load: open shirudo_task_policy: "[..], strerr(e)].concat());
                    rep.fail(
                        c"payload_load",
                        c"unknown",
                        e,
                        b"shirudo_task_policy binding failed",
                    );
                    return Err(());
                }
            };
        let sock = match open_shared_policy_map(
            SOCKET_POLICY_PIN,
            MAP_TYPE_SK_STORAGE,
            8,
            F_NO_PREALLOC | F_CLONE,
        ) {
            Ok(fd) => fd,
            Err(e) => {
                log_err(&[&b"upatch load: open shirudo_sock_policy: "[..], strerr(e)].concat());
                rep.fail(
                    c"payload_load",
                    c"unknown",
                    e,
                    b"shirudo_sock_policy binding failed",
                );
                return Err(());
            }
        };
        let fds = [task.into_raw_fd(), sock.into_raw_fd()];
        cx.set_map_fd(skip[0], fds[0]);
        cx.set_map_fd(skip[1], fds[1]);
        policy = Some(fds);
    }

    let size = cx.buf.len() as u32;
    let retval = match prog_test_run(prog.as_raw_fd(), cx.buf.as_mut_ptr().cast(), size) {
        Ok(r) => r as i32,
        Err(e) => {
            log_err(&[&b"BPF_PROG_TEST_RUN: "[..], strerr(-e)].concat());
            if vlog[0] != 0 {
                let _ = std::io::stderr()
                    .write_all(&[&b"loader runtime log:\n"[..], till_nul(&vlog), b"\n"].concat());
            }
            rep.fail(
                c"payload_load",
                c"verifier_rejected",
                -e,
                b"BPF_PROG_TEST_RUN failed",
            );
            rep.log(&vlog);
            return Err(());
        }
    };
    if retval < 0 {
        // The loader closed what it made before it failed.
        cx.forget();
        for fd in policy.into_iter().flatten() {
            // SAFETY: the policy maps opened above, closed once.
            unsafe { close(fd) };
        }
        log_err(&[&b"loader returned error: "[..], num(retval).as_bytes()].concat());
        let log = till_nul(&vlog);
        let _ = std::io::stderr().write_all(
            &[
                &b"loader runtime log (len="[..],
                num(log.len()).as_bytes(),
                b"):\n",
                &log[..log.len().min(4096)],
                b"\n",
            ]
            .concat(),
        );
        rep.fail(
            c"payload_load",
            c"verifier_rejected",
            -retval,
            b"inner loader returned error",
        );
        rep.loader_return(retval);
        rep.log(&vlog);
        return Err(());
    }
    log_info(
        &[
            &b"upatch load: loader ran, "[..],
            num(h.nr_maps).as_bytes(),
            b" maps and ",
            num(h.nr_progs).as_bytes(),
            b" programs",
        ]
        .concat(),
    );

    // Without a pinned link a program detaches when this one-shot CLI
    // exits.
    let specs = specs.as_ref().map_or(&[][..], Specs::get);
    if let Err(e) = attach_and_pin(&cx, name, specs) {
        rep.fail(
            c"link_create",
            e.category(),
            e.errno(),
            b"attach or pin failed",
        );
        return Err(());
    }
    pin_maps(&cx, skip, name);
    // After attach and pin, so that the value records a loaded upatch.
    if let Err(e) = set_pin_payload(name, &h.payload_sha256) {
        rep.fail(
            c"link_create",
            c"unknown",
            e,
            b"cannot record the payload on the pin directory; the load was undone",
        );
        return Err(());
    }
    apply_policy_labels(u);
    log_audit(
        &[
            &b"upatch load: "[..],
            name,
            b" loaded, ",
            num(h.nr_progs).as_bytes(),
            b" programs, keyring ",
            num(serial).as_bytes(),
        ]
        .concat(),
    );
    rep.loader_return(retval);
    Ok(())
}
