// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The tamper counters: what the guards refused this boot, read back
//! from the map init pinned in the private bpffs, and what each point
//! counts; and the reader the integrity counters share.

use core::ffi::{CStr, c_int};

use crate::errno::EPROTO;
use crate::sys::libc::{close, errno};
use crate::util::bpf_info::{Info, MAP_INFO_SIZE, MAP_MAX_ENTRIES, MAP_VALUE_SIZE};
use crate::util::bpf_sys::{bpf_map_lookup_elem, bpf_obj_get};

/// `TAMPER_MAX` of `bpf/lib/tamper.h`: the tamper points there are.
pub(crate) const TAMPER_MAX: usize = 42;
/// TAMPER_PIN of util/paths.h.
const TAMPER_PIN: &CStr = c"/run/shirudo/bpffs/tamper";

/// The counters of a guard map: each point's refusals, and their sum.
pub(crate) struct Counters<const N: usize> {
    pub(crate) count: [u64; N],
    pub(crate) total: u64,
}

pub(crate) type TamperCounts = Counters<TAMPER_MAX>;

/// A counter: its name, and what it counts.
pub(crate) struct Point {
    pub(crate) name: &'static str,
    pub(crate) meaning: &'static str,
}

/// Each point, in the order of `enum tamper_point` of bpf/lib/tamper.h,
/// under the member's name, which t6003 checks against the header.
const POINTS: [Point; TAMPER_MAX] = [
    // TAMPER_LOAD_NOT_LOADER
    Point {
        name: "LoadNotLoader",
        meaning: "program load that is not a signed loader",
    },
    // TAMPER_LOAD_UNSIGNED
    Point {
        name: "LoadUnsigned",
        meaning: "loader-type program load without a signature",
    },
    // TAMPER_LOAD_UNVERIFIED
    Point {
        name: "LoadUnverified",
        meaning: "program load whose signature the kernel did not verify",
    },
    // TAMPER_LOAD_KEYRING_KIND
    Point {
        name: "LoadKeyringKind",
        meaning: "program signed against a keyring of the wrong kind",
    },
    // TAMPER_LOAD_KEYRING
    Point {
        name: "LoadKeyring",
        meaning: "program signed against a keyring that is not the anchor",
    },
    // TAMPER_MAP_CREATE
    Point {
        name: "MapCreate",
        meaning: "map creation by another executable",
    },
    // TAMPER_MAP_WRITE
    Point {
        name: "MapWrite",
        meaning: "map update or freeze by another executable",
    },
    // TAMPER_MAP_FD
    Point {
        name: "MapFdWrite",
        meaning: "writable map descriptor for another executable",
    },
    // TAMPER_PROG_RUN
    Point {
        name: "ProgRun",
        meaning: "test run of a program by another executable",
    },
    // TAMPER_ATTACH
    Point {
        name: "ProgAttach",
        meaning: "link or raw tracepoint attach by another executable",
    },
    // TAMPER_OBJ_PIN
    Point {
        name: "ObjPin",
        meaning: "pin of a BPF object by another executable",
    },
    // TAMPER_BPF_CMD
    Point {
        name: "BpfCommand",
        meaning: "detach, update, delete or unclassified bpf() command",
    },
    // TAMPER_EXE_IDENTITY
    Point {
        name: "ExeIdentity",
        meaning: "executable change through PR_SET_MM",
    },
    // TAMPER_KEYRING
    Point {
        name: "KeyringWrite",
        meaning: "write, unlink, revoke or invalidate on the anchor keyring",
    },
    // TAMPER_PIN_UNLINK
    Point {
        name: "PinUnlink",
        meaning: "unlink of a pin in the private bpffs",
    },
    // TAMPER_PIN_RENAME
    Point {
        name: "PinRename",
        meaning: "rename of a pin in the private bpffs",
    },
    // TAMPER_PIN_XATTR
    Point {
        name: "PinXattr",
        meaning: "xattr change on a pin in the private bpffs",
    },
    // TAMPER_BPFFS_UMOUNT
    Point {
        name: "BpffsUmount",
        meaning: "unmount of the private bpffs",
    },
    // TAMPER_BPFFS_UMOUNT_ABOVE
    Point {
        name: "BpffsUmountAbove",
        meaning: "unmount of a mount above the private bpffs",
    },
    // TAMPER_BPFFS_MOUNT
    Point {
        name: "BpffsMount",
        meaning: "move, mount over or remount of the private bpffs",
    },
    // TAMPER_SEAL_WRITE
    Point {
        name: "SealWrite",
        meaning: "write open of a sealed file",
    },
    // TAMPER_SEAL_UNLINK
    Point {
        name: "SealUnlink",
        meaning: "unlink of a sealed file or removal of a sealed directory",
    },
    // TAMPER_SEAL_RENAME
    Point {
        name: "SealRename",
        meaning: "rename of or over a sealed file",
    },
    // TAMPER_SEAL_SETATTR
    Point {
        name: "SealSetattr",
        meaning: "truncate, chmod, chown, utimes or chattr of a sealed file",
    },
    // TAMPER_SEAL_XATTR
    Point {
        name: "SealXattr",
        meaning: "xattr or ACL change on a sealed file",
    },
    // TAMPER_SEAL_LABEL
    Point {
        name: "SealLabel",
        meaning: "seal or policy label changed by another executable",
    },
    // TAMPER_SEAL_PTRACE
    Point {
        name: "SealPtrace",
        meaning: "ptrace of a shirudo task",
    },
    // TAMPER_SEAL_PERF
    Point {
        name: "SealPerf",
        meaning: "perf event bound to a shirudo task",
    },
    // TAMPER_EXEC_TRACED
    Point {
        name: "ExecTraced",
        meaning: "exec of shirudo by a traced task",
    },
    // TAMPER_SEAL_ENTRY
    Point {
        name: "SealEntry",
        meaning: "entry into a sealed directory, or a sealed inode linked",
    },
    // TAMPER_PERF_ATTACH
    Point {
        name: "PerfAttach",
        meaning: "program attached to a perf event by another executable",
    },
    // TAMPER_PIN_ENTRY
    Point {
        name: "PinEntry",
        meaning: "directory or link made in the private bpffs by another executable",
    },
    // TAMPER_SEAL_COPY_UP
    Point {
        name: "SealCopyUp",
        meaning: "overlay copy-up of a sealed inode",
    },
    // TAMPER_KEXEC
    Point {
        name: "Kexec",
        meaning: "kexec image or initramfs load",
    },
    // TAMPER_TPM_EXTEND
    Point {
        name: "TpmExtend",
        meaning: "extension of shirudo's TPM NV index by another executable",
    },
    // TAMPER_OBJ_GET
    Point {
        name: "ObjGet",
        meaning: "pin, map or link opened by another executable",
    },
    // TAMPER_SEAL_SIGNAL
    Point {
        name: "SealSignal",
        meaning: "signal to a shirudo task (let through)",
    },
    // TAMPER_SEAL_CORE_DUMP
    Point {
        name: "SealCoreDump",
        meaning: "core dump of a shirudo task, which acts without authority",
    },
    // TAMPER_SEAL_UPROBE
    Point {
        name: "SealUprobe",
        meaning: "uprobe in a shirudo task, which acts without authority",
    },
    // TAMPER_EXEC_SHARED
    Point {
        name: "ExecShared",
        meaning: "exec of the runtime binary by a task that shares its file system context",
    },
    // TAMPER_XATTR_HANDLE
    Point {
        name: "XattrHandle",
        meaning: "XFS attribute change by file handle, which passes no xattr hook",
    },
    // TAMPER_SEAL_RLIMIT
    Point {
        name: "SealRlimit",
        meaning: "resource limit of a shirudo task changed by another task",
    },
];

/// The name of tamper point `point`, "?" past the last.
pub(crate) fn name(point: usize) -> &'static [u8] {
    point_name(&POINTS, point)
}

/// What tamper point `point` counts, "?" past the last.
pub(crate) fn meaning(point: usize) -> &'static [u8] {
    point_meaning(&POINTS, point)
}

pub(crate) fn point_name(points: &[Point], point: usize) -> &'static [u8] {
    points.get(point).map_or(b"?", |p| p.name.as_bytes())
}

pub(crate) fn point_meaning(points: &[Point], point: usize) -> &'static [u8] {
    points.get(point).map_or(b"?", |p| p.meaning.as_bytes())
}

/// The tamper counters: -ENOENT before init, -EPROTO for a map of another
/// shape, or another -errno.
pub(crate) fn read() -> Result<TamperCounts, c_int> {
    counters_read(TAMPER_PIN)
}

/// The N counters of the array map pinned at `pin`, as read() reads the
/// tamper counters.
pub(crate) fn counters_read<const N: usize>(pin: &CStr) -> Result<Counters<N>, c_int> {
    // SAFETY: a C string.
    let fd = unsafe { bpf_obj_get(pin.as_ptr()) };
    if fd < 0 {
        return Err(-errno());
    }
    let ret = read_map(fd);
    // SAFETY: the pin opened above.
    unsafe { close(fd) };
    ret
}

fn read_map<const N: usize>(fd: c_int) -> Result<Counters<N>, c_int> {
    let mut info = Info::<MAP_INFO_SIZE>::new();
    info.read(fd)?;
    if info.u32_at(MAP_MAX_ENTRIES) as usize != N
        || info.u32_at(MAP_VALUE_SIZE) as usize != size_of::<u64>()
    {
        return Err(-EPROTO);
    }
    let mut out = Counters {
        count: [0; N],
        total: 0,
    };
    for key in 0..N as u32 {
        let value = &mut out.count[key as usize];
        // SAFETY: the map, a key of its size and room for a value of its size.
        if unsafe { bpf_map_lookup_elem(fd, (&raw const key).cast(), (&raw mut *value).cast()) }
            != 0
        {
            return Err(-errno());
        }
        // The C's sum wraps; a counter is the kernel's to set.
        out.total = out.total.wrapping_add(*value);
    }
    Ok(out)
}
