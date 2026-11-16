// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The host's overview, behind `util/sysinfo.h`: its name, OS, kernel and
//! its configuration, CPUs, memory, root disk and uptime, from /proc,
//! /etc, /boot and uname(2), with no subprocess. Lines are read and
//! scanned with the C library's own calls, so that every file reads as
//! it did.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};

use crate::sys::libc::{
    O_CLOEXEC, O_RDONLY, SC_NPROCESSORS_ONLN, Statvfs, Utsname, close, fclose, fgets, fopen,
    gethostname, open, qsort, read, sscanf, statvfs, strcmp, sysconf, uname,
};
use crate::sys::malloc::{xfree, xreallocarray, xstrdup, xstrfree};
use crate::text::{cstr, digits, parse_u64, strscpy, strsprintf};
use crate::util::json::JsonEmit;
use crate::util::kernel_build_id::read_build_id;

/// `struct sysinfo`.
#[repr(C)]
pub struct Sysinfo {
    pub(crate) hostname: [u8; 256],
    pub(crate) os_pretty: [u8; 256],
    pub(crate) kernel_release: [u8; 96],
    pub(crate) kernel_version: [u8; 256],
    pub(crate) kernel_build_id: [u8; 129],
    pub(crate) machine: [u8; 96],
    pub(crate) machine_id: [u8; 64],
    pub(crate) boot_id: [u8; 64],
    pub(crate) nproc: c_long,
    pub(crate) mem_total_kb: c_long,
    pub(crate) mem_avail_kb: c_long,
    pub(crate) uptime_sec: c_long,
    pub(crate) disk_total_kb: c_long,
    pub(crate) disk_used_kb: c_long,
}

const _: () = assert!(size_of::<Sysinfo>() == 1272);
const _: () = assert!(core::mem::offset_of!(Sysinfo, nproc) == 1224);

/// `shirudo_kernel_config_cb`.
type KernelConfigCb =
    unsafe extern "C" fn(ctx: *mut c_void, key: *const c_char, value: *const c_char);

/// The first line of the file at `path`, without its line end, or "".
fn read_first_line(path: &CStr, buf: &mut [u8]) {
    buf[0] = 0;
    // SAFETY: a C string and flags without a mode.
    let fd = unsafe { open(path.as_ptr(), O_RDONLY | O_CLOEXEC) };
    if fd < 0 {
        return;
    }
    // SAFETY: the room in buf before its last byte, from the fd open()
    // gave, which is closed once, here.
    let n = unsafe {
        let n = read(fd, buf.as_mut_ptr().cast(), buf.len() - 1);
        close(fd);
        n
    };
    if n <= 0 {
        buf[0] = 0;
        return;
    }
    let n = n as usize;

    buf[n] = 0;
    let end = buf[..n]
        .iter()
        .position(|&c| matches!(c, b'\r' | b'\n' | 0))
        .unwrap_or(n);
    buf[end] = 0;
}

/// PRETTY_NAME of /etc/os-release, without its quotes, or "".
fn read_os_pretty(buf: &mut [u8]) {
    let mut line = [0u8; 512];

    buf[0] = 0;
    // SAFETY: a path and a mode.
    let f = unsafe { fopen(c"/etc/os-release".as_ptr(), c"re".as_ptr()) };
    if f.is_null() {
        return;
    }
    // SAFETY: the room of line, and the stream fopen() gave.
    while !unsafe { fgets(line.as_mut_ptr().cast(), line.len() as c_int, f) }.is_null() {
        let l = cstr(&line);

        if !l.starts_with(b"PRETTY_NAME=") {
            continue;
        }
        let mut v = &l[12..];

        if v.first() == Some(&b'"') {
            v = &v[1..];
        }
        let _ = strscpy(buf, v);
        let mut len = cstr(buf).len();

        while len > 0 && matches!(buf[len - 1], b'\n' | b'\r' | b'"') {
            len -= 1;
            buf[len] = 0;
        }
        break;
    }
    // SAFETY: the stream fopen() gave, closed once.
    unsafe { fclose(f) };
}

/// The whole seconds of /proc/uptime, or -1.
fn read_uptime_sec() -> c_long {
    let mut buf = [0u8; 64];

    // SAFETY: a C string and flags without a mode.
    let fd = unsafe { open(c"/proc/uptime".as_ptr(), O_RDONLY | O_CLOEXEC) };
    if fd < 0 {
        return -1;
    }
    // SAFETY: the room in buf before its last byte, from the fd open()
    // gave, which is closed once, here.
    let n = unsafe {
        let n = read(fd, buf.as_mut_ptr().cast(), buf.len() - 1);
        close(fd);
        n
    };
    if n <= 0 {
        return -1;
    }
    let text = &buf[..n as usize];

    match parse_u64(&text[..digits(text)], c_long::MAX as u64) {
        Ok(sec) => sec as c_long,
        Err(_) => -1,
    }
}

/// The long a format of one `%ld` scans from the line fgets() left in
/// `line`, if it does.
fn scan_long(line: &[u8], fmt: &CStr) -> Option<c_long> {
    let mut v: c_long = 0;
    // SAFETY: a C string fgets() ended within line, a format of one
    // long, and v.
    let n = unsafe { sscanf(line.as_ptr().cast::<c_char>(), fmt.as_ptr(), &mut v) };

    (n == 1).then_some(v)
}

/// MemTotal and MemAvailable of /proc/meminfo in KiB, -1 for one it
/// lacks.
fn read_mem(total_kb: &mut c_long, avail_kb: &mut c_long) {
    let mut line = [0u8; 256];

    *total_kb = -1;
    *avail_kb = -1;
    // SAFETY: a path and a mode.
    let f = unsafe { fopen(c"/proc/meminfo".as_ptr(), c"re".as_ptr()) };
    if f.is_null() {
        return;
    }
    // SAFETY: the room of line, and the stream fopen() gave.
    while !unsafe { fgets(line.as_mut_ptr().cast(), line.len() as c_int, f) }.is_null() {
        if *total_kb < 0
            && let Some(kb) = scan_long(&line, c"MemTotal: %ld kB")
        {
            *total_kb = kb;
        } else if *avail_kb < 0
            && let Some(kb) = scan_long(&line, c"MemAvailable: %ld kB")
        {
            *avail_kb = kb;
        }
        if *total_kb >= 0 && *avail_kb >= 0 {
            break;
        }
    }
    // SAFETY: the stream fopen() gave, closed once.
    unsafe { fclose(f) };
}

/// The size and the used space of the root file system in KiB, as df
/// counts them, or -1.
fn read_root_disk(total_kb: &mut c_long, used_kb: &mut c_long) {
    let mut s = Statvfs::zeroed();

    *total_kb = -1;
    *used_kb = -1;
    // SAFETY: a C string and a struct statvfs to fill.
    if unsafe { statvfs(c"/".as_ptr(), &mut s) } != 0 {
        return;
    }
    // f_frsize is the unit statvfs counts its blocks in.
    let tot_b = s.f_blocks.wrapping_mul(s.f_frsize);
    let free_b = s.f_bfree.wrapping_mul(s.f_frsize);

    *total_kb = (tot_b / 1024) as c_long;
    *used_kb = (tot_b.wrapping_sub(free_b) / 1024) as c_long;
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// trim_config_text(): the text from `start` to its NUL in `line` without
/// its leading spaces, the trailing ones cut off with NULs: where it
/// starts.
fn trim(line: &mut [u8], start: usize) -> usize {
    let mut s = start;

    while line[s] != 0 && is_space(line[s]) {
        s += 1;
    }
    let mut end = s + cstr(&line[s..]).len();

    while end > s && is_space(line[end - 1]) {
        end -= 1;
        line[end] = 0;
    }
    s
}

/// An entry of the kernel configuration, its two strings from xstrdup().
#[repr(C)]
struct ConfigEntry {
    key: *mut c_char,
    value: *mut c_char,
}

/// # Safety
///
/// The first `n` of `entries` hold strings from xstrdup() or NULL, and
/// `entries` is NULL or an allocation of `cap` entries.
unsafe fn entries_free(entries: *mut ConfigEntry, n: usize, cap: usize) {
    for i in 0..n {
        // SAFETY: the caller passes n entries, freed once, here.
        unsafe {
            let e = &*entries.add(i);

            xstrfree(e.key);
            xstrfree(e.value);
        }
    }
    // SAFETY: the caller passes an allocation of cap entries.
    unsafe { xfree(entries.cast(), cap * size_of::<ConfigEntry>()) };
}

unsafe extern "C" fn entry_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: qsort() passes two of the entries, each key a C string.
    unsafe {
        strcmp(
            (*a.cast::<ConfigEntry>()).key,
            (*b.cast::<ConfigEntry>()).key,
        )
    }
}

/// One `CONFIG_` option of a configuration line in `line`, its key and
/// value: from `KEY=value`, quotes taken off a value, or `n` from
/// `# KEY is not set`.
fn config_option(line: &mut [u8]) -> Option<(usize, Option<usize>)> {
    let end = line
        .iter()
        .position(|&c| matches!(c, b'\r' | b'\n' | 0))
        .unwrap_or(line.len() - 1);

    line[end] = 0;
    let mut key = trim(line, 0);

    if line[key] == 0 {
        return None;
    }
    let value = if cstr(&line[key..]).starts_with(b"# CONFIG_") {
        key += 2;
        let rest = cstr(&line[key..]);
        let at = key + rest.windows(11).position(|w| w == b" is not set")?;
        let after = trim(line, at + 11);

        if line[after] != 0 {
            return None;
        }
        line[at] = 0;
        None
    } else {
        let eq = key + cstr(&line[key..]).iter().position(|&c| c == b'=')?;

        line[eq] = 0;
        key = trim(line, key);
        let k = cstr(&line[key..]);

        if !k.starts_with(b"CONFIG_") || k.len() == 7 {
            return None;
        }
        let mut value = trim(line, eq + 1);
        let len = cstr(&line[value..]).len();

        if len >= 2 && line[value] == b'"' && line[value + len - 1] == b'"' {
            line[value + len - 1] = 0;
            value += 1;
        }
        Some(value)
    };
    let k = cstr(&line[key..]);

    if !k.starts_with(b"CONFIG_") || k.len() == 7 {
        return None;
    }
    Some((key, value))
}

/// The options of /boot/config-`release`, by key, each to `cb`: how many,
/// or -1.
///
/// # Safety
///
/// `release` is NULL or a C string, and `cb` takes `ctx`.
unsafe fn kernel_config_foreach(
    release: *const c_char,
    cb: Option<KernelConfigCb>,
    ctx: *mut c_void,
) -> c_int {
    let mut path = [0u8; 4096];
    let mut line = [0u8; 8192];
    let mut entries: *mut ConfigEntry = core::ptr::null_mut();
    let (mut n, mut cap) = (0usize, 0usize);

    // SAFETY: the caller passes NULL or a C string.
    let release = (!release.is_null()).then(|| unsafe { CStr::from_ptr(release) }.to_bytes());
    let (Some(release), Some(cb)) = (release.filter(|r| !r.is_empty()), cb) else {
        return -1;
    };
    if strsprintf(&mut path, &[b"/boot/config-", release]).is_err() {
        return -1;
    }
    // SAFETY: the path just written, and a mode.
    let f = unsafe { fopen(path.as_ptr().cast(), c"re".as_ptr()) };
    if f.is_null() {
        return -1;
    }
    // SAFETY: the room of line, and the stream fopen() gave.
    while !unsafe { fgets(line.as_mut_ptr().cast(), line.len() as c_int, f) }.is_null() {
        let Some((key, value)) = config_option(&mut line) else {
            continue;
        };
        let value: *const c_char = match value {
            Some(v) => line[v..].as_ptr().cast(),
            None => c"n".as_ptr(),
        };

        if n == cap {
            let grown = if cap != 0 { 2 * cap } else { 256 };
            // SAFETY: the entries so far, from xreallocarray() or NULL.
            let next: *mut ConfigEntry =
                unsafe { xreallocarray(entries.cast(), cap, grown, size_of::<ConfigEntry>()) }
                    .cast();

            if next.is_null() {
                // SAFETY: the stream, and the entries so far.
                unsafe {
                    fclose(f);
                    entries_free(entries, n, cap);
                }
                return -1;
            }
            entries = next;
            cap = grown;
        }
        // SAFETY: room for entry n, and the C strings of the line.
        unsafe {
            let e = &mut *entries.add(n);

            e.key = xstrdup(line[key..].as_ptr().cast());
            e.value = xstrdup(value);
            if e.key.is_null() || e.value.is_null() {
                xstrfree(e.key);
                xstrfree(e.value);
                e.key = core::ptr::null_mut();
                e.value = core::ptr::null_mut();
                fclose(f);
                entries_free(entries, n + 1, cap);
                return -1;
            }
        }
        n += 1;
    }
    // SAFETY: the stream fopen() gave, closed once.
    unsafe { fclose(f) };
    if n != 0 {
        // SAFETY: n entries, their size, and an order over their keys.
        unsafe { qsort(entries.cast(), n, size_of::<ConfigEntry>(), Some(entry_cmp)) };
    }
    for i in 0..n {
        // SAFETY: entry i, and the caller's callback and context.
        unsafe {
            let e = &*entries.add(i);

            cb(ctx, e.key, e.value);
        }
    }
    // SAFETY: the n entries in an allocation of cap.
    unsafe { entries_free(entries, n, cap) };
    n as c_int
}

unsafe extern "C" fn emit_config_entry(ctx: *mut c_void, key: *const c_char, value: *const c_char) {
    // SAFETY: the emitter emit_kernel_config() passes, and two C strings.
    unsafe {
        let e = &mut *ctx.cast::<JsonEmit>();

        e.kv_string(
            CStr::from_ptr(key).to_bytes(),
            CStr::from_ptr(value).to_bytes(),
        );
    }
}

fn gather(si: &mut Sysinfo) {
    let mut u = Utsname::zeroed();

    si.nproc = -1;
    si.mem_total_kb = -1;
    si.mem_avail_kb = -1;
    si.uptime_sec = -1;
    si.disk_total_kb = -1;
    si.disk_used_kb = -1;
    // SAFETY: the room of the hostname.
    if unsafe { gethostname(si.hostname.as_mut_ptr().cast(), si.hostname.len()) } != 0 {
        si.hostname[0] = 0;
    }
    si.hostname[255] = 0;
    // SAFETY: a struct utsname to fill.
    if unsafe { uname(&mut u) } == 0 {
        let _ = strscpy(&mut si.kernel_release, cstr(&u.release));
        let _ = strscpy(&mut si.kernel_version, cstr(&u.version));
        let _ = strscpy(&mut si.machine, cstr(&u.machine));
        if si.hostname[0] == 0 {
            let _ = strscpy(&mut si.hostname, cstr(&u.nodename));
        }
    }
    read_os_pretty(&mut si.os_pretty);
    read_first_line(c"/etc/machine-id", &mut si.machine_id);
    read_first_line(c"/proc/sys/kernel/random/boot_id", &mut si.boot_id);
    // SAFETY: the room of the build ID string.
    unsafe { read_build_id(si.kernel_build_id.as_mut_ptr().cast()) };
    // SAFETY: a call that takes no pointer.
    si.nproc = unsafe { sysconf(SC_NPROCESSORS_ONLN) };
    read_mem(&mut si.mem_total_kb, &mut si.mem_avail_kb);
    read_root_disk(&mut si.disk_total_kb, &mut si.disk_used_kb);
    si.uptime_sec = read_uptime_sec();
}

fn emit_json(e: &mut JsonEmit, si: &Sysinfo) {
    e.obj_open_key(b"system");
    e.kv_string(b"hostname", cstr(&si.hostname));
    e.kv_string(b"os", cstr(&si.os_pretty));
    e.kv_string(b"kernel_release", cstr(&si.kernel_release));
    e.kv_string(b"kernel_version", cstr(&si.kernel_version));
    e.kv_string(b"kernel_build_id", cstr(&si.kernel_build_id));
    e.obj_open_key(b"kernel_config");
    // SAFETY: the release, which its array ends, and the emitter the
    // callback takes.
    unsafe {
        kernel_config_foreach(
            si.kernel_release.as_ptr().cast(),
            Some(emit_config_entry),
            (&raw mut *e).cast(),
        )
    };
    e.obj_close();
    e.kv_string(b"architecture", cstr(&si.machine));
    e.kv_string(b"machine_id", cstr(&si.machine_id));
    e.kv_string(b"boot_id", cstr(&si.boot_id));
    e.kv_int(b"nproc", si.nproc);
    e.kv_int(b"mem_total_kb", si.mem_total_kb);
    e.kv_int(b"mem_avail_kb", si.mem_avail_kb);
    e.kv_int(b"disk_total_kb", si.disk_total_kb);
    e.kv_int(b"disk_used_kb", si.disk_used_kb);
    e.kv_int(b"uptime_seconds", si.uptime_sec);
    e.obj_close();
}

pub(crate) use capi::{sysinfo_emit_json, sysinfo_gather};

mod capi {
    use core::ffi::{c_char, c_int, c_void};

    use super::{KernelConfigCb, Sysinfo};
    use crate::util::json::JsonEmit;

    /// # Safety
    ///
    /// `si` points to room for a `struct sysinfo`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sysinfo_gather(si: *mut Sysinfo) {
        // SAFETY: the caller passes the room, zeroed whole, padding too,
        // before anything reads it.
        unsafe {
            si.write_bytes(0, 1);
            super::gather(&mut *si);
        }
    }

    /// # Safety
    ///
    /// `kernel_release` is NULL or a C string, and `cb` takes `ctx`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sysinfo_kernel_config_foreach(
        kernel_release: *const c_char,
        cb: Option<KernelConfigCb>,
        ctx: *mut c_void,
    ) -> c_int {
        // SAFETY: the caller passes the release, the callback and its
        // context.
        unsafe { super::kernel_config_foreach(kernel_release, cb, ctx) }
    }

    /// # Safety
    ///
    /// `e` points to an emitter, and `si` to a `struct sysinfo`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sysinfo_emit_json(e: *mut JsonEmit, si: *const Sysinfo) {
        // SAFETY: the caller passes an emitter and a sysinfo.
        unsafe { super::emit_json(&mut *e, &*si) }
    }
}
