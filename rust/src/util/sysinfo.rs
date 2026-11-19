// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The host's overview: its name, OS, kernel and
//! its configuration, CPUs, memory, root disk and uptime, from /proc,
//! /etc, /boot and uname(2), with no subprocess. Lines are read and
//! scanned with the C library's own calls, so that every file reads as
//! it did.

use core::ffi::{CStr, c_char, c_int, c_long};

use crate::errno::ENOENT;
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    SC_NPROCESSORS_ONLN, Statvfs, Utsname, fclose, fgets, fopen, gethostname, sscanf, statvfs,
    sysconf, uname,
};
use crate::text::{cstr, digits, parse_u64, strscpy, strsprintf};
use crate::util::json::JsonEmit;
use crate::util::kernel_build_id::read_build_id;
use std::os::unix::ffi::OsStrExt;

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

/// The start of the file at `path` in all of `buf` but its last byte,
/// read until that is full or the file ends: how many bytes, or None
/// where it cannot be opened or read.
fn read_start(path: &CStr, buf: &mut [u8]) -> Option<usize> {
    use std::io::{ErrorKind, Read};

    let mut f = std::fs::File::open(std::ffi::OsStr::from_bytes(path.to_bytes())).ok()?;
    let room = buf.len() - 1;
    let mut n = 0;
    // A read may return less than the file holds, and a line too long
    // for the room is told only by filling it.
    while n < room {
        match f.read(&mut buf[n..room]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    Some(n)
}

/// The first line of the file at `path`, without its line end, or "".
fn read_first_line(path: &CStr, buf: &mut [u8]) {
    buf[0] = 0;
    let n = match read_start(path, buf) {
        Some(n) if n > 0 => n,
        _ => return,
    };

    buf[n] = 0;
    let end = buf[..n]
        .iter()
        .position(|&c| matches!(c, b'\r' | b'\n' | 0))
        .unwrap_or(n);
    buf[end] = 0;
}

/// `SYSINFO_IMAGE_VALUE_MAX` and `SYSINFO_IMAGE_ROOT_MAX`.
const IMAGE_VALUE_MAX: usize = 256;
const IMAGE_ROOT_MAX: usize = 65;
const OS_RELEASE_SIZE_MAX: usize = 64 * 1024;
/// Above the COMMAND_LINE_SIZE of every architecture.
const CMDLINE_SIZE_MAX: usize = 8192;

/// `struct sysinfo_image`: the identity of the booted image, each field
/// "" when absent or refused.
#[repr(C)]
pub struct SysinfoImage {
    pub(crate) id: [u8; IMAGE_VALUE_MAX],
    pub(crate) version: [u8; IMAGE_VALUE_MAX],
    pub(crate) root: [u8; IMAGE_ROOT_MAX],
}

const _: () = assert!(size_of::<SysinfoImage>() == 577);

impl SysinfoImage {
    pub(crate) const fn zeroed() -> Self {
        SysinfoImage {
            id: [0; IMAGE_VALUE_MAX],
            version: [0; IMAGE_VALUE_MAX],
            root: [0; IMAGE_ROOT_MAX],
        }
    }
}

/// The value of an os-release assignment unquoted as os-release(5)
/// defines: one pair of matching quotes stripped, and within double
/// quotes the backslash before an escapable character dropped. It must
/// then be 1 to 255 bytes of printable ASCII.
fn os_release_unquote(mut value: &[u8]) -> Option<Vec<u8>> {
    let mut double_quoted = false;

    if let [q @ (b'"' | b'\''), .., last] = value
        && q == last
    {
        double_quoted = *q == b'"';
        value = &value[1..value.len() - 1];
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < value.len() {
        if double_quoted
            && value[i] == b'\\'
            && value.get(i + 1).is_some_and(|c| b"\"\\$`".contains(c))
        {
            i += 1;
        }
        let c = value[i];
        if !(0x20..=0x7e).contains(&c) || out.len() == IMAGE_VALUE_MAX - 1 {
            return None;
        }
        out.push(c);
        i += 1;
    }
    (!out.is_empty()).then_some(out)
}

/// The value of `key` in the os-release text: of a key given twice the
/// last one counts, as a shell reading the file has it.
fn os_release_value(text: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let value = text
        .rsplit(|&c| c == b'\n')
        .find_map(|line| line.strip_prefix(key)?.strip_prefix(b"="))?;
    os_release_unquote(value)
}

/// The file at `path`, of at most `max` bytes.
fn read_text(path: &CStr, max: usize) -> Result<Vec<u8>, c_int> {
    crate::util::io::read(path, max)
}

/// os-release(5): /usr/lib/os-release stands in only where /etc has none.
fn read_os_release(path: &CStr, fallback: &CStr) -> Result<Vec<u8>, c_int> {
    match read_text(path, OS_RELEASE_SIZE_MAX) {
        Err(err) if err == -ENOENT => read_text(fallback, OS_RELEASE_SIZE_MAX),
        r => r,
    }
}

/// `value` into the C string field `out`, or "" for none.
fn set_field(out: &mut [u8], value: Option<&[u8]>) {
    out.fill(0);
    if let Some(v) = value {
        let _ = strscpy(out, v);
    }
}

/// The image's root hash on the kernel command line: roothash=, else
/// usrhash=, the last of each, 64 hex digits in lowercase, or none.
fn cmdline_image_root(cmdline: &[u8]) -> Option<Vec<u8>> {
    let (mut roothash, mut usrhash) = (None, None);
    for arg in cmdline.split(|c| matches!(c, b' ' | b'\t' | b'\n')) {
        if let Some(v) = arg.strip_prefix(b"roothash=") {
            roothash = Some(v);
        }
        if let Some(v) = arg.strip_prefix(b"usrhash=") {
            usrhash = Some(v);
        }
    }
    let hash = roothash.or(usrhash)?;
    (hash.len() == IMAGE_ROOT_MAX - 1 && hash.iter().all(u8::is_ascii_hexdigit))
        .then(|| hash.to_ascii_lowercase())
}

/// The image the system booted: IMAGE_ID and IMAGE_VERSION of the
/// os-release at `os_release`, or `fallback` where that does not exist,
/// and the root hash of the command line at `cmdline`, none from one that
/// does not fit.
pub(crate) fn image_read_at(os_release: &CStr, fallback: &CStr, cmdline: &CStr) -> SysinfoImage {
    let mut img = SysinfoImage::zeroed();
    if let Ok(text) = read_os_release(os_release, fallback) {
        set_field(&mut img.id, os_release_value(&text, b"IMAGE_ID").as_deref());
        set_field(
            &mut img.version,
            os_release_value(&text, b"IMAGE_VERSION").as_deref(),
        );
    }
    let mut line = vec![0u8; CMDLINE_SIZE_MAX];
    read_first_line(cmdline, &mut line);
    let line = cstr(&line);
    if line.len() < CMDLINE_SIZE_MAX - 1 {
        set_field(&mut img.root, cmdline_image_root(line).as_deref());
    }
    img
}

/// image_read_at() of this system.
pub(crate) fn image_read() -> SysinfoImage {
    image_read_at(c"/etc/os-release", c"/usr/lib/os-release", c"/proc/cmdline")
}

/// The whole seconds of /proc/uptime, or -1.
fn read_uptime_sec() -> c_long {
    let mut buf = [0u8; 64];

    let n = match read_start(c"/proc/uptime", &mut buf) {
        Some(n) if n > 0 => n,
        _ => return -1,
    };
    let text = &buf[..n];

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

/// fgets()'s room for a line of the configuration, its NUL included.
const CONFIG_LINE: usize = 8192;

/// The options of /boot/config-`release`, sorted by key: none without a
/// release or a file to read. The file is taken in the pieces fgets()
/// gave the C, each line or the first CONFIG_LINE - 1 bytes of one.
fn kernel_config(release: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut path = [0u8; 4096];

    if release.is_empty() || strsprintf(&mut path, &[b"/boot/config-", release]).is_err() {
        return None;
    }
    let text = std::fs::read(std::ffi::OsStr::from_bytes(cstr(&path))).ok()?;
    let mut options = Vec::new();
    let mut rest = &text[..];
    while !rest.is_empty() {
        let take = rest
            .iter()
            .position(|&c| c == b'\n')
            .map_or(rest.len(), |i| i + 1)
            .min(CONFIG_LINE - 1);
        let (piece, tail) = rest.split_at(take);
        let mut line = [0u8; CONFIG_LINE];

        rest = tail;
        line[..piece.len()].copy_from_slice(piece);
        let Some((key, value)) = config_option(&mut line) else {
            continue;
        };
        let value = value.map_or(&b"n"[..], |v| cstr(&line[v..]));
        options.push((cstr(&line[key..]).to_vec(), value.to_vec()));
    }
    // As qsort() with strcmp() of the keys ordered them.
    options.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    Some(options)
}

/// The system's facts into `si`, zeroed whole first.
pub(crate) fn gather(si: &mut Sysinfo) {
    let room: *mut Sysinfo = si;
    // SAFETY: the caller's sysinfo, all of whose bits zeroed are one.
    unsafe { room.write_bytes(0, 1) };
    fill(si);
}

fn fill(si: &mut Sysinfo) {
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
        let _ = strscpy(
            &mut si.kernel_release,
            cstr(crate::sys::libc::bytes(&u.release)),
        );
        let _ = strscpy(
            &mut si.kernel_version,
            cstr(crate::sys::libc::bytes(&u.version)),
        );
        let _ = strscpy(&mut si.machine, cstr(crate::sys::libc::bytes(&u.machine)));
        if si.hostname[0] == 0 {
            let _ = strscpy(&mut si.hostname, cstr(crate::sys::libc::bytes(&u.nodename)));
        }
    }
    let pretty = read_os_release(c"/etc/os-release", c"/usr/lib/os-release")
        .ok()
        .and_then(|text| os_release_value(&text, b"PRETTY_NAME"));
    set_field(&mut si.os_pretty, pretty.as_deref());
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

pub(crate) fn emit_json(e: &mut JsonEmit, si: &Sysinfo) {
    e.obj_open_key(b"system");
    e.kv_string(b"hostname", cstr(&si.hostname));
    e.kv_string(b"os", cstr(&si.os_pretty));
    e.kv_string(b"kernel_release", cstr(&si.kernel_release));
    e.kv_string(b"kernel_version", cstr(&si.kernel_version));
    e.kv_string(b"kernel_build_id", cstr(&si.kernel_build_id));
    e.obj_open_key(b"kernel_config");
    for (key, value) in kernel_config(cstr(&si.kernel_release)).unwrap_or_default() {
        e.kv_string(&key, &value);
    }
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

#[cfg(test)]
mod tests;
