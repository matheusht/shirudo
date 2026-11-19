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
    SC_NPROCESSORS_ONLN, Statvfs, Utsname, bytes, fclose, fgets, fopen, gethostname, sscanf,
    statvfs, sysconf, uname,
};
use crate::text::{cstr, digits, parse_u64, strsprintf};
use crate::util::json::JsonEmit;
use crate::util::kernel_build_id::read_build_id;
use std::os::unix::ffi::OsStrExt;

/// The host's facts: a text that cannot be read is empty, a count -1.
pub struct Sysinfo {
    pub(crate) hostname: Vec<u8>,
    pub(crate) os_pretty: Vec<u8>,
    pub(crate) kernel_release: Vec<u8>,
    pub(crate) kernel_version: Vec<u8>,
    pub(crate) kernel_build_id: Vec<u8>,
    pub(crate) machine: Vec<u8>,
    pub(crate) machine_id: Vec<u8>,
    pub(crate) boot_id: Vec<u8>,
    pub(crate) nproc: c_long,
    pub(crate) mem_total_kb: c_long,
    pub(crate) mem_avail_kb: c_long,
    pub(crate) uptime_sec: c_long,
    pub(crate) disk_total_kb: c_long,
    pub(crate) disk_used_kb: c_long,
}

/// gethostname()'s room, its NUL included.
const HOSTNAME_ROOM: usize = 256;
/// The longest machine ID and boot ID shown; either is 36 bytes or less.
const ID_LEN_MAX: usize = 63;
const UPTIME_LEN_MAX: usize = 63;
const OS_RELEASE_VALUE_MAX: usize = 255;
const IMAGE_ROOT_LEN: usize = 64;
const OS_RELEASE_SIZE_MAX: usize = 64 * 1024;
/// Above the COMMAND_LINE_SIZE of every architecture.
const CMDLINE_SIZE_MAX: usize = 8192;

/// The first `max` bytes of the file at `path`, or all of a shorter
/// one, or None where it cannot be opened or read.
fn read_start(path: &CStr, max: usize) -> Option<Vec<u8>> {
    use std::io::Read;

    let f = std::fs::File::open(std::ffi::OsStr::from_bytes(path.to_bytes())).ok()?;
    let mut text = Vec::with_capacity(max);
    f.take(max as u64).read_to_end(&mut text).ok()?;
    Some(text)
}

/// The first line of the first `max` bytes of the file at `path`,
/// without its line end, or "".
fn read_first_line(path: &CStr, max: usize) -> Vec<u8> {
    let mut text = read_start(path, max).unwrap_or_default();
    let end = text
        .iter()
        .position(|&c| matches!(c, b'\r' | b'\n' | 0))
        .unwrap_or(text.len());
    text.truncate(end);
    text
}

/// The identity of the booted image, each field "" when absent or
/// refused.
pub struct SysinfoImage {
    pub(crate) id: Vec<u8>,
    pub(crate) version: Vec<u8>,
    pub(crate) root: Vec<u8>,
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
        if !(0x20..=0x7e).contains(&c) || out.len() == OS_RELEASE_VALUE_MAX {
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
    (hash.len() == IMAGE_ROOT_LEN && hash.iter().all(u8::is_ascii_hexdigit))
        .then(|| hash.to_ascii_lowercase())
}

/// The image the system booted: IMAGE_ID and IMAGE_VERSION of the
/// os-release at `os_release`, or `fallback` where that does not exist,
/// and the root hash of the command line at `cmdline`, none from one that
/// does not fit.
pub(crate) fn image_read_at(os_release: &CStr, fallback: &CStr, cmdline: &CStr) -> SysinfoImage {
    let text = read_os_release(os_release, fallback).unwrap_or_default();
    let value = |key: &[u8]| os_release_value(&text, key).unwrap_or_default();
    let line = read_first_line(cmdline, CMDLINE_SIZE_MAX - 1);
    let root = if line.len() < CMDLINE_SIZE_MAX - 1 {
        cmdline_image_root(&line).unwrap_or_default()
    } else {
        Vec::new()
    };
    SysinfoImage {
        id: value(b"IMAGE_ID"),
        version: value(b"IMAGE_VERSION"),
        root,
    }
}

/// image_read_at() of this system.
pub(crate) fn image_read() -> SysinfoImage {
    image_read_at(c"/etc/os-release", c"/usr/lib/os-release", c"/proc/cmdline")
}

/// The whole seconds of /proc/uptime, or -1.
fn read_uptime_sec() -> c_long {
    let text = match read_start(c"/proc/uptime", UPTIME_LEN_MAX) {
        Some(text) if !text.is_empty() => text,
        _ => return -1,
    };

    match parse_u64(&text[..digits(&text)], c_long::MAX as u64) {
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
fn read_mem() -> (c_long, c_long) {
    let (mut total_kb, mut avail_kb) = (-1, -1);
    let mut line = [0u8; 256];

    // SAFETY: a path and a mode.
    let f = unsafe { fopen(c"/proc/meminfo".as_ptr(), c"re".as_ptr()) };
    if f.is_null() {
        return (total_kb, avail_kb);
    }
    // SAFETY: the room of line, and the stream fopen() gave.
    while !unsafe { fgets(line.as_mut_ptr().cast(), line.len() as c_int, f) }.is_null() {
        if total_kb < 0
            && let Some(kb) = scan_long(&line, c"MemTotal: %ld kB")
        {
            total_kb = kb;
        } else if avail_kb < 0
            && let Some(kb) = scan_long(&line, c"MemAvailable: %ld kB")
        {
            avail_kb = kb;
        }
        if total_kb >= 0 && avail_kb >= 0 {
            break;
        }
    }
    // SAFETY: the stream fopen() gave, closed once.
    unsafe { fclose(f) };
    (total_kb, avail_kb)
}

/// The size and the used space of the root file system in KiB, as df
/// counts them, or -1.
fn read_root_disk() -> (c_long, c_long) {
    let mut s = Statvfs::zeroed();

    // SAFETY: a C string and a struct statvfs to fill.
    if unsafe { statvfs(c"/".as_ptr(), &mut s) } != 0 {
        return (-1, -1);
    }
    // f_frsize is the unit statvfs counts its blocks in.
    let tot_b = s.f_blocks.wrapping_mul(s.f_frsize);
    let free_b = s.f_bfree.wrapping_mul(s.f_frsize);

    (
        (tot_b / 1024) as c_long,
        (tot_b.wrapping_sub(free_b) / 1024) as c_long,
    )
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

/// gethostname(), or "" where it fails.
fn read_hostname() -> Vec<u8> {
    let mut name = [0u8; HOSTNAME_ROOM];

    // SAFETY: the room of name.
    if unsafe { gethostname(name.as_mut_ptr().cast(), name.len()) } != 0 {
        return Vec::new();
    }
    cstr(&name[..HOSTNAME_ROOM - 1]).to_vec()
}

/// The system's facts.
pub(crate) fn gather() -> Sysinfo {
    let mut u = Utsname::zeroed();
    // SAFETY: a struct utsname to fill.
    let have_uts = unsafe { uname(&mut u) } == 0;
    let uts = |field: &[c_char]| {
        if have_uts {
            cstr(bytes(field)).to_vec()
        } else {
            Vec::new()
        }
    };
    let mut hostname = read_hostname();
    if hostname.is_empty() {
        hostname = uts(&u.nodename);
    }
    let os_pretty = read_os_release(c"/etc/os-release", c"/usr/lib/os-release")
        .ok()
        .and_then(|text| os_release_value(&text, b"PRETTY_NAME"))
        .unwrap_or_default();
    let (mem_total_kb, mem_avail_kb) = read_mem();
    let (disk_total_kb, disk_used_kb) = read_root_disk();

    Sysinfo {
        hostname,
        os_pretty,
        kernel_release: uts(&u.release),
        kernel_version: uts(&u.version),
        kernel_build_id: read_build_id().unwrap_or_default(),
        machine: uts(&u.machine),
        machine_id: read_first_line(c"/etc/machine-id", ID_LEN_MAX),
        boot_id: read_first_line(c"/proc/sys/kernel/random/boot_id", ID_LEN_MAX),
        // SAFETY: a call that takes no pointer.
        nproc: unsafe { sysconf(SC_NPROCESSORS_ONLN) },
        mem_total_kb,
        mem_avail_kb,
        uptime_sec: read_uptime_sec(),
        disk_total_kb,
        disk_used_kb,
    }
}

pub(crate) fn emit_json(e: &mut JsonEmit, si: &Sysinfo) {
    e.obj_open_key(b"system");
    e.kv_string(b"hostname", &si.hostname);
    e.kv_string(b"os", &si.os_pretty);
    e.kv_string(b"kernel_release", &si.kernel_release);
    e.kv_string(b"kernel_version", &si.kernel_version);
    e.kv_string(b"kernel_build_id", &si.kernel_build_id);
    e.obj_open_key(b"kernel_config");
    for (key, value) in kernel_config(&si.kernel_release).unwrap_or_default() {
        e.kv_string(&key, &value);
    }
    e.obj_close();
    e.kv_string(b"architecture", &si.machine);
    e.kv_string(b"machine_id", &si.machine_id);
    e.kv_string(b"boot_id", &si.boot_id);
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
