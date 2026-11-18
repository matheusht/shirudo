// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The eventlog behind `util/eventlog.h`: one JSON line per register
//! extension, appended only after the extend succeeded, so that a replay
//! reproduces the live value. A walk reads the log and the record the
//! initrd left pending, and hands each line on, terminated in place as
//! strtok_r() left it.

mod capi;
mod records;

pub(crate) use capi::{
    eventlog_adopt_pending, eventlog_append, eventlog_append_to, eventlog_boot_id,
    eventlog_boot_init, eventlog_boot_lines, eventlog_boot_upatches, eventlog_lock, eventlog_path,
    eventlog_pending_path, eventlog_record_open, eventlog_replay, eventlog_timestamp,
    eventlog_tree_op_measured, eventlog_unlock, eventlog_upatches, eventlog_would_exceed,
};
pub(crate) use records::{EventlogInit, UPATCH_INIT, UPATCH_UNLOAD};

use core::ffi::{CStr, c_int};

use crate::errno::{EFBIG, EINVAL, ENAMETOOLONG, ENOENT, ENOMEM};
use crate::heap::{xfree, xmalloc};
use crate::sys::libc::{
    AT_FDCWD, F_OK, O_CLOEXEC, O_RDONLY, PATH_MAX, STATX_SIZE, Statx, access, close, env, errno,
    open, read, statx, strerror, time, unlink,
};
use crate::text::{cstr, strsprintf};
use crate::util::crypto_openssl::sha256_into;
use crate::util::hex::hex_encode;
use crate::util::image_config;
use crate::util::io::read_file;
use crate::util::json::{JsonEmit, JsonField, MAX_BYTES, parse_schema};
use crate::util::seal::{seal_append_line, seal_lock};
use crate::util::timefmt::iso8601;

/// The most bytes one record takes.
const LINE_MAX: u64 = 4096;
const DEFAULT_PATH: &CStr = c"/var/lib/shirudo/eventlog";
const DEFAULT_PENDING_PATH: &CStr = c"/run/shirudo/eventlog.pending";
/// The register's NV index, `NV_INDEX` of util/paths.h, which asserts
/// that the two agree.
pub(crate) const NV_INDEX: u32 = 0x0181_8E00;

/// The path `var` names, unless a config image fixes the paths, or
/// `default`.
fn path_from(var: &CStr, default: &'static CStr) -> &'static CStr {
    if image_config::active() {
        return default;
    }
    env(var).filter(|v| !v.is_empty()).unwrap_or(default)
}

fn path() -> &'static CStr {
    path_from(c"SHIRUDO_EVENTLOG_PATH", DEFAULT_PATH)
}

fn pending_path() -> &'static CStr {
    path_from(c"SHIRUDO_EVENTLOG_PENDING_PATH", DEFAULT_PENDING_PATH)
}

/// `line` appended to the log at `path` whole, or nothing of it: a line
/// cut short would join the next record and fail every reader on it.
fn append_to(path: &CStr, line: &CStr) -> c_int {
    // SAFETY: two C strings, and the line's length.
    let ret = unsafe { seal_append_line(path.as_ptr(), line.as_ptr(), line.to_bytes().len()) };

    if ret != 0 {
        // SAFETY: the C's format, the path, and what strerror() gives.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"eventlog: append to %s: %s".as_ptr(),
                path.as_ptr(),
                strerror(-ret),
            )
        };
    }
    ret
}

/// `line` appended to the log, after the init record the initrd left
/// pending, which opens this boot's part of it: a line appended ahead of
/// that record would drop out of every replay.
fn append(line: &CStr) -> c_int {
    let ret = adopt_pending();
    if ret != 0 {
        return ret;
    }
    append_to(path(), line)
}

/// Whether one more record could take the log past `max` bytes; never
/// for 0, no limit.
fn would_exceed(max: u64) -> c_int {
    let mut st = Statx::zeroed();
    let mut cur = 0;

    if max == 0 {
        return 0;
    }
    // SAFETY: a C string and a statx to fill.
    if unsafe { statx(AT_FDCWD, path().as_ptr(), 0, STATX_SIZE, &mut st) } == 0 {
        cur = st.size;
    }
    c_int::from(cur.wrapping_add(LINE_MAX) > max)
}

/// A file read_file() gave: `len` bytes and a NUL, freed on drop.
struct FileBuf {
    ptr: *mut u8,
    len: usize,
}

impl FileBuf {
    fn read(path: &CStr) -> Result<FileBuf, c_int> {
        let mut ptr: *mut u8 = core::ptr::null_mut();
        let mut len = 0;
        // SAFETY: a C string, and the two outputs read_file() fills.
        let ret = unsafe { read_file(path.as_ptr(), MAX_BYTES, (&raw mut ptr).cast(), &mut len) };

        if ret != 0 {
            return Err(ret);
        }
        Ok(FileBuf { ptr, len })
    }

    /// The bytes and the NUL after them.
    fn bytes(&mut self) -> &mut [u8] {
        // SAFETY: read_file() gave len bytes and a NUL, which only this
        // buffer holds.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len + 1) }
    }

    /// The records of the file: a NUL would end every walk there and hide
    /// the records after it, and a last line without its newline is no
    /// record yet, so the string ends after the last newline.
    fn records(&mut self) -> c_int {
        let len = self.len;
        let buf = self.bytes();

        if buf[..len].contains(&0) {
            return -EINVAL;
        }
        let n = buf[..len]
            .iter()
            .rposition(|&c| c == b'\n')
            .map_or(0, |i| i + 1);
        buf[n] = 0;
        0
    }
}

impl Drop for FileBuf {
    fn drop(&mut self) {
        // SAFETY: the allocation read_file() made, freed once, here.
        unsafe { xfree(self.ptr.cast(), self.len + 1) };
    }
}

/// The log and the pending record together, as one C string.
enum Log {
    File(FileBuf),
    Joined { ptr: *mut u8, alloc: usize },
}

impl Log {
    fn bytes(&mut self) -> &mut [u8] {
        match self {
            Log::File(f) => f.bytes(),
            // SAFETY: the alloc bytes xmalloc() gave, which only this
            // log holds.
            Log::Joined { ptr, alloc } => unsafe { core::slice::from_raw_parts_mut(*ptr, *alloc) },
        }
    }
}

impl Drop for Log {
    fn drop(&mut self) {
        if let Log::Joined { ptr, alloc } = *self {
            // SAFETY: the allocation xmalloc() gave, freed once, here.
            unsafe { xfree(ptr.cast(), alloc) };
        }
    }
}

fn read_log() -> Result<Log, c_int> {
    let base = match FileBuf::read(path()) {
        Err(e) if e != -ENOENT => return Err(e),
        r => r,
    };
    let pending = match FileBuf::read(pending_path()) {
        Err(e) if e != -ENOENT => return Err(e),
        r => r,
    };
    let (mut base, mut pending) = match (base, pending) {
        (Err(_), Err(_)) => return Err(-ENOENT),
        (Ok(mut base), Err(_)) => {
            if base.records() != 0 {
                return Err(-EINVAL);
            }
            return Ok(Log::File(base));
        }
        (Err(_), Ok(mut pending)) => {
            if pending.records() != 0 {
                return Err(-EINVAL);
            }
            return Ok(Log::File(pending));
        }
        (Ok(base), Ok(pending)) => (base, pending),
    };
    if base.records() != 0 || pending.records() != 0 {
        return Err(-EINVAL);
    }
    if base.len + pending.len > MAX_BYTES {
        return Err(-EFBIG);
    }
    let alloc = base.len + pending.len + 1;
    // SAFETY: xmalloc() returns NULL or alloc zeroed bytes.
    let ptr = unsafe { xmalloc(alloc) }.cast::<u8>();
    if ptr.is_null() {
        return Err(-ENOMEM);
    }
    let mut log = Log::Joined { ptr, alloc };
    let (a, b) = (cstr(base.bytes()).len(), cstr(pending.bytes()).len());
    let out = log.bytes();

    out[..a].copy_from_slice(&base.bytes()[..a]);
    out[a..a + b].copy_from_slice(&pending.bytes()[..b]);
    out[a + b] = 0;
    Ok(log)
}

/// Give a C caller its own allocation, with the same length it frees.
fn read_for_c() -> Result<(*mut u8, usize), c_int> {
    let mut log = read_log()?;
    let file_len = match &log {
        Log::File(file) => Some(file.len),
        Log::Joined { .. } => None,
    };
    let len = file_len.unwrap_or_else(|| cstr(log.bytes()).len());
    let alloc = len + 1;
    // SAFETY: xmalloc allocates alloc bytes or returns NULL.
    let ptr = unsafe { xmalloc(alloc) }.cast::<u8>();

    if ptr.is_null() {
        return Err(-ENOMEM);
    }
    // SAFETY: both the log and ptr hold alloc bytes, and do not overlap.
    unsafe { core::ptr::copy_nonoverlapping(log.bytes().as_ptr(), ptr, alloc) };
    Ok((ptr, len))
}

/// `f` on each line of the C string in `buf`, terminated in place as
/// strtok_r() leaves it, until it returns other than 0.
fn each_line(buf: &mut [u8], mut f: impl FnMut(&CStr) -> c_int) -> c_int {
    let n = cstr(buf).len();
    let mut start = 0;

    while start < n {
        if buf[start] == b'\n' {
            start += 1;
            continue;
        }
        let end = buf[start..n]
            .iter()
            .position(|&c| c == b'\n')
            .map_or(n, |i| start + i);
        if end < n {
            buf[end] = 0;
        }
        let Ok(line) = CStr::from_bytes_until_nul(&buf[start..]) else {
            return -EINVAL;
        };
        let ret = f(line);
        if ret != 0 {
            return ret;
        }
        start = end + 1;
    }
    0
}

/// What a walk calls with each line and whether it is an init record.
type Walk<'a> = &'a mut dyn FnMut(&CStr, bool) -> c_int;

/// This boot's records from its last init line on, or with `all` every
/// record; the callback learns which line is an init record so that a
/// replay can start over. -ENOENT for a boot without an init record.
fn walk_lines(buf: &mut [u8], all: bool, cb: Walk<'_>) -> c_int {
    let mut boot_id = [0u8; 64];
    let mut in_boot = false;

    read_boot_id(&mut boot_id);
    let boot = cstr(&boot_id);
    let ret = each_line(buf, |line| {
        let mut line_boot = [0u8; 64];
        let mut ty = [0u8; 32];
        let mut f = [
            JsonField::string(c"boot_id", line_boot.as_mut_ptr(), line_boot.len()),
            JsonField::string(c"type", ty.as_mut_ptr(), ty.len()),
        ];
        // SAFETY: the schema names locals of this call.
        if unsafe { parse_schema(line.to_bytes(), f.as_mut_ptr(), f.len()) } != 0 {
            return -EINVAL;
        }
        if !all && (!f[0].seen() || boot.is_empty() || cstr(&line_boot) != boot) {
            return 0;
        }
        let is_init = f[1].seen() && cstr(&ty) == b"init";
        if is_init {
            in_boot = true;
        }
        if !all && !in_boot {
            return 0;
        }
        cb(line, is_init)
    });
    if !all && ret == 0 && !in_boot {
        return -ENOENT;
    }
    ret
}

fn walk_log(all: bool, cb: Walk<'_>) -> c_int {
    match read_log() {
        Ok(mut log) => walk_lines(log.bytes(), all, cb),
        Err(e) => e,
    }
}

fn walk_boot(cb: Walk<'_>) -> c_int {
    walk_log(false, cb)
}

/// Whether this boot's part of the log holds `line`: 1 or 0.
fn log_holds(line: &[u8]) -> c_int {
    let mut found = false;
    let mut buf = match FileBuf::read(path()) {
        Ok(buf) => buf,
        Err(e) if e == -ENOENT => return 0,
        Err(e) => return e,
    };
    let mut ret = buf.records();

    if ret == 0 {
        ret = walk_lines(buf.bytes(), false, &mut |l, _| {
            if l.to_bytes() == line {
                found = true;
            }
            0
        });
    }
    if ret != 0 && ret != -ENOENT {
        return ret;
    }
    c_int::from(found)
}

/// The records the initrd left pending appended to the log, each one
/// the log does not hold yet, and the pending file gone.
fn adopt_pending() -> c_int {
    let pending = pending_path();
    let mut buf = match FileBuf::read(pending) {
        Ok(buf) => buf,
        Err(e) if e == -ENOENT => return 0,
        Err(e) => return e,
    };
    let mut ret = buf.records();

    if ret == 0 {
        ret = each_line(buf.bytes(), |line| {
            let held = log_holds(line.to_bytes());

            match held {
                0 => append_to(path(), line),
                n if n > 0 => 0,
                e => e,
            }
        });
    }
    drop(buf);
    if ret != 0 {
        return ret;
    }
    // SAFETY: a C string.
    if unsafe { unlink(pending.as_ptr()) } != 0 && errno() != ENOENT {
        return -errno();
    }
    0
}

/// The lock beside the log that keeps one process at a time extending
/// the register and appending: two measuring commands under locks of
/// their own interleaved extend, extend, append, append and left a log
/// that replays the events in the other order.
fn lock() -> c_int {
    let mut lock_path = [0u8; PATH_MAX];

    if strsprintf(&mut lock_path, &[path().to_bytes(), b".lock"]).is_err() {
        return -ENAMETOOLONG;
    }
    // SAFETY: strsprintf() terminated the path.
    unsafe { seal_lock(lock_path.as_ptr().cast()) }
}

fn unlock(fd: c_int) {
    if fd >= 0 {
        // SAFETY: the lock's fd, closed once, here.
        unsafe { close(fd) };
    }
}

/// The pending record adopted under the lock: init adopts it while a
/// command may append, and both would find it missing and append it.
/// Without a record there is nothing to adopt, nor yet a state directory
/// for the lock on a first boot.
fn adopt_pending_locked() -> c_int {
    // SAFETY: a C string.
    if unsafe { access(pending_path().as_ptr(), F_OK) } != 0 && errno() == ENOENT {
        return 0;
    }
    let fd = lock();
    if fd < 0 {
        return fd;
    }
    let ret = adopt_pending();

    unlock(fd);
    ret
}

/// The time now as ISO-8601 UTC into `out`.
fn timestamp(out: &mut [u8]) {
    // SAFETY: time() with no pointer to fill.
    iso8601(unsafe { time(core::ptr::null_mut()) }, out);
}

/// This boot's ID from /proc, without its newline, or empty.
fn read_boot_id(out: &mut [u8]) {
    out[0] = 0;
    // SAFETY: a C string and flags without a mode.
    let fd = unsafe {
        open(
            c"/proc/sys/kernel/random/boot_id".as_ptr(),
            O_RDONLY | O_CLOEXEC,
        )
    };
    if fd < 0 {
        return;
    }
    // SAFETY: room for all but the NUL at out, from the fd open() gave,
    // which is closed once, here.
    let n = unsafe {
        let n = read(fd, out.as_mut_ptr().cast(), out.len() - 1);
        close(fd);
        n
    };
    if n <= 0 {
        out[0] = 0;
        return;
    }
    let mut n = n as usize;
    out[n] = 0;
    while n > 0 && matches!(out[n - 1], b'\n' | b'\r') {
        n -= 1;
        out[n] = 0;
    }
}

/// The fields every record opens with, into `e`.
fn record_open(e: &mut JsonEmit, ty: &[u8], digest: &[u8; 32]) {
    let mut ts = [0u8; 32];
    let mut boot_id = [0u8; 64];
    let mut digest_hex = [0u8; 65];
    let mut nv_index = *b"0x00000000";

    timestamp(&mut ts);
    read_boot_id(&mut boot_id);
    for (i, d) in nv_index[2..].iter_mut().enumerate() {
        *d = b"0123456789ABCDEF"[((NV_INDEX >> (28 - 4 * i)) & 0xf) as usize];
    }
    // SAFETY: the digest, and room for its hex and a NUL.
    unsafe {
        hex_encode(
            digest.as_ptr(),
            digest.len(),
            digest_hex.as_mut_ptr().cast(),
        )
    };
    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"ts", cstr(&ts));
    e.kv_string(b"nv_index", &nv_index);
    e.kv_string(b"alg", b"sha256");
    e.kv_string(b"digest", cstr(&digest_hex));
    e.kv_string(b"type", ty);
    e.kv_string(b"boot_id", cstr(&boot_id));
}
