// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The config activation journal behind `util/config_update.h`: the
//! state file of the selection a target runs, the events file of every
//! selection measured into the config PCR, and the steps from one to
//! the next, under the journal's lock, through the operations the
//! caller supplies.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use crate::errno::{
    EBADMSG, EBUSY, EINPROGRESS, EINTR, EINVAL, EIO, ENODATA, ENOENT, EOVERFLOW, EPERM, ESTALE,
    EUCLEAN,
};
use crate::ffi;
use crate::sys::libc::{
    AT_EMPTY_PATH, EOF, File, LOCK_EX, LOCK_NB, O_APPEND, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL,
    O_NOFOLLOW, O_NONBLOCK, O_RDONLY, O_RDWR, O_WRONLY, S_IFMT, S_IFREG, STATX_BASIC_STATS, Statx,
    Timespec, close, errno, fclose, fdopen, ferror, fgetc, flock, fsync, ftello, ftruncate,
    geteuid, nanosleep, open, openat, read, renameat, statx, strerror, unlinkat,
};
use crate::sys::log::{pr_err, pr_info, pr_warn};
use crate::text::cstr;
use crate::util::chain::chain_fold;
use crate::util::config_measure::{self, EVENT_BOOT, EVENT_UPDATE};
use crate::util::hex::{hex_decode, hex_encode};
use crate::util::io::write_complete;
use crate::util::json::{JsonEmit, JsonField, parse_schema};

/// `CONFIG_UPDATE_PREFIX_MAX`.
const PREFIX_MAX: usize = 4096;
/// `RECORD_MAX`: the longest record either file holds.
const RECORD_MAX: usize = 2 * PREFIX_MAX + 1024;
/// EWOULDBLOCK, which is EAGAIN.
const EWOULDBLOCK: c_int = crate::errno::EAGAIN;

/// `enum config_update_checkpoint`: where a caller may stop the protocol.
const CHECK_PENDING_SYNC: c_int = 1;
const CHECK_EXTEND: c_int = 2;
const CHECK_EVENT_SYNC: c_int = 3;
const CHECK_ACTIVATE: c_int = 4;
const CHECK_COMPLETE_SYNC: c_int = 5;
const CHECK_STATE_WRITE: c_int = 6;
const CHECK_STATE_RENAME: c_int = 7;
const CHECK_EVENT_WRITE: c_int = 8;

/// `struct config_update_target`: a config image's mapping prefix and
/// its dm-verity root.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConfigUpdateTarget {
    pub(crate) prefix: [u8; PREFIX_MAX],
    pub(crate) root_hash: [u8; 32],
}

/// `struct config_update_record`: the state file's selection, or an
/// event, which carries no prefix and is never pending.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConfigUpdateRecord {
    pub(crate) target: ConfigUpdateTarget,
    pub(crate) initial_pcr: [u8; 32],
    pub(crate) sequence: u64,
    pub(crate) reset_count: u32,
    pub(crate) restart_count: u32,
    pub(crate) pcr: u32,
    pub(crate) kind: c_int,
    pub(crate) pending: bool,
    /// The C's trailing padding as a field, so that a record copied out
    /// has a value in every byte, as the C's memset() and `= {}` gave it.
    _pad: [u8; 7],
}

const _: () = assert!(size_of::<ConfigUpdateRecord>() == 4192);
const _: () = assert!(core::mem::offset_of!(ConfigUpdateRecord, sequence) == 4160);
const _: () = assert!(core::mem::offset_of!(ConfigUpdateRecord, kind) == 4180);
const _: () = assert!(core::mem::offset_of!(ConfigUpdateRecord, pending) == 4184);

impl ConfigUpdateRecord {
    pub(crate) const fn zeroed() -> Self {
        ConfigUpdateRecord {
            target: ConfigUpdateTarget {
                prefix: [0; PREFIX_MAX],
                root_hash: [0; 32],
            },
            initial_pcr: [0; 32],
            sequence: 0,
            reset_count: 0,
            restart_count: 0,
            pcr: 0,
            kind: 0,
            pending: false,
            _pad: [0; 7],
        }
    }
}

/// `struct config_update_ops`: what the caller does for the protocol.
#[repr(C)]
pub struct ConfigUpdateOps {
    pub(crate) boot_identity:
        Option<unsafe extern "C" fn(*mut c_void, *mut u32, *mut u32) -> c_int>,
    pub(crate) pcr_read: Option<unsafe extern "C" fn(*mut c_void, u32, *mut u8) -> c_int>,
    pub(crate) pcr_extend: Option<unsafe extern "C" fn(*mut c_void, u32, *const u8) -> c_int>,
    pub(crate) prepare:
        Option<unsafe extern "C" fn(*mut c_void, *const ConfigUpdateTarget) -> c_int>,
    pub(crate) activate:
        Option<unsafe extern "C" fn(*mut c_void, *const ConfigUpdateTarget) -> c_int>,
    pub(crate) seal: Option<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>,
    pub(crate) checkpoint: Option<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>,
    pub(crate) lock_wait_ms: u32,
}

/// `struct config_update`: an open journal, its lock held until close.
#[repr(C)]
pub struct ConfigUpdate {
    ops: *const ConfigUpdateOps,
    ctx: *mut c_void,
    dir_fd: c_int,
    lock_fd: c_int,
    boot_pending: bool,
}

/// `shirudo_config_cb`: what a walk of the events calls with each.
pub type ConfigCb = unsafe extern "C" fn(r: *const ConfigUpdateRecord, ctx: *mut c_void) -> c_int;

impl ConfigUpdate {
    /// A journal not open.
    pub(crate) const fn closed() -> Self {
        ConfigUpdate {
            ops: core::ptr::null(),
            ctx: core::ptr::null_mut(),
            dir_fd: -1,
            lock_fd: -1,
            boot_pending: false,
        }
    }

    pub(crate) fn is_open(&self) -> bool {
        self.lock_fd >= 0
    }

    /// The operations the open journal calls from here.
    pub(crate) fn set_ops(&mut self, ops: &'static ConfigUpdateOps) {
        self.ops = ops;
    }

    fn ops(&self) -> &ConfigUpdateOps {
        // SAFETY: an open journal holds the operations it was opened
        // with, which outlive it.
        unsafe { &*self.ops }
    }

    fn boot_identity(&self, reset: &mut u32, restart: &mut u32) -> c_int {
        let f = self.ops().boot_identity.expect("checked at open");

        // SAFETY: the caller's operation, its context, and room for both.
        unsafe { f(self.ctx, reset, restart) }
    }

    fn pcr_read(&self, pcr: u32, out: &mut [u8; 32]) -> c_int {
        let f = self.ops().pcr_read.expect("checked at open");

        // SAFETY: the caller's operation, its context, and room.
        unsafe { f(self.ctx, pcr, out.as_mut_ptr()) }
    }

    fn pcr_extend(&self, pcr: u32, event: &[u8; 32]) -> c_int {
        let f = self.ops().pcr_extend.expect("checked at open");

        // SAFETY: the caller's operation, its context, and the event.
        unsafe { f(self.ctx, pcr, event.as_ptr()) }
    }

    fn prepare(&self, target: *const ConfigUpdateTarget) -> c_int {
        let f = self.ops().prepare.expect("checked at open");

        // SAFETY: the caller's operation, its context, and its target.
        unsafe { f(self.ctx, target) }
    }

    fn activate(&self, target: *const ConfigUpdateTarget) -> c_int {
        let f = self.ops().activate.expect("checked at open");

        // SAFETY: the caller's operation, its context, and its target.
        unsafe { f(self.ctx, target) }
    }

    fn seal(&self, fd: c_int) -> c_int {
        let f = self.ops().seal.expect("checked at open");

        // SAFETY: the caller's operation, its context, and an fd.
        unsafe { f(self.ctx, fd) }
    }

    /// The caller's checkpoint, which may stop the protocol there.
    fn checkpoint(&self, point: c_int) -> c_int {
        match self.ops().checkpoint {
            // SAFETY: the caller's operation and its context.
            Some(f) => unsafe { f(self.ctx, point) },
            None => 0,
        }
    }
}

fn target_valid(target: Option<&ConfigUpdateTarget>) -> c_int {
    let Some(t) = target else {
        return -EINVAL;
    };
    let len = cstr(&t.prefix).len();

    if len == 0 || len == PREFIX_MAX || t.prefix[0] != b'/' {
        return -EINVAL;
    }
    if t.prefix[..len].iter().any(|&c| c < 0x20 || c == 0x7f) {
        return -EINVAL;
    }
    0
}

/// `record` as one JSON line into `out`, with the prefix and whether it
/// is pending for the state file: 0 with its length, or the emitter's
/// error.
fn record_encode(
    record: &ConfigUpdateRecord,
    state: bool,
    out: &mut [u8],
    length: &mut usize,
) -> c_int {
    let mut emit = JsonEmit::fixed(out.as_mut_ptr().cast(), out.len() - 1);
    let mut root = [0u8; 65];
    let mut initial = [0u8; 65];

    // SAFETY: two digests, and room for their hex and NULs.
    unsafe {
        hex_encode(
            record.target.root_hash.as_ptr(),
            32,
            root.as_mut_ptr().cast(),
        );
        hex_encode(record.initial_pcr.as_ptr(), 32, initial.as_mut_ptr().cast());
    }
    emit.obj_open();
    emit.kv_int(b"schema", 1);
    emit.kv_int(b"sequence", record.sequence as i64);
    emit.kv_int(b"reset_count", i64::from(record.reset_count));
    emit.kv_int(b"restart_count", i64::from(record.restart_count));
    emit.kv_int(b"pcr", i64::from(record.pcr));
    emit.kv_int(b"kind", i64::from(record.kind));
    emit.kv_string(b"root_hash", cstr(&root));
    emit.kv_string(b"initial_pcr", cstr(&initial));
    if state {
        emit.kv_string(b"prefix", cstr(&record.target.prefix));
        emit.kv_bool(b"pending", record.pending);
    }
    emit.obj_close();
    if emit.err() != 0 {
        return emit.err();
    }
    let n = emit.written();

    out[n] = b'\n';
    *length = n + 1;
    0
}

/// The record in the `length` bytes at `data` into `record`, with the
/// prefix and whether it is pending for the state file: 0, or -EBADMSG
/// for one that is not a record, or the parser's error.
///
/// # Safety
///
/// `data` holds `length` bytes, or is NULL with none.
unsafe fn record_decode(
    data: *const u8,
    length: usize,
    state: bool,
    record: &mut ConfigUpdateRecord,
) -> c_int {
    let (mut schema, mut sequence, mut reset, mut restart) = (0i64, 0i64, 0i64, 0i64);
    let (mut pcr, mut kind) = (0i64, 0i64);
    let mut root = [0u8; 65];
    let mut initial = [0u8; 65];
    let mut pending: c_int = 0;

    *record = ConfigUpdateRecord::zeroed();
    let mut fields = [
        JsonField::int(c"schema", &mut schema),
        JsonField::int(c"sequence", &mut sequence),
        JsonField::int(c"reset_count", &mut reset),
        JsonField::int(c"restart_count", &mut restart),
        JsonField::int(c"pcr", &mut pcr),
        JsonField::int(c"kind", &mut kind),
        JsonField::string(c"root_hash", root.as_mut_ptr(), root.len()),
        JsonField::string(c"initial_pcr", initial.as_mut_ptr(), initial.len()),
        JsonField::string(c"prefix", record.target.prefix.as_mut_ptr(), PREFIX_MAX),
        JsonField::boolean(c"pending", &mut pending),
    ];
    // SAFETY: the caller's bytes, and the schema, which names locals of
    // this call and the caller's record.
    let ret = unsafe { parse_schema(ffi::slice(data, length), fields.as_mut_ptr(), fields.len()) };
    if ret != 0 {
        return ret;
    }
    let required = fields.len() - if state { 0 } else { 2 };
    if fields[..required].iter().any(|f| !f.seen()) {
        return -EBADMSG;
    }
    if schema != 1
        || sequence <= 0
        || !(0..=i64::from(u32::MAX)).contains(&reset)
        || !(0..=i64::from(u32::MAX)).contains(&restart)
        || !(0..=15).contains(&pcr)
        || config_measure::pcr_valid(pcr as u32) != 0
        || (kind != i64::from(EVENT_BOOT) && kind != i64::from(EVENT_UPDATE))
        // SAFETY: a C string the parser wrote, and room for a digest.
        || unsafe { hex_decode(root.as_ptr().cast(), record.target.root_hash.as_mut_ptr(), 32) } != 0
        // SAFETY: as above.
        || unsafe { hex_decode(initial.as_ptr().cast(), record.initial_pcr.as_mut_ptr(), 32) } != 0
        || (state && target_valid(Some(&record.target)) != 0)
    {
        return -EBADMSG;
    }
    record.sequence = sequence as u64;
    record.reset_count = reset as u32;
    record.restart_count = restart as u32;
    record.pcr = pcr as u32;
    record.kind = kind as c_int;
    record.pending = pending != 0;
    0
}

/// The status of the open `fd` into `st`, as fstat() gave it: 0 or
/// -errno.
fn stat_fd(fd: c_int, st: &mut Statx) -> c_int {
    // SAFETY: the caller's fd, an empty path, and room for its status.
    if unsafe { statx(fd, c"".as_ptr(), AT_EMPTY_PATH, STATX_BASIC_STATS, st) } != 0 {
        return -errno();
    }
    0
}

/// Whether `fd` is a regular file of one link, the effective user's,
/// that no one else may read or write: 0, -EPERM, or -errno.
fn regular_file(fd: c_int) -> c_int {
    let mut st = Statx::zeroed();

    let ret = stat_fd(fd, &mut st);
    if ret != 0 {
        return ret;
    }
    if st.mode & S_IFMT != S_IFREG || st.nlink != 1 {
        return -EPERM;
    }
    // SAFETY: a call that takes nothing.
    if st.uid != unsafe { geteuid() } || st.mode & 0o77 != 0 {
        return -EPERM;
    }
    0
}

/// The journal's lock taken, waiting up to `wait_ms` for another
/// command's, as the keepalive and map-export timers take turns.
fn lock_wait(fd: c_int, wait_ms: u32) -> c_int {
    let pause = Timespec {
        tv_sec: 0,
        tv_nsec: 100 * 1000 * 1000,
    };
    let mut told = false;
    let mut waited: u32 = 0;

    loop {
        // SAFETY: the caller's fd.
        if unsafe { flock(fd, LOCK_EX | LOCK_NB) } == 0 {
            return 0;
        }
        let err = errno();

        if err != EWOULDBLOCK || waited >= wait_ms {
            return -err;
        }
        if !told && waited >= 1000 {
            // SAFETY: the C's format.
            unsafe {
                pr_info(
                    c"image: waiting for another shirudo command to release the config operation lock"
                        .as_ptr(),
                )
            };
            told = true;
        }
        // SAFETY: a pause, and no room for what is left of it.
        unsafe { nanosleep(&pause, ptr::null_mut()) };
        waited = waited.wrapping_add(100);
    }
}

/// config_update_open().
///
/// # Safety
///
/// `directory` is NULL or a C string, `ops` NULL or operations that
/// outlive the journal and take `ctx`, and `out` NULL or room for one.
unsafe fn open_journal(
    directory: *const c_char,
    ops: *const ConfigUpdateOps,
    ctx: *mut c_void,
    out: *mut ConfigUpdate,
) -> c_int {
    if out.is_null() {
        return -EINVAL;
    }
    // SAFETY: the caller's room, all of whose bits zeroed are a journal.
    let u = unsafe {
        out.write_bytes(0, 1);
        &mut *out
    };
    u.dir_fd = -1;
    u.lock_fd = -1;
    // SAFETY: the caller's operations or NULL.
    let Some(o) = (unsafe { ops.as_ref() }) else {
        return -EINVAL;
    };
    if directory.is_null()
        || o.boot_identity.is_none()
        || o.pcr_read.is_none()
        || o.pcr_extend.is_none()
        || o.prepare.is_none()
        || o.activate.is_none()
        || o.seal.is_none()
    {
        return -EINVAL;
    }
    u.ops = ops;
    u.ctx = ctx;
    // SAFETY: the caller's C string.
    u.dir_fd = unsafe { open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW) };
    if u.dir_fd < 0 {
        return -errno();
    }
    let ret = 'fail: {
        let mut st = Statx::zeroed();

        let ret = stat_fd(u.dir_fd, &mut st);
        if ret != 0 {
            break 'fail ret;
        }
        // SAFETY: a call that takes nothing.
        if st.uid != unsafe { geteuid() } || st.mode & 0o22 != 0 {
            break 'fail -EPERM;
        }
        let ret = u.seal(u.dir_fd);
        if ret != 0 {
            break 'fail ret;
        }
        // SAFETY: the directory's fd and a C string.
        u.lock_fd = unsafe {
            openat(
                u.dir_fd,
                c"lock".as_ptr(),
                O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
                0o600,
            )
        };
        if u.lock_fd < 0 {
            break 'fail -errno();
        }
        let ret = regular_file(u.lock_fd);
        if ret != 0 {
            break 'fail ret;
        }
        let ret = lock_wait(u.lock_fd, o.lock_wait_ms);
        if ret != 0 {
            if ret == -EWOULDBLOCK {
                // SAFETY: the C's format and its arguments.
                unsafe {
                    pr_err(
                        c"image: another shirudo command still holds the config operation lock %s/lock after %u seconds"
                            .as_ptr(),
                        directory,
                        o.lock_wait_ms / 1000,
                    )
                };
            }
            break 'fail ret;
        }
        let ret = u.seal(u.lock_fd);
        if ret != 0 {
            break 'fail ret;
        }
        // SAFETY: the two fds.
        if unsafe { fsync(u.lock_fd) } != 0 || unsafe { fsync(u.dir_fd) } != 0 {
            break 'fail -errno();
        }
        return 0;
    };
    close_journal(u);
    ret
}

/// config_update_close(): the journal's fds closed, the lock with them.
fn close_journal(u: &mut ConfigUpdate) {
    if u.lock_fd >= 0 {
        // SAFETY: the journal's own fd.
        unsafe { close(u.lock_fd) };
    }
    if u.dir_fd >= 0 {
        // SAFETY: the journal's own fd.
        unsafe { close(u.dir_fd) };
    }
    u.dir_fd = -1;
    u.lock_fd = -1;
}

/// config_update_read(): the state file's record into `out`.
fn selection_read(u: &ConfigUpdate, name: &CStr, out: &mut ConfigUpdateRecord) -> c_int {
    let mut wire = [0u8; RECORD_MAX];
    let mut st = Statx::zeroed();
    let mut done = 0usize;

    // SAFETY: the journal's directory and a C string.
    let fd = unsafe {
        openat(
            u.dir_fd,
            name.as_ptr(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
        )
    };
    if fd < 0 {
        return -errno();
    }
    let mut ret = regular_file(fd);
    if ret == 0 {
        ret = stat_fd(fd, &mut st);
    }
    if ret == 0 && (st.size == 0 || st.size >= wire.len() as u64) {
        ret = -EBADMSG;
    }
    while ret == 0 && done < st.size as usize {
        // SAFETY: the file's fd and the room left in wire.
        let got = unsafe {
            read(
                fd,
                wire[done..].as_mut_ptr().cast(),
                st.size as usize - done,
            )
        };

        if got < 0 {
            if errno() == EINTR {
                continue;
            }
            ret = -errno();
        } else if got == 0 {
            ret = -EIO;
        } else {
            done += got as usize;
        }
    }
    if ret == 0 {
        // SAFETY: the bytes read.
        ret = unsafe { record_decode(wire.as_ptr(), done, true, out) };
    }
    // SAFETY: the file's fd, closed once.
    unsafe { close(fd) };
    ret
}

fn read_state(u: &ConfigUpdate, out: &mut ConfigUpdateRecord) -> c_int {
    selection_read(u, c"state", out)
}

/// The state file replaced by `record`, through a sealed temporary file
/// renamed over it; `inject` lets the caller's checkpoints stop it.
fn selection_save(
    u: &ConfigUpdate,
    record: &ConfigUpdateRecord,
    name: &CStr,
    temporary: &CStr,
    inject: bool,
) -> c_int {
    let mut wire = [0u8; RECORD_MAX];
    let mut length = 0;

    let ret = record_encode(record, true, &mut wire, &mut length);
    if ret != 0 {
        return ret;
    }
    // SAFETY: the journal's directory and a C string.
    if unsafe { unlinkat(u.dir_fd, temporary.as_ptr(), 0) } != 0 && errno() != ENOENT {
        return -errno();
    }
    // SAFETY: as above.
    let fd = unsafe {
        openat(
            u.dir_fd,
            temporary.as_ptr(),
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return -errno();
    }
    let mut ret = u.seal(fd);
    if ret == 0 {
        // SAFETY: the file's fd and the record's bytes.
        ret = unsafe { write_complete(fd, wire.as_ptr().cast(), length) };
    }
    if ret == 0 && inject {
        ret = u.checkpoint(CHECK_STATE_WRITE);
    }
    // SAFETY: the file's fd.
    if ret == 0 && unsafe { fsync(fd) } != 0 {
        ret = -errno();
    }
    // SAFETY: the file's fd, closed once.
    if unsafe { close(fd) } != 0 && ret == 0 {
        ret = -errno();
    }
    if ret == 0
        // SAFETY: the journal's directory and two C strings.
        && unsafe { renameat(u.dir_fd, temporary.as_ptr(), u.dir_fd, name.as_ptr()) } != 0
    {
        ret = -errno();
    }
    if ret == 0 && inject {
        ret = u.checkpoint(CHECK_STATE_RENAME);
    }
    // SAFETY: the journal's directory.
    if ret == 0 && unsafe { fsync(u.dir_fd) } != 0 {
        ret = -errno();
    }
    if ret != 0 {
        // SAFETY: the journal's directory and a C string.
        unsafe { unlinkat(u.dir_fd, temporary.as_ptr(), 0) };
    }
    ret
}

fn state_save(u: &ConfigUpdate, record: &ConfigUpdateRecord, inject: bool) -> c_int {
    selection_save(u, record, c"state", c".state.tmp", inject)
}

/// A staged next-boot selection is stored beside the active state.
fn stage_read(u: &ConfigUpdate, out: &mut ConfigUpdateRecord) -> c_int {
    selection_read(u, c"next-boot", out)
}

fn clear_staged(u: &ConfigUpdate) -> c_int {
    if u.lock_fd < 0 {
        return -EINVAL;
    }
    // SAFETY: the journal's directory and a fixed file name.
    if unsafe { unlinkat(u.dir_fd, c"next-boot".as_ptr(), 0) } != 0 {
        return if errno() == ENOENT { 0 } else { -errno() };
    }
    // SAFETY: the journal's directory is still open.
    if unsafe { fsync(u.dir_fd) } != 0 {
        -errno()
    } else {
        0
    }
}

fn stage(u: &ConfigUpdate, target: &ConfigUpdateTarget) -> c_int {
    if u.lock_fd < 0 || target_valid(Some(target)) != 0 {
        return -EINVAL;
    }
    let mut record = ConfigUpdateRecord::zeroed();
    let ret = check(u, Some(&mut record));
    if ret != 0 {
        return ret;
    }
    record.target = *target;
    selection_save(u, &record, c"next-boot", c".next-boot.tmp", false)
}

fn same_target(a: &ConfigUpdateTarget, b: &ConfigUpdateTarget) -> bool {
    cstr(&a.prefix) == cstr(&b.prefix) && a.root_hash == b.root_hash
}

fn staged(
    u: &ConfigUpdate,
    previous: &ConfigUpdateRecord,
    reset: u32,
    target: &mut ConfigUpdateTarget,
) -> c_int {
    let mut selection = ConfigUpdateRecord::zeroed();
    let ret = stage_read(u, &mut selection);
    if ret != 0 {
        return if ret == -ENOENT { 0 } else { ret };
    }
    if selection.pending {
        return -EBADMSG;
    }
    if selection.reset_count == reset || same_target(&selection.target, &previous.target) {
        return 0;
    }
    if selection.sequence != previous.sequence || selection.reset_count != previous.reset_count {
        // SAFETY: the format string is fixed and has no arguments.
        unsafe {
            pr_warn(c"image: ignoring staged config because the active selection changed".as_ptr())
        };
        return 0;
    }
    *target = selection.target;
    1
}

fn same_boot(a: &ConfigUpdateRecord, b: &ConfigUpdateRecord) -> bool {
    a.reset_count == b.reset_count && a.restart_count == b.restart_count
}

fn same_event(a: &ConfigUpdateRecord, b: &ConfigUpdateRecord) -> bool {
    same_boot(a, b)
        && a.sequence == b.sequence
        && a.pcr == b.pcr
        && a.kind == b.kind
        && a.initial_pcr == b.initial_pcr
        && a.target.root_hash == b.target.root_hash
}

/// Whether `record` may follow `previous`: 0 or -EUCLEAN.
fn event_follows(previous: &ConfigUpdateRecord, record: &ConfigUpdateRecord) -> c_int {
    if record.sequence != previous.sequence.wrapping_add(1) {
        return -EUCLEAN;
    }
    if previous.sequence == 0 || !same_boot(previous, record) {
        return if record.kind == EVENT_BOOT {
            0
        } else {
            -EUCLEAN
        };
    }
    if record.kind != EVENT_UPDATE
        || previous.pcr != record.pcr
        || previous.initial_pcr != record.initial_pcr
    {
        return -EUCLEAN;
    }
    0
}

/// The next line of `file` into `line`, its newline with it: 1, 0 at the
/// end, -ENODATA for a last line without one, which only a later trusted
/// boot may discard, or -EBADMSG for a NUL or a line too long.
///
/// # Safety
///
/// `file` is an open stream.
unsafe fn read_line(file: *mut File, line: &mut [u8], length: &mut usize) -> c_int {
    *length = 0;
    loop {
        // SAFETY: the caller's stream.
        let c = unsafe { fgetc(file) };

        if c == EOF {
            break;
        }
        if c == 0 || *length == line.len() {
            return -EBADMSG;
        }
        line[*length] = c as u8;
        *length += 1;
        if c == c_int::from(b'\n') {
            return 1;
        }
    }
    // SAFETY: as above.
    if unsafe { ferror(file) } != 0 {
        return -EIO;
    }
    if *length != 0 { -ENODATA } else { 0 }
}

/// The events file replayed: each event decoded, checked to follow the
/// one before, folded into the PCR value from its boot's initial value,
/// and handed to `consume`. The last event goes into `last`, the value
/// into `value` and the offset after the last whole line into `end`,
/// each unless NULL; `partial` forgives a torn last line.
///
/// # Safety
///
/// `value` is NULL or room for a digest, `end` NULL or room for an
/// offset, and `consume` takes `ctx`.
unsafe fn events_scan(
    u: &ConfigUpdate,
    last: &mut ConfigUpdateRecord,
    value: *mut u8,
    end: *mut i64,
    partial: bool,
    consume: Option<ConfigCb>,
    ctx: *mut c_void,
) -> c_int {
    let mut previous = ConfigUpdateRecord::zeroed();
    let mut record = ConfigUpdateRecord::zeroed();
    let mut running = [0u8; 32];
    let mut digest = [0u8; 32];
    let mut wire = [0u8; RECORD_MAX];
    let mut length = 0;

    *last = ConfigUpdateRecord::zeroed();
    if !end.is_null() {
        // SAFETY: the caller's room.
        unsafe { *end = 0 };
    }
    // SAFETY: the journal's directory and a C string.
    let fd = unsafe {
        openat(
            u.dir_fd,
            c"events".as_ptr(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
        )
    };
    if fd < 0 {
        return if errno() == ENOENT { 0 } else { -errno() };
    }
    let ret = regular_file(fd);
    if ret != 0 {
        // SAFETY: the file's fd, closed once.
        unsafe { close(fd) };
        return ret;
    }
    // SAFETY: the file's fd, which the stream takes over.
    let file = unsafe { fdopen(fd, c"r".as_ptr()) };
    if file.is_null() {
        let ret = -errno();

        // SAFETY: the file's fd, closed once.
        unsafe { close(fd) };
        return ret;
    }
    let mut ret;
    loop {
        // SAFETY: the stream.
        ret = unsafe { read_line(file, &mut wire, &mut length) };
        if ret <= 0 {
            break;
        }
        // SAFETY: the line read.
        ret = unsafe { record_decode(wire.as_ptr(), length, false, &mut record) };
        if ret == 0 {
            ret = event_follows(&previous, &record);
        }
        if ret == 0 && record.kind == EVENT_BOOT {
            running = record.initial_pcr;
        }
        if ret == 0 {
            ret = config_measure::event(record.kind, &record.target.root_hash, digest.as_mut_ptr());
        }
        if ret == 0 {
            // SAFETY: two digests.
            ret = unsafe { chain_fold(running.as_mut_ptr(), digest.as_ptr()) };
        }
        if ret == 0 {
            if let Some(cb) = consume {
                // SAFETY: the caller's function and context, with the
                // event.
                ret = unsafe { cb(&record, ctx) };
            }
        }
        if ret != 0 {
            break;
        }
        previous = record;
        if !end.is_null() {
            // SAFETY: the stream, and the caller's room.
            unsafe {
                *end = ftello(file);
                if *end < 0 {
                    ret = -errno();
                    break;
                }
            }
        }
    }
    if ret == -ENODATA && partial {
        ret = 0;
    }
    if ret == 0 {
        *last = previous;
        if !value.is_null() {
            // SAFETY: the caller's room for a digest.
            unsafe { ptr::copy_nonoverlapping(running.as_ptr(), value, 32) };
        }
    }
    // SAFETY: the stream, closed once with its fd.
    unsafe { fclose(file) };
    ret
}

/// `record` appended to the events file after the last whole line, once
/// it follows the last event.
fn event_append(u: &ConfigUpdate, record: &ConfigUpdateRecord) -> c_int {
    let mut last = ConfigUpdateRecord::zeroed();
    let mut wire = [0u8; RECORD_MAX];
    let mut length = 0;
    let mut end: i64 = 0;

    // SAFETY: room for the offset.
    let mut ret = unsafe {
        events_scan(
            u,
            &mut last,
            ptr::null_mut(),
            &mut end,
            record.kind == EVENT_BOOT,
            None,
            ptr::null_mut(),
        )
    };
    if ret == 0 {
        ret = event_follows(&last, record);
    }
    if ret == 0 {
        ret = record_encode(record, false, &mut wire, &mut length);
    }
    if ret != 0 {
        return ret;
    }
    // SAFETY: the journal's directory and a C string.
    let fd = unsafe {
        openat(
            u.dir_fd,
            c"events".as_ptr(),
            O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return -errno();
    }
    let mut ret = regular_file(fd);
    if ret == 0 {
        ret = u.seal(fd);
    }
    // SAFETY: the file's fd.
    if ret == 0 && unsafe { ftruncate(fd, end) } != 0 {
        ret = -errno();
    }
    if ret == 0 {
        // SAFETY: the file's fd and the event's bytes.
        ret = unsafe { write_complete(fd, wire.as_ptr().cast(), length) };
    }
    if ret == 0 {
        ret = u.checkpoint(CHECK_EVENT_WRITE);
    }
    // SAFETY: the file's fd.
    if ret == 0 && unsafe { fsync(fd) } != 0 {
        ret = -errno();
    }
    // SAFETY: the file's fd, closed once.
    if unsafe { close(fd) } != 0 && ret == 0 {
        ret = -errno();
    }
    // SAFETY: the journal's directory.
    if ret == 0 && unsafe { fsync(u.dir_fd) } != 0 {
        ret = -errno();
    }
    ret
}

/// The PCR's value between two readings of the TPM's boot, which must
/// agree, or -ESTALE.
fn live_read(
    u: &ConfigUpdate,
    pcr: u32,
    reset: &mut u32,
    restart: &mut u32,
    value: &mut [u8; 32],
) -> c_int {
    let (mut reset_after, mut restart_after) = (0u32, 0u32);

    let mut ret = u.boot_identity(reset, restart);
    if ret == 0 {
        ret = u.pcr_read(pcr, value);
    }
    if ret == 0 {
        ret = u.boot_identity(&mut reset_after, &mut restart_after);
    }
    if ret == 0 && (*reset != reset_after || *restart != restart_after) {
        ret = -ESTALE;
    }
    ret
}

/// Whether `record` is the last event, of this TPM boot, and the PCR
/// holds what the events replay to.
fn check_record(u: &ConfigUpdate, record: &ConfigUpdateRecord) -> c_int {
    let mut last = ConfigUpdateRecord::zeroed();
    let mut expected = [0u8; 32];
    let mut value = [0u8; 32];
    let (mut reset, mut restart) = (0u32, 0u32);

    // SAFETY: room for the value.
    let mut ret = unsafe {
        events_scan(
            u,
            &mut last,
            expected.as_mut_ptr(),
            ptr::null_mut(),
            false,
            None,
            ptr::null_mut(),
        )
    };
    if ret == 0 && !same_event(record, &last) {
        ret = -EUCLEAN;
    }
    if ret == 0 {
        ret = live_read(u, record.pcr, &mut reset, &mut restart, &mut value);
    }
    if ret == 0 && (reset != record.reset_count || restart != record.restart_count) {
        ret = -ESTALE;
    }
    if ret == 0 && value != expected {
        ret = -EUCLEAN;
    }
    ret
}

/// config_update_check(): the active record into `out` unless NULL.
fn check(u: &ConfigUpdate, out: Option<&mut ConfigUpdateRecord>) -> c_int {
    let mut record = ConfigUpdateRecord::zeroed();

    let mut ret = read_state(u, &mut record);
    if ret == 0 && record.pending {
        ret = -EINPROGRESS;
    }
    if ret == 0 {
        ret = check_record(u, &record);
    }
    if ret == 0 {
        if let Some(out) = out {
            *out = record;
        }
    }
    ret
}

/// The pending selection marked done, or put back if that fails.
fn complete(u: &ConfigUpdate) -> c_int {
    let mut record = ConfigUpdateRecord::zeroed();

    let mut ret = read_state(u, &mut record);
    if ret == 0 {
        ret = check_record(u, &record);
    }
    if ret != 0 {
        return ret;
    }
    record.pending = false;
    ret = state_save(u, &record, true);
    if ret == 0 {
        ret = u.checkpoint(CHECK_COMPLETE_SYNC);
    }
    if ret != 0 {
        record.pending = true;
        let restore = state_save(u, &record, false);

        if restore != 0 {
            // SAFETY: the C's format and strerror()'s.
            unsafe {
                pr_err(
                    c"image: cannot restore pending selection: %s".as_ptr(),
                    strerror(-restore),
                )
            };
        }
    }
    ret
}

/// The selection of `target` after `previous`: saved pending, measured
/// into the PCR, appended to the events and activated; an update then
/// completed, a boot left for config_update_complete_boot().
///
/// # Safety
///
/// `target` is a target.
unsafe fn begin_event(
    u: &mut ConfigUpdate,
    target: *const ConfigUpdateTarget,
    previous: &ConfigUpdateRecord,
    pcr: u32,
    kind: c_int,
) -> c_int {
    let mut record = ConfigUpdateRecord::zeroed();
    let mut before = [0u8; 32];
    let mut value = [0u8; 32];
    let mut event = [0u8; 32];
    let (mut reset, mut restart) = (0u32, 0u32);

    if previous.sequence == i64::MAX as u64 {
        return -EOVERFLOW;
    }
    let ret = u.prepare(target);
    if ret != 0 {
        return ret;
    }
    // SAFETY: the caller's target.
    record.target = unsafe { *target };
    record.sequence = previous.sequence + 1;
    record.pcr = pcr;
    record.kind = kind;
    record.pending = true;
    let ret = live_read(
        u,
        pcr,
        &mut record.reset_count,
        &mut record.restart_count,
        &mut before,
    );
    if ret != 0 {
        return ret;
    }
    record.initial_pcr = if kind == EVENT_BOOT {
        before
    } else {
        previous.initial_pcr
    };
    let mut ret = event_follows(previous, &record);
    if ret == 0 {
        // SAFETY: the caller's target.
        let root = unsafe { &(*target).root_hash };

        ret = config_measure::event(kind, root, event.as_mut_ptr());
    }
    let mut expected = before;
    if ret == 0 {
        // SAFETY: two digests.
        ret = unsafe { chain_fold(expected.as_mut_ptr(), event.as_ptr()) };
    }
    if ret == 0 {
        ret = state_save(u, &record, true);
    }
    if ret == 0 {
        ret = u.checkpoint(CHECK_PENDING_SYNC);
    }
    if ret == 0 {
        ret = u.pcr_extend(pcr, &event);
    }
    if ret == 0 {
        ret = u.checkpoint(CHECK_EXTEND);
    }
    if ret == 0 {
        ret = live_read(u, pcr, &mut reset, &mut restart, &mut value);
    }
    if ret == 0
        && (reset != record.reset_count || restart != record.restart_count || value != expected)
    {
        ret = -EUCLEAN;
    }
    if ret == 0 {
        ret = event_append(u, &record);
    }
    if ret == 0 {
        ret = u.checkpoint(CHECK_EVENT_SYNC);
    }
    if ret == 0 {
        ret = u.activate(target);
    }
    if ret == 0 {
        ret = u.checkpoint(CHECK_ACTIVATE);
    }
    if ret != 0 {
        return ret;
    }
    if kind == EVENT_BOOT {
        u.boot_pending = true;
        return 0;
    }
    complete(u)
}

/// The journal of an open update, or None for NULL or one not open.
///
/// # Safety
///
/// `update` is NULL or a journal.
unsafe fn journal<'a>(update: *mut ConfigUpdate) -> Option<&'a mut ConfigUpdate> {
    // SAFETY: the caller's journal or NULL.
    unsafe { update.as_mut() }.filter(|u| u.dir_fd >= 0)
}

/// config_update_begin().
///
/// # Safety
///
/// `update` is NULL or a journal, and `t` NULL or a target.
unsafe fn begin(update: *mut ConfigUpdate, t: *const ConfigUpdateTarget, pcr: u32) -> c_int {
    // SAFETY: the caller's journal and target, or NULL.
    let (Some(u), target) = (unsafe { journal(update) }, unsafe { t.as_ref() }) else {
        return -EINVAL;
    };
    if target_valid(target) != 0 || config_measure::pcr_valid(pcr) != 0 {
        return -EINVAL;
    }
    let mut previous = ConfigUpdateRecord::zeroed();

    let ret = check(u, Some(&mut previous));
    if ret != 0 {
        return ret;
    }
    if pcr != previous.pcr {
        return -EPERM;
    }
    // SAFETY: the caller's target, valid above.
    if unsafe { (*t).root_hash } == previous.target.root_hash {
        return 0;
    }
    // SAFETY: as above.
    unsafe { begin_event(u, t, &previous, pcr, EVENT_UPDATE) }
}

/// config_update_boot().
///
/// # Safety
///
/// `update` is NULL or a journal, and `t` NULL or a target.
unsafe fn boot(update: *mut ConfigUpdate, t: *const ConfigUpdateTarget, pcr: u32) -> c_int {
    // SAFETY: the caller's journal and target, or NULL.
    let (Some(u), target) = (unsafe { journal(update) }, unsafe { t.as_ref() }) else {
        return -EINVAL;
    };
    if target_valid(target) != 0 || config_measure::pcr_valid(pcr) != 0 {
        return -EINVAL;
    }
    // SAFETY: valid above.
    let target = unsafe { &*t };
    let mut previous = ConfigUpdateRecord::zeroed();
    let mut last = ConfigUpdateRecord::zeroed();
    let (mut reset, mut restart) = (0u32, 0u32);

    u.boot_pending = false;
    let ret = read_state(u, &mut previous);
    if ret != 0 && ret != -ENOENT {
        return ret;
    }
    let ret = u.boot_identity(&mut reset, &mut restart);
    if ret != 0 {
        return ret;
    }
    if previous.sequence != 0 && previous.reset_count == reset && previous.restart_count == restart
    {
        if previous.pending {
            return -EINPROGRESS;
        }
        if previous.pcr != pcr || target.root_hash != previous.target.root_hash {
            return -EBUSY;
        }
        return check(u, None);
    }
    if previous.sequence != 0
        && (cstr(&target.prefix) != cstr(&previous.target.prefix)
            || target.root_hash != previous.target.root_hash)
    {
        return -EUCLEAN;
    }
    // SAFETY: NULL for what the scan need not give.
    let ret = unsafe {
        events_scan(
            u,
            &mut last,
            ptr::null_mut(),
            ptr::null_mut(),
            previous.pending,
            None,
            ptr::null_mut(),
        )
    };
    if ret != 0 {
        return ret;
    }
    if previous.sequence == 0 && last.sequence != 0 {
        return -EUCLEAN;
    }
    if previous.sequence != 0
        && !(same_event(&previous, &last)
            || (previous.pending && event_follows(&last, &previous) == 0))
    {
        return -EUCLEAN;
    }
    // SAFETY: the caller's target.
    unsafe { begin_event(u, t, &last, pcr, EVENT_BOOT) }
}

pub(crate) use capi::{
    config_update_begin, config_update_boot, config_update_check, config_update_close,
    config_update_complete_boot, config_update_events, config_update_open, config_update_read,
};

mod capi {
    use core::ffi::{c_char, c_int, c_void};
    use core::ptr;

    use super::{ConfigCb, ConfigUpdate, ConfigUpdateOps, ConfigUpdateRecord, ConfigUpdateTarget};

    /// # Safety
    ///
    /// `directory` is NULL or a C string, `ops` NULL or operations that
    /// outlive the journal and take `ctx`, and `out` NULL or room.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_update_open(
        directory: *const c_char,
        ops: *const ConfigUpdateOps,
        ctx: *mut c_void,
        out: *mut ConfigUpdate,
    ) -> c_int {
        // SAFETY: the caller passes what the function takes.
        unsafe { super::open_journal(directory, ops, ctx, out) }
    }

    /// # Safety
    ///
    /// `update` is NULL or a journal.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_update_close(update: *mut ConfigUpdate) {
        // SAFETY: the caller's journal or NULL.
        if let Some(u) = unsafe { update.as_mut() } {
            super::close_journal(u);
        }
    }

    /// # Safety
    ///
    /// `update` is NULL or a journal, and `out` NULL or room for a
    /// record.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_update_read(
        update: *mut ConfigUpdate,
        out: *mut ConfigUpdateRecord,
    ) -> c_int {
        // SAFETY: the caller's journal and room, or NULL.
        match unsafe { (super::journal(update), out.as_mut()) } {
            (Some(u), Some(out)) => super::read_state(u, out),
            _ => -super::EINVAL,
        }
    }

    /// # Safety
    ///
    /// `update` is NULL or a journal, and `t` NULL or a target.
    /// # Safety
    ///
    /// `update` is an open journal and `target` a valid target.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_update_stage(
        update: *mut ConfigUpdate,
        target: *const ConfigUpdateTarget,
    ) -> c_int {
        // SAFETY: caller supplies a journal and target, or NULL.
        match unsafe { (super::journal(update), target.as_ref()) } {
            (Some(u), Some(target)) => super::stage(u, target),
            _ => -super::EINVAL,
        }
    }

    /// # Safety
    ///
    /// `update` is an open journal and `out` is room for a record.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_update_stage_read(
        update: *mut ConfigUpdate,
        out: *mut ConfigUpdateRecord,
    ) -> c_int {
        // SAFETY: caller supplies a journal and record, or NULL.
        match unsafe { (super::journal(update), out.as_mut()) } {
            (Some(u), Some(out)) => super::stage_read(u, out),
            _ => -super::EINVAL,
        }
    }

    /// # Safety
    ///
    /// `update` is an open journal.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_update_clear_staged(update: *mut ConfigUpdate) -> c_int {
        // SAFETY: caller supplies a journal, or NULL.
        match unsafe { super::journal(update) } {
            Some(u) => super::clear_staged(u),
            None => -super::EINVAL,
        }
    }

    /// # Safety
    ///
    /// `update` is an open journal; `previous` and `target` are valid.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_update_staged(
        update: *mut ConfigUpdate,
        previous: *const ConfigUpdateRecord,
        reset: u32,
        target: *mut ConfigUpdateTarget,
    ) -> c_int {
        // SAFETY: caller supplies a journal and both records, or NULL.
        match unsafe { (super::journal(update), previous.as_ref(), target.as_mut()) } {
            (Some(u), Some(previous), Some(target)) => super::staged(u, previous, reset, target),
            _ => -super::EINVAL,
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_update_begin(
        update: *mut ConfigUpdate,
        t: *const ConfigUpdateTarget,
        pcr: u32,
    ) -> c_int {
        // SAFETY: the caller's journal and target, or NULL.
        unsafe { super::begin(update, t, pcr) }
    }

    /// # Safety
    ///
    /// `update` is NULL or a journal, and `t` NULL or a target.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_update_boot(
        update: *mut ConfigUpdate,
        t: *const ConfigUpdateTarget,
        pcr: u32,
    ) -> c_int {
        // SAFETY: the caller's journal and target, or NULL.
        unsafe { super::boot(update, t, pcr) }
    }

    /// # Safety
    ///
    /// `update` is NULL or a journal.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_update_complete_boot(update: *mut ConfigUpdate) -> c_int {
        // SAFETY: the caller's journal or NULL.
        let Some(u) = (unsafe { super::journal(update) }) else {
            return -super::EINVAL;
        };
        if !u.boot_pending {
            return super::check(u, None);
        }
        u.boot_pending = false;
        super::complete(u)
    }

    /// # Safety
    ///
    /// `update` is NULL or a journal, and `out` NULL or room for a
    /// record.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_update_check(
        update: *mut ConfigUpdate,
        out: *mut ConfigUpdateRecord,
    ) -> c_int {
        // SAFETY: the caller's journal or NULL; the C read through it
        // first, which refuses NULL.
        let Some(u) = (unsafe { update.as_mut() }) else {
            return -super::EINVAL;
        };
        if u.dir_fd < 0 {
            return -super::EINVAL;
        }
        // SAFETY: the caller's room or NULL.
        super::check(u, unsafe { out.as_mut() })
    }

    /// # Safety
    ///
    /// `update` is NULL or a journal, and `consume` takes `ctx`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_update_events(
        update: *mut ConfigUpdate,
        consume: Option<ConfigCb>,
        ctx: *mut c_void,
    ) -> c_int {
        // SAFETY: the caller's journal or NULL.
        let Some(u) = (unsafe { super::journal(update) }) else {
            return -super::EINVAL;
        };
        if consume.is_none() {
            return -super::EINVAL;
        }
        let mut last = ConfigUpdateRecord::zeroed();

        // SAFETY: the caller's function and context.
        unsafe {
            super::events_scan(
                u,
                &mut last,
                ptr::null_mut(),
                ptr::null_mut(),
                false,
                consume,
                ctx,
            )
        }
    }

    /// # Safety
    ///
    /// `data` holds `length` bytes, or is NULL with none, and `record` is
    /// room for one.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_update_record_decode(
        data: *const c_char,
        length: usize,
        state: bool,
        record: *mut ConfigUpdateRecord,
    ) -> c_int {
        // SAFETY: the caller's bytes and room.
        unsafe { super::record_decode(data.cast(), length, state, &mut *record) }
    }

    /// # Safety
    ///
    /// `update` is a journal whose directory is open, `last` room for a
    /// record, `value` NULL or room for a digest, `end` NULL or room for
    /// an offset, and `consume` takes `ctx`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_update_events_scan(
        update: *mut ConfigUpdate,
        last: *mut ConfigUpdateRecord,
        value: *mut u8,
        end: *mut i64,
        partial: bool,
        consume: Option<ConfigCb>,
        ctx: *mut c_void,
    ) -> c_int {
        // SAFETY: the caller passes what the scan takes.
        unsafe { super::events_scan(&*update, &mut *last, value, end, partial, consume, ctx) }
    }
}
