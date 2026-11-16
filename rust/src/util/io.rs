// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The file helpers behind `util/io.h`: whole writes and reads, the log
//! records an append keeps whole, opens beneath a directory, text lines,
//! and whether a file may steer what shirudo trusts.

use core::ffi::{CStr, c_char, c_int, c_void};

use crate::errno::{E2BIG, EFBIG, EINTR, EINVAL, EIO, ENOENT, ENOMEM, EPERM};
use crate::ffi;
use crate::sys::libc::{
    AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, File, LOCK_EX, O_CLOEXEC, O_DIRECTORY,
    O_NOFOLLOW, O_PATH, O_RDONLY, PATH_MAX, S_IFDIR, S_IFMT, S_IFREG, S_ISVTX,
    STATX_ATTR_MOUNT_ROOT, STATX_BASIC_STATS, Statfs, Statx, close, errno, flock, fstatfs, fsync,
    ftruncate, geteuid, getline, open, pread, realpath, set_errno, statx, strerror, syscall, write,
};
use crate::sys::log::{pr_err, pr_warn};
use crate::sys::malloc::{xfree, xmalloc};
use crate::sys::seal::seal_open_read;

/// `ETC_DIR` of util/paths.h.
const ETC_DIR: &CStr = c"/etc/shirudo";
/// `VAR_LIB` of util/paths.h.
const VAR_LIB: &CStr = c"/var/lib/shirudo";
/// `BPF_FS_MAGIC` of <linux/magic.h>.
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;
/// openat2(2), the same number on every architecture.
const SYS_OPENAT2: core::ffi::c_long = 437;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

/// `struct open_how`.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// All `len` bytes at `buf` to `fd`, through short writes and signals:
/// 0, -EIO for a write of nothing, or -errno.
///
/// # Safety
///
/// `buf` holds `len` bytes.
pub(crate) unsafe fn write_complete(fd: c_int, buf: *const c_void, len: usize) -> c_int {
    let mut p = buf.cast::<u8>();
    let mut len = len;

    while len != 0 {
        // SAFETY: the caller's bytes, len of them left at p.
        let n = unsafe { write(fd, p.cast(), len) };

        if n < 0 {
            if errno() == EINTR {
                continue;
            }
            return -errno();
        }
        if n == 0 {
            return -EIO;
        }
        // SAFETY: within the caller's bytes.
        p = unsafe { p.add(n as usize) };
        len -= n as usize;
    }
    0
}

/// How much of `buf` is whole records, each ending in its newline.
fn lines_len(buf: &[u8]) -> usize {
    buf.iter().rposition(|&c| c == b'\n').map_or(0, |i| i + 1)
}

/// The offset after the last newline of the `size` bytes of `fd`, read
/// back from its end a chunk at a time, or 0 for none.
fn last_line_end(fd: c_int, size: i64, end: &mut i64) -> c_int {
    let mut chunk = [0u8; 4096];
    let step = chunk.len() as i64;
    let mut off = size;

    while off > 0 {
        let n = off.min(step) as usize;
        let start = off - n as i64;
        // SAFETY: the caller's fd and room for n bytes.
        let got = unsafe { pread(fd, chunk.as_mut_ptr().cast(), n, start) };

        if got < 0 && errno() == EINTR {
            continue;
        }
        if got < 0 {
            return -errno();
        }
        if got as usize != n {
            return -EIO;
        }
        if let Some(i) = chunk[..n].iter().rposition(|&c| c == b'\n') {
            *end = start + i as i64 + 1;
            return 0;
        }
        off = start;
    }
    *end = 0;
    0
}

/// The status of the open `fd`, as fstat() gave it: 0 or -errno.
pub(crate) fn stat_fd(fd: c_int, st: &mut Statx) -> c_int {
    // SAFETY: the caller's fd, an empty path, and room for its status.
    if unsafe { statx(fd, c"".as_ptr(), AT_EMPTY_PATH, STATX_BASIC_STATS, st) } != 0 {
        return -errno();
    }
    0
}

/// `line` and its newline appended to the log open on `fd` at `path`,
/// after a torn tail is dropped; the log taken back to its last record
/// when the append fails.
///
/// # Safety
///
/// `path` is a C string and `line` holds `len` bytes.
unsafe fn append_line(fd: c_int, path: *const c_char, line: *const c_char, len: usize) -> c_int {
    let mut st = Statx::zeroed();
    let mut end: i64 = 0;
    // SAFETY: the caller's bytes.
    let mut text = unsafe { ffi::slice(line.cast::<u8>(), len) };

    if text.last() == Some(&b'\n') {
        text = &text[..text.len() - 1];
    }
    if text.contains(&b'\n') || text.contains(&0) {
        return -EINVAL;
    }
    let ret = stat_fd(fd, &mut st);
    if ret != 0 {
        return ret;
    }
    let size = st.size as i64;
    let ret = last_line_end(fd, size, &mut end);
    if ret != 0 {
        return ret;
    }
    if end != size {
        // SAFETY: the caller's fd.
        if unsafe { ftruncate(fd, end) } != 0 {
            return -errno();
        }
        // SAFETY: the C's format and its arguments.
        unsafe {
            pr_warn(
                c"%s: dropped %lld bytes at its end, an append that did not finish".as_ptr(),
                path,
                size - end,
            )
        };
    }
    let n = text.len();
    // SAFETY: an allocation of n + 1 bytes, freed below by its size.
    let buf = unsafe { xmalloc(n + 1) }.cast::<u8>();
    if buf.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the allocation's n + 1 bytes, the line and its newline
    // written, then freed once.
    let mut ret = unsafe {
        let out = core::slice::from_raw_parts_mut(buf, n + 1);

        out[..n].copy_from_slice(text);
        out[n] = b'\n';
        let ret = write_complete(fd, buf.cast(), n + 1);

        xfree(buf.cast(), n + 1);
        ret
    };
    // SAFETY: the caller's fd.
    if ret == 0 && unsafe { fsync(fd) } != 0 {
        ret = -errno();
    }
    // SAFETY: the caller's fd.
    if ret != 0 && unsafe { ftruncate(fd, end) } != 0 {
        // SAFETY: the C's format and its arguments.
        unsafe {
            pr_warn(
                c"%s: could not roll back a partial append: %s".as_ptr(),
                path,
                strerror(errno()),
            )
        };
    }
    ret
}

/// `rel` opened beneath the directory open as `dirfd`, with `flags` and
/// close-on-exec, through no symlink, no magic link and nothing outside
/// it: an fd, or -errno.
///
/// # Safety
///
/// `rel` is NULL or a C string.
pub(crate) unsafe fn open_beneath(dirfd: c_int, rel: *const c_char, flags: c_int) -> c_int {
    let how = OpenHow {
        flags: flags as u64 | O_CLOEXEC as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };

    // SAFETY: the caller's C string or NULL.
    if dirfd < 0 || rel.is_null() || matches!(unsafe { *rel } as u8, 0 | b'/') {
        return -EINVAL;
    }
    // SAFETY: the caller's fd and C string, and the open_how and its size.
    let fd = unsafe {
        syscall(
            SYS_OPENAT2,
            dirfd,
            rel,
            &raw const how,
            size_of::<OpenHow>(),
        )
    };
    if fd < 0 { -errno() } else { fd as c_int }
}

/// The whole regular file behind `fd`, from its start, of at most `max`
/// bytes, which may steer trust as `label` says, into `*out`, xmalloc'd
/// to `*len + 1` bytes and NUL-terminated.
///
/// # Safety
///
/// `label` is a C string, `out` room for a pointer and `len` for a
/// length.
pub(crate) unsafe fn read_fd(
    fd: c_int,
    label: *const c_char,
    max: usize,
    out: *mut c_void,
    len: *mut usize,
) -> c_int {
    let mut st = Statx::zeroed();

    let ret = stat_fd(fd, &mut st);
    if ret != 0 {
        return ret;
    }
    if st.mode & S_IFMT != S_IFREG {
        return -EINVAL;
    }
    // SAFETY: the caller's C string.
    let ret = unsafe { check_trusted(fd, label, false) };
    if ret != 0 {
        return ret;
    }
    if st.size > max as u64 {
        return -EFBIG;
    }
    let size = st.size as usize;
    // SAFETY: an allocation of size + 1 zeroed bytes, which the caller
    // frees by that size.
    let buf = unsafe { xmalloc(size + 1) }.cast::<u8>();
    if buf.is_null() {
        return -ENOMEM;
    }
    let (mut done, mut off) = (0usize, 0i64);
    while done < size {
        // SAFETY: the caller's fd, and the room left in the allocation.
        let n = unsafe { pread(fd, buf.add(done).cast(), size - done, off) };

        if n < 0 && errno() == EINTR {
            continue;
        }
        if n <= 0 {
            let ret = if n < 0 { -errno() } else { -EIO };

            // SAFETY: the allocation, by its size.
            unsafe { xfree(buf.cast(), size + 1) };
            return ret;
        }
        done += n as usize;
        off += n as i64;
    }
    // SAFETY: the caller's rooms.
    unsafe {
        *out.cast::<*mut u8>() = buf;
        *len = size;
    }
    0
}

/// One line of text of at most `max` bytes before its newline, in
/// getline()'s buffer: 1, 0 at the end, -E2BIG for a longer line and
/// -EINVAL for one holding a NUL.
///
/// # Safety
///
/// `f` is an open stream, and `line` and `cap` getline()'s buffer and
/// its size.
pub(crate) unsafe fn read_text_line(
    f: *mut File,
    line: *mut *mut c_char,
    cap: *mut usize,
    max: usize,
) -> c_int {
    set_errno(0);
    // SAFETY: the caller's stream and buffer.
    let n = unsafe { getline(line, cap, f) };
    if n < 0 {
        let e = errno();

        return if e != 0 { -e } else { 0 };
    }
    // SAFETY: the n bytes getline() read into the caller's buffer.
    let text = unsafe { ffi::slice((*line).cast::<u8>(), n as usize) };
    if text.contains(&0) {
        return -EINVAL;
    }
    let mut n = text.len();
    if text[n - 1] == b'\n' {
        n -= 1;
    }
    if n > max { -E2BIG } else { 1 }
}

/// Whether the C string `path` lies below `dir`.
///
/// # Safety
///
/// `path` is a C string.
unsafe fn under(path: *const c_char, dir: &CStr) -> bool {
    // SAFETY: the caller's C string.
    let p = unsafe { CStr::from_ptr(path) }.to_bytes();
    let d = dir.to_bytes();

    p.starts_with(d) && p.get(d.len()) == Some(&b'/')
}

/// The regular file at `path`, of at most `max` bytes, into `*out`,
/// xmalloc'd to `*len + 1` bytes and NUL-terminated; one under
/// /var/lib/shirudo opened through its seal.
///
/// # Safety
///
/// `path` is a C string, `out` room for a pointer and `len` for a
/// length.
pub(crate) unsafe fn read_file(
    path: *const c_char,
    max: usize,
    out: *mut c_void,
    len: *mut usize,
) -> c_int {
    // SAFETY: the caller's C string.
    let fd = if unsafe { under(path, VAR_LIB) } {
        // SAFETY: as above.
        let fd = unsafe { seal_open_read(path) };

        if fd < 0 {
            return fd;
        }
        fd
    } else {
        // SAFETY: as above.
        let fd = unsafe { open(path, O_RDONLY | O_CLOEXEC) };

        if fd < 0 {
            return -errno();
        }
        fd
    };
    // SAFETY: the file's fd and the caller's rooms; the fd closed once.
    unsafe {
        let ret = read_fd(fd, path, max, out, len);

        close(fd);
        ret
    }
}

fn trusted_owner(uid: u32) -> bool {
    // SAFETY: a call that takes nothing.
    uid == 0 || uid == unsafe { geteuid() }
}

/// Whether the file open on `fd` at `path` may steer what shirudo
/// trusts: under /etc/shirudo and /var/lib/shirudo a regular file of
/// root's or the user's that nobody else can write, nor with `secret`
/// read, in directories up to / that nobody else can change, a sticky
/// one of root's guarding its files; elsewhere the caller's to vouch
/// for. 0, or -EPERM logged, or -errno.
///
/// # Safety
///
/// `path` is a C string.
pub(crate) unsafe fn check_trusted(fd: c_int, path: *const c_char, secret: bool) -> c_int {
    let mut real = [0u8; PATH_MAX];
    let mut st = Statx::zeroed();

    // SAFETY: the caller's C string.
    if !unsafe { under(path, ETC_DIR) } && !unsafe { under(path, VAR_LIB) } {
        return 0;
    }
    let ret = stat_fd(fd, &mut st);
    if ret != 0 {
        return ret;
    }
    if st.mode & S_IFMT != S_IFREG
        || !trusted_owner(st.uid)
        || st.mode & if secret { 0o77 } else { 0o22 } != 0
    {
        let could = if secret { c"read or change" } else { c"change" };

        // SAFETY: the C's format and its arguments.
        unsafe {
            pr_err(
                c"%s: owner %u, mode %04o: refusing a file another user could %s".as_ptr(),
                path,
                st.uid,
                u32::from(st.mode & 0o7777),
                could.as_ptr(),
            )
        };
        return -EPERM;
    }
    // SAFETY: the caller's C string, and room for PATH_MAX bytes.
    if unsafe { realpath(path, real.as_mut_ptr().cast()) }.is_null() {
        return -errno();
    }
    loop {
        let end = real.iter().position(|&c| c == 0).unwrap_or(real.len());
        let slash = real[..end].iter().rposition(|&c| c == b'/').unwrap_or(0);

        if slash == 0 {
            real[1] = 0;
        } else {
            real[slash] = 0;
        }
        // SAFETY: the directory's C string, and room for its status.
        if unsafe {
            statx(
                AT_FDCWD,
                real.as_ptr().cast(),
                0,
                STATX_BASIC_STATS,
                &mut st,
            )
        } != 0
        {
            return -errno();
        }
        if st.mode & S_IFMT != S_IFDIR
            || !trusted_owner(st.uid)
            || (st.mode & 0o22 != 0 && !(st.mode & S_ISVTX != 0 && st.uid == 0))
        {
            // SAFETY: the C's format and its arguments.
            unsafe {
                pr_err(
                    c"%s: directory %s, owner %u, mode %04o: refusing a file another user could replace"
                        .as_ptr(),
                    path,
                    real.as_ptr(),
                    st.uid,
                    u32::from(st.mode & 0o7777),
                )
            };
            return -EPERM;
        }
        if slash == 0 {
            break;
        }
    }
    0
}

/// A st_dev or st_rdev as the kernel encodes the dev_t in s_dev.
pub(crate) fn kernel_dev(dev: u64) -> u32 {
    let major = ((dev >> 8) & 0xfff) as u32 | ((dev >> 32) as u32 & !0xfff);
    let minor = (dev & 0xff) as u32 | ((dev >> 12) as u32 & !0xff);

    major << 20 | (minor & 0xfffff)
}

/// 1 when `path` is the root of a bpf file system mount, 0 when it is
/// not or there is no such path, else -errno.
///
/// # Safety
///
/// `path` is a C string.
pub(crate) unsafe fn bpffs_mounted_at(path: *const c_char) -> c_int {
    let mut stx = Statx::zeroed();
    let mut fs = Statfs::zeroed();

    // SAFETY: the caller's C string.
    let fd = unsafe { open(path, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) };
    if fd < 0 {
        return if errno() == ENOENT { 0 } else { -errno() };
    }
    // SAFETY: the path's fd, an empty path, and room for both statuses.
    let failed = unsafe {
        fstatfs(fd, &mut fs) != 0
            || statx(
                fd,
                c"".as_ptr(),
                AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
                0,
                &mut stx,
            ) != 0
    };
    let ret = if failed {
        -errno()
    } else {
        c_int::from(
            fs.f_type == BPF_FS_MAGIC
                && stx.attributes_mask & STATX_ATTR_MOUNT_ROOT != 0
                && stx.attributes & STATX_ATTR_MOUNT_ROOT != 0,
        )
    };
    // SAFETY: the path's fd, closed once.
    unsafe { close(fd) };
    ret
}

/// An exclusive flock() on `fd`, waited for through signals.
fn lock_exclusive(fd: c_int) -> c_int {
    // SAFETY: the caller's fd.
    while unsafe { flock(fd, LOCK_EX) } != 0 {
        if errno() != EINTR {
            return -errno();
        }
    }
    0
}

mod capi {
    use core::ffi::{c_char, c_int, c_void};

    use crate::ffi;
    use crate::sys::libc::File;

    /// # Safety
    ///
    /// `buf` holds `len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn write_complete(fd: c_int, buf: *const c_void, len: usize) -> c_int {
        // SAFETY: the caller passes the bytes.
        unsafe { super::write_complete(fd, buf, len) }
    }

    /// # Safety
    ///
    /// `buf` holds `len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn lines_len(buf: *const c_char, len: usize) -> usize {
        // SAFETY: the caller passes the bytes.
        super::lines_len(unsafe { ffi::slice(buf.cast::<u8>(), len) })
    }

    /// # Safety
    ///
    /// `path` is a C string and `line` holds `len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn append_line(
        fd: c_int,
        path: *const c_char,
        line: *const c_char,
        len: usize,
    ) -> c_int {
        // SAFETY: the caller passes a C string and the line.
        unsafe { super::append_line(fd, path, line, len) }
    }

    /// # Safety
    ///
    /// `path` is a C string, `out` room for a pointer and `len` for a
    /// length.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn read_file(
        path: *const c_char,
        max: usize,
        out: *mut c_void,
        len: *mut usize,
    ) -> c_int {
        // SAFETY: the caller passes a C string and the rooms.
        unsafe { super::read_file(path, max, out, len) }
    }

    /// # Safety
    ///
    /// `label` is a C string, `out` room for a pointer and `len` for a
    /// length.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn read_fd(
        fd: c_int,
        label: *const c_char,
        max: usize,
        out: *mut c_void,
        len: *mut usize,
    ) -> c_int {
        // SAFETY: the caller passes a C string and the rooms.
        unsafe { super::read_fd(fd, label, max, out, len) }
    }

    /// # Safety
    ///
    /// `rel` is NULL or a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn open_beneath(dirfd: c_int, rel: *const c_char, flags: c_int) -> c_int {
        // SAFETY: the caller passes NULL or a C string.
        unsafe { super::open_beneath(dirfd, rel, flags) }
    }

    /// # Safety
    ///
    /// `f` is an open stream, and `line` and `cap` getline()'s buffer
    /// and its size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn read_text_line(
        f: *mut File,
        line: *mut *mut c_char,
        cap: *mut usize,
        max: usize,
    ) -> c_int {
        // SAFETY: the caller passes the stream and the buffer.
        unsafe { super::read_text_line(f, line, cap, max) }
    }

    /// # Safety
    ///
    /// `path` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn check_trusted(fd: c_int, path: *const c_char, secret: bool) -> c_int {
        // SAFETY: the caller passes a C string.
        unsafe { super::check_trusted(fd, path, secret) }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn lock_exclusive(fd: c_int) -> c_int {
        super::lock_exclusive(fd)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn kernel_dev(dev: u64) -> u32 {
        super::kernel_dev(dev)
    }

    /// # Safety
    ///
    /// `path` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn bpffs_mounted_at(path: *const c_char) -> c_int {
        // SAFETY: the caller passes a C string.
        unsafe { super::bpffs_mounted_at(path) }
    }
}
