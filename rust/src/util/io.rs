// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The file helpers: whole writes and reads, the log
//! records an append keeps whole, opens beneath a directory, text lines,
//! and whether a file may steer what shirudo trusts.

use core::ffi::{CStr, c_char, c_int, c_void};

use crate::errno::{E2BIG, EFBIG, EINTR, EINVAL, EIO, ENOENT, ENOMEM, EPERM};
use crate::ffi;
use crate::heap::xmalloc;
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW, Dir, File, LOCK_EX, O_CLOEXEC, O_DIRECTORY, O_NOFOLLOW,
    O_PATH, O_RDONLY, PATH_MAX, S_IFDIR, S_IFMT, S_IFREG, S_ISVTX, STATX_ATTR_MOUNT_ROOT,
    STATX_BASIC_STATS, Statfs, Statx, close, closedir, errno, fdopendir, flock, fstatfs, fsync,
    ftruncate, geteuid, getline, open, openat, pread, readdir, set_errno, statx, syscall, write,
};
use crate::util::seal;
use core::ptr::NonNull;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};

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

/// The offset after the last newline of the `size` bytes of `fd`, read
/// back from its end a chunk at a time, or 0 for none.
fn last_line_end(fd: BorrowedFd<'_>, size: i64) -> Result<i64, c_int> {
    let mut chunk = [0u8; 4096];
    let step = chunk.len() as i64;
    let mut off = size;

    while off > 0 {
        let n = off.min(step) as usize;
        let start = off - n as i64;
        // SAFETY: the caller's fd and room for n bytes.
        let got = unsafe { pread(fd.as_raw_fd(), chunk.as_mut_ptr().cast(), n, start) };

        if got < 0 && errno() == EINTR {
            continue;
        }
        if got < 0 {
            return Err(-errno());
        }
        if got as usize != n {
            return Err(-EIO);
        }
        if let Some(i) = chunk[..n].iter().rposition(|&c| c == b'\n') {
            return Ok(start + i as i64 + 1);
        }
        off = start;
    }
    Ok(0)
}

/// The file open on `fd` cut to `len` bytes: -errno.
fn truncate_to(fd: BorrowedFd<'_>, len: i64) -> Result<(), c_int> {
    // SAFETY: the caller's fd.
    if unsafe { ftruncate(fd.as_raw_fd(), len) } != 0 {
        return Err(-errno());
    }
    Ok(())
}

/// The status of the open `fd`, as fstat() gave it: 0 or -errno.
/// The names of the directory at `dir` that `keep` keeps, in the order
/// alphasort() gives them in the C locale shirudo runs in: bytewise.
/// "." and ".." are no entry. -errno when the directory cannot be read.
pub(crate) fn dir_names(dir: &[u8], keep: impl Fn(&[u8]) -> bool) -> Result<Vec<Vec<u8>>, c_int> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let errno = |e: std::io::Error| -e.raw_os_error().unwrap_or(crate::errno::EIO);
    let mut names = Vec::new();
    for entry in std::fs::read_dir(std::ffi::OsStr::from_bytes(dir)).map_err(errno)? {
        let name = entry.map_err(errno)?.file_name().into_vec();
        if keep(&name) {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// [`dir_names`] of the directory open as `dir`, read through a
/// descriptor of its own, as scandirat(dir, ".") reads it.
pub(crate) fn dir_names_at(
    dir: BorrowedFd<'_>,
    keep: impl Fn(&[u8]) -> bool,
) -> Result<Vec<Vec<u8>>, c_int> {
    let mut stream = DirStream::open_at(dir)?;
    let mut names = Vec::new();

    while let Some(name) = stream.next_name()? {
        if name != b"." && name != b".." && keep(&name) {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// A directory stream, closed with its descriptor when it goes.
struct DirStream(NonNull<Dir>);

impl DirStream {
    /// A stream on the directory open as `dir`, through a descriptor of
    /// its own: -errno.
    fn open_at(dir: BorrowedFd<'_>) -> Result<Self, c_int> {
        // SAFETY: the caller's fd, a C string and flags.
        let fd = unsafe {
            openat(
                dir.as_raw_fd(),
                c".".as_ptr(),
                O_RDONLY | O_DIRECTORY | O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(-errno());
        }
        // SAFETY: the fd openat() just gave, owned from here.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: the fd, which the stream owns once fdopendir() takes it.
        let stream = NonNull::new(unsafe { fdopendir(fd.as_raw_fd()) }).ok_or_else(|| -errno())?;
        let _ = fd.into_raw_fd();
        Ok(DirStream(stream))
    }

    /// The name of the next entry, None at the end, or -errno.
    fn next_name(&mut self) -> Result<Option<Vec<u8>>, c_int> {
        // The end of the stream tells from an error by errno alone.
        set_errno(0);
        // SAFETY: the stream's own DIR.
        let entry = unsafe { readdir(self.0.as_ptr()) };
        if entry.is_null() {
            return match errno() {
                0 => Ok(None),
                err => Err(-err),
            };
        }
        // SAFETY: the entry readdir() gave, whose name is a C string,
        // copied before the stream reads on.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        Ok(Some(name.to_bytes().to_vec()))
    }
}

impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: the stream, closed once with its fd.
        unsafe { closedir(self.0.as_ptr()) };
    }
}

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
pub(crate) fn append_line(fd: BorrowedFd<'_>, path: &CStr, line: &[u8]) -> Result<(), c_int> {
    let mut st = Statx::zeroed();
    let mut text = line;

    if text.last() == Some(&b'\n') {
        text = &text[..text.len() - 1];
    }
    if text.contains(&b'\n') || text.contains(&0) {
        return Err(-EINVAL);
    }
    let ret = stat_fd(fd.as_raw_fd(), &mut st);
    if ret != 0 {
        return Err(ret);
    }
    let size = st.stx_size as i64;
    let end = last_line_end(fd, size)?;
    if end != size {
        truncate_to(fd, end)?;
        crate::log::warn(
            &[
                path.to_bytes(),
                b": dropped ",
                format!("{}", size - end).as_bytes(),
                b" bytes at its end, an append that did not finish",
            ]
            .concat(),
        );
    }
    let record = [text, b"\n"].concat();
    // SAFETY: the caller's fd, and the record's bytes.
    let mut ret = unsafe { write_complete(fd.as_raw_fd(), record.as_ptr().cast(), record.len()) };
    // SAFETY: the caller's fd.
    if ret == 0 && unsafe { fsync(fd.as_raw_fd()) } != 0 {
        ret = -errno();
    }
    if ret == 0 {
        return Ok(());
    }
    if let Err(err) = truncate_to(fd, end) {
        crate::log::warn(
            &[
                path.to_bytes(),
                b": could not roll back a partial append: ",
                crate::errno::text(err).as_bytes(),
            ]
            .concat(),
        );
    }
    Err(ret)
}

/// `rel` opened beneath the directory open as `dirfd`, with `flags` and
/// close-on-exec, through no symlink, no magic link and nothing outside
/// it: -EINVAL for an empty or absolute `rel`, or -errno.
pub(crate) fn open_beneath(dirfd: c_int, rel: &CStr, flags: c_int) -> Result<OwnedFd, c_int> {
    let how = OpenHow {
        flags: flags as u64 | O_CLOEXEC as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };

    if dirfd < 0 || matches!(rel.to_bytes().first(), None | Some(b'/')) {
        return Err(-EINVAL);
    }
    // SAFETY: the caller's fd and C string, and the open_how and its size.
    let fd = unsafe {
        syscall(
            SYS_OPENAT2,
            dirfd,
            rel.as_ptr(),
            &raw const how,
            size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(-errno());
    }
    // SAFETY: the fd openat2() just gave, owned from here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as c_int) })
}

/// The whole regular file behind `fd`, from its start, of at most `max`
/// bytes, which may steer trust as `label` says.
pub(crate) fn read_whole(fd: BorrowedFd<'_>, label: &CStr, max: usize) -> Result<Vec<u8>, c_int> {
    let mut st = Statx::zeroed();

    let ret = stat_fd(fd.as_raw_fd(), &mut st);
    if ret != 0 {
        return Err(ret);
    }
    if st.stx_mode & S_IFMT != S_IFREG {
        return Err(-EINVAL);
    }
    let ret = check_trusted(fd, label, false);
    if ret != 0 {
        return Err(ret);
    }
    let size = usize::try_from(st.stx_size)
        .ok()
        .filter(|&size| size <= max)
        .ok_or(-EFBIG)?;
    let mut buf = vec![0u8; size];
    let mut done = 0usize;
    while done < size {
        // SAFETY: the caller's fd, and the room left in buf.
        let n = unsafe {
            pread(
                fd.as_raw_fd(),
                buf[done..].as_mut_ptr().cast(),
                size - done,
                done as i64,
            )
        };

        if n < 0 && errno() == EINTR {
            continue;
        }
        if n <= 0 {
            return Err(if n < 0 { -errno() } else { -EIO });
        }
        done += n as usize;
    }
    Ok(buf)
}

/// What a read gave, into `*out`, xmalloc'd to `*len + 1` bytes and
/// NUL-terminated, for the callers that still free it so.
///
/// # Safety
///
/// `out` is room for a pointer and `len` for a length.
unsafe fn hand_over(read: Result<Vec<u8>, c_int>, out: *mut c_void, len: *mut usize) -> c_int {
    let body = match read {
        Ok(body) => body,
        Err(err) => return err,
    };
    // SAFETY: an allocation of the body and a NUL, zeroed.
    let buf = unsafe { xmalloc(body.len() + 1) }.cast::<u8>();
    if buf.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the allocation's room for the body, and the caller's rooms.
    unsafe {
        core::ptr::copy_nonoverlapping(body.as_ptr(), buf, body.len());
        *out.cast::<*mut u8>() = buf;
        *len = body.len();
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

/// Whether `p` names something beneath the directory `dir`.
fn under_dir(p: &[u8], dir: &CStr) -> bool {
    let d = dir.to_bytes();

    p.starts_with(d) && p.get(d.len()) == Some(&b'/')
}

/// The regular file at `path`, of at most `max` bytes; one under
/// /var/lib/shirudo opened through its seal.
pub(crate) fn read(path: &CStr, max: usize) -> Result<Vec<u8>, c_int> {
    let fd = if under_dir(path.to_bytes(), VAR_LIB) {
        seal::open_read(path.to_bytes())?
    } else {
        // SAFETY: a C string and flags.
        let fd = unsafe { open(path.as_ptr(), O_RDONLY | O_CLOEXEC) };

        if fd < 0 {
            return Err(-errno());
        }
        // SAFETY: the fd just opened, owned from here and closed when it
        // goes.
        unsafe { OwnedFd::from_raw_fd(fd) }
    };
    read_whole(fd.as_fd(), path, max)
}

/// As [`read`], into `*out`, xmalloc'd to `*len + 1` bytes and
/// NUL-terminated.
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
    // SAFETY: the caller's C string and rooms.
    unsafe { hand_over(read(CStr::from_ptr(path), max), out, len) }
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
pub(crate) fn check_trusted(fd: BorrowedFd<'_>, path: &CStr, secret: bool) -> c_int {
    let path_text = path.to_bytes();
    let mut st = Statx::zeroed();

    if !under_dir(path_text, ETC_DIR) && !under_dir(path_text, VAR_LIB) {
        return 0;
    }
    let ret = stat_fd(fd.as_raw_fd(), &mut st);
    if ret != 0 {
        return ret;
    }
    if st.stx_mode & S_IFMT != S_IFREG
        || !trusted_owner(st.stx_uid)
        || st.stx_mode & if secret { 0o77 } else { 0o22 } != 0
    {
        let could = if secret { c"read or change" } else { c"change" };

        crate::log::err(
            &[
                path_text,
                b": owner ",
                format!("{}", st.stx_uid).as_bytes(),
                b", mode ",
                format!("{:04o}", u32::from(st.stx_mode & 0o7777)).as_bytes(),
                b": refusing a file another user could ",
                could.to_bytes(),
            ]
            .concat(),
        );
        return -EPERM;
    }
    use std::ffi::{CString, OsStr};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    // The file's directories up to /, as realpath() resolves its path
    // and as statx() of each, following links, finds them.
    let errno = |e: std::io::Error| -e.raw_os_error().unwrap_or(crate::errno::EIO);
    let real = match std::fs::canonicalize(OsStr::from_bytes(path_text)) {
        Ok(real) => real,
        Err(e) => return errno(e),
    };
    // realpath()'s bound, which canonicalize() does not keep.
    if real.as_os_str().len() >= PATH_MAX {
        return -crate::errno::ENAMETOOLONG;
    }
    for dir in real.ancestors().skip(1) {
        let st = match std::fs::metadata(dir) {
            Ok(st) => st,
            Err(e) => return errno(e),
        };
        let mode = st.mode();
        let sticky_root = mode & u32::from(S_ISVTX) != 0 && st.uid() == 0;
        if mode & u32::from(S_IFMT) != u32::from(S_IFDIR)
            || !trusted_owner(st.uid())
            || (mode & 0o22 != 0 && !sticky_root)
        {
            let dir = CString::new(dir.as_os_str().as_bytes()).unwrap_or_default();
            crate::log::err(
                &[
                    path_text,
                    b": directory ",
                    dir.to_bytes(),
                    b", owner ",
                    format!("{}", st.uid()).as_bytes(),
                    b", mode ",
                    format!("{:04o}", mode & 0o7777).as_bytes(),
                    b": refusing a file another user could replace",
                ]
                .concat(),
            );
            return -EPERM;
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
                && stx.stx_attributes_mask & STATX_ATTR_MOUNT_ROOT != 0
                && stx.stx_attributes & STATX_ATTR_MOUNT_ROOT != 0,
        )
    };
    // SAFETY: the path's fd, closed once.
    unsafe { close(fd) };
    ret
}

/// An exclusive flock() on `fd`, waited for through signals.
pub(crate) fn lock_exclusive(fd: c_int) -> c_int {
    // SAFETY: the caller's fd.
    while unsafe { flock(fd, LOCK_EX) } != 0 {
        if errno() != EINTR {
            return -errno();
        }
    }
    0
}

#[cfg(test)]
mod tests;

mod capi {
    use core::ffi::{CStr, c_char, c_int, c_void};
    use std::os::fd::{BorrowedFd, IntoRawFd};

    use crate::sys::libc::File;

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
    /// `fd` is an open descriptor, `label` is a C string, `out` room
    /// for a pointer and `len` for a length.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn read_fd(
        fd: c_int,
        label: *const c_char,
        max: usize,
        out: *mut c_void,
        len: *mut usize,
    ) -> c_int {
        // SAFETY: the caller passes a C string.
        let label = unsafe { CStr::from_ptr(label) };
        // SAFETY: the caller keeps the open descriptor valid for this call.
        let fd = unsafe { BorrowedFd::borrow_raw(fd) };
        // SAFETY: the caller provides rooms for the output pointer and length.
        unsafe { super::hand_over(super::read_whole(fd, label, max), out, len) }
    }

    /// # Safety
    ///
    /// `rel` is NULL or a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn open_beneath(dirfd: c_int, rel: *const c_char, flags: c_int) -> c_int {
        if rel.is_null() {
            return -crate::errno::EINVAL;
        }
        // SAFETY: the caller passes a C string.
        let rel = unsafe { CStr::from_ptr(rel) };
        match super::open_beneath(dirfd, rel, flags) {
            Ok(fd) => fd.into_raw_fd(),
            Err(err) => err,
        }
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

    #[unsafe(no_mangle)]
    pub extern "C" fn kernel_dev(dev: u64) -> u32 {
        super::kernel_dev(dev)
    }
}

/// An anonymous file in memory, named `name` where /proc shows its
/// descriptors, closed on exec: what a download is kept in rather than a
/// file of /tmp.
pub(crate) fn memfd(name: &core::ffi::CStr) -> Result<std::os::fd::OwnedFd, core::ffi::c_int> {
    // SAFETY: a C string and flags.
    let fd =
        unsafe { crate::sys::libc::memfd_create(name.as_ptr(), crate::sys::libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(-crate::sys::libc::errno());
    }
    // SAFETY: the descriptor memfd_create() gave, owned from here.
    Ok(unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) })
}
