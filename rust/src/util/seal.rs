// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The labels of the filesystem seal. bpf/seal.c denies every task but
//! shirudo the inodes that carry its label, so shirudo's state is the
//! labelled tree under /var/lib/shirudo, and what shirudo makes there it
//! labels as it makes it. An entry under a labelled directory without
//! the label came from someone else: it is refused, never followed or
//! read as shirudo's own. Output a command writes for its caller is the
//! other way round: it must carry no label, so root cannot point shirudo
//! at sealed state to overwrite.

use core::ffi::{CStr, c_int};
use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use crate::errno::{
    EEXIST, EINVAL, ELOOP, ENAMETOOLONG, ENODATA, ENOENT, ENOTDIR, EOPNOTSUPP, EPERM, ERANGE, text,
};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    AT_SYMLINK_NOFOLLOW, O_APPEND, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_NONBLOCK,
    O_TRUNC, S_IFMT, S_IFREG, Statx, close, fgetxattr, fsetxattr, fsync, ftruncate, lgetxattr,
    lsetxattr, mkdirat, openat, renameat, unlinkat,
};
use crate::util::io::{append_line, lock_exclusive, stat_fd, write_complete};

/// XATTR_SEAL: the attribute bpf/seal.c reads.
pub(crate) const XATTR: &CStr = c"security.bpf.shirudo";
/// SEAL_LABEL: the label's value.
pub(crate) const LABEL: &CStr = c"94442b45cfcdc59aabc2a91364ed2ae129418e05a5c1985231b9c032e673f469";
const LABEL_LEN: usize = LABEL.to_bytes().len();
/// VAR_LIB: the root of shirudo's sealed state.
const VAR_LIB: &CStr = c"/var/lib/shirudo";
const PATH_MAX: usize = 4096;
const NAME_MAX: usize = 255;
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_RDWR: c_int = 2;

fn say(level: fn(&[u8]), text: String) {
    let text = CString::new(text).unwrap_or_default();

    level(text.to_bytes());
}

fn error(text: String) {
    say(crate::log::err, text);
}

fn warn(text: String) {
    say(crate::log::warn, text);
}

fn errno() -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(EINVAL)
}

fn shown(p: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(p)
}

/// An fd, closed when it goes; [`Fd::close`] for when the close's
/// error counts.
struct Fd(c_int);

impl Fd {
    fn open_at(dfd: c_int, name: &CStr, flags: c_int, mode: u32) -> Result<Fd, c_int> {
        // SAFETY: an open directory and a C string.
        let fd = unsafe { openat(dfd, name.as_ptr(), flags, mode) };
        if fd < 0 { Err(-errno()) } else { Ok(Fd(fd)) }
    }

    fn into_raw(self) -> c_int {
        let fd = self.0;
        core::mem::forget(self);
        fd
    }

    /// Closes it: 0 or -errno.
    fn close(self) -> c_int {
        // SAFETY: the fd, closed once, here.
        if unsafe { close(self.into_raw()) } != 0 {
            -errno()
        } else {
            0
        }
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        // SAFETY: the fd, closed once, here.
        unsafe { close(self.0) };
    }
}

/// XATTR_ANCESTOR: the mark of a directory above the state root.
const XATTR_ANCESTOR: &CStr = c"security.bpf.shirudo.ancestor";

/// The parent of directory `dir`, opened, and its status.
fn open_dir_parent(dir: &std::fs::File) -> Result<(std::fs::File, std::fs::Metadata), c_int> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // SAFETY: the directory's descriptor and a C string.
    let fd = unsafe {
        openat(
            dir.as_raw_fd(),
            c"..".as_ptr(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(-errno());
    }
    // SAFETY: the descriptor just opened, owned here alone.
    let parent = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let st = parent
        .metadata()
        .map_err(|e| -e.raw_os_error().unwrap_or(EINVAL))?;
    Ok((parent, st))
}

/// Marks each directory above the state root at `root`, up to the root
/// of its file system, so that the seal refuses to rename them: 0 or
/// -errno. A directory whose parent is another file system, or itself,
/// is the root of its own: renaming it does not move the state tree off
/// the device the next boot mounts there.
pub(crate) fn mark_ancestors(root: &[u8]) -> c_int {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let walk = || -> Result<(), c_int> {
        let io = |e: std::io::Error| -e.raw_os_error().unwrap_or(EINVAL);
        let root = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW)
            .open(OsStr::from_bytes(root))
            .map_err(io)?;
        let dev = root.metadata().map_err(io)?.dev();
        let (mut dir, mut cur) = open_dir_parent(&root)?;
        drop(root);
        while cur.dev() == dev {
            let (parent, up) = open_dir_parent(&dir)?;
            if up.dev() != cur.dev() || up.ino() == cur.ino() {
                break;
            }
            // SAFETY: the directory's descriptor, a C string and the
            // value's one byte.
            if unsafe {
                fsetxattr(
                    dir.as_raw_fd(),
                    XATTR_ANCESTOR.as_ptr(),
                    b"1".as_ptr().cast(),
                    1,
                    0,
                )
            } != 0
            {
                return Err(-errno());
            }
            (dir, cur) = (parent, up);
        }
        Ok(())
    };
    walk().err().unwrap_or(0)
}

/// The label of `path` itself, a symbolic link's own inode rather than
/// its target's: 0 or -errno.
fn label(path: &CStr) -> c_int {
    // SAFETY: a C string, the attribute and its value.
    if unsafe {
        lsetxattr(
            path.as_ptr(),
            XATTR.as_ptr(),
            LABEL.as_ptr().cast(),
            LABEL_LEN,
            0,
        )
    } != 0
    {
        return -errno();
    }
    0
}

/// What a read of the label returned, as the seal takes it: its length,
/// 0 for none or one of another size, or -errno.
fn label_len(n: isize) -> isize {
    if n >= 0 {
        return if n as usize == LABEL_LEN { n } else { 0 };
    }
    match errno() {
        ENODATA | EOPNOTSUPP | ERANGE => 0,
        e => -(e as isize),
    }
}

fn fget(fd: c_int, out: &mut [u8; LABEL_LEN]) -> isize {
    // SAFETY: the fd, the attribute and the room for its value.
    label_len(unsafe { fgetxattr(fd, XATTR.as_ptr(), out.as_mut_ptr().cast(), LABEL_LEN) })
}

fn lget(path: &CStr, out: &mut [u8; LABEL_LEN]) -> isize {
    // SAFETY: a C string, the attribute and the room for its value.
    label_len(unsafe {
        lgetxattr(
            path.as_ptr(),
            XATTR.as_ptr(),
            out.as_mut_ptr().cast(),
            LABEL_LEN,
        )
    })
}

/// The walk of [`label_tree`].
struct Walk {
    dev: u64,
    first: bool,
}

impl Walk {
    /// One entry: from the first init on, everything shirudo makes is
    /// labelled as it is made, so an entry without the label, or of a
    /// kind shirudo never makes, came from someone else and is left
    /// alone. Err stops the walk.
    fn visit(&self, path: &[u8], st: &std::fs::Metadata) -> Result<(), c_int> {
        // Another filesystem, the bpffs mount, is bpf2's: a label there
        // would make the seal contend for its inodes.
        if st.dev() != self.dev {
            return Ok(());
        }
        if !st.is_file() && !st.is_dir() {
            warn(format!(
                "seal: {} is not a file or directory of shirudo's (foreign entry); ignored",
                shown(path)
            ));
            return Ok(());
        }
        let c = CString::new(path).map_err(|_| -EINVAL)?;
        if !self.first {
            if lget(&c, &mut [0; LABEL_LEN]) <= 0 {
                warn(format!(
                    "seal: {} carries no label (foreign entry); ignored",
                    shown(path)
                ));
            }
            return Ok(());
        }
        let ret = label(&c);
        if ret != 0 {
            error(format!("seal: label {}: {}", shown(path), text(ret)));
            return Err(ret);
        }
        Ok(())
    }

    /// `path` and, a directory, what it holds, in directory order and
    /// on its own filesystem, links not followed.
    fn walk(&self, path: &[u8], st: &std::fs::Metadata) -> Result<(), c_int> {
        self.visit(path, st)?;
        if !st.is_dir() {
            return Ok(());
        }
        let entries = match std::fs::read_dir(OsStr::from_bytes(path)) {
            Ok(entries) => entries,
            // nftw() hands an unreadable directory to the visit alone.
            Err(e) if e.raw_os_error() == Some(crate::errno::EACCES) => return Ok(()),
            Err(e) => return Err(-e.raw_os_error().unwrap_or(EINVAL)),
        };
        for entry in entries {
            let entry = entry.map_err(|e| -e.raw_os_error().unwrap_or(EINVAL))?;
            let child = [path, b"/", entry.file_name().as_bytes()].concat();
            // An entry gone or unreadable since the directory was read,
            // nftw() leaves to a visit with no state; it is skipped.
            let st = match std::fs::symlink_metadata(OsStr::from_bytes(&child)) {
                Ok(st) => st,
                Err(e) if matches!(e.raw_os_error(), Some(ENOENT | crate::errno::EACCES)) => {
                    continue;
                }
                Err(e) => return Err(-e.raw_os_error().unwrap_or(EINVAL)),
            };
            if st.dev() != self.dev {
                continue;
            }
            self.walk(&child, &st)?;
        }
        Ok(())
    }
}

/// Labels shirudo's state tree, or with it labelled, checks it. The
/// first labelling is the bootstrap's alone, before enforcement is live
/// (`allow_first`): with the hooks attached, a state root without the
/// label is not the one init sealed but a tree bound over its path, and
/// labelling it would hand root inodes the seal takes for shirudo's.
fn label_tree(allow_first: bool) -> c_int {
    let root = VAR_LIB.to_bytes();
    let st = match std::fs::metadata(OsStr::from_bytes(root)) {
        Ok(st) => st,
        Err(e) => return -e.raw_os_error().unwrap_or(EINVAL),
    };
    let first = lget(VAR_LIB, &mut [0; LABEL_LEN]) <= 0;
    if first && !allow_first {
        error(format!(
            "seal: {} carries no label with enforcement live (foreign state tree); refusing",
            shown(root)
        ));
        return -EPERM;
    }
    let walk = Walk {
        dev: st.dev(),
        first,
    };
    let top = match std::fs::symlink_metadata(OsStr::from_bytes(root)) {
        Ok(st) => st,
        Err(e) => return -e.raw_os_error().unwrap_or(EINVAL),
    };
    match walk.walk(root, &top) {
        Ok(()) => 0,
        Err(err) => err,
    }
}

/// Whether the inode behind `fd` carries the label of the directory open
/// as `dfd`: under a labelled directory an entry must, so one renamed or
/// linked in, or made while the seal could not label it, is refused. 0
/// when it does or the directory carries none, -EPERM when not.
fn same(dfd: c_int, fd: c_int) -> c_int {
    let (mut parent, mut own) = ([0u8; LABEL_LEN], [0u8; LABEL_LEN]);
    let plen = fget(dfd, &mut parent);
    if plen <= 0 {
        return plen as c_int;
    }
    let olen = fget(fd, &mut own);
    if olen < 0 {
        return olen as c_int;
    }
    if olen == plen && parent == own {
        0
    } else {
        -EPERM
    }
}

/// Gives the inode behind `fd` the label of its directory, open as
/// `dfd`.
fn inherit(dfd: c_int, fd: c_int) -> c_int {
    let (mut parent, mut own) = ([0u8; LABEL_LEN], [0u8; LABEL_LEN]);
    let plen = fget(dfd, &mut parent);
    if plen <= 0 {
        return plen as c_int;
    }
    let olen = fget(fd, &mut own);
    if olen < 0 {
        return olen as c_int;
    }
    if olen == plen && parent == own {
        return 0;
    }
    // SAFETY: the fd, the attribute and the parent's label.
    if unsafe { fsetxattr(fd, XATTR.as_ptr(), parent.as_ptr().cast(), plen as usize, 0) } != 0 {
        return -errno();
    }
    0
}

/// The directory at `path`, opened a component at a time, following no
/// symbolic link and taking no foreign entry for shirudo's own; with
/// `create`, what is missing made, labelled as its parent is.
fn open_dir(path: &[u8], create: bool, mode: u32) -> Result<Fd, c_int> {
    if path.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    let start = if path.first() == Some(&b'/') {
        c"/"
    } else {
        c"."
    };
    let mut dir = Fd::open_at(-100, start, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0)?;
    for comp in path.split(|&c| c == b'/').filter(|c| !c.is_empty()) {
        let name = CString::new(comp).map_err(|_| -EINVAL)?;
        let mut created = false;
        if create {
            // SAFETY: the open directory and a C string.
            created = unsafe { mkdirat(dir.0, name.as_ptr(), mode) } == 0;
            if !created && errno() != EEXIST {
                return Err(-errno());
            }
        }
        let next = Fd::open_at(
            dir.0,
            &name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            0,
        )
        .inspect_err(|&err| {
            if err == -ELOOP || err == -ENOTDIR {
                error(format!(
                    "{}: {} is not a directory of shirudo's (foreign entry in sealed state)",
                    shown(path),
                    shown(comp)
                ));
            }
        })?;
        let ret = if created {
            inherit(dir.0, next.0)
        } else {
            same(dir.0, next.0)
        };
        if ret == -EPERM {
            error(format!(
                "{}: {} carries no label (foreign entry in sealed state); refusing",
                shown(path),
                shown(comp)
            ));
        }
        dir = next;
        if ret != 0 {
            return Err(ret);
        }
    }
    Ok(dir)
}

/// The directory that holds `path`, opened as [`open_dir`] does, and the
/// name in it.
fn open_parent(path: &[u8]) -> Result<(Fd, &[u8]), c_int> {
    let (dir, name) = match path.iter().rposition(|&c| c == b'/') {
        None => (
            Fd::open_at(-100, c".", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0)?,
            path,
        ),
        Some(slash) => {
            let len = if slash == 0 { 1 } else { slash };
            if len >= PATH_MAX {
                return Err(-ENAMETOOLONG);
            }
            (open_dir(&path[..len], false, 0)?, &path[slash + 1..])
        }
    };
    if name.is_empty() {
        return Err(-EINVAL);
    }
    Ok((dir, name))
}

fn stat(fd: c_int) -> Result<Statx, c_int> {
    let mut st = Statx::zeroed();
    match stat_fd(fd, &mut st) {
        0 => Ok(st),
        err => Err(err),
    }
}

/// A FIFO planted before the seal was live would hold its opener
/// forever: the open does not wait, and what is not a regular file is
/// refused.
fn regular(fd: c_int) -> c_int {
    match stat(fd) {
        Ok(st) if st.stx_mode & S_IFMT == S_IFREG => 0,
        Ok(_) => -EINVAL,
        Err(err) => err,
    }
}

/// 1 for a label of any size, 0 for none, -errno when unreadable.
fn sealed(fd: c_int) -> c_int {
    // SAFETY: the fd and the attribute, its size only.
    if unsafe { fgetxattr(fd, XATTR.as_ptr(), core::ptr::null_mut(), 0) } >= 0 {
        return 1;
    }
    match errno() {
        ENODATA | EOPNOTSUPP => 0,
        e => -e,
    }
}

/// Output a command writes for its caller: a regular file that carries
/// no label, not under a labelled directory, not reached through a
/// symbolic link, truncated only once it is checked. The file and, when
/// asked, its directory and its name there.
fn output_open(path: &[u8], flags: c_int, mode: u32) -> Result<(Fd, Fd, &[u8]), c_int> {
    let (dir, name) = open_parent(path)?;
    let name_c = CString::new(name).map_err(|_| -EINVAL)?;
    let checked = (|| {
        let ret = sealed(dir.0);
        if ret != 0 {
            return Err(ret);
        }
        let fd = Fd::open_at(
            dir.0,
            &name_c,
            (flags & !O_TRUNC) | O_NOFOLLOW | O_CLOEXEC,
            mode,
        )?;
        let ret = regular(fd.0);
        if ret != 0 {
            return Err(ret);
        }
        let ret = sealed(fd.0);
        if ret != 0 {
            return Err(ret);
        }
        // SAFETY: the open file.
        if flags & O_TRUNC != 0 && unsafe { ftruncate(fd.0, 0) } != 0 {
            return Err(-errno());
        }
        Ok(fd)
    })();
    match checked {
        Ok(fd) => Ok((fd, dir, name)),
        Err(ret) if ret > 0 => {
            error(format!("{}: refusing to write sealed state", shown(path)));
            Err(-EPERM)
        }
        Err(ret) => Err(ret),
    }
}

/// open(2) under the seal: an existing file must be a regular one that
/// carries its directory's label; one it creates takes that label.
fn open(path: &[u8], flags: c_int, mode: u32) -> Result<Fd, c_int> {
    let (dir, name) = open_parent(path)?;
    let name = CString::new(name).map_err(|_| -EINVAL)?;
    let opened = Fd::open_at(
        dir.0,
        &name,
        (flags & !(O_CREAT | O_TRUNC)) | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
        mode,
    );
    match opened {
        Ok(_) if flags & O_EXCL != 0 => Err(-EEXIST),
        Ok(fd) => {
            let mut ret = regular(fd.0);
            if ret == 0 {
                ret = same(dir.0, fd.0);
            }
            if ret == -EPERM {
                error(format!(
                    "{}: carries no label (foreign entry in sealed state); refusing",
                    shown(path)
                ));
            }
            // SAFETY: the open file.
            if ret == 0 && flags & O_TRUNC != 0 && unsafe { ftruncate(fd.0, 0) } != 0 {
                ret = -errno();
            }
            if ret != 0 { Err(ret) } else { Ok(fd) }
        }
        Err(err) if err == -ENOENT && flags & O_CREAT != 0 => {
            let fd = Fd::open_at(dir.0, &name, flags | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)?;
            match inherit(dir.0, fd.0) {
                0 => Ok(fd),
                err => Err(err),
            }
        }
        Err(err) => {
            if err == -ELOOP {
                error(format!(
                    "{}: is a symbolic link (foreign entry in sealed state); refusing",
                    shown(path)
                ));
            }
            Err(err)
        }
    }
}

/// A file of shirudo's own, opened to be read.
fn open_read(path: &[u8]) -> Result<Fd, c_int> {
    open_file(path, false)
}

/// [`open_read`] of an entry whose directory must carry the label: one of
/// root's making, which no task without authority can label, holds
/// nothing shirudo takes for its own. -EPERM when it does not.
pub(crate) fn open_sealed(path: &[u8]) -> Result<std::os::fd::OwnedFd, c_int> {
    open_file(path, true).map(|fd| {
        // SAFETY: the descriptor the open made, owned from here.
        unsafe { std::os::fd::FromRawFd::from_raw_fd(fd.into_raw()) }
    })
}

/// [`open_read`], the descriptor owned.
pub(crate) fn open_owned(path: &[u8]) -> Result<std::os::fd::OwnedFd, c_int> {
    open_read(path).map(|fd| {
        // SAFETY: the descriptor the open made, owned from here.
        unsafe { std::os::fd::FromRawFd::from_raw_fd(fd.into_raw()) }
    })
}

/// Whether the directory `path` names an entry of carries the label.
pub(crate) fn parent_labeled(path: &[u8]) -> bool {
    open_parent(path).is_ok_and(|(dir, _)| fget(dir.0, &mut [0; LABEL_LEN]) == LABEL_LEN as isize)
}

fn open_file(path: &[u8], sealed: bool) -> Result<Fd, c_int> {
    let (dir, name) = open_parent(path)?;
    if sealed && fget(dir.0, &mut [0; LABEL_LEN]) != LABEL_LEN as isize {
        error(format!(
            "{}: its directory is not sealed state; refusing to read it",
            shown(path)
        ));
        return Err(-EPERM);
    }
    let name = CString::new(name).map_err(|_| -EINVAL)?;
    let result = Fd::open_at(
        dir.0,
        &name,
        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
        0,
    )
    .and_then(|fd| {
        let mut ret = regular(fd.0);
        if ret == 0 {
            ret = same(dir.0, fd.0);
        }
        if ret != 0 { Err(ret) } else { Ok(fd) }
    });
    if let Err(err) = result {
        if err == -EPERM || err == -ELOOP {
            error(format!(
                "{}: not shirudo's own (foreign entry in sealed state); refusing to read it",
                shown(path)
            ));
        }
    }
    result
}

/// The lock file at `path`, created sealed when missing, held
/// exclusively until its fd is closed.
fn lock(path: &[u8]) -> Result<Fd, c_int> {
    let fd = open(path, O_RDWR | O_CREAT, 0o600)?;
    match lock_exclusive(fd.0) {
        0 => Ok(fd),
        err => Err(err),
    }
}

/// `line` appended as one record to the sealed log at `path`, under the
/// lock that keeps its appenders apart.
fn append(path: &CStr, line: &[u8]) -> c_int {
    let fd = match open(path.to_bytes(), O_RDWR | O_CREAT | O_APPEND, 0o600) {
        Ok(fd) => fd,
        Err(err) => return err,
    };
    let mut ret = lock_exclusive(fd.0);
    if ret == 0 {
        ret = append_line(fd.0, path, line);
    }
    let closed = fd.close();
    if ret == 0 { closed } else { ret }
}

/// A document and its newline written to an output [`output_open`]
/// made, which it closes. A file the write does not complete is removed,
/// through the directory it was opened in and only while its name still
/// holds the inode written: root, who picks the path and can make the
/// write fail, could otherwise point it at sealed state to remove.
fn commit(fd: Fd, dir: Fd, name: &[u8], buf: &[u8]) -> c_int {
    // SAFETY: the open output and the document's bytes, then a newline.
    let mut ret = unsafe { write_complete(fd.0, buf.as_ptr().cast(), buf.len()) };
    if ret == 0 {
        // SAFETY: as above.
        ret = unsafe { write_complete(fd.0, c"\n".as_ptr().cast(), 1) };
    }
    let wrote = stat(fd.0).ok();
    let closed = fd.close();
    if ret == 0 {
        ret = closed;
    }
    if ret != 0 {
        if let (Some(wrote), Ok(name)) = (wrote, CString::new(name)) {
            let mut named = Statx::zeroed();
            // SAFETY: the directory, a C string and room for its state.
            let found = unsafe {
                crate::sys::libc::statx(
                    dir.0,
                    name.as_ptr(),
                    AT_SYMLINK_NOFOLLOW,
                    crate::sys::libc::STATX_BASIC_STATS,
                    &mut named,
                )
            } == 0;
            let same_inode = (named.stx_dev_major, named.stx_dev_minor, named.stx_ino)
                == (wrote.stx_dev_major, wrote.stx_dev_minor, wrote.stx_ino);
            if found && same_inode {
                // SAFETY: the directory and a C string.
                unsafe { unlinkat(dir.0, name.as_ptr(), 0) };
            }
        }
    }
    ret
}

/// mkdir -p, every directory it makes labelled as its parent is.
pub(crate) fn mkdir_p(path: &[u8], mode: u32) -> c_int {
    match open_dir(path, true, mode) {
        Ok(_) => 0,
        Err(err) => err,
    }
}

/// `data` written whole to `path` through a labelled temporary file,
/// synced and renamed into place.
pub(crate) fn write_file(path: &[u8], data: &[u8], mode: u32) -> c_int {
    let (dir, name) = match open_parent(path) {
        Ok(p) => p,
        Err(err) => return err,
    };
    let tmp = [name, b".tmp"].concat();
    if tmp.len() > NAME_MAX {
        return -ENAMETOOLONG;
    }
    let (Ok(tmp), Ok(name)) = (CString::new(tmp), CString::new(name)) else {
        return -EINVAL;
    };
    let fd = match Fd::open_at(
        dir.0,
        &tmp,
        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
        mode,
    ) {
        Ok(fd) => fd,
        Err(err) => return err,
    };
    let mut ret = inherit(dir.0, fd.0);
    if ret == 0 {
        // SAFETY: the open file and the data.
        ret = unsafe { write_complete(fd.0, data.as_ptr().cast(), data.len()) };
    }
    // SAFETY: the open file.
    if ret == 0 && unsafe { fsync(fd.0) } != 0 {
        ret = -errno();
    }
    let closed = fd.close();
    if ret == 0 {
        ret = closed;
    }
    // SAFETY: the directory and two C strings.
    if ret == 0 && unsafe { renameat(dir.0, tmp.as_ptr(), dir.0, name.as_ptr()) } != 0 {
        ret = -errno();
    }
    // SAFETY: the directory.
    if ret == 0 && unsafe { fsync(dir.0) } != 0 {
        ret = -errno();
    }
    if ret != 0 {
        // SAFETY: the directory and a C string.
        unsafe { unlinkat(dir.0, tmp.as_ptr(), 0) };
    }
    ret
}

/// The C entry points, which shirudo's C and its Rust both call.
mod capi {
    use core::ffi::{CStr, c_char, c_int, c_void};

    use super::Fd;

    /// `struct seal_output`: an output being written, its directory and
    /// its name there, which points into the caller's path.
    #[repr(C)]
    pub struct SealOutput {
        fd: c_int,
        dfd: c_int,
        name: *const c_char,
    }

    impl SealOutput {
        /// One not open, for seal_output_create() to fill.
        pub const fn closed() -> Self {
            SealOutput {
                fd: -1,
                dfd: -1,
                name: core::ptr::null(),
            }
        }
    }

    fn fd_or_err(r: Result<Fd, c_int>) -> c_int {
        r.map_or_else(|err| err, Fd::into_raw)
    }

    /// # Safety
    ///
    /// `path` is a C string.
    pub unsafe extern "C" fn seal_label(path: *const c_char) -> c_int {
        // SAFETY: the caller's C string.
        super::label(unsafe { CStr::from_ptr(path) })
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn seal_label_tree(allow_first: bool) -> c_int {
        super::label_tree(allow_first)
    }

    /// # Safety
    ///
    /// `path` is a C string.
    pub unsafe extern "C" fn seal_open(path: *const c_char, flags: c_int, mode: u32) -> c_int {
        // SAFETY: the caller's C string.
        fd_or_err(super::open(
            unsafe { CStr::from_ptr(path) }.to_bytes(),
            flags,
            mode,
        ))
    }

    /// # Safety
    ///
    /// `path` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn seal_open_read(path: *const c_char) -> c_int {
        // SAFETY: the caller's C string.
        fd_or_err(super::open_read(unsafe { CStr::from_ptr(path) }.to_bytes()))
    }

    /// # Safety
    ///
    /// `path` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn seal_open_sealed(path: *const c_char) -> c_int {
        // SAFETY: the caller's C string.
        fd_or_err(super::open_file(
            unsafe { CStr::from_ptr(path) }.to_bytes(),
            true,
        ))
    }

    /// # Safety
    ///
    /// `path` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn seal_parent_labeled(path: *const c_char) -> bool {
        // SAFETY: the caller's C string.
        super::parent_labeled(unsafe { CStr::from_ptr(path) }.to_bytes())
    }

    /// # Safety
    ///
    /// `path` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn seal_owns(path: *const c_char) -> bool {
        // SAFETY: the caller's C string.
        super::open_read(unsafe { CStr::from_ptr(path) }.to_bytes()).is_ok()
    }

    /// # Safety
    ///
    /// `path` is a C string.
    pub unsafe extern "C" fn seal_mkdir_p(path: *const c_char, mode: u32) -> c_int {
        // SAFETY: the caller's C string.
        super::mkdir_p(unsafe { CStr::from_ptr(path) }.to_bytes(), mode)
    }

    /// # Safety
    ///
    /// `path` is a C string and `data` holds `len` bytes.
    pub unsafe extern "C" fn seal_write_file(
        path: *const c_char,
        data: *const c_void,
        len: usize,
        mode: u32,
    ) -> c_int {
        // SAFETY: the caller's C string and bytes.
        unsafe {
            super::write_file(
                CStr::from_ptr(path).to_bytes(),
                crate::ffi::slice(data.cast(), len),
                mode,
            )
        }
    }

    /// # Safety
    ///
    /// `path` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn seal_lock(path: *const c_char) -> c_int {
        // SAFETY: the caller's C string.
        fd_or_err(super::lock(unsafe { CStr::from_ptr(path) }.to_bytes()))
    }

    /// # Safety
    ///
    /// `path` is a C string and `line` holds `len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn seal_append_line(
        path: *const c_char,
        line: *const c_char,
        len: usize,
    ) -> c_int {
        // SAFETY: the caller's C string and bytes.
        unsafe { super::append(CStr::from_ptr(path), crate::ffi::slice(line.cast(), len)) }
    }

    /// # Safety
    ///
    /// `path` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn seal_output_open(
        path: *const c_char,
        flags: c_int,
        mode: u32,
    ) -> c_int {
        // SAFETY: the caller's C string.
        match super::output_open(unsafe { CStr::from_ptr(path) }.to_bytes(), flags, mode) {
            Ok((fd, _, _)) => fd.into_raw(),
            Err(err) => err,
        }
    }

    /// # Safety
    ///
    /// `out` is room for an output and `path` a C string that outlives
    /// it, which keeps the name in it.
    pub unsafe extern "C" fn seal_output_create(
        out: *mut SealOutput,
        path: *const c_char,
        mode: u32,
    ) -> c_int {
        // SAFETY: the caller's C string.
        let p = unsafe { CStr::from_ptr(path) }.to_bytes();
        let flags = super::O_WRONLY | super::O_CREAT | super::O_TRUNC;
        match super::output_open(p, flags, mode) {
            Ok((fd, dir, name)) => {
                // SAFETY: the caller's room; the name is in its path.
                unsafe {
                    (*out).fd = fd.into_raw();
                    (*out).dfd = dir.into_raw();
                    (*out).name = path.add(p.len() - name.len());
                }
                0
            }
            Err(err) => err,
        }
    }

    /// # Safety
    ///
    /// `out` is an output seal_output_create() made, its path still
    /// valid, and `buf` holds `len` bytes.
    pub unsafe extern "C" fn seal_output_commit(
        out: *mut SealOutput,
        buf: *const c_void,
        len: usize,
    ) -> c_int {
        // SAFETY: the caller's output, its fds taken over, and bytes.
        unsafe {
            let (fd, dir) = (Fd((*out).fd), Fd((*out).dfd));
            let name = CStr::from_ptr((*out).name).to_bytes();
            super::commit(fd, dir, name, crate::ffi::slice(buf.cast(), len))
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn seal_inherit(dfd: c_int, fd: c_int) -> c_int {
        super::inherit(dfd, fd)
    }

    /// # Safety
    ///
    /// `path` is a C string.
    pub unsafe extern "C" fn seal_inherit_path(path: *const c_char) -> c_int {
        // SAFETY: the caller's C string.
        let p = unsafe { CStr::from_ptr(path) };
        let (dir, _) = match super::open_parent(p.to_bytes()) {
            Ok(d) => d,
            Err(err) => return err,
        };
        let (mut parent, mut own) = ([0u8; super::LABEL_LEN], [0u8; super::LABEL_LEN]);
        let plen = super::fget(dir.0, &mut parent);
        drop(dir);
        if plen <= 0 {
            return plen as c_int;
        }
        let olen = super::lget(p, &mut own);
        if olen < 0 {
            return olen as c_int;
        }
        if olen == plen && parent == own {
            return 0;
        }
        // SAFETY: a C string, the attribute and the parent's label.
        if unsafe {
            super::lsetxattr(
                path,
                super::XATTR.as_ptr(),
                parent.as_ptr().cast(),
                plen as usize,
                0,
            )
        } != 0
        {
            return -super::errno();
        }
        0
    }
}

pub(crate) use capi::{
    SealOutput, seal_append_line, seal_inherit, seal_inherit_path, seal_label, seal_label_tree,
    seal_lock, seal_mkdir_p, seal_open, seal_open_read, seal_output_commit, seal_output_create,
    seal_output_open, seal_owns, seal_write_file,
};
