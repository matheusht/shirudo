// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The config image a target runs from:
//! its verified root, held open, and the configuration it carries in
//! place of /etc/shirudo/shirudo.conf. What the image holds is opened
//! from its root and never through a path: a path, /proc/<pid>/fd
//! included, is root's to mount over before the exec.

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_uint};
use core::mem::MaybeUninit;

use crate::errno::{E2BIG, EINVAL, EIO, ELOOP, ENOENT, ENOTDIR, EPERM};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW, F_DUPFD_CLOEXEC, O_CLOEXEC, O_DIRECTORY, O_NOFOLLOW,
    O_RDONLY, S_IFDIR, S_IFMT, S_IFREG, STATX_TYPE, Statx, close, closedir, errno, explicit_bzero,
    fclose, fcntl, fdopen, fdopendir, ferror, free, getline, openat, readdir, set_errno, statx,
};
use crate::text::parse_u64;
use crate::util::config::{Config, Scrubbed, load_fd};
use crate::util::io::open_beneath;

/// `enum image_path`: the entries of the image, by their paths under its
/// root.
const RELATIVE: [&CStr; 7] = [
    c"etc/shirudo/bpm",
    c"etc/shirudo/bpm/registries.d",
    c"etc/shirudo/bpm/keys",
    c"etc/shirudo/bpm/upatch-tree.conf",
    c"etc/shirudo/node.labels",
    c"keys/trusted",
    c"keys/revoked",
];

/// IMAGE_REGISTRIES, IMAGE_TREE_CONF and IMAGE_NODE_LABELS of `enum
/// image_path`.
pub(crate) const REGISTRIES: c_uint = 1;
pub(crate) const TREE_CONF: c_uint = 3;
pub(crate) const NODE_LABELS: c_uint = 4;

const SHIRUDO_CONF: &CStr = c"etc/shirudo/shirudo.conf";

/// What image_config_set() keeps for the rest of the process, set at
/// startup before any thread, as the C's statics were.
struct Global {
    effective: UnsafeCell<MaybeUninit<Config>>,
    active: UnsafeCell<bool>,
    config_fd: UnsafeCell<c_int>,
}

// SAFETY: set at startup on the main thread and read after, as the C's
// statics were.
unsafe impl Sync for Global {}

static STATE: Global = Global {
    effective: UnsafeCell::new(MaybeUninit::zeroed()),
    active: UnsafeCell::new(false),
    config_fd: UnsafeCell::new(-1),
};

pub(crate) fn active() -> bool {
    // SAFETY: a read of the state, which only startup writes.
    unsafe { *STATE.active.get() }
}

/// An entry of the image, opened from its verified root: an fd, or
/// -errno.
pub(crate) fn open(which: c_uint, flags: c_int) -> c_int {
    let fd = root_fd();

    if which as usize >= RELATIVE.len() || fd < 0 {
        return -ENOENT;
    }
    // SAFETY: the root, a relative path and the caller's flags.
    unsafe { open_beneath(fd, RELATIVE[which as usize].as_ptr(), flags) }
}

/// `path`, relative to the image's root and never above it, open with
/// `flags`: an fd or -errno.
pub(crate) fn open_relative(path: &CStr, flags: c_int) -> c_int {
    let fd = root_fd();
    let rel = path.to_bytes();

    if fd < 0 || rel.first() == Some(&b'/') || rel.windows(2).any(|w| w == b"..") {
        return -EINVAL;
    }
    // SAFETY: the root, the relative path and flags.
    unsafe { open_beneath(fd, path.as_ptr(), flags) }
}

pub(crate) fn root_fd() -> c_int {
    // SAFETY: as above.
    unsafe { *STATE.config_fd.get() }
}

/// The configuration the image carries into `out`, as a struct copy of
/// the C made it, to the byte: 1, or 0 without an image.
///
/// # Safety
///
/// `out` points to room for a configuration.
pub(crate) unsafe fn get(out: *mut Config) -> c_int {
    if !active() {
        return 0;
    }
    // SAFETY: the configuration set, every byte of it, into the caller's
    // room.
    unsafe { core::ptr::copy_nonoverlapping(STATE.effective.get().cast::<Config>(), out, 1) };
    1
}

/// The image's shirudo.conf into `cfg`, read through its root.
///
/// # Safety
///
/// `cfg` points to room for a configuration.
unsafe fn load_root(cfg: *mut Config, root_fd: c_int) -> c_int {
    // SAFETY: the root's fd, a relative path and flags.
    let fd = unsafe { open_beneath(root_fd, SHIRUDO_CONF.as_ptr(), O_RDONLY) };
    if fd < 0 {
        return fd;
    }
    // SAFETY: the caller's room, the fd open_beneath() gave, closed once,
    // and a label.
    unsafe {
        let ret = load_fd(cfg, fd, c"config image shirudo.conf".as_ptr());

        close(fd);
        ret
    }
}

/// A device as statx() gives it.
type Dev = (u32, u32);

/// The tree under `root_fd`: only regular files and directories, on the
/// root's device, at most 32 deep and 65536 entries in all.
fn validate_tree(root_fd: c_int, device: Dev, depth: u32, entries: &mut u32) -> c_int {
    let mut ret = 0;

    if depth > 32 {
        return -ELOOP;
    }
    // SAFETY: the directory's fd, "." and flags.
    let fd = unsafe { openat(root_fd, c".".as_ptr(), O_RDONLY | O_DIRECTORY | O_CLOEXEC) };
    if fd < 0 {
        return -errno();
    }
    // SAFETY: the fd openat() gave, which the stream takes over.
    let dir = unsafe { fdopendir(fd) };
    if dir.is_null() {
        let ret = -errno();

        // SAFETY: the fd openat() gave, closed once.
        unsafe { close(fd) };
        return ret;
    }
    loop {
        set_errno(0);
        // SAFETY: the stream fdopendir() gave.
        let entry = unsafe { readdir(dir) };
        if entry.is_null() {
            let e = errno();

            if e != 0 {
                ret = -e;
            }
            break;
        }
        // SAFETY: the entry readdir() gave, its name a C string within it.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };

        if name == c"." || name == c".." {
            continue;
        }
        *entries += 1;
        if *entries > 65536 {
            ret = -E2BIG;
            break;
        }
        let mut st = Statx::zeroed();
        // SAFETY: the directory's fd, a name in it, and a statx to fill.
        if unsafe { statx(fd, name.as_ptr(), AT_SYMLINK_NOFOLLOW, STATX_TYPE, &mut st) } != 0 {
            ret = -errno();
            break;
        }
        let kind = st.stx_mode & S_IFMT;

        if (st.stx_dev_major, st.stx_dev_minor) != device || (kind != S_IFREG && kind != S_IFDIR) {
            ret = -EPERM;
            break;
        }
        if kind == S_IFDIR {
            // SAFETY: the directory's fd, a name in it, and flags.
            let child = unsafe {
                openat(
                    fd,
                    name.as_ptr(),
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW,
                )
            };

            if child < 0 {
                ret = -errno();
                break;
            }
            ret = validate_tree(child, device, depth + 1, entries);
            // SAFETY: the fd openat() gave, closed once.
            unsafe { close(child) };
            if ret != 0 {
                break;
            }
        }
    }
    // SAFETY: the stream fdopendir() gave, closed once with its fd.
    unsafe { closedir(dir) };
    ret
}

fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// A line of the image's shirudo.conf as the image may hold it: a
/// comment, a blank line, eventlog.max_bytes as a number, or a
/// map_export setting; 0, -E2BIG, -EINVAL or -EPERM.
fn setting_ok(line: &[u8]) -> c_int {
    let mut p = 0;

    while p < line.len() && is_blank(line[p]) {
        p += 1;
    }
    if p == line.len() || line[p] == b'#' || line[p] == b'\n' {
        return 0;
    }
    let Some(eq) = line[p..].iter().position(|&c| c == b'=').map(|i| p + i) else {
        return -EINVAL;
    };
    let mut end = eq;

    while end > p && is_blank(line[end - 1]) {
        end -= 1;
    }
    let key = &line[p..end];

    if key == b"eventlog.max_bytes" {
        let mut v = eq + 1;
        let mut end = line.len();

        while v < end && is_blank(line[v]) {
            v += 1;
        }
        while end > v && matches!(line[end - 1], b' ' | b'\t' | b'\r' | b'\n') {
            end -= 1;
        }
        if parse_u64(&line[v..end], u64::MAX).is_err() {
            return -EINVAL;
        }
    } else if !key.starts_with(b"map_export.") {
        return -EPERM;
    }
    0
}

/// The image's shirudo.conf holds only what an image may set.
fn validate_settings(root_fd: c_int) -> c_int {
    let mut line: *mut c_char = core::ptr::null_mut();
    let mut capacity = 0usize;
    let mut ret = 0;

    // SAFETY: the root's fd, a relative path and flags.
    let fd = unsafe {
        openat(
            root_fd,
            SHIRUDO_CONF.as_ptr(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return -errno();
    }
    // SAFETY: the fd openat() gave, which the stream takes over.
    let file = unsafe { fdopen(fd, c"r".as_ptr()) };
    if file.is_null() {
        let ret = -errno();

        // SAFETY: the fd openat() gave, closed once.
        unsafe { close(fd) };
        return ret;
    }
    loop {
        // SAFETY: getline()'s buffer and its size, and the stream.
        let length = unsafe { getline(&mut line, &mut capacity, file) };
        if length < 0 {
            break;
        }
        let length = length as usize;
        // SAFETY: the length bytes getline() read into line.
        let text = unsafe { core::slice::from_raw_parts(line.cast::<u8>(), length) };

        if length > 1023 || text.contains(&0) {
            ret = -E2BIG;
            break;
        }
        ret = setting_ok(text);
        if ret != 0 {
            break;
        }
    }
    // SAFETY: the stream, and getline()'s buffer, freed once.
    unsafe {
        if ferror(file) != 0 && ret == 0 {
            ret = -EIO;
        }
        free(line.cast());
        fclose(file);
    }
    ret
}

/// Whether the tree under `root_fd` is a config image this target may
/// run from: 0 or -errno.
pub(crate) fn validate(root_fd: c_int) -> c_int {
    let mut candidate = Scrubbed(MaybeUninit::zeroed());
    let mut entries = 0u32;
    let mut st = Statx::zeroed();

    // SAFETY: the caller's fd, an empty path, and a statx to fill.
    if unsafe { statx(root_fd, c"".as_ptr(), AT_EMPTY_PATH, STATX_TYPE, &mut st) } != 0 {
        return -errno();
    }
    if st.stx_mode & S_IFMT != S_IFDIR {
        return -ENOTDIR;
    }
    let mut ret = validate_tree(
        root_fd,
        (st.stx_dev_major, st.stx_dev_minor),
        0,
        &mut entries,
    );

    if ret == 0 {
        ret = validate_settings(root_fd);
    }
    if ret == 0 {
        // SAFETY: the candidate's room.
        ret = unsafe { load_root(candidate.ptr(), root_fd) };
        // SAFETY: the candidate, filled by the load.
        let c = unsafe { &*candidate.ptr() };

        if ret == 0 && (!c.map_export_valid || !c.tls_classical_hosts_valid) {
            ret = -EINVAL;
        }
    }
    ret
}

/// The image's configuration over the bootstrap one, from the verified
/// root at `root_fd`, or the bootstrap one alone without a root: 0, or
/// -errno with nothing changed.
///
/// # Safety
///
/// `bootstrap` points to a configuration.
unsafe fn set(bootstrap: *const Config, root_fd: c_int) -> c_int {
    let mut candidate = Scrubbed(MaybeUninit::uninit());
    let mut fd = -1;

    // SAFETY: the bootstrap configuration, every byte of it, into the
    // candidate.
    unsafe { core::ptr::copy_nonoverlapping(bootstrap, candidate.ptr(), 1) };
    if root_fd >= 0 {
        let ret = validate(root_fd);
        if ret != 0 {
            return ret;
        }
        // SAFETY: the caller's fd, and a minimum.
        fd = unsafe { fcntl(root_fd, F_DUPFD_CLOEXEC, 3 as c_int) };
        if fd < 0 {
            return -errno();
        }
        // SAFETY: the candidate's room, and the copy of the root.
        let ret = unsafe { load_root(candidate.ptr(), fd) };
        // SAFETY: the candidate, filled, and the caller's bootstrap.
        let (c, b) = unsafe { (&mut *candidate.ptr(), &*bootstrap) };

        if ret != 0 || !c.map_export_valid || !c.tls_classical_hosts_valid {
            // SAFETY: the copy fcntl() gave, closed once.
            unsafe { close(fd) };
            return if ret != 0 { ret } else { -EINVAL };
        }
        c.tpm_owner_auth = b.tpm_owner_auth;
        c.tpm_owner_auth_len = b.tpm_owner_auth_len;
        c.tpm_tcti = b.tpm_tcti;
        c.tls_classical_hosts = b.tls_classical_hosts;
        c.tls_classical_hosts_valid = b.tls_classical_hosts_valid;
    }
    // SAFETY: the state, written at startup alone, and the candidate's
    // bytes copied whole.
    unsafe {
        let config_fd = &mut *STATE.config_fd.get();

        if *config_fd >= 0 {
            close(*config_fd);
        }
        *config_fd = fd;
        core::ptr::copy_nonoverlapping(
            candidate.ptr().cast_const(),
            STATE.effective.get().cast::<Config>(),
            1,
        );
        *STATE.active.get() = true;
    }
    0
}

/// Forgets the image: its root closed, its configuration scrubbed.
fn clear() {
    // SAFETY: the state, written at startup alone.
    unsafe {
        let config_fd = &mut *STATE.config_fd.get();

        if *config_fd >= 0 {
            close(*config_fd);
        }
        *config_fd = -1;
        *STATE.active.get() = false;
        explicit_bzero(STATE.effective.get().cast(), size_of::<Config>());
    }
}

pub(crate) use capi::{image_config_clear, image_config_set};

mod capi {
    use core::ffi::c_int;

    use crate::util::config::Config;

    /// # Safety
    ///
    /// `bootstrap` points to a configuration.
    pub unsafe extern "C" fn image_config_set(bootstrap: *const Config, root_fd: c_int) -> c_int {
        // SAFETY: the caller passes a configuration.
        unsafe { super::set(bootstrap, root_fd) }
    }

    pub extern "C" fn image_config_clear() {
        super::clear();
    }
}
