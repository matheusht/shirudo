// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Reading a `.bee`, a gzip'd ustar archive of one top-level directory:
//! one member, the names of all, or all of it unpacked.

use core::ffi::{CStr, c_char, c_int, c_uint};

use super::tar::{
    BLOCK, NAME, PREFIX, SIZE, TYPEFLAG, archive_rel_ok, header_ok, octal, package_member_name_ok,
    padding,
};
use crate::errno::{E2BIG, EFBIG, EINVAL, EIO, ENAMETOOLONG, ENOENT, ENOMEM, EPERM};
use crate::ffi;
use crate::sys::libc::{
    F_DUPFD_CLOEXEC, O_CREAT, O_EXCL, O_WRONLY, PATH_MAX, SEEK_SET, close, errno, fchmod, fcntl,
    lseek,
};
use crate::sys::malloc::{xfree, xmalloc};
use crate::sys::zlib::{GzFileS, Z_OK, gzclose, gzdirect, gzdopen, gzopen, gzread};
use crate::text::{at, cstr, strsprintf};
use crate::util::bpm_oci::{MAX_PACKAGE_BYTES, MAX_PACKAGE_ENTRIES};
use crate::util::io::write_complete;
use crate::util::seal::{seal_mkdir_p, seal_open};

/// The most a read asks zlib for at once.
const CHUNK: usize = 65536;

/// The room for the top-level directory's name.
const ROOT_MAX: usize = 256;

/// What a member walk calls with each package-relative name and its
/// type: 0 to go on, anything else to stop the walk with it.
pub(super) type Visit<'a> = &'a mut dyn FnMut(&CStr, c_char) -> c_int;

/// A gzip file open for reading.
struct Gz(*mut GzFileS);

impl Gz {
    /// `path` opened; None, with errno set, when it cannot be.
    fn open(path: *const c_char) -> Option<Gz> {
        // SAFETY: gzopen() refuses a NULL path and reads a C string,
        // which the caller passes otherwise.
        let file = unsafe { gzopen(path, c"rb".as_ptr()) };

        (!file.is_null()).then_some(Gz(file))
    }

    /// Rewind the caller's descriptor and give zlib a separate descriptor
    /// to close. The caller keeps its descriptor for later reads.
    fn open_fd(fd: c_int) -> Result<Gz, c_int> {
        // SAFETY: lseek uses the caller's open descriptor.
        if unsafe { lseek(fd, 0, SEEK_SET) } < 0 {
            return Err(-errno());
        }
        // SAFETY: fcntl duplicates the caller's descriptor with CLOEXEC.
        let copy = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, 0) };
        if copy < 0 {
            return Err(-errno());
        }
        // SAFETY: zlib takes ownership of copy on success.
        let file = unsafe { gzdopen(copy, c"rb".as_ptr()) };
        if file.is_null() {
            // SAFETY: zlib did not take the duplicate.
            unsafe { close(copy) };
            return Err(-ENOMEM);
        }
        Ok(Gz(file))
    }

    /// Whether zlib reads the file as it is, it not being gzip.
    fn direct(&self) -> bool {
        // SAFETY: an open file.
        unsafe { gzdirect(self.0) != 0 }
    }

    /// Up to `buf.len()` bytes, at most `CHUNK`: how many, 0 at the end,
    /// below 0 on an error.
    fn read(&mut self, buf: &mut [u8]) -> c_int {
        debug_assert!(buf.len() <= CHUNK);
        // SAFETY: an open file, and buf.len() writable bytes.
        unsafe { gzread(self.0, buf.as_mut_ptr().cast(), buf.len() as c_uint) }
    }

    /// Z_OK, or what went wrong reading the file, its trailer included.
    fn close(self) -> c_int {
        let file = self.0;

        core::mem::forget(self);
        // SAFETY: an open file, closed once, here.
        unsafe { gzclose(file) }
    }
}

impl Drop for Gz {
    fn drop(&mut self) {
        // SAFETY: an open file, closed once, here.
        unsafe { gzclose(self.0) };
    }
}

/// `n` bytes read and dropped in pieces of `buf`; false when the archive
/// ends or fails first.
fn skip(gz: &mut Gz, mut n: u64, buf: &mut [u8]) -> bool {
    while n != 0 {
        let want = n.min(buf.len() as u64) as usize;
        let got = gz.read(&mut buf[..want]);

        if got <= 0 {
            return false;
        }
        n -= got as u64;
    }
    true
}

/// The next header, None at the end: the end of the file or a zero block.
fn next_header(gz: &mut Gz, h: &mut [u8; BLOCK]) -> Result<Option<()>, c_int> {
    let n = gz.read(h);

    if n == 0 {
        return Ok(None);
    }
    if n != BLOCK as c_int {
        return Err(-EINVAL);
    }
    if h.iter().all(|&c| c == 0) {
        return Ok(None);
    }
    Ok(Some(()))
}

/// The name a header holds, which must end within its field.
fn header_name(h: &[u8; BLOCK]) -> Option<&[u8]> {
    h[NAME].contains(&0).then(|| cstr(&h[NAME]))
}

/// What `read_member_in()` fills on success.
pub(super) struct Found<'a> {
    pub out: &'a mut *mut u8,
    pub out_len: &'a mut usize,
    pub dir: Option<&'a mut [u8]>,
}

/// One member of a gzip'd ustar `.bee` into an xmalloc'd buffer of
/// `out_len + 1` bytes. `member` is relative to the single top-level
/// package directory; `package_dir` pins that directory when known, the
/// found directory reports it otherwise.
pub(super) fn read_member_in(
    archive: *const c_char,
    member: Option<&[u8]>,
    package_dir: Option<&[u8]>,
    found: &mut Found<'_>,
    max: usize,
) -> c_int {
    let Some(gz) = Gz::open(archive) else {
        return -errno();
    };
    read_member_gz(gz, member, package_dir, found, max)
}

/// Read from the start of fd, leaving the caller's descriptor open.
pub(super) fn read_member_fd(
    fd: c_int,
    member: Option<&[u8]>,
    package_dir: Option<&[u8]>,
    found: &mut Found<'_>,
    max: usize,
) -> c_int {
    let gz = match Gz::open_fd(fd) {
        Ok(gz) => gz,
        Err(err) => return err,
    };
    read_member_gz(gz, member, package_dir, found, max)
}

fn read_member_gz(
    mut gz: Gz,
    member: Option<&[u8]>,
    package_dir: Option<&[u8]>,
    found: &mut Found<'_>,
    max: usize,
) -> c_int {
    if gz.direct() {
        gz.close();
        return -EINVAL;
    }
    let ret = find_member(&mut gz, member, package_dir, found, max);

    if gz.close() != Z_OK && ret == 0 {
        // SAFETY: the allocation find_member() made, given back once.
        unsafe { xfree((*found.out).cast(), *found.out_len + 1) };
        *found.out = core::ptr::null_mut();
        *found.out_len = 0;
        return -EINVAL;
    }
    ret
}

fn find_member(
    gz: &mut Gz,
    member: Option<&[u8]>,
    package_dir: Option<&[u8]>,
    found: &mut Found<'_>,
    max: usize,
) -> c_int {
    let mut h = [0u8; BLOCK];
    let mut discard = [0u8; CHUNK];

    loop {
        match next_header(gz, &mut h) {
            Ok(Some(())) => {}
            Ok(None) => return -ENOENT,
            Err(e) => return e,
        }
        let Some(name) = header_name(&h).filter(|_| header_ok(&h)) else {
            return -EINVAL;
        };
        let Ok(size) = octal(&h[SIZE]) else {
            return -EINVAL;
        };
        if package_member_name_ok(name, member) {
            let dir_len = name.iter().position(|&c| c == b'/').unwrap_or(0);

            if package_dir.is_none_or(|d| &name[..dir_len] == d) {
                return take_member(gz, &h, &name[..dir_len], size, found, max);
            }
        }
        if !skip(gz, size, &mut discard) || !skip(gz, padding(size), &mut discard) {
            return -EINVAL;
        }
    }
}

/// The data of the member `h` heads, of the package directory `dir`.
fn take_member(
    gz: &mut Gz,
    h: &[u8; BLOCK],
    dir: &[u8],
    size: u64,
    found: &mut Found<'_>,
    max: usize,
) -> c_int {
    if (h[TYPEFLAG] != 0 && h[TYPEFLAG] != b'0')
        || h[PREFIX] != 0
        || found.dir.as_ref().is_some_and(|d| dir.len() >= d.len())
    {
        return -EINVAL;
    }
    if size > max as u64 {
        return -E2BIG;
    }
    let Some(alloc) = size.checked_add(1).and_then(|a| usize::try_from(a).ok()) else {
        return -E2BIG;
    };
    let size = alloc - 1;
    // SAFETY: xmalloc() returns NULL or alloc zeroed bytes.
    let body = unsafe { xmalloc(alloc) }.cast::<u8>();
    if body.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the alloc bytes xmalloc() just gave, which nothing else
    // holds.
    let buf = unsafe { ffi::bytes_mut(body, alloc) };
    let mut done = 0;

    while done < size {
        let want = (size - done).min(CHUNK);
        let n = gz.read(&mut buf[done..done + want]);

        if n <= 0 {
            // SAFETY: the allocation above, given back once.
            unsafe { xfree(body.cast(), alloc) };
            return -EINVAL;
        }
        done += n as usize;
    }
    buf[size] = 0;
    *found.out = body;
    *found.out_len = size;
    if let Some(d) = found.dir.as_deref_mut() {
        d[..dir.len()].copy_from_slice(dir);
        d[dir.len()] = 0;
    }
    0
}

/// Visit the validated package-relative members of a `.bee`, each name
/// with its type, without extracting them.
pub(super) fn visit_members(
    archive: *const c_char,
    package_dir: Option<&[u8]>,
    visit: Option<Visit<'_>>,
) -> c_int {
    let Some(gz) = Gz::open(archive) else {
        return -errno();
    };
    visit_members_gz(gz, package_dir, visit)
}

/// Walk from the start of fd, leaving the caller's descriptor open.
pub(super) fn visit_members_fd(
    fd: c_int,
    package_dir: Option<&[u8]>,
    visit: Option<Visit<'_>>,
) -> c_int {
    let gz = match Gz::open_fd(fd) {
        Ok(gz) => gz,
        Err(err) => return err,
    };
    visit_members_gz(gz, package_dir, visit)
}

fn visit_members_gz(mut gz: Gz, package_dir: Option<&[u8]>, visit: Option<Visit<'_>>) -> c_int {
    if gz.direct() {
        gz.close();
        return -EINVAL;
    }
    let ret = walk_members(&mut gz, package_dir, visit);

    if gz.close() != Z_OK && ret == 0 {
        return -EINVAL;
    }
    ret
}

fn walk_members(gz: &mut Gz, package_dir: Option<&[u8]>, mut visit: Option<Visit<'_>>) -> c_int {
    let mut h = [0u8; BLOCK];
    let mut discard = [0u8; CHUNK];
    let mut root = [0u8; ROOT_MAX];
    let mut root_len = 0;
    let mut rel = [0u8; NAME.end + 1];

    let ret = loop {
        match next_header(gz, &mut h) {
            Ok(Some(())) => {}
            Ok(None) => break 0,
            Err(e) => break e,
        }
        let Some(mut name) = header_name(&h).filter(|_| header_ok(&h) && h[PREFIX] == 0) else {
            break -EINVAL;
        };
        let Ok(size) = octal(&h[SIZE]) else {
            break -EINVAL;
        };
        let ty = if h[TYPEFLAG] != 0 { h[TYPEFLAG] } else { b'0' };
        if ty == b'5' && name.last() == Some(&b'/') {
            name = &name[..name.len() - 1];
        }
        if !archive_rel_ok(name) {
            break -EINVAL;
        }
        if root_len == 0 {
            let slash = name.iter().position(|&c| c == b'/');
            let len = slash.unwrap_or(name.len());

            if (slash.is_none() && ty != b'5') || slash == Some(0) || len >= ROOT_MAX {
                break -EINVAL;
            }
            root[..len].copy_from_slice(&name[..len]);
            root_len = len;
        }
        let root = &root[..root_len];
        if !name.starts_with(root) || !matches!(at(name, root_len), 0 | b'/') {
            break -EINVAL;
        }
        if package_dir.is_some_and(|d| d != root) {
            break -EINVAL;
        }
        if ty != b'0' && ty != b'5' {
            break -EPERM;
        }
        let r = &name[root_len + usize::from(at(name, root_len) == b'/')..];
        if r.is_empty() {
            if ty != b'5' {
                break -EINVAL;
            }
        } else if !archive_rel_ok(r) {
            break -EINVAL;
        } else if let Some(visit) = visit.as_mut() {
            rel[..r.len()].copy_from_slice(r);
            rel[r.len()] = 0;
            let Ok(r) = CStr::from_bytes_until_nul(&rel) else {
                break -EINVAL;
            };
            let ret = visit(r, ty as c_char);
            if ret != 0 {
                break ret;
            }
        }
        if !skip(gz, size, &mut discard) || !skip(gz, padding(size), &mut discard) {
            return -EINVAL;
        }
    };
    if root_len == 0 { -EINVAL } else { ret }
}

/// Unpack the regular files and directories under the single top-level
/// directory of a `.bee` into `dest`; anything else fails the archive.
pub(super) fn extract(archive: *const c_char, dest: &CStr) -> c_int {
    let Some(mut gz) = Gz::open(archive) else {
        return -EINVAL;
    };
    // SAFETY: a C string.
    let ret = unsafe { seal_mkdir_p(dest.as_ptr(), 0o700) };
    if ret != 0 {
        gz.close();
        return ret;
    }
    let (ret, rooted) = unpack(&mut gz, dest.to_bytes());

    if gz.close() != Z_OK && ret == 0 {
        return -EINVAL;
    }
    if ret != 0 {
        return ret;
    }
    if rooted { 0 } else { -EINVAL }
}

/// The members of `gz` under `dest`, and whether there was a top-level
/// directory.
fn unpack(gz: &mut Gz, dest: &[u8]) -> (c_int, bool) {
    let mut h = [0u8; BLOCK];
    let mut buf = [0u8; CHUNK];
    let mut root = [0u8; ROOT_MAX];
    let mut root_len = 0;
    let mut total = 0u64;
    let mut entries = 0u32;
    let mut path = [0u8; PATH_MAX];

    let ret = loop {
        match next_header(gz, &mut h) {
            Ok(Some(())) => {}
            Ok(None) => break 0,
            Err(e) => break e,
        }
        // A ustar prefix would make the member another reader's
        // prefix/name.
        let Some(name) = header_name(&h).filter(|_| header_ok(&h) && h[PREFIX] == 0) else {
            break -EINVAL;
        };
        if !archive_rel_ok(name) {
            break -EINVAL;
        }
        let Ok(size) = octal(&h[SIZE]) else {
            break -EINVAL;
        };
        let ty = if h[TYPEFLAG] != 0 { h[TYPEFLAG] } else { b'0' };
        entries += 1;
        if entries > MAX_PACKAGE_ENTRIES || size > MAX_PACKAGE_BYTES - total {
            break -EFBIG;
        }
        total += size;
        if root_len == 0 {
            match name.iter().position(|&c| c == b'/') {
                Some(slash) if slash != 0 && slash < ROOT_MAX => {
                    root[..slash].copy_from_slice(&name[..slash]);
                    root_len = slash;
                }
                _ => break -EINVAL,
            }
        }
        if !name.starts_with(&root[..root_len]) || at(name, root_len) != b'/' {
            break -EINVAL;
        }
        let rel = &name[root_len + 1..];
        if (rel.is_empty() && ty != b'5') || (!rel.is_empty() && !archive_rel_ok(rel)) {
            break -EINVAL;
        }
        if strsprintf(&mut path, &[dest, b"/", rel]).is_err() {
            break -ENAMETOOLONG;
        }
        let ret = match ty {
            b'5' => make_dir(gz, &path, size, &mut buf),
            b'0' => write_file(gz, &path, size, &mut buf),
            _ => -EPERM,
        };
        if ret != 0 {
            break ret;
        }
        if !skip(gz, padding(size), &mut buf) {
            break -EINVAL;
        }
    };
    (ret, root_len != 0)
}

/// A directory member at `path`, its data read as the other walkers do,
/// whatever a directory carries.
fn make_dir(gz: &mut Gz, path: &[u8; PATH_MAX], size: u64, buf: &mut [u8]) -> c_int {
    // SAFETY: strsprintf() terminated path.
    let ret = unsafe { seal_mkdir_p(path.as_ptr().cast(), 0o700) };
    if ret != 0 {
        return ret;
    }
    if !skip(gz, size, buf) {
        return -EIO;
    }
    0
}

/// A regular member at `path`, under the directories it needs.
fn write_file(gz: &mut Gz, path: &[u8; PATH_MAX], size: u64, buf: &mut [u8]) -> c_int {
    let file = cstr(path);

    if let Some(slash) = file.iter().rposition(|&c| c == b'/') {
        let mut parent = [0u8; PATH_MAX];

        parent[..slash].copy_from_slice(&file[..slash]);
        // SAFETY: parent is terminated within its room.
        let ret = unsafe { seal_mkdir_p(parent.as_ptr().cast(), 0o700) };
        if ret != 0 {
            return ret;
        }
    }
    // SAFETY: strsprintf() terminated path.
    let fd = unsafe { seal_open(path.as_ptr().cast(), O_WRONLY | O_CREAT | O_EXCL, 0o644) };
    if fd < 0 {
        return fd;
    }
    let mut ret = 0;
    let mut remain = size;
    while remain != 0 {
        let want = remain.min(CHUNK as u64) as usize;
        let n = gz.read(&mut buf[..want]);

        // SAFETY: n bytes gzread() wrote at buf, to the fd seal_open()
        // gave.
        if n <= 0 || unsafe { write_complete(fd, buf.as_ptr().cast(), n as usize) } != 0 {
            ret = -EIO;
            break;
        }
        remain -= n as u64;
    }
    // SAFETY: the fd seal_open() gave, closed once, here.
    unsafe {
        if ret == 0 && fchmod(fd, 0o644) != 0 {
            ret = -errno();
        }
        close(fd);
    }
    ret
}
