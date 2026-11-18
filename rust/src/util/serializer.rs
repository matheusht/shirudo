// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The user side of the map serializer, behind `util/serializer.h`: the
//! lock that keeps one reader on a map, the ID of a read, and the check
//! of each chunk the BPF side hands back.

use core::ffi::{CStr, c_char, c_int};

use crate::errno::{EAGAIN, EBADMSG, EBUSY, EINTR, EINVAL, EIO, ENAMETOOLONG};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    AT_EMPTY_PATH, LOCK_EX, LOCK_NB, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_NOFOLLOW, O_RDONLY, O_RDWR,
    S_IFMT, S_IFREG, STATX_TYPE, Statx, close, errno, flock, getrandom, open, openat, statx,
};
use crate::text::{decimal, strsprintf};
use crate::util::seal::{seal_inherit, seal_mkdir_p};

/// `SERIAL_MAGIC`, "SRLZ" little-endian, and `SERIAL_VERSION` of
/// bpf/lib/serializer.h.
pub(crate) const SERIAL_MAGIC: u32 = 0x5a4c_5253;
pub(crate) const SERIAL_VERSION: u32 = 1;
/// `SERIAL_CHUNK_PAYLOAD`: the bytes of a chunk after its header.
pub(crate) const SERIAL_CHUNK_PAYLOAD: u32 = 4032;

/// LOCKS_DIR of util/paths.h.
const LOCKS_DIR: &CStr = c"/var/lib/shirudo/locks";

/// `struct serial_chunk` of bpf/lib/serializer.h, which the BPF side
/// writes.
#[repr(C)]
pub struct SerialChunk {
    pub(crate) magic: u32,
    pub(crate) version: u32,
    pub(crate) flags: u32,
    pub(crate) status: c_int,
    pub(crate) chunk_index: u32,
    pub(crate) total_chunks: u32,
    pub(crate) bytes_total: u32,
    pub(crate) bytes_in_chunk: u32,
    pub(crate) page_index: u32,
    pub(crate) reserved: u32,
    pub(crate) cursor: u64,
    pub(crate) next_cursor: u64,
    pub(crate) invocation_id: u64,
    pub(crate) data: [u8; SERIAL_CHUNK_PAYLOAD as usize],
}

const _: () = assert!(size_of::<SerialChunk>() == 4096);

/// The lock of map `map_id` in `dir`, created sealed when it is not
/// there and held exclusively until the fd returned is closed; -EBUSY
/// when another holds it, or another -errno.
pub(crate) fn lock_acquire_at(dir: &CStr, map_id: u32) -> c_int {
    let mut name = [0u8; 64];
    let mut id = [0u8; 20];

    if dir.is_empty() || map_id == 0 {
        return -EINVAL;
    }
    // SAFETY: a C string and a mode.
    let ret = unsafe { seal_mkdir_p(dir.as_ptr(), 0o700) };
    if ret != 0 {
        return ret;
    }
    // SAFETY: a C string and flags without a mode.
    let dir_fd = unsafe {
        open(
            dir.as_ptr(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW,
        )
    };
    if dir_fd < 0 {
        return -errno();
    }
    if strsprintf(
        &mut name,
        &[
            b"serializer-map-",
            decimal(u64::from(map_id), &mut id),
            b".lock",
        ],
    )
    .is_err()
    {
        // SAFETY: the fd open() gave, closed once.
        unsafe { close(dir_fd) };
        return -ENAMETOOLONG;
    }
    // SAFETY: the directory's fd, the name just written, flags and a
    // mode.
    let fd = unsafe {
        openat(
            dir_fd,
            name.as_ptr().cast::<c_char>(),
            O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW,
            0o600 as core::ffi::c_uint,
        )
    };
    if fd < 0 {
        let ret = -errno();

        // SAFETY: the fd open() gave, closed once.
        unsafe { close(dir_fd) };
        return ret;
    }
    // SAFETY: the two fds, the directory's closed once, here.
    let ret = unsafe {
        let ret = seal_inherit(dir_fd, fd);

        close(dir_fd);
        ret
    };
    if ret != 0 {
        // SAFETY: the fd openat() gave, closed once.
        unsafe { close(fd) };
        return ret;
    }
    let mut st = Statx::zeroed();
    // SAFETY: the fd, an empty path, and a struct statx to fill.
    if unsafe { statx(fd, c"".as_ptr(), AT_EMPTY_PATH, STATX_TYPE, &mut st) } != 0 {
        let ret = -errno();

        // SAFETY: the fd openat() gave, closed once.
        unsafe { close(fd) };
        return ret;
    }
    if st.stx_mode & S_IFMT != S_IFREG {
        // SAFETY: the fd openat() gave, closed once.
        unsafe { close(fd) };
        return -EINVAL;
    }
    // The open fd owns the lock; callers release it with close().
    // SAFETY: the fd openat() gave, and flags.
    if unsafe { flock(fd, LOCK_EX | LOCK_NB) } != 0 {
        let e = errno();
        let ret = if e == EAGAIN { -EBUSY } else { -e };

        // SAFETY: the fd openat() gave, closed once.
        unsafe { close(fd) };
        return ret;
    }
    fd
}

/// A random ID for one read of a map, never 0.
pub(crate) fn new_invocation_id(out: &mut u64) -> c_int {
    let mut id = [0u8; 8];

    loop {
        let mut off = 0;

        while off < id.len() {
            // SAFETY: the room left in id.
            let n = unsafe { getrandom(id[off..].as_mut_ptr().cast(), id.len() - off, 0) };

            if n < 0 {
                if errno() == EINTR {
                    continue;
                }
                return -errno();
            }
            if n == 0 {
                return -EIO;
            }
            off += n as usize;
        }
        if id != [0; 8] {
            break;
        }
    }
    *out = u64::from_ne_bytes(id);
    0
}

/// Whether the chunk is the one asked for, of this read: 0, -EINVAL or
/// -EBADMSG.
pub(crate) fn chunk_validate(
    c: Option<&SerialChunk>,
    want_index: u32,
    total_chunks: u32,
    page_index: u32,
    cursor: u64,
    next_cursor: u64,
    invocation_id: u64,
) -> c_int {
    let Some(c) = c.filter(|_| invocation_id != 0) else {
        return -EINVAL;
    };

    if c.magic != SERIAL_MAGIC
        || c.version != SERIAL_VERSION
        || c.chunk_index != want_index
        || c.total_chunks != total_chunks
        || c.bytes_in_chunk > SERIAL_CHUNK_PAYLOAD
        || c.page_index != page_index
        || c.cursor != cursor
        || c.next_cursor != next_cursor
        || c.invocation_id != invocation_id
    {
        return -EBADMSG;
    }
    0
}

pub(crate) use capi::serializer_lock_acquire;

mod capi {
    use core::ffi::{CStr, c_char, c_int};

    use super::SerialChunk;
    use crate::errno::EINVAL;

    /// # Safety
    ///
    /// `dir` is NULL or a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn serializer_lock_acquire_at(dir: *const c_char, map_id: u32) -> c_int {
        if dir.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller passes a C string.
        super::lock_acquire_at(unsafe { CStr::from_ptr(dir) }, map_id)
    }

    pub extern "C" fn serializer_lock_acquire(map_id: u32) -> c_int {
        super::lock_acquire_at(super::LOCKS_DIR, map_id)
    }

    /// # Safety
    ///
    /// `out` is NULL or points to a u64.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn serializer_new_invocation_id(out: *mut u64) -> c_int {
        if out.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller passes a u64.
        super::new_invocation_id(unsafe { &mut *out })
    }

    /// # Safety
    ///
    /// `c` is NULL or points to a chunk.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn serial_chunk_validate(
        c: *const SerialChunk,
        want_index: u32,
        total_chunks: u32,
        page_index: u32,
        cursor: u64,
        next_cursor: u64,
        invocation_id: u64,
    ) -> c_int {
        // SAFETY: the caller passes NULL or a chunk.
        let c = unsafe { c.as_ref() };

        super::chunk_validate(
            c,
            want_index,
            total_chunks,
            page_index,
            cursor,
            next_cursor,
            invocation_id,
        )
    }
}
