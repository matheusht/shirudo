// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C library, as the C code of the tree calls it.

use core::ffi::{CStr, c_char, c_int, c_void};

pub const AT_FDCWD: c_int = -100;
pub const SEEK_SET: c_int = 0;
pub const STATX_TYPE: u32 = 0x1;
pub const STATX_SIZE: u32 = 0x200;
pub const S_IFMT: u16 = 0o170000;
pub const S_IFREG: u16 = 0o100000;

/// `struct statx`, which unlike `struct stat` has one layout on every
/// architecture: the fields read here, and the rest of its 256 bytes.
#[repr(C)]
pub struct Statx {
    pub mask: u32,
    pub blksize: u32,
    pub attributes: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    spare0: u16,
    pub ino: u64,
    pub size: u64,
    rest: [u64; 26],
}

const _: () = assert!(size_of::<Statx>() == 256);

impl Statx {
    pub const fn zeroed() -> Self {
        Statx {
            mask: 0,
            blksize: 0,
            attributes: 0,
            nlink: 0,
            uid: 0,
            gid: 0,
            mode: 0,
            spare0: 0,
            ino: 0,
            size: 0,
            rest: [0; 26],
        }
    }
}

unsafe extern "C" {
    pub fn calloc(nmemb: usize, size: usize) -> *mut c_void;
    pub fn posix_memalign(memptr: *mut *mut c_void, alignment: usize, size: usize) -> c_int;
    pub fn free(ptr: *mut c_void);
    pub fn explicit_bzero(s: *mut c_void, n: usize);
    pub fn abort() -> !;
    pub fn getenv(name: *const c_char) -> *mut c_char;
    pub fn statx(
        dirfd: c_int,
        path: *const c_char,
        flags: c_int,
        mask: u32,
        buf: *mut Statx,
    ) -> c_int;
    pub fn ftruncate(fd: c_int, length: i64) -> c_int;
    pub fn lseek(fd: c_int, offset: i64, whence: c_int) -> i64;
    fn __errno_location() -> *mut c_int;
}

/// The errno of the last failed call.
pub fn errno() -> c_int {
    // SAFETY: glibc gives each thread its errno, valid while it runs.
    unsafe { *__errno_location() }
}

/// The value of the environment variable `name`, as getenv() gives it.
pub fn env(name: &CStr) -> Option<&'static CStr> {
    // SAFETY: a C string; nothing in shirudo changes the environment, so
    // what getenv() returns stays valid.
    let value = unsafe { getenv(name.as_ptr()) };

    if value.is_null() {
        return None;
    }
    // SAFETY: getenv() returns a C string.
    Some(unsafe { CStr::from_ptr(value) })
}

/// Zeroes a buffer that held a secret, in a way the compiler keeps.
pub fn scrub(buf: &mut [u8]) {
    // SAFETY: buf is buf.len() writable bytes.
    unsafe { explicit_bzero(buf.as_mut_ptr().cast(), buf.len()) };
}
