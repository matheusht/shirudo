// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C library, as the C code of the tree calls it.

use core::ffi::{CStr, c_char, c_int, c_void};

pub const PATH_MAX: usize = 4096;
pub const AT_FDCWD: c_int = -100;
pub const F_DUPFD_CLOEXEC: c_int = 1030;
pub const SEEK_SET: c_int = 0;
pub const F_OK: c_int = 0;
pub const O_RDONLY: c_int = 0;
pub const O_WRONLY: c_int = 0o1;
pub const O_RDWR: c_int = 0o2;
pub const O_CREAT: c_int = 0o100;
pub const O_EXCL: c_int = 0o200;
pub const O_NONBLOCK: c_int = 0o4000;
pub const O_CLOEXEC: c_int = 0o2000000;
#[cfg(target_arch = "x86_64")]
pub const O_NOFOLLOW: c_int = 0o400000;
#[cfg(target_arch = "aarch64")]
pub const O_NOFOLLOW: c_int = 0o100000;
pub const AT_EMPTY_PATH: c_int = 0x1000;
pub const F_GETFD: c_int = 1;
/// setvbuf()'s full buffering, and the size of a stdio buffer.
pub const IOFBF: c_int = 0;
pub const BUFSIZ: usize = 8192;
pub const STATX_TYPE: u32 = 0x1;
pub const STATX_SIZE: u32 = 0x200;
pub const S_IFMT: u16 = 0o170000;
pub const S_IFREG: u16 = 0o100000;
pub const PR_SET_DUMPABLE: c_int = 4;
pub const PR_SET_NO_NEW_PRIVS: c_int = 38;
/// Yama's PR_SET_PTRACER, "Yama" in ASCII.
pub const PR_SET_PTRACER: c_int = 0x59616d61;
pub const RLIMIT_CORE: c_int = 4;
pub const MCL_CURRENT: c_int = 1;
pub const MCL_FUTURE: c_int = 2;

/// A stdio `FILE`.
pub enum File {}

/// `struct utsname`: the fields read here, and the rest as the C library
/// lays them out.
#[repr(C)]
pub struct Utsname {
    sysname: [c_char; 65],
    nodename: [c_char; 65],
    pub release: [c_char; 65],
    version: [c_char; 65],
    machine: [c_char; 65],
    domainname: [c_char; 65],
}

const _: () = assert!(size_of::<Utsname>() == 390);

impl Utsname {
    pub const fn zeroed() -> Self {
        Utsname {
            sysname: [0; 65],
            nodename: [0; 65],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
            domainname: [0; 65],
        }
    }
}

/// `struct rlimit`.
#[repr(C)]
pub struct Rlimit {
    pub cur: u64,
    pub max: u64,
}

/// glibc's `struct tm`.
#[repr(C)]
pub struct Tm {
    fields: [c_int; 9],
    gmtoff: core::ffi::c_long,
    zone: *const c_char,
}

const _: () = assert!(size_of::<Tm>() == 56);

impl Tm {
    pub const fn zeroed() -> Self {
        Tm {
            fields: [0; 9],
            gmtoff: 0,
            zone: core::ptr::null(),
        }
    }
}

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
    pub fn _exit(status: c_int) -> !;
    pub fn prctl(option: c_int, ...) -> c_int;
    pub fn setrlimit(resource: c_int, rlim: *const Rlimit) -> c_int;
    pub fn mlockall(flags: c_int) -> c_int;
    pub fn getrandom(buf: *mut c_void, len: usize, flags: u32) -> isize;
    pub fn __nss_configure_lookup(db: *const c_char, service: *const c_char) -> c_int;
    pub fn getenv(name: *const c_char) -> *mut c_char;
    pub fn statx(
        dirfd: c_int,
        path: *const c_char,
        flags: c_int,
        mask: u32,
        buf: *mut Statx,
    ) -> c_int;
    pub fn ftruncate(fd: c_int, length: i64) -> c_int;
    pub fn fchmod(fd: c_int, mode: u32) -> c_int;
    pub fn close(fd: c_int) -> c_int;
    pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    pub fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    pub fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    pub fn pread(fd: c_int, buf: *mut c_void, count: usize, offset: i64) -> isize;
    pub fn unlink(path: *const c_char) -> c_int;
    pub fn access(path: *const c_char, mode: c_int) -> c_int;
    pub fn time(t: *mut i64) -> i64;
    pub fn strerror(errnum: c_int) -> *const c_char;
    /// The name of an errno number, "ENOENT", or NULL for one it does not
    /// know.
    pub fn strerrorname_np(errnum: c_int) -> *const c_char;
    pub fn uname(buf: *mut Utsname) -> c_int;
    pub fn fopen(path: *const c_char, mode: *const c_char) -> *mut File;
    pub fn fdopen(fd: c_int, mode: *const c_char) -> *mut File;
    pub fn setvbuf(f: *mut File, buf: *mut c_char, mode: c_int, size: usize) -> c_int;
    pub fn ferror(f: *mut File) -> c_int;
    pub fn fclose(f: *mut File) -> c_int;
    pub fn fileno(f: *mut File) -> c_int;
    pub fn fputs(s: *const c_char, f: *mut File) -> c_int;
    pub fn fputc(c: c_int, f: *mut File) -> c_int;
    pub fn fwrite(ptr: *const c_void, size: usize, n: usize, f: *mut File) -> usize;
    pub fn fprintf(f: *mut File, fmt: *const c_char, ...) -> c_int;
    pub fn printf(fmt: *const c_char, ...) -> c_int;
    /// The C library's standard error stream, unbuffered.
    pub static mut stderr: *mut File;
    pub fn snprintf(buf: *mut c_char, size: usize, fmt: *const c_char, ...) -> c_int;
    pub fn gmtime_r(t: *const i64, tm: *mut Tm) -> *mut Tm;
    pub fn strftime(out: *mut c_char, max: usize, fmt: *const c_char, tm: *const Tm) -> usize;
    pub fn strptime(s: *const c_char, fmt: *const c_char, tm: *mut Tm) -> *mut c_char;
    pub fn timegm(tm: *mut Tm) -> i64;
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
