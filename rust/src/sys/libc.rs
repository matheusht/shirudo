// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C library, as the C code of the tree calls it.

use core::ffi::{CStr, c_char, c_int, c_void};

pub const PATH_MAX: usize = 4096;
pub const AT_FDCWD: c_int = -100;
pub const F_DUPFD_CLOEXEC: c_int = 1030;
pub const SEEK_SET: c_int = 0;
pub const STDOUT_FILENO: c_int = 1;

/// A `va_list` a C caller hands on, as x86_64 and aarch64 pass one in an
/// argument: a pointer, to the array x86_64 makes it or to the copy of
/// its struct aarch64 makes. Rust takes it and passes it on alone.
pub type VaList = *mut c_void;
pub const F_OK: c_int = 0;
pub const R_OK: c_int = 4;
pub const W_OK: c_int = 2;
pub const X_OK: c_int = 1;
pub const O_RDONLY: c_int = 0;
pub const O_WRONLY: c_int = 0o1;
pub const O_RDWR: c_int = 0o2;
pub const O_CREAT: c_int = 0o100;
pub const O_EXCL: c_int = 0o200;
pub const O_TRUNC: c_int = 0o1000;
pub const O_APPEND: c_int = 0o2000;
pub const O_NONBLOCK: c_int = 0o4000;
pub const O_CLOEXEC: c_int = 0o2000000;
#[cfg(target_arch = "x86_64")]
pub const O_NOFOLLOW: c_int = 0o400000;
#[cfg(target_arch = "aarch64")]
pub const O_NOFOLLOW: c_int = 0o100000;
/// The add_key(2) and keyctl(2) system calls, which the C library does not
/// wrap.
#[cfg(target_arch = "x86_64")]
pub const SYS_ADD_KEY: core::ffi::c_long = 248;
#[cfg(target_arch = "x86_64")]
pub const SYS_KEYCTL: core::ffi::c_long = 250;
#[cfg(target_arch = "aarch64")]
pub const SYS_ADD_KEY: core::ffi::c_long = 217;
#[cfg(target_arch = "aarch64")]
pub const SYS_KEYCTL: core::ffi::c_long = 219;
#[cfg(target_arch = "x86_64")]
pub const O_DIRECTORY: c_int = 0o200000;
#[cfg(target_arch = "x86_64")]
pub const O_DIRECT: c_int = 0o40000;
#[cfg(target_arch = "aarch64")]
pub const O_DIRECT: c_int = 0o200000;
#[cfg(target_arch = "aarch64")]
pub const O_DIRECTORY: c_int = 0o40000;
pub const AT_EMPTY_PATH: c_int = 0x1000;
pub const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
pub const F_GETFD: c_int = 1;
/// setvbuf()'s full buffering, and the size of a stdio buffer.
pub const IOFBF: c_int = 0;
pub const BUFSIZ: usize = 8192;
pub const STATX_TYPE: u32 = 0x1;
pub const STATX_SIZE: u32 = 0x200;
pub const STATX_BASIC_STATS: u32 = 0x7ff;
/// `STATX_ATTR_MOUNT_ROOT`: the file is the root of a mount.
pub const STATX_ATTR_MOUNT_ROOT: u64 = 0x2000;
pub const O_PATH: c_int = 0o10000000;
pub const S_ISVTX: u16 = 0o1000;
pub const S_IFMT: u16 = 0o170000;
pub const S_IFREG: u16 = 0o100000;
pub const S_IFDIR: u16 = 0o040000;
pub const S_IFCHR: u16 = 0o020000;
pub const S_IFBLK: u16 = 0o060000;
pub const PR_SET_DUMPABLE: c_int = 4;
pub const PR_SET_NO_NEW_PRIVS: c_int = 38;
/// Yama's PR_SET_PTRACER, "Yama" in ASCII.
pub const PR_SET_PTRACER: c_int = 0x59616d61;
pub const RLIMIT_CORE: c_int = 4;
pub const MCL_CURRENT: c_int = 1;
pub const MCL_FUTURE: c_int = 2;
pub const SC_NPROCESSORS_ONLN: c_int = 84;
pub const LOCK_EX: c_int = 2;
pub const LOCK_UN: c_int = 8;
pub const LOCK_NB: c_int = 4;

/// A stdio `FILE`.
pub enum File {}

/// `struct statfs` of the 64-bit ABIs: its type, and the rest of its
/// 120 bytes.
#[repr(C)]
pub struct Statfs {
    pub f_type: i64,
    rest: [i64; 14],
}

const _: () = assert!(size_of::<Statfs>() == 120);

impl Statfs {
    pub const fn zeroed() -> Self {
        Statfs {
            f_type: 0,
            rest: [0; 14],
        }
    }
}

/// What fgetc() returns at the end or on an error.
pub const EOF: c_int = -1;

/// `struct timespec` of the 64-bit ABIs.
#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// A `DIR` stream.
pub enum Dir {}

/// `struct dirent` of the 64-bit ABIs, as readdir() gives it.
#[repr(C)]
pub struct Dirent {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
    pub d_name: [c_char; 256],
}

const _: () = assert!(core::mem::offset_of!(Dirent, d_name) == 19);

/// `struct utsname`: the fields read here, and the rest as the C library
/// lays them out.
#[repr(C)]
pub struct Utsname {
    sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    domainname: [u8; 65],
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

/// `struct statvfs` of the 64-bit ABIs: the fields read here, and the rest
/// as the C library lays them out.
#[repr(C)]
pub struct Statvfs {
    f_bsize: core::ffi::c_ulong,
    pub f_frsize: core::ffi::c_ulong,
    pub f_blocks: u64,
    pub f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_favail: u64,
    f_fsid: core::ffi::c_ulong,
    f_flag: core::ffi::c_ulong,
    f_namemax: core::ffi::c_ulong,
    f_spare: [c_int; 6],
}

const _: () = assert!(size_of::<Statvfs>() == 112);

impl Statvfs {
    pub const fn zeroed() -> Self {
        Statvfs {
            f_bsize: 0,
            f_frsize: 0,
            f_blocks: 0,
            f_bfree: 0,
            f_bavail: 0,
            f_files: 0,
            f_ffree: 0,
            f_favail: 0,
            f_fsid: 0,
            f_flag: 0,
            f_namemax: 0,
            f_spare: [0; 6],
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
    blocks: u64,
    pub attributes_mask: u64,
    times: [u64; 8],
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub dev_major: u32,
    pub dev_minor: u32,
    rest: [u64; 14],
}

const _: () = assert!(size_of::<Statx>() == 256);
const _: () = assert!(core::mem::offset_of!(Statx, dev_major) == 136);

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
            blocks: 0,
            attributes_mask: 0,
            times: [0; 8],
            rdev_major: 0,
            rdev_minor: 0,
            dev_major: 0,
            dev_minor: 0,
            rest: [0; 14],
        }
    }
}

/// The filter of scandir(), which keeps the entries it is not 0 for.
pub type DirentFilter = unsafe extern "C" fn(e: *const Dirent) -> c_int;
/// The order of scandir(), alphasort() for one.
pub type DirentCompare =
    unsafe extern "C" fn(a: *mut *const Dirent, b: *mut *const Dirent) -> c_int;

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
    pub fn setenv(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int;
    pub fn unsetenv(name: *const c_char) -> c_int;
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
    pub fn openat(dirfd: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
    pub fn flock(fd: c_int, op: c_int) -> c_int;
    pub fn fsync(fd: c_int) -> c_int;
    pub fn fstatfs(fd: c_int, buf: *mut Statfs) -> c_int;
    pub fn realpath(path: *const c_char, resolved: *mut c_char) -> *mut c_char;
    pub fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    pub fn nanosleep(req: *const Timespec, rem: *mut Timespec) -> c_int;
    pub fn renameat(
        olddirfd: c_int,
        oldpath: *const c_char,
        newdirfd: c_int,
        newpath: *const c_char,
    ) -> c_int;
    pub fn unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int;
    pub fn fdopendir(fd: c_int) -> *mut Dir;
    pub fn opendir(name: *const c_char) -> *mut Dir;
    pub fn mkstemp(template: *mut c_char) -> c_int;
    pub fn readdir(dir: *mut Dir) -> *mut Dirent;
    /// The entries of `dir` the filter takes, sorted by `compar`, in an
    /// array of allocations free() takes: how many, or -1.
    pub fn scandir(
        dir: *const c_char,
        namelist: *mut *mut *mut Dirent,
        filter: Option<DirentFilter>,
        compar: Option<DirentCompare>,
    ) -> c_int;
    pub fn scandirat(
        dirfd: c_int,
        dir: *const c_char,
        namelist: *mut *mut *mut Dirent,
        filter: Option<DirentFilter>,
        compar: Option<DirentCompare>,
    ) -> c_int;
    pub fn alphasort(a: *mut *const Dirent, b: *mut *const Dirent) -> c_int;
    pub fn closedir(dir: *mut Dir) -> c_int;
    pub fn getline(line: *mut *mut c_char, cap: *mut usize, f: *mut File) -> isize;
    pub fn syscall(num: core::ffi::c_long, ...) -> core::ffi::c_long;
    pub fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    pub fn pread(fd: c_int, buf: *mut c_void, count: usize, offset: i64) -> isize;
    pub fn unlink(path: *const c_char) -> c_int;
    pub fn link(from: *const c_char, to: *const c_char) -> c_int;
    pub fn rename(from: *const c_char, to: *const c_char) -> c_int;
    pub fn rmdir(path: *const c_char) -> c_int;
    pub fn mkdtemp(template: *mut c_char) -> *mut c_char;
    pub fn ioctl(fd: c_int, request: core::ffi::c_ulong, ...) -> c_int;
    pub fn mknod(path: *const c_char, mode: u32, dev: u64) -> c_int;
    pub fn mount(
        source: *const c_char,
        target: *const c_char,
        fstype: *const c_char,
        flags: core::ffi::c_ulong,
        data: *const c_void,
    ) -> c_int;
    pub fn umount2(target: *const c_char, flags: c_int) -> c_int;
    pub fn access(path: *const c_char, mode: c_int) -> c_int;
    pub fn execv(path: *const c_char, argv: *const *const c_char) -> c_int;
    pub fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int;
    pub fn geteuid() -> u32;
    pub fn faccessat(dirfd: c_int, path: *const c_char, mode: c_int, flags: c_int) -> c_int;
    pub fn time(t: *mut i64) -> i64;
    pub fn strerror(errnum: c_int) -> *const c_char;
    /// The name of an errno number, "ENOENT", or NULL for one it does not
    /// know.
    pub fn strerrorname_np(errnum: c_int) -> *const c_char;
    pub fn uname(buf: *mut Utsname) -> c_int;
    pub fn gethostname(name: *mut c_char, len: usize) -> c_int;
    pub fn sysconf(name: c_int) -> core::ffi::c_long;
    pub fn statvfs(path: *const c_char, buf: *mut Statvfs) -> c_int;
    pub fn fgets(s: *mut c_char, n: c_int, f: *mut File) -> *mut c_char;
    pub fn sscanf(s: *const c_char, fmt: *const c_char, ...) -> c_int;
    pub fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
    pub fn strlen(s: *const c_char) -> usize;
    pub fn strnlen(s: *const c_char, max: usize) -> usize;
    pub fn getxattr(
        path: *const c_char,
        name: *const c_char,
        value: *mut c_void,
        size: usize,
    ) -> isize;
    pub fn fsetxattr(
        fd: c_int,
        name: *const c_char,
        value: *const c_void,
        size: usize,
        flags: c_int,
    ) -> c_int;
    pub fn strcasecmp(a: *const c_char, b: *const c_char) -> c_int;
    pub fn strncasecmp(a: *const c_char, b: *const c_char, n: usize) -> c_int;
    pub fn qsort(
        base: *mut c_void,
        n: usize,
        size: usize,
        cmp: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>,
    );
    pub fn fopen(path: *const c_char, mode: *const c_char) -> *mut File;
    pub fn fdopen(fd: c_int, mode: *const c_char) -> *mut File;
    pub fn setvbuf(f: *mut File, buf: *mut c_char, mode: c_int, size: usize) -> c_int;
    pub fn ferror(f: *mut File) -> c_int;
    pub fn fgetc(f: *mut File) -> c_int;
    pub fn ftello(f: *mut File) -> i64;
    pub fn fclose(f: *mut File) -> c_int;
    pub fn fileno(f: *mut File) -> c_int;
    pub fn fputs(s: *const c_char, f: *mut File) -> c_int;
    pub fn fputc(c: c_int, f: *mut File) -> c_int;
    pub fn fwrite(ptr: *const c_void, size: usize, n: usize, f: *mut File) -> usize;
    pub fn fprintf(f: *mut File, fmt: *const c_char, ...) -> c_int;
    pub fn printf(fmt: *const c_char, ...) -> c_int;
    pub fn vfprintf(f: *mut File, fmt: *const c_char, args: VaList) -> c_int;
    pub fn putchar(c: c_int) -> c_int;
    /// The C library's standard output stream.
    pub static mut stdout: *mut File;
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

/// Sets errno, as a caller that tells an end from a failure by it does.
pub fn set_errno(e: c_int) {
    // SAFETY: glibc gives each thread its errno, valid while it runs.
    unsafe { *__errno_location() = e };
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
