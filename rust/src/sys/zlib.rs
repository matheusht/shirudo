// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The gzip file reading of zlib, and the inflate stream of a gzip
//! member in memory.

use core::ffi::{CStr, c_char, c_int, c_uint, c_ulong, c_void};

pub const Z_OK: c_int = 0;
pub const Z_STREAM_END: c_int = 1;
pub const Z_MEM_ERROR: c_int = -4;
pub const Z_NO_FLUSH: c_int = 0;
pub const MAX_WBITS: c_int = 15;
/// The `ZLIB_VERSION` of zlib.h shirudo builds with, which
/// inflateInit2() passes and zlib checks the major version of.
pub const ZLIB_VERSION: &CStr = c"1.3.1";

/// `z_stream`.
#[repr(C)]
pub struct ZStream {
    pub next_in: *mut u8,
    pub avail_in: c_uint,
    pub total_in: c_ulong,
    pub next_out: *mut u8,
    pub avail_out: c_uint,
    pub total_out: c_ulong,
    pub msg: *mut c_char,
    state: *mut c_void,
    zalloc: *mut c_void,
    zfree: *mut c_void,
    opaque: *mut c_void,
    pub data_type: c_int,
    pub adler: c_ulong,
    reserved: c_ulong,
}

const _: () = assert!(size_of::<ZStream>() == 112);

impl ZStream {
    /// A stream with zlib's default allocator, as `= {}` is in C.
    pub const fn zeroed() -> Self {
        ZStream {
            next_in: core::ptr::null_mut(),
            avail_in: 0,
            total_in: 0,
            next_out: core::ptr::null_mut(),
            avail_out: 0,
            total_out: 0,
            msg: core::ptr::null_mut(),
            state: core::ptr::null_mut(),
            zalloc: core::ptr::null_mut(),
            zfree: core::ptr::null_mut(),
            opaque: core::ptr::null_mut(),
            data_type: 0,
            adler: 0,
            reserved: 0,
        }
    }
}

/// A `gzFile`'s `struct gzFile_s`, which only zlib looks into.
pub enum GzFileS {}

unsafe extern "C" {
    pub fn gzopen(path: *const c_char, mode: *const c_char) -> *mut GzFileS;
    pub fn gzdopen(fd: c_int, mode: *const c_char) -> *mut GzFileS;
    /// Whether the file is read as it is, not being gzip.
    pub fn gzdirect(file: *mut GzFileS) -> c_int;
    /// Up to `len` bytes into `buf`: how many, 0 at the end, -1 on error.
    pub fn gzread(file: *mut GzFileS, buf: *mut c_void, len: c_uint) -> c_int;
    /// Z_OK, or what went wrong reading the file, its trailer included.
    pub fn gzclose(file: *mut GzFileS) -> c_int;
    /// Compresses the `len` bytes at `buf` into the file: how many, 0 on
    /// error.
    pub fn gzwrite(file: *mut GzFileS, buf: *const c_void, len: c_uint) -> c_int;
    /// inflateInit2(): the macro passes the version and size of the
    /// stream it was compiled with.
    pub fn inflateInit2_(
        strm: *mut ZStream,
        window_bits: c_int,
        version: *const c_char,
        stream_size: c_int,
    ) -> c_int;
    pub fn inflate(strm: *mut ZStream, flush: c_int) -> c_int;
    pub fn inflateEnd(strm: *mut ZStream) -> c_int;
    /// deflateInit2(): the macro passes the version and size of the
    /// stream.
    pub fn deflateInit2_(
        strm: *mut ZStream,
        level: c_int,
        method: c_int,
        window_bits: c_int,
        mem_level: c_int,
        strategy: c_int,
        version: *const c_char,
        stream_size: c_int,
    ) -> c_int;
    pub fn deflate(strm: *mut ZStream, flush: c_int) -> c_int;
    pub fn deflateEnd(strm: *mut ZStream) -> c_int;
    pub fn deflateSetHeader(strm: *mut ZStream, head: *mut GzHeader) -> c_int;
    pub fn compressBound(source_len: c_ulong) -> c_ulong;
}

/// `gz_header`: the gzip header deflate() writes.
#[repr(C)]
pub struct GzHeader {
    pub text: c_int,
    pub time: c_ulong,
    pub xflags: c_int,
    pub os: c_int,
    extra: *mut u8,
    extra_len: c_uint,
    extra_max: c_uint,
    name: *mut u8,
    name_max: c_uint,
    comment: *mut u8,
    comm_max: c_uint,
    hcrc: c_int,
    done: c_int,
}

const _: () = assert!(size_of::<GzHeader>() == 80);

impl GzHeader {
    /// No name, comment or extra field, as `= {}` is in C.
    pub const fn zeroed() -> Self {
        GzHeader {
            text: 0,
            time: 0,
            xflags: 0,
            os: 0,
            extra: core::ptr::null_mut(),
            extra_len: 0,
            extra_max: 0,
            name: core::ptr::null_mut(),
            name_max: 0,
            comment: core::ptr::null_mut(),
            comm_max: 0,
            hcrc: 0,
            done: 0,
        }
    }
}
