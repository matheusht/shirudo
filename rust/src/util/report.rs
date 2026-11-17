// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The JSON report of `upatch load` and `unload --report`, behind
//! `util/report.h`: what the operation did, the phase it stopped at and
//! why, and the verifier's log verbatim.

use core::ffi::{CStr, c_char, c_int};

use crate::errno::{E2BIG, ENOMEM};
use crate::sys::libc::{Utsname, printf, strerror, strerrorname_np, uname};
use crate::sys::log::pr_err;
use crate::sys::malloc::{xfree, xmalloc, xstrfree, xstrndup};
use crate::text::{cstr, strsprintf};
use crate::util::eventlog::NV_INDEX;
use crate::util::json::JsonEmit;
use crate::util::seal::{SealOutput, seal_output_commit, seal_output_create};

/// `VERIFIER_LOG_MAX`: the most of a verifier log a report keeps.
const VERIFIER_LOG_MAX: usize = 16 * 1024 * 1024;

/// `struct op_report`.
#[repr(C)]
pub struct OpReport {
    pub(crate) ok: bool,
    pub(crate) op: *const c_char,
    pub(crate) phase: *const c_char,
    pub(crate) err: c_int,
    pub(crate) category: *const c_char,
    pub(crate) message: [c_char; 256],
    pub(crate) verifier_log: *mut c_char,
    pub(crate) loader_return: c_int,
    pub(crate) path: *const c_char,
    pub(crate) name: *const c_char,
    pub(crate) payload_hex: [c_char; 65],
    pub(crate) tpm_present: bool,
    pub(crate) chain_after: [c_char; 65],
}

const _: () = assert!(size_of::<OpReport>() == 464);
const _: () = assert!(core::mem::offset_of!(OpReport, verifier_log) == 296);
const _: () = assert!(core::mem::offset_of!(OpReport, path) == 312);
const _: () = assert!(core::mem::offset_of!(OpReport, chain_after) == 394);

impl OpReport {
    /// A report of operation `op`, done until a failure says otherwise.
    pub(crate) fn new(op: &'static CStr) -> Self {
        OpReport {
            ok: false,
            op: op.as_ptr(),
            phase: c"done".as_ptr(),
            err: 0,
            category: core::ptr::null(),
            message: [0; 256],
            verifier_log: core::ptr::null_mut(),
            loader_return: 0,
            path: core::ptr::null(),
            name: core::ptr::null(),
            payload_hex: [0; 65],
            tpm_present: false,
            chain_after: [0; 65],
        }
    }
}

/// The string of a nullable C string field, or `default` for NULL.
///
/// # Safety
///
/// `s` is NULL or a C string.
unsafe fn or(s: *const c_char, default: &[u8]) -> &[u8] {
    if s.is_null() {
        return default;
    }
    // SAFETY: the caller passes a C string.
    unsafe { CStr::from_ptr(s) }.to_bytes()
}

/// The string in a fixed array, up to its NUL.
fn in_array(a: &[c_char]) -> &[u8] {
    // SAFETY: c_char and u8 have one size and alignment.
    let bytes = unsafe { core::slice::from_raw_parts(a.as_ptr().cast::<u8>(), a.len()) };

    &bytes[..bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len())]
}

/// The report into `e`.
///
/// # Safety
///
/// The strings of `r` are NULL or C strings.
unsafe fn encode(e: &mut JsonEmit, r: &OpReport, vlog: &[u8], nv_index: &[u8]) {
    // SAFETY: errno numbers alone.
    let errname = (r.err != 0)
        .then(|| unsafe { strerrorname_np(r.err) })
        .filter(|p| !p.is_null());
    let mut uts = Utsname::zeroed();

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"result", if r.ok { b"ok" } else { b"failed" });
    // SAFETY: the caller passes C strings or NULL.
    unsafe {
        e.kv_string(b"op", or(r.op, b""));
        e.kv_string(b"phase", or(r.phase, b"done"));
    }
    if r.err != 0 {
        e.kv_int(b"errno", i64::from(r.err));
    } else {
        e.kv_null(b"errno");
    }
    match errname {
        // SAFETY: strerrorname_np() gives a C string.
        Some(name) => e.kv_string(b"errno_name", unsafe { CStr::from_ptr(name) }.to_bytes()),
        None => e.kv_null(b"errno_name"),
    }
    let category: &[u8] = if r.ok { b"ok" } else { b"unknown" };
    // SAFETY: the caller passes a C string or NULL.
    e.kv_string(b"category", unsafe { or(r.category, category) });
    e.kv_string(b"message", in_array(&r.message));
    e.kv_string(b"verifier_log", vlog);
    e.kv_int(b"loader_return", i64::from(r.loader_return));

    e.obj_open_key(b"upatch");
    // SAFETY: the caller passes C strings or NULL.
    unsafe {
        e.kv_string(b"path", or(r.path, b""));
        e.kv_string(b"name", or(r.name, b""));
    }
    e.kv_string(b"payload_sha256", in_array(&r.payload_hex));
    e.obj_close();

    e.obj_open_key(b"kernel");
    // SAFETY: a struct utsname to fill.
    let release = if unsafe { uname(&mut uts) } == 0 {
        cstr(&uts.release)
    } else {
        b""
    };
    e.kv_string(b"release", release);
    e.obj_close();

    if r.ok && r.tpm_present {
        e.obj_open_key(b"tpm");
        e.kv_string(b"nv_index", nv_index);
        e.kv_string(b"chain_after", in_array(&r.chain_after));
        e.obj_close();
    } else {
        e.kv_null(b"tpm");
    }
    e.obj_close();
}

/// Writes the report to `path`, sealed, or to stdout for `-`: 0 or
/// -errno, with the reason reported.
///
/// # Safety
///
/// `path` is a C string, and the strings of `r` are NULL or C strings.
pub(crate) unsafe fn report_emit(path: *const c_char, r: &OpReport) -> c_int {
    // SAFETY: the caller passes a C string or NULL.
    let vlog = unsafe { or(r.verifier_log, b"") };
    // The worst case of escaping, and slack for the rest.
    let cap = vlog.len() * 6 + 16384;
    let mut nv_index = [0u8; 16];
    let mut hex = [0u8; 8];

    for (i, d) in hex.iter_mut().enumerate() {
        *d = b"0123456789ABCDEF"[((NV_INDEX >> (28 - 4 * i)) & 0xf) as usize];
    }
    let Ok(n) = strsprintf(&mut nv_index, &[b"0x", &hex]) else {
        return -E2BIG;
    };
    // SAFETY: a size alone.
    let buf: *mut c_char = unsafe { xmalloc(cap) }.cast();

    if buf.is_null() {
        return -ENOMEM;
    }
    let mut e = JsonEmit::fixed(buf, cap);

    // SAFETY: the caller passes the strings.
    unsafe { encode(&mut e, r, vlog, &nv_index[..n]) };
    let mut ret = e.err();
    // SAFETY: the caller passes a C string.
    let to_stdout = unsafe { CStr::from_ptr(path) } == c"-";

    if ret != 0 {
        // SAFETY: a format of one C string, and strerror()'s.
        unsafe { pr_err(c"report: encode failed: %s".as_ptr(), strerror(-ret)) };
    } else if to_stdout {
        // SAFETY: a format of one C string, and the report, which the
        // emitter ends with a NUL.
        unsafe { printf(c"%s\n".as_ptr(), buf) };
    } else {
        let mut out = SealOutput::closed();

        // SAFETY: an output to fill, the caller's path, and a mode.
        ret = unsafe { seal_output_create(&mut out, path, 0o644) };
        if ret != 0 {
            // SAFETY: a format of two C strings, the path and
            // strerror()'s.
            unsafe { pr_err(c"report: open %s: %s".as_ptr(), path, strerror(-ret)) };
        } else {
            // SAFETY: the output just created, and the report, which
            // the emitter ends with a NUL.
            ret = unsafe {
                seal_output_commit(&mut out, buf.cast(), CStr::from_ptr(buf).to_bytes().len())
            };
            if ret != 0 {
                // SAFETY: a format of two C strings, the path and
                // strerror()'s.
                unsafe { pr_err(c"report: write %s: %s".as_ptr(), path, strerror(-ret)) };
            }
        }
    }
    // SAFETY: what xmalloc() gave, and its size.
    unsafe { xfree(buf.cast(), cap) };
    ret
}

/// Keeps a copy of the verifier's log, at most `VERIFIER_LOG_MAX` bytes
/// of it, in place of the one before; none for an empty log.
///
/// # Safety
///
/// `log` is NULL or a C string, and the report's log NULL or one
/// xstrndup() gave.
pub(crate) unsafe fn report_set_log(r: &mut OpReport, log: *const c_char) {
    // SAFETY: the caller passes a log from xstrndup() or NULL.
    unsafe { xstrfree(r.verifier_log) };
    r.verifier_log = core::ptr::null_mut();
    // SAFETY: the caller passes a C string or NULL.
    if log.is_null() || unsafe { *log } == 0 {
        return;
    }
    // The verifier log is the kernel's diagnostic output: the copy is
    // bounded, and xstrfree() scrubs it.
    // SAFETY: a C string, and a bound.
    r.verifier_log = unsafe { xstrndup(log, VERIFIER_LOG_MAX) };
}

pub(crate) use capi::report_free;

mod capi {
    use core::ffi::{c_char, c_int};

    use super::OpReport;

    /// # Safety
    ///
    /// `path` is a C string, and `r` points to a report whose strings
    /// are NULL or C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn report_emit(path: *const c_char, r: *const OpReport) -> c_int {
        // SAFETY: the caller passes a path and a report.
        unsafe { super::report_emit(path, &*r) }
    }

    /// # Safety
    ///
    /// `r` is NULL or points to a report whose log is NULL or from
    /// xstrndup(), and `log` is NULL or a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn report_set_log(r: *mut OpReport, log: *const c_char) {
        if r.is_null() {
            return;
        }
        // SAFETY: the caller passes a report and a log.
        unsafe { super::report_set_log(&mut *r, log) }
    }

    /// # Safety
    ///
    /// `r` points to a report whose log is NULL or from xstrndup().
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn report_free(r: *mut OpReport) {
        // SAFETY: the caller passes a report.
        let r = unsafe { &mut *r };

        // SAFETY: the log is NULL or from xstrndup().
        unsafe { crate::sys::malloc::xstrfree(r.verifier_log) };
        r.verifier_log = core::ptr::null_mut();
    }
}
