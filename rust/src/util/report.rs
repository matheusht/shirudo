// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The JSON report of `upatch load` and `unload --report`:
//! what the operation did, the phase it stopped at and
//! why, and the verifier's log verbatim.

use core::ffi::{CStr, c_char, c_int};
use std::ffi::CString;

use crate::errno::{E2BIG, text};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{Utsname, printf, strerrorname_np, uname};
use crate::text::{cstr, strsprintf};
use crate::util::eventlog::NV_INDEX;
use crate::util::json::JsonEmit;
use crate::util::seal::{SealOutput, seal_output_commit, seal_output_create};

/// `VERIFIER_LOG_MAX`: the most of a verifier log a report keeps.
const VERIFIER_LOG_MAX: usize = 16 * 1024 * 1024;

/// What an operation did, for its report.
pub struct OpReport {
    pub(crate) ok: bool,
    op: &'static CStr,
    pub(crate) phase: &'static CStr,
    pub(crate) err: c_int,
    pub(crate) category: Option<&'static CStr>,
    pub(crate) message: [c_char; 256],
    /// The verifier's log, at most VERIFIER_LOG_MAX bytes of it; the
    /// allocator scrubs it when it goes.
    verifier_log: Option<Vec<u8>>,
    pub(crate) loader_return: c_int,
    pub(crate) path: Option<CString>,
    pub(crate) name: Option<CString>,
    pub(crate) payload_hex: [c_char; 65],
    pub(crate) tpm_present: bool,
    pub(crate) chain_after: [c_char; 65],
}

impl OpReport {
    /// A report of operation `op`, done until a failure says otherwise.
    pub(crate) fn new(op: &'static CStr) -> Self {
        OpReport {
            ok: false,
            op,
            phase: c"done",
            err: 0,
            category: None,
            message: [0; 256],
            verifier_log: None,
            loader_return: 0,
            path: None,
            name: None,
            payload_hex: [0; 65],
            tpm_present: false,
            chain_after: [0; 65],
        }
    }
}

impl OpReport {
    /// Keeps a copy of the verifier's log, up to its NUL and at most
    /// VERIFIER_LOG_MAX bytes of it, in place of the one before; none for
    /// an empty log.
    pub(crate) fn set_log(&mut self, log: &[u8]) {
        let log = cstr(log);
        self.verifier_log =
            (!log.is_empty()).then(|| log[..log.len().min(VERIFIER_LOG_MAX)].to_vec());
    }
}

/// The string in a fixed array, up to its NUL.
fn in_array(a: &[c_char]) -> &[u8] {
    // SAFETY: c_char and u8 have one size and alignment.
    let bytes = unsafe { core::slice::from_raw_parts(a.as_ptr().cast::<u8>(), a.len()) };

    &bytes[..bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len())]
}

/// The report into `e`.
fn encode(e: &mut JsonEmit, r: &OpReport, vlog: &[u8], nv_index: &[u8]) {
    // SAFETY: errno numbers alone.
    let errname = (r.err != 0)
        .then(|| unsafe { strerrorname_np(r.err) })
        .filter(|p| !p.is_null());
    let mut uts = Utsname::zeroed();

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"result", if r.ok { b"ok" } else { b"failed" });
    e.kv_string(b"op", r.op.to_bytes());
    e.kv_string(b"phase", r.phase.to_bytes());
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
    e.kv_string(b"category", r.category.map_or(category, CStr::to_bytes));
    e.kv_string(b"message", in_array(&r.message));
    e.kv_string(b"verifier_log", vlog);
    e.kv_int(b"loader_return", i64::from(r.loader_return));

    e.obj_open_key(b"upatch");
    e.kv_string(b"path", r.path.as_deref().map_or(b"", CStr::to_bytes));
    e.kv_string(b"name", r.name.as_deref().map_or(b"", CStr::to_bytes));
    e.kv_string(b"payload_sha256", in_array(&r.payload_hex));
    e.obj_close();

    e.obj_open_key(b"kernel");
    // SAFETY: a struct utsname to fill.
    let release = if unsafe { uname(&mut uts) } == 0 {
        cstr(crate::sys::libc::bytes(&uts.release))
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
pub(crate) fn report_emit(path: &CStr, r: &OpReport) -> c_int {
    let vlog = r.verifier_log.as_deref().unwrap_or_default();
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
    let mut buf = vec![0u8; cap];
    let mut e = JsonEmit::fixed(&mut buf);

    encode(&mut e, r, vlog, &nv_index[..n]);
    let mut ret = e.err();
    let doc = CString::new(e.output()).unwrap_or_default();
    let path_c = path;
    let to_stdout = path_c == c"-";

    if ret != 0 {
        crate::log::err(format!("report: encode failed: {}", text(ret)).as_bytes());
    } else if to_stdout {
        // SAFETY: a format of one C string, and the report.
        unsafe { printf(c"%s\n".as_ptr(), doc.as_ptr()) };
    } else {
        let mut out = SealOutput::closed();

        // SAFETY: an output to fill, the caller's path, and a mode.
        ret = unsafe { seal_output_create(&mut out, path.as_ptr(), 0o644) };
        if ret != 0 {
            crate::log::err(
                &[
                    &b"report: open "[..],
                    path_c.to_bytes(),
                    b": ",
                    text(ret).as_bytes(),
                ]
                .concat(),
            );
        } else {
            let doc = doc.as_bytes();
            // SAFETY: the output just created, and the report's bytes.
            ret = unsafe { seal_output_commit(&mut out, doc.as_ptr().cast(), doc.len()) };
            if ret != 0 {
                crate::log::err(
                    &[
                        &b"report: write "[..],
                        path_c.to_bytes(),
                        b": ",
                        text(ret).as_bytes(),
                    ]
                    .concat(),
                );
            }
        }
    }
    ret
}
