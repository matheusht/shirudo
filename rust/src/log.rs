// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The log: each message to syslog under LOG_AUTHPRIV, as `shirudo` with
//! its pid, and to stderr, at the priority of err(), warn(), info() or
//! audit(); log_c! for a message a C format spells. A fuzz build makes
//! each line and drops it.

use core::ffi::c_int;
use std::ffi::CString;

use crate::sys::libc::{errno, fputs, openlog, set_errno, stderr, syslog};

const LOG_PID: c_int = 0x01;
const LOG_NDELAY: c_int = 0x08;
const LOG_AUTHPRIV: c_int = 10 << 3;
/// The most an escaped message of 8192 bytes takes, with its NUL.
const OUT_MAX: usize = 4 * 8192 + 1;

/// Opens syslog for the messages to come.
pub(crate) fn init() {
    // SAFETY: a static name, which syslog keeps.
    unsafe { openlog(c"shirudo".as_ptr(), LOG_PID | LOG_NDELAY, LOG_AUTHPRIV) };
}

/// `msg` up to its NUL as a line that forges no record and drives no
/// terminal, in at most `cap` bytes with a NUL: printable ASCII kept, a
/// backslash doubled, any other byte a backslash and three octal digits.
/// A message carries text from outside, a registry's error body or a
/// name from a package, and with it escape sequences or line breaks.
pub(crate) fn escape(msg: &[u8], cap: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len().min(cap));
    for &c in msg.iter().take_while(|&&c| c != 0) {
        if out.len() + 5 > cap {
            break;
        }
        match c {
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x20..0x7f => out.push(c),
            _ => out.extend_from_slice(&[
                b'\\',
                b'0' + (c >> 6),
                b'0' + ((c >> 3) & 7),
                b'0' + (c & 7),
            ]),
        }
    }
    out
}

/// Logs `msg` at syslog priority `priority`, escaped, and leaves errno
/// as it found it: a caller reports a failure and then returns -errno,
/// and syslog and stdio may change it on the way, as without /dev/log in
/// an early initrd.
pub(crate) fn emit(priority: c_int, msg: &[u8]) {
    let saved = errno();
    let line = CString::new(escape(msg, OUT_MAX)).unwrap_or_default();
    if cfg!(shirudo_fuzz) {
        set_errno(saved);
        return;
    }
    // SAFETY: a "%s" format with a C string, and the C library's stderr.
    unsafe {
        syslog(priority, c"%s".as_ptr(), line.as_ptr());
        fputs(line.as_ptr(), stderr);
        fputs(c"\n".as_ptr(), stderr);
    }
    set_errno(saved);
}

/// The syslog priorities a message is logged at.
const LOG_ERR: c_int = 3;
const LOG_WARNING: c_int = 4;
const LOG_NOTICE: c_int = 5;
const LOG_INFO: c_int = 6;

/// A failure.
pub(crate) fn err(msg: &[u8]) {
    emit(LOG_ERR, msg);
}

/// What a command goes on without.
pub(crate) fn warn(msg: &[u8]) {
    emit(LOG_WARNING, msg);
}

/// What a command did.
pub(crate) fn info(msg: &[u8]) {
    emit(LOG_INFO, msg);
}

/// What changed the trust state, for the audit trail.
pub(crate) fn audit(msg: &[u8]) {
    emit(LOG_NOTICE, msg);
}

/// The message snprintf() wrote into `buf`, which it said is `n` bytes,
/// or when it did not fit the format `fmt` itself, cut to the buffer.
///
/// # Safety
///
/// `fmt` is a C string.
pub(crate) unsafe fn formatted(buf: &[u8], n: c_int, fmt: *const core::ffi::c_char) -> Vec<u8> {
    match usize::try_from(n) {
        Ok(n) if n < buf.len() => buf[..n].to_vec(),
        _ => {
            // SAFETY: the caller's C string.
            let fmt = unsafe { core::ffi::CStr::from_ptr(fmt) }.to_bytes();
            fmt[..fmt.len().min(buf.len() - 1)].to_vec()
        }
    }
}

/// A message of a C format and the arguments it converts, made by the C
/// library's snprintf() into 8192 bytes, or the bare format when it does
/// not fit, and logged by `level`, err() or its kin; errno as the caller
/// left it. The caller's unsafe block holds the format and its
/// arguments.
macro_rules! log_c {
    ($level:expr, $fmt:expr $(, $arg:expr)* $(,)?) => {{
        let saved = $crate::sys::libc::errno();
        let mut buf = [0u8; 8192];
        let fmt: *const ::core::ffi::c_char = $fmt;
        let n = $crate::sys::libc::snprintf(buf.as_mut_ptr().cast(), buf.len(), fmt $(, $arg)*);
        ($level)(&$crate::log::formatted(&buf, n, fmt));
        $crate::sys::libc::set_errno(saved);
    }};
}
pub(crate) use log_c;

mod capi {
    use core::ffi::{CStr, c_char, c_int};

    #[unsafe(no_mangle)]
    pub extern "C" fn log_init() {
        super::init();
    }

    /// # Safety
    ///
    /// `msg` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn log_emit(priority: c_int, msg: *const c_char) {
        // SAFETY: the C logger passes a terminated message.
        super::emit(priority, unsafe { CStr::from_ptr(msg) }.to_bytes());
    }
}
