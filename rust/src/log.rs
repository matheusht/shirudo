// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The log: each message to syslog under LOG_AUTHPRIV, as `shirudo` with
//! its pid, and to stderr, at the priority of err(), warn(), info() or
//! audit(). A fuzz build makes each line and drops it.

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
