// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! A panic is a bug: say where through pr_err() and abort, as a failed
//! assertion does in C.

use core::fmt::{self, Write};
use core::panic::PanicInfo;

use crate::sys::libc::abort;
use crate::sys::log::pr_err;

/// A message cut to the buffer, which keeps room for its NUL.
struct Message {
    buf: [u8; 512],
    len: usize,
}

impl Write for Message {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = self.buf.len() - 1 - self.len;
        let n = s.len().min(room);

        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// The personality routine the unwind tables of the prebuilt core and
/// alloc name, which std would otherwise define. Nothing unwinds with
/// `panic = "abort"`, so nothing calls it.
#[unsafe(no_mangle)]
extern "C" fn rust_eh_personality() {
    // SAFETY: abort() takes nothing and does not return.
    unsafe { abort() }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let mut msg = Message {
        buf: [0; 512],
        len: 0,
    };

    let _ = write!(msg, "{info}");
    // A NUL inside would only cut the message short.
    msg.buf[msg.len] = 0;
    // SAFETY: a "%s" format with the NUL-terminated message, and abort()
    // does not return.
    unsafe {
        pr_err(c"rust: %s".as_ptr(), msg.buf.as_ptr());
        abort()
    }
}
