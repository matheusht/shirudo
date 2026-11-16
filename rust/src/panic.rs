// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! A panic is a bug: say where through pr_err() and abort, as a failed
//! assertion does in C. The crate unwinds only so that a Lua error can
//! cross a Rust callback; a panic never unwinds.

use std::fmt::{self, Write};
use std::panic::{self, PanicHookInfo};
use std::process;

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

fn report(info: &PanicHookInfo<'_>) {
    let mut msg = Message {
        buf: [0; 512],
        len: 0,
    };

    let _ = write!(msg, "{info}");
    // A NUL inside would only cut the message short.
    msg.buf[msg.len] = 0;
    // SAFETY: a "%s" format with the NUL-terminated message.
    unsafe { pr_err(c"rust: %s".as_ptr(), msg.buf.as_ptr()) };
    process::abort()
}

extern "C" fn install() {
    panic::set_hook(Box::new(report));
}

/// Every binary that links the archive takes the hook before main().
#[used]
// SAFETY: the C runtime calls each function of .init_array before main()
// with no arguments, which install takes.
#[unsafe(link_section = ".init_array")]
static INSTALL: extern "C" fn() = install;
