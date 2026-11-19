// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-rodata: a .upatch in memory, its rodata's offset and a symbol's
//! range within its data, and its rodata printed as text and JSON, to a
//! stdout that the setup sends to /dev/null.

use super::RodataRange;
use super::{Loader, print, rodata_offset, symbol_range};
use crate::fuzzing::fuzz_target;
use crate::util::upatch::{Upatch, upatch_close, upatch_open_memory};

fn init() {
    // SAFETY: /dev/null put in place of stdout.
    unsafe {
        let fd = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 || libc::dup2(fd, libc::STDOUT_FILENO) < 0 {
            std::process::abort();
        }
        libc::close(fd);
    }
}

fuzz_target!(
    shirudo_fuzz_rodata,
    shirudo_fuzz_rodata_init,
    |data| {
        // SAFETY: a container of nothing, which the open fills from the
        // input, and closes after.
        unsafe {
            let mut u: Box<Upatch> = Box::new(core::mem::zeroed());
            if upatch_open_memory(data.as_ptr().cast(), data.len(), &mut *u) != 0 {
                return;
            }
            if rodata_offset(&Loader::of(&u)).is_ok_and(|off| off != u.hdr.rodata_data_off) {
                std::process::abort();
            }
            let mut range = RodataRange { offset: 0, size: 0 };
            if symbol_range(&u, c"fuzz_limits", &mut range) == 0
                && (range.offset > u.hdr.data_len || range.size > u.hdr.data_len - range.offset)
            {
                std::process::abort();
            }
            for json in [false, true] {
                if print(&u, c"fuzz", json) == 0 {
                    libc::fflush(core::ptr::null_mut());
                }
            }
            upatch_close(&mut *u);
        }
    },
    init
);
