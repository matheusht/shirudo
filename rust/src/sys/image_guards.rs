// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The config root guard of `util/image_guards.h`, which stays in C.

use core::ffi::c_int;

/// `struct config_root_guard`: the fds the guard holds, -1 for none.
#[repr(C)]
pub struct ConfigRootGuard {
    pub map_fd: c_int,
    pub task_fd: c_int,
}

unsafe extern "C" {
    /// The root this task expects staged for the image guards while a
    /// config image's table loads: 0 or -errno.
    pub fn config_root_begin(root: *const u8, guard: *mut ConfigRootGuard) -> c_int;
    /// The staged root taken back: 0 or -errno.
    pub fn config_root_end(guard: *mut ConfigRootGuard) -> c_int;
}
