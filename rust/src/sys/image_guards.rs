// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The config root guard of `util/image_guards.h`, which stays in C.

use core::ffi::{c_char, c_int};

/// `struct image_guard`: a program and where its link is pinned.
#[repr(C)]
pub struct ImageGuard {
    pub prog: *const c_char,
    pub pin: *const c_char,
}

/// `struct guard_map`: a map the guards share, and where it is pinned.
#[repr(C)]
pub struct GuardMap {
    pub name: *const c_char,
    pub pin: *const c_char,
    pub ty: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
}

const _: () = assert!(size_of::<GuardMap>() == 40);

// The counts and indices util/image_guards.h defines.
pub const SEAL_HOOK_COUNT: usize = 27;
pub const IMAGE_SEAL_HOOK_COUNT: usize = 2;
pub const MOUNT_HOOK_COUNT: usize = 5;
pub const OBSERVER_HOOK_COUNT: usize = 9;
pub const IMAGE_OBSERVER_HOOK_COUNT: usize = 4;
/// `enum gate_guard`.
pub const GUARD_UNLINK: usize = 0;
pub const GUARD_SETXATTR: usize = 1;
pub const GUARD_REMOVEXATTR: usize = 2;
pub const GUARD_KEY_PERMISSION: usize = 3;
pub const GUARD_TPM_COMMAND: usize = 4;
pub const GUARD_BPF_MAP: usize = 5;
pub const GUARD_PROG_LOAD: usize = 6;
pub const GUARD_BPF: usize = 7;
pub const GATE_HOOK_COUNT: usize = 8;
/// `enum guard_map_index`.
pub const GUARD_TASKS: usize = 1;
pub const GUARD_ROOTS: usize = 3;
pub const GUARD_MAP_COUNT: usize = 7;

unsafe extern "C" {
    pub static shirudo_seal_guards: [ImageGuard; SEAL_HOOK_COUNT];
    pub static shirudo_image_seal_guards: [ImageGuard; IMAGE_SEAL_HOOK_COUNT];
    pub static shirudo_image_observer_guards: [ImageGuard; IMAGE_OBSERVER_HOOK_COUNT];
    pub static shirudo_mount_guards: [ImageGuard; MOUNT_HOOK_COUNT];
    pub static shirudo_observer_guards: [ImageGuard; OBSERVER_HOOK_COUNT];
    pub static shirudo_gate_guards: [ImageGuard; GATE_HOOK_COUNT];
    pub static shirudo_guard_maps: [GuardMap; GUARD_MAP_COUNT];
}

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
    /// Whether every guard the initrd installs is pinned, attached and
    /// frozen as it left them: 0 or -errno.
    pub fn image_guards_ready() -> c_int;
}
