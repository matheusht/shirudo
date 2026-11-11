// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The kernel ABI check of `util/kernel_abi.h`, which stays in C with the
//! BTF it reads through libbpf.

use core::ffi::{c_char, c_int};

unsafe extern "C" {
    /// Whether the running kernel's BTF has what the signed loader needs:
    /// 0, or -errno with why in the `detail_sz` bytes at `detail`.
    pub fn kernel_abi_check(detail: *mut c_char, detail_sz: usize) -> c_int;
}
