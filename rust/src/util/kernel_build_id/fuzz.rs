// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-kernel: the build ID read from a kernel's notes.

use core::ffi::c_char;

use crate::fuzzing::fuzz_target;

fuzz_target!(shirudo_fuzz_kernel, shirudo_fuzz_kernel_init, |data| {
    let mut build_id = [0 as c_char; 2 * super::BUILD_ID_MAX + 1];
    // SAFETY: room for the ID as a string.
    unsafe { super::from_notes(data, build_id.as_mut_ptr()) };
});
