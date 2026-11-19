// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-kernel: the build ID read from a kernel's notes.

use crate::fuzzing::fuzz_target;

fuzz_target!(shirudo_fuzz_kernel, shirudo_fuzz_kernel_init, |data| {
    let _ = super::from_notes(data);
});
