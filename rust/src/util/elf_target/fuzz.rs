// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-elf: the build ID of an ELF file.

use crate::fuzzing::{fuzz_target, input_file};

fuzz_target!(shirudo_fuzz_elf, shirudo_fuzz_elf_init, |data| {
    if let Some(input) = input_file(data) {
        let _ = super::build_id(&std::fs::File::from(input.fd));
    }
});
