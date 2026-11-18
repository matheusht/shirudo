// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-tree-state: a tree state file read, with the checks of
//! bpm_tree_state's fuzz().

use std::os::fd::AsRawFd;

use crate::fuzzing::{fuzz_target, input_file};

fuzz_target!(
    shirudo_fuzz_tree_state,
    shirudo_fuzz_tree_state_init,
    |data| {
        if let Some(input) = input_file(data) {
            super::fuzz(&input.path, input.fd.as_raw_fd(), data.len());
        }
    }
);
