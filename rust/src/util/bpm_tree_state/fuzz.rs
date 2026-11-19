// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-tree-state: a tree state file read, as a state, an eventlog
//! and an outcome record at once; fuzz-kconfig: a kernel config read plain
//! and gzip for a selector's keys, and a labels file.

use core::ffi::CStr;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::OnceLock;

use super::{
    OUTCOME_LINE_MAX, Outcomes, event_replay_at, eventlog_matches_at, kconfig_read, outcome_emit,
    outcome_parse, outcome_valid, read_config_file, state_read_at,
};

use crate::util::bpm_tree::{MAX_LABELS, TreeSelector, TreeSelectorKv};

use crate::fuzzing::{fuzz_target, input_file};

/// The checks on a state, eventlog and outcome record at once, the file
/// at `path`, open at `fd` and of `size` bytes: the eventlog replays alike
/// whether or not it matches the state, and matches no state that could
/// not be read; and each line the outcome reader takes lies within the
/// record, follows the line before it and is written again as a line it
/// takes the same. It aborts where one does not hold.
fn check_file(path: &CStr, fd: BorrowedFd<'_>, size: usize) {
    let state = state_read_at(path);
    let replay = event_replay_at(path);
    let held = match eventlog_matches_at(path, state.as_ref().ok()) {
        Ok((again, matches)) => replay == Ok(again) && !(state.is_err() && matches),
        Err(err) => replay == Err(err),
    };
    if !held {
        std::process::abort();
    }
    // A descriptor of the file for the reader to own.
    let Ok(dup) = fd.try_clone_to_owned() else {
        return;
    };
    let mut o = Outcomes::new(dup);
    let mut seq = 0i64;
    while o.next().is_ok() {
        seq += 1;
        let mut buf = [0u8; OUTCOME_LINE_MAX];
        let back = outcome_emit(&o.line, &mut buf).and_then(|len| outcome_parse(&buf[..len]));
        if o.end > size as u64
            || o.line.seq != seq
            || !outcome_valid(o.line.outcome)
            || back != Ok(o.line)
        {
            std::process::abort();
        }
    }
    let _ = o.close();
}

fuzz_target!(
    shirudo_fuzz_tree_state,
    shirudo_fuzz_tree_state_init,
    |data| {
        if let Some(input) = input_file(data) {
            check_file(&input.path, input.fd.as_fd(), data.len());
        }
    }
);

/// The selector of the kernel config keys the target reads, made once
/// and kept for the process.
static SELECTOR: OnceLock<TreeSelector> = OnceLock::new();

fn kconfig_init() {
    const KEYS: [&[u8]; 5] = [
        b"CONFIG_BPF_LSM",
        b"CONFIG_DEBUG_INFO_BTF",
        b"CONFIG_LOCALVERSION",
        b"CONFIG_LSM",
        b"CONFIG_MODULES",
    ];
    let kconfig = KEYS
        .iter()
        .map(|key| TreeSelectorKv {
            key: key.to_vec(),
            values: Vec::new(),
        })
        .collect();
    let _ = SELECTOR.set(TreeSelector {
        kconfig,
        ..TreeSelector::default()
    });
}

fuzz_target!(
    shirudo_fuzz_kconfig,
    shirudo_fuzz_kconfig_init,
    |data| {
        let (Some(sel), Some(input)) = (SELECTOR.get(), input_file(data)) else {
            return;
        };
        let _ = kconfig_read(&input.path, sel, false);
        let _ = kconfig_read(&input.path, sel, true);
        let _ = read_config_file(&input.path, MAX_LABELS);
    },
    kconfig_init
);
