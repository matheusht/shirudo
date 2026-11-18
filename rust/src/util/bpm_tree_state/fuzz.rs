// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-tree-state: a tree state file read, as a state, an eventlog
//! and an outcome record at once; fuzz-kconfig: a kernel config read plain
//! and gzip for a selector's keys, and a labels file.

use core::ffi::CStr;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::OnceLock;

use super::{
    OUTCOME_LINE_MAX, Outcomes, TreeState, event_replay, eventlog_matches_at, outcome_emit,
    outcome_parse, outcome_valid, state_read,
};

use crate::util::bpm_tree::{
    MAX_KCONFIG, MAX_LABELS, STRING_MAX, TreeKv, TreeSelector, TreeSelectorKv,
};

use crate::fuzzing::{fuzz_target, input_file};

/// The checks on a state, eventlog and outcome record at once, the file
/// at `path`, open at `fd` and of `size` bytes: the eventlog replays alike
/// whether or not it matches the state, and matches no state that could
/// not be read; and each line the outcome reader takes lies within the
/// record, follows the line before it and is written again as a line it
/// takes the same. It aborts where one does not hold.
fn check_file(path: &CStr, fd: BorrowedFd<'_>, size: usize) {
    let mut state = TreeState::zeroed();
    let mut root = [0u8; 32];

    // SAFETY: a C string, and rooms for a state and 32 bytes.
    let (rc, ret) = unsafe {
        (
            state_read(path.as_ptr(), &mut state),
            event_replay(path.as_ptr(), root.as_mut_ptr()),
        )
    };
    let held = match eventlog_matches_at(path, &state, rc) {
        Ok((again, matches)) => ret == 0 && again == root && !(rc != 0 && matches),
        Err(err) => err == ret,
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
struct Selector(Box<TreeSelector>);

// SAFETY: made once, then only read, by the fuzzer's one thread.
unsafe impl Sync for Selector {}
// SAFETY: as Sync.
unsafe impl Send for Selector {}

static SELECTOR: OnceLock<Selector> = OnceLock::new();

fn kconfig_init() {
    const KEYS: [&[u8]; 5] = [
        b"CONFIG_BPF_LSM",
        b"CONFIG_DEBUG_INFO_BTF",
        b"CONFIG_LOCALVERSION",
        b"CONFIG_LSM",
        b"CONFIG_MODULES",
    ];
    let mut kvs = Vec::with_capacity(KEYS.len());
    for key in KEYS {
        // SAFETY: a pair of nothing, for which zeros are the value.
        let mut kv: TreeSelectorKv = unsafe { core::mem::zeroed() };
        kv.key[..key.len()].copy_from_slice(key);
        kvs.push(kv);
    }
    // SAFETY: a selector of nothing, for which zeros are the value.
    let mut sel: Box<TreeSelector> = Box::new(unsafe { core::mem::zeroed() });
    sel.n_kconfig = kvs.len() as i32;
    sel.kconfig = Box::leak(kvs.into_boxed_slice()).as_mut_ptr();
    let _ = SELECTOR.set(Selector(sel));
}

fuzz_target!(
    shirudo_fuzz_kconfig,
    shirudo_fuzz_kconfig_init,
    |data| {
        let (Some(sel), Some(input)) = (SELECTOR.get(), input_file(data)) else {
            return;
        };
        let mut values = vec![[0u8; STRING_MAX]; MAX_KCONFIG];
        let mut found = [false; MAX_KCONFIG];
        // SAFETY: labels of nothing, for which zeros are the value.
        let mut labels: Vec<TreeKv> = (0..MAX_LABELS)
            .map(|_| unsafe { core::mem::zeroed() })
            .collect();
        let mut n = 0;
        // SAFETY: a C string, the selector, and rooms for the values, what
        // was found, and the labels.
        unsafe {
            super::kconfig_read(
                input.path.as_ptr(),
                &*sel.0,
                values.as_mut_ptr(),
                found.as_mut_ptr(),
                false,
            );
            super::kconfig_read(
                input.path.as_ptr(),
                &*sel.0,
                values.as_mut_ptr(),
                found.as_mut_ptr(),
                true,
            );
            super::read_config_file(
                input.path.as_ptr(),
                labels.as_mut_ptr(),
                &mut n,
                MAX_LABELS as i32,
            );
        }
    },
    kconfig_init
);
