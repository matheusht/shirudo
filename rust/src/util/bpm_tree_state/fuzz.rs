// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-tree-state: a tree state file read, with the checks of
//! bpm_tree_state's fuzz(); fuzz-kconfig: a kernel config read plain
//! and gzip for a selector's keys, and a labels file.

use std::os::fd::AsRawFd;
use std::sync::OnceLock;

use crate::util::bpm_tree::{
    MAX_KCONFIG, MAX_LABELS, STRING_MAX, TreeKv, TreeSelector, TreeSelectorKv,
};

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
