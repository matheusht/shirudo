// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-prog-metadata: a LOAD upatch's program metadata parsed, with the
//! counts its own header claims; fuzz-upatch: a .upatch opened and its
//! signed sections and decoders read.

use crate::fuzzing::{fuzz_target, input_file};

/// The metadata's specs parsed, and freed.
fn specs(metadata: &[u8], nr_maps: u32, nr_progs: u32) {
    drop(super::Specs::parse(metadata, nr_maps, nr_progs));
}

fuzz_target!(
    shirudo_fuzz_prog_metadata,
    shirudo_fuzz_prog_metadata_init,
    |data| {
        // The header claims the counts the container's header must match.
        let le32 = |off: usize| {
            data.get(off..off + 4)
                .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };
        let (nr_progs, nr_maps) = if data.len() >= super::PROG_METADATA {
            (le32(8), le32(12))
        } else {
            (0, 0)
        };
        specs(data, nr_maps, nr_progs);
    }
);

fuzz_target!(shirudo_fuzz_upatch, shirudo_fuzz_upatch_init, |data| {
    let Some(input) = input_file(data) else {
        return;
    };
    let Ok(u) = super::Upatch::open(&input.path) else {
        return;
    };
    if let Some(attach) = u.signed_attach() {
        specs(attach, u.hdr.nr_maps, u.hdr.nr_progs);
    }
    core::hint::black_box((u.signed_name(), u.is_unload(), u.policy_labels()));
    for d in u.decoders() {
        core::hint::black_box(d);
    }
});
