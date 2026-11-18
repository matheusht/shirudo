// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-prog-metadata: a LOAD upatch's program metadata parsed, with the
//! counts its own header claims; fuzz-upatch: a .upatch opened and its
//! signed sections and decoders read.

use crate::fuzzing::{fuzz_target, input_file};

/// The metadata's specs parsed, and freed.
fn specs(metadata: &[u8], nr_maps: u32, nr_progs: u32) {
    let mut specs: *mut super::ProgSpec = core::ptr::null_mut();
    let Ok(len) = u32::try_from(metadata.len()) else {
        return;
    };
    // SAFETY: the metadata's bytes, and room for the specs, freed once.
    unsafe {
        if super::specs_parse(metadata.as_ptr().cast(), len, nr_maps, nr_progs, &mut specs) == 0 {
            super::specs_free(specs, nr_progs);
        }
    }
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
    let Ok(u) = super::Opened::open(&input.path) else {
        return;
    };
    let u: &super::Upatch = &u;
    // SAFETY: the open container's signed sections, which it holds.
    unsafe {
        let mut len = 0u32;
        let attach = super::capi::upatch_signed_attach(u, &mut len);
        if !attach.is_null() {
            specs(
                crate::ffi::slice(attach.cast::<u8>(), len as usize),
                u.hdr.nr_maps,
                u.hdr.nr_progs,
            );
        }
        super::capi::upatch_signed_name(u);
        super::capi::upatch_signed_unload_payload(u);
        super::capi::upatch_is_unload(u);
        if super::capi::upatch_has_decoders(u) {
            let mut d: super::DecoderView = core::mem::zeroed();
            let mut i = 0;
            while super::capi::upatch_decoder_view(u, i, &mut d) == 0 {
                i += 1;
            }
        }
    }
});
