// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-tpm-wire: TPM structures parsed: a public area, which marshals
//! back to its bytes and names, an ECC public key, an ECDSA signature,
//! and an attestation, whose parts stay within the input.

use super::parse::{ecc_public_parse, ecdsa_signature_parse};
use super::{
    ALG_ECC, ALG_SHA256, NAME_LEN, ST_ATTEST_NV, TpmAttest, TpmEccPublic, TpmPublic, attest_parse,
    object_name, public_marshal, public_parse,
};
use crate::fuzzing::fuzz_target;

fuzz_target!(shirudo_fuzz_tpm_wire, shirudo_fuzz_tpm_wire_init, |data| {
    let mut public = TpmPublic::zeroed();
    let mut name = [0u8; NAME_LEN];
    let parsed = public_parse(data, &mut public) == 0;
    let named = object_name(data, &mut name) == 0;
    if named != (data.len() >= 4 && u16::from_be_bytes([data[2], data[3]]) == ALG_SHA256) {
        std::process::abort();
    }
    if parsed {
        let mut again = [0u8; 1024];
        let mut len = 0;
        if !named
            || public_marshal(&public, &mut again, &mut len) != 0
            || again.get(..len) != Some(data)
        {
            std::process::abort();
        }
    }
    let mut ecc = TpmEccPublic::zeroed();
    if ecc_public_parse(data, &mut ecc) == 0 && (!parsed || public.ty != ALG_ECC) {
        std::process::abort();
    }
    let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
    if ecdsa_signature_parse(data, &mut r, &mut s) == 0 && data.len() != 72 {
        std::process::abort();
    }
    let mut at = TpmAttest::zeroed();
    if attest_parse(data, &mut at) == 0
        && (at.signer_len > NAME_LEN
            || at.extra_in(data).is_none()
            || (at.ty == ST_ATTEST_NV
                && (at.index_name_len > NAME_LEN || at.nv_data_in(data).is_none())))
    {
        std::process::abort();
    }
});
