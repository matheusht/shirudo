// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-tpm-wire: tpm_wire's policy digests, names, key derivations and
//! structure parsing, each a subcommand with its inputs in hex.

use core::ffi::{CStr, c_int};

use super::{helper_main, out};
use crate::util::hex::{decode, encode};
use crate::util::tpm_wire::{
    CREDENTIAL_LEN, DIGEST_LEN, EK_POLICY, HmacKey, ID_OBJECT_LEN, NAME_LEN, NV_RSA_BYTES,
    NV_RSA_PUBLIC_AREA_LEN, RegisterPolicy, ST_ATTEST_QUOTE, TpmAttest, TpmEccPublic, TpmPublic,
    attest_parse, credential_protect, ecc_public_parse, ecdsa_signature_parse, kdfa, kdfe,
    nv_extend_cphash, nv_name, object_name, policy_command_code, policy_nv_written, policy_or,
    policy_pcr, policy_signed, public_marshal, public_parse, register_policy,
    register_policy_final, writer_auth_hash, writer_public,
};

helper_main!(shirudo_helper_test_tpm_wire, run);

type Digest = [u8; DIGEST_LEN];

/// Why a subcommand did not print: 2 for inputs that do not decode, 1
/// for a computation that failed.
enum Fail {
    Input,
    Compute,
}

fn puthex(bytes: &[u8]) {
    if bytes.len() <= 2048 {
        out(&format!("{}\n", String::from_utf8_lossy(&encode(bytes))));
    }
}

/// `hex` decoded whole into an array of its size.
fn fixed<const N: usize>(hex: &CStr) -> Result<[u8; N], Fail> {
    let mut b = [0u8; N];
    decode(hex.to_bytes(), &mut b)
        .map(|()| b)
        .map_err(|_| Fail::Input)
}

/// `hex` of an even length and at most `cap` bytes, decoded.
fn bytes(hex: &CStr, cap: usize) -> Result<Vec<u8>, Fail> {
    let h = hex.to_bytes();
    if !h.len().is_multiple_of(2) || h.len() / 2 > cap {
        return Err(Fail::Input);
    }
    let mut b = vec![0u8; h.len() / 2];
    decode(h, &mut b).map(|()| b).map_err(|_| Fail::Input)
}

/// As strtoul() of base 0, which the C helper called: decimal, hex
/// after 0x or octal after 0, as far as digits go; 0 for none.
fn number(text: &CStr) -> u64 {
    let t = text.to_bytes();
    let (radix, digits) = match t {
        [b'0', b'x' | b'X', rest @ ..] => (16, rest),
        [b'0', rest @ ..] if !rest.is_empty() => (8, rest),
        _ => (10, t),
    };
    let n = digits
        .iter()
        .take_while(|c| (**c as char).is_digit(radix))
        .count();
    std::str::from_utf8(&digits[..n])
        .ok()
        .and_then(|d| u64::from_str_radix(d, radix).ok())
        .unwrap_or(0)
}

/// As atoi(): the leading decimal number, 0 for none.
fn atoi(text: &CStr) -> i64 {
    let t = text.to_bytes();
    let (neg, rest) = match t {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        _ => (false, t),
    };
    let n = rest.iter().take_while(|c| c.is_ascii_digit()).count();
    let v: i64 = std::str::from_utf8(&rest[..n])
        .ok()
        .and_then(|d| d.parse().ok())
        .unwrap_or(0);
    if neg { -v } else { v }
}

/// The digest `f` computes, printed.
fn digest(f: impl FnOnce(&mut Digest) -> c_int) -> Result<(), Fail> {
    let mut d = [0u8; DIGEST_LEN];
    if f(&mut d) != 0 {
        return Err(Fail::Compute);
    }
    puthex(&d);
    Ok(())
}

fn public(args: &[&CStr]) -> Result<(), Fail> {
    let buf = bytes(args[2], 2048)?;
    let mut p = TpmPublic::zeroed();
    let ret = public_parse(&buf, &mut p);
    out(&format!("rc={ret}\n"));
    if ret != 0 {
        return Ok(());
    }
    out(&format!(
        "type=0x{:04x} attrs=0x{:08x} policy_len={} sym=0x{:04x}/{}/0x{:04x} scheme=0x{:04x}/0x{:04x} \
         curve=0x{:04x} rsa_bits={} exponent={} n_len={}\n",
        p.ty,
        p.attrs,
        p.policy_len,
        p.sym_alg,
        p.sym_bits,
        p.sym_mode,
        p.scheme,
        p.scheme_hash,
        p.curve,
        p.rsa_bits,
        p.rsa_exponent,
        p.n_len
    ));
    let mut again = [0u8; 512];
    let mut len = 0;
    let ret = public_marshal(&p, &mut again, &mut len);
    let same = ret == 0 && again[..len] == buf[..];
    out(&format!("marshal_rc={ret} same={}\n", c_int::from(same)));
    Ok(())
}

fn attest(args: &[&CStr]) -> Result<(), Fail> {
    let buf = bytes(args[2], 2048)?;
    let mut at = TpmAttest::zeroed();
    let ret = attest_parse(&buf, &mut at);
    out(&format!("rc={ret}\n"));
    if ret != 0 {
        return Ok(());
    }
    out(&format!(
        "type=0x{:04x} reset={} restart={} safe={}\n",
        at.ty,
        at.reset_count,
        at.restart_count,
        c_int::from(at.safe)
    ));
    out("signer=");
    puthex(&at.signer[..at.signer_len.min(NAME_LEN)]);
    out("extra=");
    puthex(at.extra_in(&buf).unwrap_or_default());
    if at.ty == ST_ATTEST_QUOTE {
        out(&format!("mask=0x{:06x}\npcr_digest=", at.pcr_mask));
        puthex(&at.pcr_digest);
    } else {
        out("index_name=");
        puthex(&at.index_name[..at.index_name_len.min(NAME_LEN)]);
        out(&format!("offset={}\nnv=", at.offset));
        puthex(at.nv_data_in(&buf).unwrap_or_default());
    }
    Ok(())
}

fn run_case(args: &[&CStr]) -> Result<(), Fail> {
    let n = args.len();
    let a = |i: usize| args[i];
    match (args[1].to_bytes(), n) {
        (b"writer-public", 3) => {
            let modulus = fixed::<NV_RSA_BYTES>(a(2))?;
            let mut area = [0u8; NV_RSA_PUBLIC_AREA_LEN];
            writer_public(&modulus, &mut area);
            puthex(&area);
            Ok(())
        }
        (b"policy-signed", 4) => {
            let (prev, modulus) = (fixed::<DIGEST_LEN>(a(2))?, fixed::<NV_RSA_BYTES>(a(3))?);
            digest(|d| policy_signed(&prev, &modulus, d))
        }
        (b"extend-cphash", 4) => {
            let (name, event) = (fixed::<NAME_LEN>(a(2))?, fixed::<DIGEST_LEN>(a(3))?);
            digest(|d| nv_extend_cphash(&name, &event, d))
        }
        (b"writer-auth", 4) => {
            let nonce = bytes(a(2), 64)?;
            let cphash = fixed::<DIGEST_LEN>(a(3))?;
            let mut d = [0u8; DIGEST_LEN];
            if writer_auth_hash(&nonce, &cphash, &mut d) != 0 {
                return Err(Fail::Input);
            }
            puthex(&d);
            Ok(())
        }
        (b"command-code", 4) => {
            let prev = fixed::<DIGEST_LEN>(a(2))?;
            digest(|d| policy_command_code(&prev, number(a(3)) as u32, d))
        }
        (b"register-final", 5) => {
            let (w, i) = (fixed::<DIGEST_LEN>(a(2))?, fixed::<DIGEST_LEN>(a(3))?);
            let modulus = fixed::<NV_RSA_BYTES>(a(4))?;
            digest(|d| register_policy_final(&w, &i, &modulus, d))
        }
        (b"nv-written", 4) => {
            let prev = fixed::<DIGEST_LEN>(a(2))?;
            digest(|d| policy_nv_written(&prev, atoi(a(3)) != 0, d))
        }
        (b"pcr", 5) => {
            let (prev, pcrs) = (fixed::<DIGEST_LEN>(a(2))?, fixed::<DIGEST_LEN>(a(4))?);
            digest(|d| policy_pcr(&prev, number(a(3)) as u32, &pcrs, d))
        }
        (b"or", 4) => {
            let (x, y) = (fixed::<DIGEST_LEN>(a(2))?, fixed::<DIGEST_LEN>(a(3))?);
            digest(|d| policy_or(&x, &y, d))
        }
        (b"register-policy", 6) => {
            let mut values = [0u8; 2 * DIGEST_LEN];
            values[..DIGEST_LEN].copy_from_slice(&fixed::<DIGEST_LEN>(a(3))?);
            values[DIGEST_LEN..].copy_from_slice(&fixed::<DIGEST_LEN>(a(4))?);
            let modulus = fixed::<NV_RSA_BYTES>(a(5))?;
            let (mut w, mut i, mut p) = ([0u8; DIGEST_LEN], [0u8; DIGEST_LEN], [0u8; DIGEST_LEN]);
            let out = RegisterPolicy {
                branch_written: &mut w,
                branch_init: &mut i,
                policy: &mut p,
            };
            if register_policy(number(a(2)) as u32, &values, &modulus, out) != 0 {
                return Err(Fail::Compute);
            }
            puthex(&w);
            puthex(&i);
            puthex(&p);
            Ok(())
        }
        (b"nv-name", 5) => {
            let policy = fixed::<DIGEST_LEN>(a(4))?;
            let mut name = [0u8; NAME_LEN];
            if nv_name(
                number(a(2)) as u32,
                number(a(3)) as u32,
                &policy,
                32,
                &mut name,
            ) != 0
            {
                return Err(Fail::Compute);
            }
            puthex(&name);
            Ok(())
        }
        (b"object-name", 3) => {
            let buf = bytes(a(2), 2048).map_err(|_| Fail::Compute)?;
            let mut name = [0u8; NAME_LEN];
            if object_name(&buf, &mut name) != 0 {
                return Err(Fail::Compute);
            }
            puthex(&name);
            Ok(())
        }
        (b"ecc-public", 3) => {
            let buf = bytes(a(2), 2048)?;
            let mut p = TpmEccPublic::zeroed();
            let ret = ecc_public_parse(&buf, &mut p);
            out(&format!("rc={ret}\n"));
            if ret == 0 {
                out(&format!(
                    "attrs=0x{:08x} scheme=0x{:04x} hash=0x{:04x} curve=0x{:04x}\n",
                    p.attrs, p.scheme, p.hash, p.curve
                ));
                puthex(&p.x);
                puthex(&p.y);
            }
            Ok(())
        }
        (b"public", 3) => public(args),
        (b"kdfa", 6) => {
            let key = bytes(a(2), 64)?;
            let ctx = if a(4).to_bytes() == b"-" {
                Vec::new()
            } else {
                bytes(a(4), 64)?
            };
            let len = atoi(a(5)) as usize;
            if len > 64 {
                return Err(Fail::Input);
            }
            let mut res = [0u8; 64];
            let k = HmacKey {
                ptr: key.as_ptr(),
                len: key.len(),
            };
            if kdfa(&k, a(3).to_bytes(), &ctx, &[], &mut res[..len]) != 0 {
                return Err(Fail::Compute);
            }
            puthex(&res[..len]);
            Ok(())
        }
        (b"kdfe", 6) => {
            let z = bytes(a(2), 32)?;
            let z: Digest = z.try_into().map_err(|_| Fail::Input)?;
            let (u, v) = (bytes(a(4), 64)?, bytes(a(5), 64)?);
            digest(|d| kdfe(&z, a(3).to_bytes(), &u, &v, d))
        }
        (b"ek-policy", _) => {
            puthex(&EK_POLICY);
            Ok(())
        }
        (b"credential", 5) => {
            let exact = |i, len| {
                bytes(a(i), len).and_then(|b| {
                    if b.len() == len {
                        Ok(b)
                    } else {
                        Err(Fail::Input)
                    }
                })
            };
            let seed: Digest = exact(2, 32)?.try_into().map_err(|_| Fail::Input)?;
            let name: [u8; NAME_LEN] = exact(3, NAME_LEN)?.try_into().map_err(|_| Fail::Input)?;
            let cred: [u8; CREDENTIAL_LEN] = exact(4, 32)?.try_into().map_err(|_| Fail::Input)?;
            let mut blob = [0u8; ID_OBJECT_LEN];
            if credential_protect(&seed, &name, &cred, &mut blob) != 0 {
                return Err(Fail::Compute);
            }
            puthex(&blob);
            Ok(())
        }
        (b"signature", 3) => {
            let buf = bytes(a(2), 2048)?;
            let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
            let ret = ecdsa_signature_parse(&buf, &mut r, &mut s);
            out(&format!("rc={ret}\n"));
            if ret == 0 {
                puthex(&r);
                puthex(&s);
            }
            Ok(())
        }
        (b"attest", 3) => attest(args),
        _ => Err(Fail::Input),
    }
}

fn run(args: &[&CStr]) -> c_int {
    if args.len() < 2 {
        return 2;
    }
    match run_case(args) {
        Ok(()) => 0,
        Err(Fail::Compute) => 1,
        Err(Fail::Input) => 2,
    }
}
