// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-register: the measurement register driven against a TPM
//! (SHIRUDO_TPM_TCTI), with the eventlog and certificate where the
//! environment says, and what a shell test asserts on printed. Besides
//! init, loads, tree operations, reads and status, it sets up the NV
//! writer's identity as init would, and makes the attacks the register
//! must withstand: the index recreated, the init branch tried again, and
//! a register of the target's own forged in the real one's place.
//!
//!   test-register writer-create|writer-remove|writer-public|read|status
//!   test-register init <event hex>
//!   test-register load <upatch> <payload hex>
//!   test-register tree <seq> <op> <id> sha256:<hex>
//!   test-register extend-raw <event hex>
//!   test-register pcr <pcr> | pcr-extend <pcr> <digest hex>
//!   test-register ek-public rsa|ecc | recreate | first-write <event hex>
//!   test-register forge <index hex> <pcr> <phase pcr> <event hex> <nonce hex>
//!   test-register evidence <nonce hex> [<challenge>]

use core::ffi::{CStr, c_char, c_int};

use super::{err, helper_main, out, out_bytes, perror, strerror};
use crate::heap::xfree;
use crate::sys::identity::Identity;
use crate::sys::version::shirudo_version_id;
use crate::util::attest::{AttestChallenge, PCR_DEFAULT, attest_evidence_config, challenge_read};
use crate::util::bpf_sys::{
    Attr, BPF_ANY, BPF_MAP_CREATE, bpf_map_freeze, bpf_map_update_elem, bpf_obj_pin,
};
use crate::util::chain::{self, ANCHOR_MAX, ChainInitInfo, ChainStatus, PCR, PCR_MASK, PHASE_PCR};
use crate::util::crypto_openssl::sha256;
use crate::util::eventlog::{self, EventlogInit, NV_INDEX, boot_init, read_boot_id, timestamp};
use crate::util::hex::{decode, encode};
use crate::util::identity::IDENTITY_PIN;
use crate::util::json::JsonEmit;
use crate::util::nv_writer;
use crate::util::tpm::{
    Tpm, TpmAttestation, TpmKey, TpmNvInfo, tpm_ak_create, tpm_close, tpm_ek_create, tpm_key_flush,
    tpm_nv_certify, tpm_nv_define, tpm_nv_extend_first, tpm_nv_info, tpm_nv_read,
    tpm_nv_set_writer, tpm_nv_undefine, tpm_open, tpm_pcr_extend, tpm_pcr_read, tpm_quote,
    tpm_reset_count,
};
use crate::util::tpm_wire::{NV_RSA_BYTES, tpm_register_policy};

helper_main!(shirudo_helper_test_register, run);

const BPF_MAP_TYPE_ARRAY: u32 = 2;

fn hex(b: &[u8]) -> String {
    String::from_utf8_lossy(&encode(b)).into_owned()
}

fn puthex(b: &[u8]) {
    if b.len() <= 1024 {
        out(&format!("{}\n", hex(b)));
    }
}

/// `text` decoded into 32 bytes.
fn digest(text: &CStr) -> Option<[u8; 32]> {
    let mut d = [0u8; 32];
    decode(text.to_bytes(), &mut d).ok().map(|()| d)
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

/// The TPM writer's public identity recorded, as init pins it, before the
/// VM attaches its LSM.
fn writer_create() -> c_int {
    let mut id = Identity::zeroed();
    let ret = (|| {
        let ret = nv_writer::create(&mut id.nv_writer_seed, &mut id.nv_writer_public);
        if ret != 0 {
            return ret;
        }
        let mut name = [0u8; 16];
        name[..15].copy_from_slice(b"shirudo_test_id");
        let fd = match Attr::new()
            .u32(0, BPF_MAP_TYPE_ARRAY)
            .u32(4, size_of::<u32>() as u32)
            .u32(8, size_of::<Identity>() as u32)
            .u32(12, 1)
            .put(28, &name)
            .run(BPF_MAP_CREATE)
        {
            Ok(fd) => fd,
            Err(e) => return -e,
        };
        let zero = 0u32;
        // SAFETY: the map, a key and a value of its sizes, and a C string;
        // the map's fd closed once.
        unsafe {
            let mut ret = bpf_map_update_elem(
                fd,
                (&raw const zero).cast(),
                (&raw const id).cast(),
                BPF_ANY,
            );
            if ret == 0 {
                ret = bpf_map_freeze(fd);
            }
            if ret == 0 {
                ret = bpf_obj_pin(fd, IDENTITY_PIN.as_ptr());
            }
            libc::close(fd);
            ret
        }
    })();
    if ret == 0 {
        return 0;
    }
    err(&format!("TPM writer setup: {}\n", strerror(-ret)));
    1
}

/// The common head of a record of the log: its time, index, digest,
/// type and boot.
fn record_head(e: &mut JsonEmit, index: u32, event: &[u8; 32], ty: &[u8]) {
    let (mut ts, mut boot_id) = ([0u8; 32], [0u8; 64]);
    timestamp(&mut ts);
    read_boot_id(&mut boot_id);
    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"ts", crate::text::cstr(&ts));
    e.kv_string(b"nv_index", format!("0x{index:08X}").as_bytes());
    e.kv_string(b"alg", b"sha256");
    e.kv_string(b"digest", &encode(event));
    e.kv_string(b"type", ty);
    e.kv_string(b"boot_id", crate::text::cstr(&boot_id));
}

/// The record `fill` emits appended to the log.
fn append(fill: impl FnOnce(&mut JsonEmit)) -> c_int {
    let mut buf = [0u8; 4096];
    let mut e = JsonEmit::fixed(&mut buf);
    fill(&mut e);
    if e.err() != 0 {
        return e.err();
    }
    eventlog::append(e.output())
}

/// An init recorded the way shirudo init does, minus the set details.
fn append_init(event: &[u8; 32], info: &ChainInitInfo) -> c_int {
    append(|e| {
        record_head(e, NV_INDEX, event, b"init");
        e.kv_int(b"tpm_reset_count", info.reset_count.into());
        e.kv_int(b"pcr", PCR.into());
        e.kv_string(b"pcr_before", &encode(&info.pcr_before));
        e.kv_int(b"phase_pcr", PHASE_PCR.into());
        e.kv_string(b"phase_before", &encode(&info.phase_before));
        e.kv_string(b"bound_in", if info.initrd { b"initrd" } else { b"root" });
        e.kv_string(b"nv_name", &encode(&info.name[..info.name_len]));
        e.kv_string(b"nv_writer_public", &encode(&info.writer_public));
        e.kv_string(b"anchor", crate::text::cstr(&info.anchor));
        e.kv_string(b"anchor_digest", &encode(&info.anchor_digest));
        e.kv_string(b"chain", &encode(&info.value));
        e.obj_close();
    })
}

fn print_init(event: &[u8; 32]) -> c_int {
    // SAFETY: a record of numbers and arrays, for which zeros are a value.
    let mut info: ChainInitInfo = unsafe { core::mem::zeroed() };
    let ret = chain::init(event, &mut info);
    out(&format!("rc={ret}\n"));
    if ret != 0 {
        return 1;
    }
    out(&format!(
        "reused={}\nreset_count={}\nvalue={}\nname={}\npcr_before={}\nphase_before={}\nbound_in={}\nanchor={}\n",
        c_int::from(info.reused),
        info.reset_count,
        hex(&info.value),
        hex(&info.name[..info.name_len]),
        hex(&info.pcr_before),
        hex(&info.phase_before),
        if info.initrd { "initrd" } else { "root" },
        String::from_utf8_lossy(crate::text::cstr(&info.anchor))
    ));
    c_int::from(!info.reused && append_init(event, &info) != 0)
}

/// `event` extended into the register, its value printed, and `record`
/// appended to the log.
/// What makes the log's record of an extension, given its value.
type Record<'a> = &'a dyn Fn(&mut JsonEmit, &[u8; 32]);

fn extend(event: &[u8; 32], record: Option<Record<'_>>) -> c_int {
    let mut chain = [0u8; 32];
    let ret = chain::extend(event, Some(&mut chain));
    out(&format!("rc={ret}\n"));
    if ret != 0 {
        return 1;
    }
    out("value=");
    puthex(&chain);
    match record {
        Some(fill) => c_int::from(append(|e| fill(e, &chain)) != 0),
        None => 0,
    }
}

fn load(name: &CStr, payload_hex: &CStr) -> c_int {
    let Some(payload) = digest(payload_hex) else {
        return 2;
    };
    let mut event = [0u8; 32];
    if chain::upatch_event(c"shirudo-upatch", name.to_bytes(), &payload, &mut event) != 0 {
        return 1;
    }
    extend(
        &event,
        Some(&|e: &mut JsonEmit, chain: &[u8; 32]| {
            record_head(e, NV_INDEX, &event, b"upatch_load");
            e.obj_open_key(b"upatch");
            e.kv_string(b"name", name.to_bytes());
            e.kv_string(b"payload_sha256", &encode(&payload));
            e.obj_close();
            e.kv_string(b"chain", &encode(chain));
            e.obj_close();
        }),
    )
}

/// A tree operation, with the digest in the form the target records.
fn tree(args: &[&CStr]) -> c_int {
    let seq = atoi(args[2]);
    let (op, id, digest_text) = (args[3], args[4], args[5]);
    let Some(hex_part) = digest_text.to_bytes().strip_prefix(b"sha256:") else {
        return 2;
    };
    let mut operation = [0u8; 32];
    let mut event = [0u8; 32];
    if decode(hex_part, &mut operation).is_err() {
        return 2;
    }
    if chain::tree_event(seq, &operation, &mut event) != 0 {
        return 2;
    }
    extend(
        &event,
        Some(&|e: &mut JsonEmit, chain: &[u8; 32]| {
            record_head(e, NV_INDEX, &event, b"tree_op");
            e.obj_open_key(b"tree");
            e.kv_int(b"seq", seq);
            e.kv_string(b"op", op.to_bytes());
            e.kv_string(b"id", id.to_bytes());
            e.kv_string(b"operation_digest", digest_text.to_bytes());
            e.obj_close();
            e.kv_string(b"chain", &encode(chain));
            e.obj_close();
        }),
    )
}

fn status() -> c_int {
    // SAFETY: a status of numbers and arrays, for which zeros are a value.
    let mut st: Box<ChainStatus> = Box::new(unsafe { core::mem::zeroed() });
    let ret = chain::status(&mut st);
    let b = |v: bool| c_int::from(v);
    out(&format!(
        "rc={ret}\ntpm={} defined={} written={} logged={} anchored={}\nrebound={}\n",
        b(st.tpm),
        b(st.defined),
        b(st.written),
        b(st.logged),
        b(st.anchored),
        b(st.rebound)
    ));
    if st.defined && st.written {
        out("value=");
        puthex(&st.value);
    }
    c_int::from(ret != 0)
}

/// `f` on a TPM connection, closed after; None when it does not open.
fn with_tpm<R>(f: impl FnOnce(*mut Tpm) -> R) -> Option<R> {
    let mut t: *mut Tpm = core::ptr::null_mut();
    // SAFETY: room for the connection, closed once.
    unsafe {
        if tpm_open(&mut t) != 0 {
            tpm_close(t);
            return None;
        }
        let r = f(t);
        tpm_close(t);
        Some(r)
    }
}

fn ek_public(kind: &CStr) -> c_int {
    let Some(ret) = with_tpm(|t| {
        let mut ek = TpmKey::zeroed();
        // SAFETY: the connection and room for the key, flushed after.
        unsafe {
            let ret = tpm_ek_create(t, kind.to_bytes() == b"rsa", &mut ek);
            if ret == 0 {
                out("public=");
                puthex(&ek.public[..ek.public_len]);
                out("name=");
                puthex(&ek.name[..ek.name_len]);
                tpm_key_flush(t, &mut ek);
            }
            ret
        }
    }) else {
        return 1;
    };
    out(&format!("rc={ret}\n"));
    c_int::from(ret != 0)
}

/// The attack: recreate the index with the same public area.
fn recreate() -> c_int {
    // SAFETY: a structure of numbers and arrays, for which zeros are a
    // value.
    let mut nv: TpmNvInfo = unsafe { core::mem::zeroed() };
    let Some(ret) = with_tpm(|t| {
        // SAFETY: the connection, the index's info and its policy.
        unsafe {
            let mut ret = tpm_nv_info(t, NV_INDEX, &mut nv);
            if ret == 0 && nv.defined {
                ret = tpm_nv_undefine(t, NV_INDEX, core::ptr::null(), 0);
            }
            if ret == 0 {
                ret = tpm_nv_define(t, NV_INDEX, nv.policy.as_ptr(), core::ptr::null(), 0);
            }
            if ret == 0 {
                ret = tpm_nv_info(t, NV_INDEX, &mut nv);
            }
            ret
        }
    }) else {
        return 1;
    };
    out(&format!("rc={ret}\n"));
    if ret != 0 {
        return 1;
    }
    out(&format!("written={}\nname=", c_int::from(nv.written)));
    puthex(&nv.name[..nv.name_len]);
    0
}

/// The attack: try the init branch again after the anchor.
fn first_write(event_hex: &CStr) -> c_int {
    let Some(event) = digest(event_hex) else {
        return 2;
    };
    // SAFETY: a record of numbers and arrays, for which zeros are a value.
    let mut rec: Box<EventlogInit> = Box::new(unsafe { core::mem::zeroed() });
    let (mut seed, mut public) = ([0u8; 32], [0u8; NV_RSA_BYTES]);
    if boot_init(&mut rec) != 0 {
        return 2;
    }
    if nv_writer::read(&mut seed, &mut public) != 0 || public != rec.writer_public {
        return 2;
    }
    let values = [rec.pcr_before, rec.phase_before].concat();
    let (mut written, mut init, mut policy) = ([0u8; 32], [0u8; 32], [0u8; 32]);
    // SAFETY: the PCR values, the writer's key and rooms for the policy.
    let ret = unsafe {
        tpm_register_policy(
            PCR_MASK,
            values.as_ptr(),
            2,
            rec.writer_public.as_ptr(),
            written.as_mut_ptr(),
            init.as_mut_ptr(),
            policy.as_mut_ptr(),
        )
    };
    if ret != 0 {
        err(&format!("register policy: {}\n", strerror(-ret)));
        return 1;
    }
    let Some(ret) = with_tpm(|t| {
        // SAFETY: the connection, the writer and the branches.
        unsafe {
            let mut ret = tpm_nv_set_writer(t, seed.as_ptr(), public.as_ptr());
            if ret == 0 {
                ret = tpm_nv_extend_first(
                    t,
                    NV_INDEX,
                    PCR_MASK,
                    written.as_ptr(),
                    init.as_ptr(),
                    event.as_ptr(),
                );
            }
            ret
        }
    }) else {
        return 1;
    };
    out(&format!("rc={ret}\n"));
    c_int::from(ret != 0)
}

/// What forge() made on the TPM, for the evidence it prints.
struct Forged {
    reset: u32,
    before: [u8; 64],
    anchor: [u8; ANCHOR_MAX],
    anchor_digest: [u8; 32],
    value: [u8; 32],
    values: [[u8; 32]; 24],
    ak: TpmKey,
    ek: TpmKey,
    quote: TpmAttestation,
    certify: TpmAttestation,
    nv: TpmNvInfo,
}

/// The register of the target's own at `index`, bound to `pcr` and
/// `phase`, written with `event`, anchored into `pcr`, quoted and
/// certified with `nonce`.
#[allow(clippy::too_many_arguments)]
fn forge_on_tpm(
    t: *mut Tpm,
    f: &mut Forged,
    seed: &[u8; 32],
    public: &[u8; NV_RSA_BYTES],
    index: u32,
    (pcr, phase): (u32, u32),
    event: &[u8; 32],
    nonce: &[u8],
) -> c_int {
    let mask = (1u32 << pcr) | (1u32 << phase);
    let quoted = PCR_DEFAULT | mask;
    let (mut written, mut init, mut policy) = ([0u8; 32], [0u8; 32], [0u8; 32]);
    let mut ak = TpmKey::zeroed();
    let mut ek = TpmKey::zeroed();
    // SAFETY: the connection, its keys and rooms of this helper.
    let ret = unsafe {
        let mut ret = tpm_nv_set_writer(t, seed.as_ptr(), public.as_ptr());
        if ret == 0 {
            ret = tpm_reset_count(t, &mut f.reset);
        }
        if ret == 0 {
            ret = tpm_pcr_read(t, pcr, f.before.as_mut_ptr());
        }
        if ret == 0 {
            ret = tpm_pcr_read(t, phase, f.before.as_mut_ptr().add(32));
        }
        if ret == 0 {
            ret = tpm_register_policy(
                mask,
                f.before.as_ptr(),
                2,
                public.as_ptr(),
                written.as_mut_ptr(),
                init.as_mut_ptr(),
                policy.as_mut_ptr(),
            );
        }
        if ret == 0 {
            ret = tpm_nv_define(t, index, policy.as_ptr(), core::ptr::null(), 0);
        }
        if ret == 0 {
            ret = tpm_nv_extend_first(
                t,
                index,
                mask,
                written.as_ptr(),
                init.as_ptr(),
                event.as_ptr(),
            );
        }
        if ret == 0 {
            ret = tpm_nv_info(t, index, &mut f.nv);
        }
        if ret == 0 {
            ret = chain::anchor(&f.nv.name, &mut f.anchor);
        }
        if ret == 0 {
            match sha256(crate::text::cstr(&f.anchor)) {
                Ok(d) => f.anchor_digest = d,
                Err(e) => ret = e,
            }
        }
        if ret == 0 {
            ret = tpm_pcr_extend(t, pcr, f.anchor_digest.as_ptr());
        }
        if ret == 0 {
            ret = tpm_nv_read(t, index, f.value.as_mut_ptr());
        }
        if ret == 0 {
            ret = tpm_ak_create(t, &mut ak);
        }
        if ret == 0 {
            ret = tpm_ek_create(t, false, &mut ek);
        }
        for i in 0..24 {
            if ret == 0 && quoted & (1 << i) != 0 {
                ret = tpm_pcr_read(t, i, f.values[i as usize].as_mut_ptr());
            }
        }
        if ret == 0 {
            ret = tpm_quote(t, &ak, nonce.as_ptr(), nonce.len(), quoted, &mut f.quote);
        }
        if ret == 0 {
            ret = tpm_nv_certify(t, &ak, index, nonce.as_ptr(), nonce.len(), &mut f.certify);
        }
        ret
    };
    // Flushing scrubs the keys; keep their public parts.
    f.ak = ak;
    f.ek = ek;
    // SAFETY: the connection's keys, flushed once.
    unsafe {
        tpm_key_flush(t, &mut ek);
        tpm_key_flush(t, &mut ak);
    }
    ret
}

/// The attack: a register of the target's own at another handle, bound
/// to PCRs the target can extend and reset at will, written with the init
/// event the operator expects, anchored into one of those PCRs and
/// certified by the genuine attestation key in the real register's place;
/// the attestation document it makes printed.
fn forge(args: &[&CStr]) -> c_int {
    let index_text = args[2].to_bytes();
    let n = index_text
        .iter()
        .take_while(|c| c.is_ascii_hexdigit())
        .count();
    let index = std::str::from_utf8(&index_text[..n])
        .ok()
        .and_then(|d| u32::from_str_radix(d, 16).ok())
        .unwrap_or(0);
    let (pcr, phase) = (atoi(args[3]) as u32, atoi(args[4]) as u32);
    let nonce_hex = args[6].to_bytes();
    let nonce_len = nonce_hex.len() / 2;
    let mut nonce = [0u8; 64];
    let Some(event) = digest(args[5]) else {
        return 2;
    };
    if pcr > 23
        || phase > 23
        || pcr == phase
        || nonce_len == 0
        || nonce_len > nonce.len()
        || decode(nonce_hex, &mut nonce[..nonce_len]).is_err()
    {
        return 2;
    }
    let nonce = &nonce[..nonce_len];
    let (mut seed, mut public) = ([0u8; 32], [0u8; NV_RSA_BYTES]);
    if nv_writer::read(&mut seed, &mut public) != 0 {
        return 1;
    }
    // SAFETY: what the forge fills, all of whose bits zero are a value.
    let mut f: Box<Forged> = Box::new(unsafe { core::mem::zeroed() });
    let Some(ret) = with_tpm(|t| {
        forge_on_tpm(
            t,
            &mut f,
            &seed,
            &public,
            index,
            (pcr, phase),
            &event,
            nonce,
        )
    }) else {
        return 1;
    };
    if ret != 0 {
        out(&format!("rc={ret}\n"));
        return 1;
    }
    let quoted = PCR_DEFAULT | (1u32 << pcr) | (1u32 << phase);
    let (mut ts, mut boot_id) = ([0u8; 32], [0u8; 64]);
    timestamp(&mut ts);
    read_boot_id(&mut boot_id);
    let (ts, boot_id) = (
        crate::text::cstr(&ts).to_vec(),
        crate::text::cstr(&boot_id).to_vec(),
    );
    let nv_index = format!("0x{index:08X}");
    let mut buf = vec![0u8; 32 * 1024];
    let mut e = JsonEmit::fixed(&mut buf);
    // SAFETY: the version ID, a static C string.
    let version_id = unsafe { CStr::from_ptr(&raw const shirudo_version_id) };
    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"kind", b"shirudo-attestation");
    e.kv_string(b"version_id", version_id.to_bytes());
    e.kv_string(b"ts", &ts);
    e.kv_string(b"boot_id", &boot_id);
    e.kv_string(b"nonce", &encode(nonce));
    e.kv_string(b"pcr_bank", b"sha256");
    e.kv_int(b"pcr_mask", quoted.into());
    e.arr_open(b"pcrs");
    for i in (0..24).filter(|i| quoted & (1 << i) != 0) {
        e.obj_open();
        e.kv_int(b"index", i);
        e.kv_string(b"value", &encode(&f.values[i as usize]));
        e.obj_close();
    }
    e.arr_close();
    e.obj_open_key(b"ak");
    e.kv_string(b"public", &encode(&f.ak.public[..f.ak.public_len]));
    e.kv_string(b"name", &encode(&f.ak.name[..f.ak.name_len]));
    e.obj_close();
    e.obj_open_key(b"ek");
    e.kv_string(b"type", b"ecc");
    e.kv_string(b"public", &encode(&f.ek.public[..f.ek.public_len]));
    e.kv_string(b"name", &encode(&f.ek.name[..f.ek.name_len]));
    e.obj_close();
    e.obj_open_key(b"quote");
    e.kv_string(b"attest", &encode(&f.quote.attest[..f.quote.attest_len]));
    e.kv_string(
        b"signature",
        &encode(&f.quote.signature[..f.quote.signature_len]),
    );
    e.obj_close();
    e.obj_open_key(b"register");
    e.kv_string(b"nv_index", nv_index.as_bytes());
    e.kv_int(b"pcr", pcr.into());
    e.kv_string(b"name", &encode(&f.nv.name[..f.nv.name_len]));
    e.kv_string(b"value", &encode(&f.value));
    e.kv_string(
        b"attest",
        &encode(&f.certify.attest[..f.certify.attest_len]),
    );
    e.kv_string(
        b"signature",
        &encode(&f.certify.signature[..f.certify.signature_len]),
    );
    e.obj_close();
    e.arr_open(b"eventlog");
    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"ts", &ts);
    e.kv_string(b"nv_index", nv_index.as_bytes());
    e.kv_string(b"alg", b"sha256");
    e.kv_string(b"digest", &encode(&event));
    e.kv_string(b"type", b"init");
    e.kv_string(b"boot_id", &boot_id);
    e.kv_int(b"tpm_reset_count", f.reset.into());
    e.kv_int(b"pcr", pcr.into());
    e.kv_string(b"pcr_before", &encode(&f.before[..32]));
    e.kv_int(b"phase_pcr", phase.into());
    e.kv_string(b"phase_before", &encode(&f.before[32..]));
    e.kv_string(b"bound_in", b"initrd");
    e.kv_string(b"nv_name", &encode(&f.nv.name[..f.nv.name_len]));
    e.kv_string(b"nv_writer_public", &encode(&public));
    e.kv_string(b"anchor", crate::text::cstr(&f.anchor));
    e.kv_string(b"anchor_digest", &encode(&f.anchor_digest));
    e.kv_string(b"chain", &encode(&f.value));
    e.obj_close();
    e.arr_close();
    e.kv_null(b"credential");
    e.kv_null(b"ek_certificate");
    e.obj_open_key(b"logs");
    e.kv_null(b"firmware");
    e.kv_null(b"systemd");
    e.obj_close();
    e.obj_close();
    if e.err() != 0 {
        return 1;
    }
    out_bytes(e.output());
    out("\n");
    0
}

fn evidence(args: &[&CStr]) -> c_int {
    let nonce_hex = args[2].to_bytes();
    let nonce_len = nonce_hex.len() / 2;
    let mut nonce = [0u8; 64];
    if nonce_len > nonce.len() || decode(nonce_hex, &mut nonce[..nonce_len]).is_err() {
        return 2;
    }
    let mut challenge = None;
    if let Some(path) = args.get(3) {
        match challenge_read(path) {
            Ok(read) => challenge = Some(read),
            Err(_) => {
                err("evidence: bad challenge\n");
                return 2;
            }
        }
    }
    let c: *const AttestChallenge = challenge
        .as_ref()
        .map_or(core::ptr::null(), core::ptr::from_ref);
    let (mut doc, mut len, mut cap): (*mut c_char, usize, usize) = (core::ptr::null_mut(), 0, 0);
    // SAFETY: the nonce, the challenge or NULL, no journal, and rooms for
    // the document, freed after.
    unsafe {
        let ret = attest_evidence_config(
            nonce.as_ptr(),
            nonce_len,
            PCR_DEFAULT,
            c,
            core::ptr::null_mut(),
            &mut doc,
            &mut len,
            &mut cap,
        );
        if ret != 0 {
            err(&format!("evidence: {}\n", strerror(-ret)));
            return 1;
        }
        out_bytes(crate::ffi::slice(doc.cast::<u8>(), len));
        out("\n");
        xfree(doc.cast(), cap);
    }
    0
}

fn run(args: &[&CStr]) -> c_int {
    if args.len() < 2 {
        return 2;
    }
    let mut chain = [0u8; 32];
    match (args[1].to_bytes(), args.len()) {
        (b"writer-create", 2) => writer_create(),
        (b"writer-remove", 2) => {
            // SAFETY: a C string.
            if unsafe { libc::unlink(IDENTITY_PIN.as_ptr()) } != 0 {
                perror("unlink protocol-test identity");
                return 1;
            }
            0
        }
        (b"writer-public", 2) => {
            let (mut seed, mut public) = ([0u8; 32], [0u8; NV_RSA_BYTES]);
            if nv_writer::read(&mut seed, &mut public) != 0 {
                return 1;
            }
            puthex(&public);
            0
        }
        (b"init", 3) => match digest(args[2]) {
            Some(event) => print_init(&event),
            None => 2,
        },
        (b"load", 4) => load(args[2], args[3]),
        (b"tree", 6) => tree(args),
        (b"extend-raw", 3) => match digest(args[2]) {
            Some(event) => extend(&event, None),
            None => 2,
        },
        (b"read", _) => {
            let ret = chain::read(&mut chain);
            out(&format!("rc={ret}\n"));
            if ret != 0 {
                return 1;
            }
            out("value=");
            puthex(&chain);
            0
        }
        (b"status", _) => status(),
        // A measurement into a PCR, as systemd's boot phases make them.
        (b"pcr-extend", 4) => {
            let Some(d) = digest(args[3]) else {
                return 2;
            };
            // SAFETY: the connection and the digest.
            match with_tpm(|t| unsafe { tpm_pcr_extend(t, atoi(args[2]) as u32, d.as_ptr()) }) {
                Some(ret) => {
                    out(&format!("rc={ret}\n"));
                    c_int::from(ret != 0)
                }
                None => 2,
            }
        }
        (b"pcr", 3) => {
            let mut v = [0u8; 32];
            // SAFETY: the connection and room for the PCR.
            match with_tpm(|t| unsafe { tpm_pcr_read(t, atoi(args[2]) as u32, v.as_mut_ptr()) }) {
                Some(0) => {
                    puthex(&v);
                    0
                }
                _ => 1,
            }
        }
        // The endorsement key of a type, as a target without a certificate
        // presents it.
        (b"ek-public", 3) => ek_public(args[2]),
        (b"recreate", _) => recreate(),
        (b"first-write", 3) => first_write(args[2]),
        (b"forge", 7) => forge(args),
        (b"evidence", 3 | 4) => evidence(args),
        _ => 2,
    }
}
