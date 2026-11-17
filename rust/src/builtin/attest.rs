// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo attest`: on a target, a TPM-signed evidence document; on the
//! operator, verifying one, predicting the register a set of upatches
//! yields, and making a credential challenge for a target's key.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use std::ffi::CString;

use super::words;
use crate::errno::{EEXIST, EINVAL, EIO, EKEYREJECTED, ENODATA, ENODEV, ENXIO};
use crate::ffi;
use crate::heap::xfree;
use crate::sys::libc::{fwrite, stdout, strerror};
use crate::sys::log::{pr_err, pr_warn};
use crate::text::{cstr, parse_u64};
use crate::util::attest::{
    AttestChallenge, AttestChallengePolicy, AttestExpect, attest_challenge_make,
    attest_challenge_read, attest_evidence_config, attest_parse_name_digest,
    attest_parse_pcr_value, attest_parse_pcrs, attest_verify,
};
use crate::util::chain::{
    MeasuredUpatch, chain_anchor, chain_fold, chain_init_event, chain_key_event, chain_tree_event,
    chain_upatch_event,
};
use crate::util::config_measure::config_measure_pcr_valid;
use crate::util::crypto_openssl::sha256_calc;
use crate::util::help::{
    Help, HelpItem, HelpSection, is_help, is_list_cmds, print_help, print_subcmd_list,
    resolve_subcommand,
};
use crate::util::image_runtime;
use crate::util::io::read_file;
use crate::util::json::{JsonEmit, MAX_BYTES};
use crate::util::keys::{KEYS_MAX, keys_anchor_digest};
use crate::util::measured::{measured_set_add, measured_upatch_of};
use crate::util::seal::{SealOutput, seal_output_commit, seal_output_create};
use crate::util::tpm_wire::{tpm_nv_name, tpm_register_policy};
use crate::util::upatch::{self, Upatch, upatch_close, upatch_open};

const NONCE_MAX: usize = 64;
const MEMBERS_MAX: usize = 256;
const REPORT_MAX: usize = 8192;
const PCR_DEFAULT: u32 = 0x0000_FAFF;
const EVENTS_MAX: usize = 256;
const KEYS_DER_MAX: usize = 1024 * 1024;
const NAME_LEN: usize = 34;
const NV_RSA_BYTES: usize = 384;
const CREDENTIAL_LEN: usize = 32;
const NV_INDEX: u32 = 0x0181_8E00;
const REGISTER_ATTRS: u32 = 0x0E06_0048;
const NV_WRITTEN: u32 = 0x2000_0000;
const CHAIN_PCR: u64 = 9;
const CHAIN_PHASE_PCR: u64 = 11;
const CHAIN_PCR_MASK: u32 = (1 << 9) | (1 << 11);
const ANCHOR_MAX: usize = 128;

fn print(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stdout.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stdout) };
}

fn message(parts: &[&[u8]]) -> CString {
    let mut text = parts.concat();

    if let Some(nul) = text.iter().position(|&c| c == 0) {
        text.truncate(nul);
    }
    CString::new(text).unwrap_or_default()
}

fn error(parts: &[&[u8]]) {
    let msg = message(parts);
    // SAFETY: a "%s" format with a C string.
    unsafe { pr_err(c"%s".as_ptr(), msg.as_ptr()) };
}

fn warn(parts: &[&[u8]]) {
    let msg = message(parts);
    // SAFETY: a "%s" format with a C string.
    unsafe { pr_warn(c"%s".as_ptr(), msg.as_ptr()) };
}

fn strerr(err: c_int) -> &'static [u8] {
    // SAFETY: strerror() gives a C string that outlives the message.
    unsafe { ffi::c_str(strerror(err)) }
}

fn hex(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    bytes
        .iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xf)]])
        .collect()
}

/// The `out.len()` bytes exactly twice as many hex digits of either case
/// spell, as hex_decode() takes them.
fn unhex(text: &[u8], out: &mut [u8]) -> bool {
    let digit = |c: u8| char::from(c).to_digit(16);

    if text.len() != 2 * out.len() {
        return false;
    }
    for (b, pair) in out.iter_mut().zip(text.chunks_exact(2)) {
        match (digit(pair[0]), digit(pair[1])) {
            (Some(hi), Some(lo)) => *b = (hi << 4 | lo) as u8,
            _ => return false,
        }
    }
    true
}

/// An even run of at most `2 * out.len()` hex digits: how many bytes,
/// as hex_decode_max() takes it.
fn unhex_max(text: &[u8], out: &mut [u8]) -> Option<usize> {
    if text.len() % 2 != 0 || text.len() / 2 > out.len() {
        return None;
    }
    let n = text.len() / 2;
    unhex(text, &mut out[..n]).then_some(n)
}

/// A valued option: `<name>=<value>` or `<name> <value>`, or one that
/// came last with nothing after it, as opt_arg() reads them.
enum Opt<'a> {
    No,
    Value(&'a [u8]),
    Missing,
}

fn opt<'a>(name: &[u8], arg: &[u8], args: &[&'a [u8]], i: &mut usize) -> Opt<'a> {
    let Some(rest) = arg.strip_prefix(name) else {
        return Opt::No;
    };
    match rest.first() {
        Some(b'=') => Opt::Value(&args[*i][args[*i].len() - rest.len() + 1..]),
        Some(_) => Opt::No,
        None if *i + 1 >= args.len() => Opt::Missing,
        None => {
            *i += 1;
            Opt::Value(args[*i])
        }
    }
}

const fn item(name: &'static CStr, summary: &'static CStr) -> HelpItem {
    HelpItem {
        name: name.as_ptr(),
        summary: summary.as_ptr(),
    }
}

const SUBCMDS: [HelpItem; 3] = [
    item(
        c"verify",
        c"check an evidence document against the expected state",
    ),
    item(
        c"predict",
        c"compute the register value a set of upatches yields",
    ),
    item(
        c"challenge",
        c"make a credential challenge for a target's attestation key",
    ),
];
const ATTEST_OPTIONS: [HelpItem; 4] = [
    item(
        c"--nonce=<hex>",
        c"freshness value from the verifier (up to 64 bytes)",
    ),
    item(
        c"--pcrs=<list>",
        c"PCRs to quote, comma separated (default 0-7,9,11-15)",
    ),
    item(
        c"--challenge=<path>",
        c"a challenge from the verifier to activate while attesting",
    ),
    item(
        c"-o, --output <path>",
        c"write the evidence there (0600) instead of stdout",
    ),
];
const VERIFY_OPTIONS: [HelpItem; 18] = [
    item(c"--evidence=<path>", c"the document a target produced"),
    item(
        c"--nonce=<hex>",
        c"the nonce that document was requested with",
    ),
    item(
        c"--ak-name=<hex>",
        c"the attestation key name pinned at enrollment",
    ),
    item(
        c"--cert=<cert.der>",
        c"a certificate the target enrols (repeatable)",
    ),
    item(c"--upatch=<file>", c"an installed artifact (repeatable)"),
    item(
        c"--expect=<name>=<hex>",
        c"an installed upatch by name and payload digest",
    ),
    item(
        c"--tree-root=<hex>",
        c"the upatch tree projection root at boot",
    ),
    item(
        c"--expect-chain=<hex>",
        c"the register value after the expected events",
    ),
    item(c"--expect-config-root=<hex>", c"approved config image hash"),
    item(c"--expect-config-pcr=<n>", c"reserved config PCR number"),
    item(
        c"--expect-pcr=<n>=<hex>",
        c"a PCR value the quote must carry (repeatable)",
    ),
    item(
        c"--allow-runtime-events",
        c"accept loads, unloads and revocations after boot",
    ),
    item(c"--json", c"print the checks and the verdict as JSON"),
    item(
        c"--strict-anchor",
        c"require the anchoring PCR to hold only the anchor",
    ),
    item(
        c"--expect-credential=<hex>",
        c"the credential the challenge given to the target carried",
    ),
    item(
        c"--ek-name=<hex>",
        c"the endorsement key name pinned at enrollment",
    ),
    item(
        c"--expect-bind-pcr=<n>=<hex>",
        c"a PCR value the register was bound under (repeatable)",
    ),
    item(
        c"--require-initrd",
        c"fail unless init bound the register from the initrd",
    ),
];
const CHALLENGE_OPTIONS: [HelpItem; 6] = [
    item(
        c"--evidence=<path>",
        c"a document the target produced, carrying its keys",
    ),
    item(
        c"--ak-name=<hex>",
        c"the attestation key name the challenge is for",
    ),
    item(
        c"--ek-ca=<bundle>",
        c"PEM issuers the endorsement certificate must chain to",
    ),
    item(
        c"--ek-name=<hex>",
        c"an endorsement key name known out of band",
    ),
    item(
        c"--trust-presented-ek",
        c"accept an endorsement key nothing vouches for",
    ),
    item(c"-o, --output <path>", c"write the challenge there (0600)"),
];
const PREDICT_OPTIONS: [HelpItem; 8] = [
    item(
        c"--cert=<cert.der>",
        c"a certificate the target enrols (repeatable)",
    ),
    item(c"--upatch=<file>", c"an installed artifact (repeatable)"),
    item(
        c"--expect=<name>=<hex>",
        c"an installed upatch by name and payload digest",
    ),
    item(
        c"--tree-root=<hex>",
        c"the upatch tree projection root at boot",
    ),
    item(
        c"--event=<kind>:<name>=<hex>",
        c"a load, unload, tree:<seq> or revoke:<fingerprint> event after boot",
    ),
    item(
        c"--bind-pcr=<n>=<hex>",
        c"PCR 9 and 11 values at binding, for the register name",
    ),
    item(c"--json", c"print the values as JSON"),
    item(
        c"--writer-public=<hex>",
        c"init record's 384-byte RSA modulus (with --bind-pcr)",
    ),
];

fn attest_help() {
    let sections = [
        (c"subcommands:", &SUBCMDS[..]),
        (c"evidence options (target):", &ATTEST_OPTIONS[..]),
        (c"verify options (operator):", &VERIFY_OPTIONS[..]),
        (c"predict options (operator):", &PREDICT_OPTIONS[..]),
        (c"challenge options (operator):", &CHALLENGE_OPTIONS[..]),
    ]
    .map(|(header, items)| HelpSection {
        header: header.as_ptr(),
        items: items.as_ptr(),
        n_items: items.len(),
    });
    let help = Help {
        usage: c"shirudo attest [--nonce=<hex>] [--pcrs=<list>] [--challenge=<path>] [--output=<path>]\n       \
shirudo attest verify --evidence=<path> --nonce=<hex> --ak-name=<hex> [options]\n       \
shirudo attest predict --cert=<cert.der> [options]\n       \
shirudo attest challenge --evidence=<path> --output=<path> --ek-ca=<bundle>|--ek-name=<hex>|--trust-presented-ek [options]"
            .as_ptr(),
        summary: c"Without a subcommand: emit a TPM-signed evidence document for this\n\
target (quote over the PCRs, certification of the measurement register,\n\
this boot's eventlog, the firmware and systemd measurement logs), activating\n\
the verifier's challenge when given one.\n\
verify, predict and challenge run on the operator and touch no TPM."
            .as_ptr(),
        sections: sections.as_ptr(),
        n_sections: sections.len(),
        footer: ptr::null(),
    };

    // SAFETY: the help, its strings constants and its sections live.
    unsafe { print_help(&help) };
}

fn parse_hex32(what: &[u8], text: &[u8], out: &mut [u8; 32]) -> Result<(), ()> {
    if unhex(text, out) {
        return Ok(());
    }
    error(&[b"attest: ", what, b" must be 64 hex characters"]);
    Err(())
}

/// The upatches the init event counts, at most MEMBERS_MAX.
struct Members {
    set: Vec<MeasuredUpatch>,
    n: usize,
}

impl Members {
    fn new() -> Self {
        // SAFETY: an all-zero member is an empty one.
        let set = (0..MEMBERS_MAX)
            .map(|_| unsafe { core::mem::zeroed() })
            .collect();
        Members { set, n: 0 }
    }

    fn add(&mut self, name: &CStr, payload_hex: &CStr) -> c_int {
        // SAFETY: the set's room, its count and two C strings.
        unsafe {
            measured_set_add(
                self.set.as_mut_ptr(),
                &mut self.n,
                MEMBERS_MAX,
                name.as_ptr(),
                payload_hex.as_ptr(),
            )
        }
    }

    fn add_file(&mut self, path: &[u8]) -> Result<(), ()> {
        // SAFETY: an all-zero container is a closed one.
        let mut u: Upatch = unsafe { core::mem::zeroed() };
        // SAFETY: an all-zero member is an empty one.
        let mut e: MeasuredUpatch = unsafe { core::mem::zeroed() };
        let p = message(&[path]);

        // SAFETY: a C string and a container to fill.
        let ret = unsafe { upatch_open(p.as_ptr(), &mut u) };
        if ret != 0 {
            error(&[b"attest: open ", path, b": ", strerr(-ret)]);
            return Err(());
        }
        // SAFETY: the member's room and the open container, then closed.
        unsafe {
            measured_upatch_of(&mut e, &u);
            upatch_close(&mut u);
        }
        let ret = self.add(
            &message(&[cstr(&e.name)]),
            &message(&[cstr(&e.payload_hex)]),
        );
        if ret != 0 {
            let why: &[u8] = if ret == -EEXIST {
                b"a second upatch of that name"
            } else {
                strerr(-ret)
            };
            error(&[b"attest: --upatch ", path, b": ", why]);
            return Err(());
        }
        Ok(())
    }

    fn add_spec(&mut self, spec: &[u8]) -> Result<(), ()> {
        let mut name = [0u8; upatch::NAME_MAX + 1];
        let mut payload = [0u8; 32];
        let s = message(&[spec]);

        // SAFETY: a C string and the room for a name and a digest.
        let mut ret = unsafe {
            attest_parse_name_digest(s.as_ptr(), name.as_mut_ptr().cast(), payload.as_mut_ptr())
        };
        if ret == 0 {
            ret = self.add(&message(&[cstr(&name)]), &message(&[&hex(&payload)]));
        }
        if ret != 0 {
            let why: &[u8] = if ret == -EEXIST {
                b"a second upatch of that name"
            } else if ret == -EINVAL {
                b"not an upatch name and a digest"
            } else {
                strerr(-ret)
            };
            error(&[b"attest: --expect '", spec, b"': ", why]);
            return Err(());
        }
        Ok(())
    }
}

/// A buffer read_file() filled, freed when it goes.
struct File(*mut u8, usize);

impl File {
    fn bytes(&self) -> &[u8] {
        if self.0.is_null() {
            return &[];
        }
        // SAFETY: the len bytes read.
        unsafe { core::slice::from_raw_parts(self.0, self.1) }
    }
}

impl Drop for File {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: read_file()'s buffer of len + 1 bytes.
            unsafe { xfree(self.0.cast(), self.1 + 1) };
        }
    }
}

fn read(path: &[u8], max: usize) -> Result<File, c_int> {
    let mut f = File(ptr::null_mut(), 0);
    let p = message(&[path]);

    // SAFETY: a C string and room for the buffer and its length.
    match unsafe { read_file(p.as_ptr(), max, (&raw mut f.0).cast(), &mut f.1) } {
        0 => Ok(f),
        err => Err(err),
    }
}

/// What the init event counts of a certificate: the SHA-256 of its DER.
fn cert_digest(path: &[u8]) -> Result<[u8; 32], ()> {
    let mut out = [0; 32];
    let ret = match read(path, KEYS_DER_MAX) {
        Ok(der) if der.bytes().is_empty() => -ENODATA,
        Ok(der) => sha256_calc(der.bytes(), &mut out),
        Err(err) => err,
    };

    if ret != 0 {
        error(&[b"attest: --cert ", path, b": ", strerr(-ret)]);
        return Err(());
    }
    Ok(out)
}

/// Folds a `<kind>:<name>=<hex>` event into `chain`.
fn apply_event(spec: &[u8], chain: &mut [u8; 32]) -> Result<(), c_int> {
    let colon = spec.iter().position(|&c| c == b':').ok_or(-EINVAL)?;
    let (kind, rest) = (&spec[..colon], &spec[colon + 1..]);
    let mut name = [0u8; upatch::NAME_MAX + 1];
    let mut digest = [0u8; 32];
    let mut event = [0u8; 32];
    let r = message(&[rest]);

    // SAFETY: a C string and the room for a name and a digest.
    if unsafe {
        attest_parse_name_digest(r.as_ptr(), name.as_mut_ptr().cast(), digest.as_mut_ptr())
    } != 0
    {
        return Err(-EINVAL);
    }
    let name_c = message(&[cstr(&name)]);
    // SAFETY: C strings, the digest and room for the event.
    let failed = unsafe {
        match kind {
            b"load" => chain_upatch_event(
                c"shirudo-upatch".as_ptr(),
                name_c.as_ptr(),
                digest.as_ptr(),
                event.as_mut_ptr(),
            ),
            b"unload" => chain_upatch_event(
                c"shirudo-unload".as_ptr(),
                name_c.as_ptr(),
                digest.as_ptr(),
                event.as_mut_ptr(),
            ),
            b"tree" => {
                let seq = parse_u64(cstr(&name), i64::MAX as u64)
                    .ok()
                    .filter(|&s| s >= 1)
                    .ok_or(-EINVAL)?;
                chain_tree_event(seq as i64, digest.as_ptr(), event.as_mut_ptr())
            }
            b"revoke" => chain_key_event(
                c"shirudo-key-revoke".as_ptr(),
                digest.as_ptr(),
                event.as_mut_ptr(),
            ),
            _ => return Err(-EINVAL),
        }
    } != 0;
    if failed {
        return Err(-EIO);
    }
    // SAFETY: the chain and the event.
    if unsafe { chain_fold(chain.as_mut_ptr(), event.as_ptr()) } != 0 {
        return Err(-EIO);
    }
    Ok(())
}

/// The values predict prints: `key: value` lines, or members of JSON.
struct Predicted {
    json: Option<(Vec<u8>, JsonEmit)>,
}

impl Predicted {
    fn kv(&mut self, key: &[u8], value: &[u8]) {
        match &mut self.json {
            Some((_, e)) => e.kv_string(key, value),
            None => print(&[key, b": ", value, b"\n"].concat()),
        }
    }
}

fn missing(cmd: &[u8], a: &[u8]) {
    error(&[cmd, b": ", a, b" takes a value"]);
}

/// The SHA-256 of the certificates a target enrols, as the init event
/// counts them.
fn anchor_digest(certs: &[[u8; 32]]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];

    // SAFETY: the digests and room for one.
    (unsafe { keys_anchor_digest(certs.as_ptr(), certs.len(), &mut out) } == 0).then_some(out)
}

fn predict(args: &[&[u8]]) -> c_int {
    const CMD: &[u8] = b"attest predict";
    let mut writer_public = [0u8; NV_RSA_BYTES];
    let mut tree_root = [0u8; 32];
    let mut certs: Vec<[u8; 32]> = Vec::new();
    let mut bind = [[0u8; 32]; 2];
    let mut have_bind = [false; 2];
    let mut have_writer = false;
    let mut chain = [0u8; 32];
    let mut events: Vec<&[u8]> = Vec::new();
    let mut m = Members::new();
    let mut json = false;
    let mut i = 2;

    while i < args.len() {
        let a = args[i];
        macro_rules! value {
            ($name:expr) => {
                match opt($name, a, args, &mut i) {
                    Opt::No => None,
                    Opt::Missing => {
                        missing(CMD, a);
                        return 2;
                    }
                    Opt::Value(v) => Some(v),
                }
            };
        }

        if let Some(v) = value!(b"--cert") {
            if certs.len() >= KEYS_MAX {
                error(&[
                    CMD,
                    b": at most ",
                    KEYS_MAX.to_string().as_bytes(),
                    b" --cert",
                ]);
                return 2;
            }
            let Ok(digest) = cert_digest(v) else {
                return 2;
            };
            certs.push(digest);
        } else if let Some(v) = value!(b"--upatch") {
            if m.add_file(v).is_err() {
                return 2;
            }
        } else if let Some(v) = value!(b"--expect") {
            if m.add_spec(v).is_err() {
                return 2;
            }
        } else if let Some(v) = value!(b"--tree-root") {
            if parse_hex32(b"--tree-root", v, &mut tree_root).is_err() {
                return 2;
            }
        } else if let Some(v) = value!(b"--event") {
            if events.len() >= EVENTS_MAX {
                return 2;
            }
            events.push(v);
        } else if let Some(v) = value!(b"--writer-public") {
            if !unhex(v, &mut writer_public) {
                error(&[CMD, b": invalid RSA-3072 --writer-public"]);
                return 2;
            }
            have_writer = true;
        } else if a == b"--json" {
            json = true;
        } else if let Some(v) = value!(b"--bind-pcr") {
            let mut n = 0u64;
            let mut value: *const c_char = ptr::null();
            let vc = message(&[v]);
            // SAFETY: a C string and the rooms for the number and value.
            let slot = match unsafe { attest_parse_pcr_value(vc.as_ptr(), &mut n, &mut value) } {
                0 if n == CHAIN_PCR => Some(0),
                0 if n == CHAIN_PHASE_PCR => Some(1),
                _ => None,
            };
            let parsed = slot.is_some_and(|s| {
                // SAFETY: the value, a C string within the argument.
                let text = unsafe { ffi::c_str(value) };
                parse_hex32(b"--bind-pcr value", text, &mut bind[s]).is_ok()
            });
            if !parsed {
                error(&[CMD, b": --bind-pcr takes 9=<hex> or 11=<hex>"]);
                return 2;
            }
            have_bind[slot.unwrap_or(0)] = true;
        } else if is_help(Some(a)) {
            attest_help();
            return 0;
        } else {
            error(&[CMD, b": unknown option '", a, b"'"]);
            return 2;
        }
        i += 1;
    }
    if certs.is_empty() {
        error(&[CMD, b": --cert is required"]);
        return 2;
    }
    let mut out = Predicted {
        json: json.then(|| {
            let buf = vec![0u8; 4096];
            let e = JsonEmit::fixed(buf.as_ptr().cast_mut().cast(), buf.len());
            (buf, e)
        }),
    };
    if let Some((_, e)) = &mut out.json {
        e.obj_open();
        e.kv_int(b"schema", 1);
    }
    let (mut set_digest, mut init) = ([0u8; 32], [0u8; 32]);
    let ok = anchor_digest(&certs).is_some_and(|cert_sha| {
        // SAFETY: the digest, the set, the root and the rooms.
        let ret = unsafe {
            chain_init_event(
                cert_sha.as_ptr(),
                m.set.as_mut_ptr(),
                m.n,
                tree_root.as_ptr(),
                set_digest.as_mut_ptr(),
                init.as_mut_ptr(),
            )
        };
        ret == 0
    });
    if !ok {
        error(&[CMD, b": cannot hash the init event"]);
        return 2;
    }
    out.kv(b"set_digest", &hex(&set_digest));
    out.kv(b"init_event", &hex(&init));
    // SAFETY: the chain and the event.
    if unsafe { chain_fold(chain.as_mut_ptr(), init.as_ptr()) } != 0 {
        error(&[CMD, b": cannot hash the register at boot"]);
        return 2;
    }
    out.kv(b"register_at_boot", &hex(&chain));
    for ev in &events {
        if apply_event(ev, &mut chain).is_err() {
            error(&[CMD, b": bad --event '", ev, b"'"]);
            return 2;
        }
    }
    if !events.is_empty() {
        out.kv(b"register_after_events", &hex(&chain));
    }
    if have_bind[0] && have_bind[1] {
        let (mut written, mut initial, mut policy) = ([0u8; 32], [0u8; 32], [0u8; 32]);
        let mut name = [0u8; NAME_LEN];
        let mut anchor = [0u8; ANCHOR_MAX];
        let mut anchor_digest = [0u8; 32];

        if !have_writer {
            error(&[CMD, b": --bind-pcr requires --writer-public"]);
            return 2;
        }
        // SAFETY: the two PCR values, the modulus and three rooms.
        let ret = unsafe {
            tpm_register_policy(
                CHAIN_PCR_MASK,
                bind.as_ptr().cast(),
                2,
                writer_public.as_ptr(),
                written.as_mut_ptr(),
                initial.as_mut_ptr(),
                policy.as_mut_ptr(),
            )
        };
        if ret != 0 {
            error(&[CMD, b": cannot compute the signed write policy"]);
            return 1;
        }
        // SAFETY: the policy and room for the name.
        if unsafe {
            tpm_nv_name(
                NV_INDEX,
                REGISTER_ATTRS | NV_WRITTEN,
                policy.as_ptr(),
                32,
                name.as_mut_ptr(),
            )
        } != 0
        {
            error(&[CMD, b": cannot compute the register name"]);
            return 1;
        }
        out.kv(b"register_name", &hex(&name));
        // SAFETY: the name and room for the anchor.
        if unsafe { chain_anchor(name.as_ptr(), anchor.as_mut_ptr().cast(), anchor.len()) } != 0 {
            error(&[CMD, b": the anchor does not fit"]);
            return 2;
        }
        out.kv(b"anchor", cstr(&anchor));
        if sha256_calc(cstr(&anchor), &mut anchor_digest) != 0 {
            error(&[CMD, b": cannot hash the anchor"]);
            return 2;
        }
        // SAFETY: the PCR value and the digest.
        if unsafe { chain_fold(bind[0].as_mut_ptr(), anchor_digest.as_ptr()) } != 0 {
            error(&[CMD, b": cannot hash PCR 9 after the anchor"]);
            return 2;
        }
        out.kv(b"pcr9_after_anchor", &hex(&bind[0]));
    } else if have_bind[0] || have_bind[1] || have_writer {
        error(&[CMD, b": --bind-pcr needs both 9 and 11"]);
        return 2;
    }
    if let Some((buf, e)) = &mut out.json {
        e.obj_close();
        if e.err() != 0 {
            error(&[CMD, b": json encode failed"]);
            return 1;
        }
        print(&[&buf[..e.written()], b"\n"].concat());
    }
    0
}

/// The report as JSON: one check or note per line, OK, FAIL or NOTE then
/// the text.
fn report_json(report: &[u8], verdict: &[u8]) -> c_int {
    let mut buf = vec![0u8; 2 * REPORT_MAX];
    let mut e = JsonEmit::fixed(buf.as_mut_ptr().cast(), buf.len());

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"verdict", verdict);
    e.arr_open(b"checks");
    for line in report.split(|&c| c == b'\n') {
        let kind: &[u8] = match line.get(..8) {
            Some(b"  OK    ") if line.len() > 8 => b"ok",
            Some(b"  FAIL  ") if line.len() > 8 => b"fail",
            Some(b"  NOTE  ") if line.len() > 8 => b"note",
            _ => continue,
        };
        let text = &line[8..];
        e.obj_open();
        e.kv_string(b"result", kind);
        e.kv_string(b"text", &text[..text.len().min(REPORT_MAX - 1)]);
        e.obj_close();
    }
    e.arr_close();
    e.obj_close();
    if e.err() != 0 {
        error(&[b"attest: json encode failed"]);
        return 1;
    }
    let n = e.written();
    print(&[&buf[..n], b"\n"].concat());
    0
}

fn read_evidence(path: &[u8]) -> Result<File, ()> {
    let ret = match read(path, MAX_BYTES) {
        Ok(f) if f.bytes().is_empty() => Err(-ENODATA),
        r => r,
    };

    ret.map_err(|err| error(&[b"attest: evidence ", path, b": ", strerr(-err)]))
}

fn verify(args: &[&[u8]]) -> c_int {
    const CMD: &[u8] = b"attest verify";
    // SAFETY: an all-zero expectation expects nothing.
    let mut x: Box<AttestExpect> = Box::new(unsafe { core::mem::zeroed() });
    let mut nonce = [0u8; NONCE_MAX];
    let mut nonce_len = 0;
    let mut certs: Vec<[u8; 32]> = Vec::new();
    let mut tree_root = [0u8; 32];
    let mut evidence_path: Option<&[u8]> = None;
    let mut m = Members::new();
    let (mut json, mut have_tree_root) = (false, false);
    let mut i = 2;
    let ret = (|| -> c_int {
        while i < args.len() {
            let a = args[i];
            macro_rules! value {
                ($name:expr) => {
                    match opt($name, a, args, &mut i) {
                        Opt::No => None,
                        Opt::Missing => {
                            missing(CMD, a);
                            return 2;
                        }
                        Opt::Value(v) => Some(v),
                    }
                };
            }

            if let Some(v) = value!(b"--evidence") {
                evidence_path = Some(v);
            } else if let Some(v) = value!(b"--nonce") {
                match unhex_max(v, &mut nonce) {
                    Some(n) if n > 0 => nonce_len = n,
                    _ => {
                        error(&[CMD, b": --nonce must be hex of up to 64 bytes"]);
                        return 2;
                    }
                }
            } else if let Some(v) = value!(b"--ak-name") {
                if !unhex(v, &mut x.ak_name) {
                    error(&[CMD, b": --ak-name must be 68 hex characters"]);
                    return 2;
                }
                x.have_ak_name = true;
            } else if let Some(v) = value!(b"--cert") {
                if certs.len() >= KEYS_MAX {
                    error(&[
                        CMD,
                        b": at most ",
                        KEYS_MAX.to_string().as_bytes(),
                        b" --cert",
                    ]);
                    return 2;
                }
                let Ok(digest) = cert_digest(v) else {
                    return 2;
                };
                certs.push(digest);
            } else if let Some(v) = value!(b"--upatch") {
                if m.add_file(v).is_err() {
                    return 2;
                }
            } else if let Some(v) = value!(b"--expect") {
                if m.add_spec(v).is_err() {
                    return 2;
                }
            } else if let Some(v) = value!(b"--tree-root") {
                if parse_hex32(b"--tree-root", v, &mut tree_root).is_err() {
                    return 2;
                }
                have_tree_root = true;
            } else if let Some(v) = value!(b"--expect-config-root") {
                if x.have_config_root
                    || parse_hex32(b"--expect-config-root", v, &mut x.config_root).is_err()
                {
                    return 2;
                }
                x.have_config_root = true;
            } else if let Some(v) = value!(b"--expect-config-pcr") {
                let Ok(pcr) = parse_u64(v, 15) else {
                    return 2;
                };
                if x.have_config_pcr || config_measure_pcr_valid(pcr as u32) != 0 {
                    return 2;
                }
                x.config_pcr = pcr as u32;
                x.have_config_pcr = true;
            } else if let Some(v) = value!(b"--expect-chain") {
                if parse_hex32(b"--expect-chain", v, &mut x.chain).is_err() {
                    return 2;
                }
                x.have_chain = true;
            } else if let Some(v) = value!(b"--expect-pcr") {
                let Some((n, value)) = pcr_value(v) else {
                    return 2;
                };
                if parse_hex32(b"--expect-pcr value", value, &mut x.pcrs[n]).is_err() {
                    return 2;
                }
                x.pcr_expect_mask |= 1 << n;
            } else if a == b"--json" {
                json = true;
            } else if a == b"--allow-runtime-events" {
                x.allow_runtime_events = true;
            } else if a == b"--strict-anchor" {
                x.strict_anchor = true;
            } else if let Some(v) = value!(b"--expect-credential") {
                if parse_hex32(b"--expect-credential", v, &mut x.credential).is_err() {
                    return 2;
                }
                x.have_credential = true;
            } else if let Some(v) = value!(b"--ek-name") {
                if !unhex(v, &mut x.ek_name) {
                    error(&[CMD, b": --ek-name must be 68 hex characters"]);
                    return 2;
                }
                x.have_ek_name = true;
            } else if let Some(v) = value!(b"--expect-bind-pcr") {
                let Some((n, value)) = pcr_value(v) else {
                    return 2;
                };
                if parse_hex32(b"--expect-bind-pcr value", value, &mut x.bind_values[n]).is_err() {
                    return 2;
                }
                x.bind_expect_mask |= 1 << n;
            } else if a == b"--require-initrd" {
                x.require_initrd = true;
            } else if is_help(Some(a)) {
                attest_help();
                return 0;
            } else {
                error(&[CMD, b": unknown option '", a, b"'"]);
                return 2;
            }
            i += 1;
        }
        if x.have_config_root && !x.have_config_pcr {
            error(&[CMD, b": --expect-config-root requires --expect-config-pcr"]);
            return 2;
        }
        let Some(evidence_path) = evidence_path.filter(|_| nonce_len > 0) else {
            error(&[CMD, b": --evidence and --nonce are required"]);
            return 2;
        };
        if certs.is_empty() && (m.n != 0 || have_tree_root) {
            error(&[
                CMD,
                b": --upatch, --expect and --tree-root describe the init event and need --cert",
            ]);
            return 2;
        }
        // The credential proves that the pinned attestation key sits
        // beside the endorsement key; recovered on the target, its value
        // says nothing about which key signed the evidence.
        if x.have_credential && !x.have_ak_name {
            error(&[
                CMD,
                b": --expect-credential needs the key the challenge was made for; give --ak-name",
            ]);
            return 2;
        }
        if !x.have_ak_name {
            warn(&[CMD, b": no --ak-name; the signer is not pinned"]);
        }
        x.nonce = nonce.as_ptr();
        x.nonce_len = nonce_len;
        if !certs.is_empty() {
            let mut set_digest = [0u8; 32];
            let ok = anchor_digest(&certs).is_some_and(|cert_sha| {
                // SAFETY: the digest, the set, the root and the rooms.
                let ret = unsafe {
                    chain_init_event(
                        cert_sha.as_ptr(),
                        m.set.as_mut_ptr(),
                        m.n,
                        tree_root.as_ptr(),
                        set_digest.as_mut_ptr(),
                        x.init_event.as_mut_ptr(),
                    )
                };
                ret == 0
            });
            if !ok {
                error(&[CMD, b": cannot hash the init event"]);
                return 2;
            }
            x.have_init = true;
        }
        let Ok(evidence) = read_evidence(evidence_path) else {
            return 2;
        };
        let mut report = vec![0u8; REPORT_MAX];
        let doc = evidence.bytes();
        // SAFETY: the evidence, the expectation and room for the report.
        let err = unsafe {
            attest_verify(
                doc.as_ptr().cast(),
                doc.len(),
                &*x,
                report.as_mut_ptr().cast(),
                report.len(),
            )
        };
        let report = cstr(&report);
        if err == -EINVAL {
            if !json {
                print(report);
            }
            error(&[
                CMD,
                b": ",
                evidence_path,
                b" is not a shirudo evidence document",
            ]);
            return 2;
        }
        if json {
            let ret = report_json(report, if err != 0 { b"fail" } else { b"ok" });
            return if ret == 0 && err != 0 { 1 } else { ret };
        }
        print(report);
        print(if err != 0 {
            b"verdict: fail\n"
        } else {
            b"verdict: ok\n"
        });
        if err != 0 { 1 } else { 0 }
    })();
    // SAFETY: the expectation, scrubbed before it goes.
    unsafe { ptr::write_bytes(&raw mut *x, 0, 1) };
    ret
}

/// `<n>=<hex>` of a PCR, n its number below 24, as
/// attest_parse_pcr_value() reads it.
fn pcr_value(v: &[u8]) -> Option<(usize, &[u8])> {
    let vc = message(&[v]);
    let mut n = 0u64;
    let mut value: *const c_char = ptr::null();

    // SAFETY: a C string and the rooms for the number and value.
    if unsafe { attest_parse_pcr_value(vc.as_ptr(), &mut n, &mut value) } != 0 {
        return None;
    }
    // SAFETY: the value points into vc, a C string.
    let at = unsafe { value.offset_from(vc.as_ptr()) } as usize;
    Some((n as usize, &v[at..]))
}

fn challenge(args: &[&[u8]]) -> c_int {
    const CMD: &[u8] = b"attest challenge";
    let (mut ak_name, mut ek_name) = ([0u8; NAME_LEN], [0u8; NAME_LEN]);
    let (mut have_ak, mut have_ek, mut trust_presented) = (false, false, false);
    let mut ek_ca: Option<CString> = None;
    let (mut evidence_path, mut out_path): (Option<&[u8]>, Option<&[u8]>) = (None, None);
    let mut i = 2;

    while i < args.len() {
        let a = if args[i] == b"-o" {
            &b"--output"[..]
        } else {
            args[i]
        };
        macro_rules! value {
            ($name:expr) => {
                match opt($name, a, args, &mut i) {
                    Opt::No => None,
                    Opt::Missing => {
                        missing(CMD, a);
                        return 2;
                    }
                    Opt::Value(v) => Some(v),
                }
            };
        }

        if let Some(v) = value!(b"--evidence") {
            evidence_path = Some(v);
        } else if let Some(v) = value!(b"--ek-ca") {
            ek_ca = Some(message(&[v]));
        } else if let Some(v) = value!(b"--ak-name") {
            if !unhex(v, &mut ak_name) {
                error(&[CMD, b": --ak-name must be 68 hex characters"]);
                return 2;
            }
            have_ak = true;
        } else if let Some(v) = value!(b"--ek-name") {
            if !unhex(v, &mut ek_name) {
                error(&[CMD, b": --ek-name must be 68 hex characters"]);
                return 2;
            }
            have_ek = true;
        } else if a == b"--trust-presented-ek" {
            trust_presented = true;
        } else if let Some(v) = value!(b"--output") {
            out_path = Some(v);
        } else if is_help(Some(a)) {
            attest_help();
            return 0;
        } else {
            error(&[CMD, b": unknown option '", a, b"'"]);
            return 2;
        }
        i += 1;
    }
    let (Some(evidence_path), Some(out_path)) = (evidence_path, out_path) else {
        error(&[CMD, b": --evidence and --output are required"]);
        return 2;
    };
    let Ok(evidence) = read_evidence(evidence_path) else {
        return 2;
    };
    let pol = AttestChallengePolicy {
        ek_ca: ek_ca.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
        ak_name: if have_ak {
            ak_name.as_ptr()
        } else {
            ptr::null()
        },
        ek_name: if have_ek {
            ek_name.as_ptr()
        } else {
            ptr::null()
        },
        trust_presented,
    };
    let mut credential = [0u8; CREDENTIAL_LEN];
    let mut report = vec![0u8; REPORT_MAX];
    let (mut doc, mut len, mut cap): (*mut c_char, usize, usize) = (ptr::null_mut(), 0, 0);
    let ev = evidence.bytes();
    // SAFETY: the evidence, the policy, and rooms for the credential, the
    // document and the report.
    let err = unsafe {
        attest_challenge_make(
            ev.as_ptr().cast(),
            ev.len(),
            &pol,
            credential.as_mut_ptr(),
            &mut doc,
            &mut len,
            &mut cap,
            report.as_mut_ptr().cast(),
            report.len(),
        )
    };
    print(cstr(&report));
    let ret = (|| {
        if err == -EINVAL {
            error(&[CMD, b": ", evidence_path, b" carries no endorsement key"]);
            return 2;
        }
        if err != 0 {
            print(b"verdict: fail\n");
            return 1;
        }
        let path = message(&[out_path]);
        let mut out = SealOutput::closed();
        // SAFETY: the output to create and a C string.
        let e = unsafe { seal_output_create(&mut out, path.as_ptr(), 0o600) };
        if e != 0 {
            error(&[CMD, b": open ", out_path, b": ", strerr(-e)]);
            return 1;
        }
        // SAFETY: the output created above and the document's bytes.
        let e = unsafe { seal_output_commit(&mut out, doc.cast(), len) };
        if e != 0 {
            error(&[CMD, b": write ", out_path, b": ", strerr(-e)]);
            return 1;
        }
        print(
            &[
                b"challenge: ",
                out_path,
                b"\ncredential: ",
                &hex(&credential),
                b"\n",
            ]
            .concat(),
        );
        0
    })();
    credential.fill(0);
    // SAFETY: the document's buffer of cap bytes, or NULL.
    unsafe { xfree(doc.cast(), cap) };
    ret
}

fn evidence(args: &[&[u8]]) -> c_int {
    let mut nonce = [0u8; NONCE_MAX];
    let mut nonce_len = 0;
    let mut mask = PCR_DEFAULT;
    let (mut out_path, mut challenge_path): (Option<&[u8]>, Option<&[u8]>) = (None, None);
    let mut i = 1;

    while i < args.len() {
        let a = if args[i] == b"-o" {
            &b"--output"[..]
        } else {
            args[i]
        };
        macro_rules! value {
            ($name:expr) => {
                match opt($name, a, args, &mut i) {
                    Opt::No => None,
                    Opt::Missing => {
                        missing(b"attest", a);
                        return 2;
                    }
                    Opt::Value(v) => Some(v),
                }
            };
        }

        if let Some(v) = value!(b"--challenge") {
            challenge_path = Some(v);
        } else if let Some(v) = value!(b"--nonce") {
            match unhex_max(v, &mut nonce) {
                Some(n) if n > 0 => nonce_len = n,
                _ => {
                    error(&[b"attest: --nonce must be hex of up to 64 bytes"]);
                    return 2;
                }
            }
        } else if let Some(v) = value!(b"--pcrs") {
            let vc = message(&[v]);
            // SAFETY: a C string and room for the mask.
            if unsafe { attest_parse_pcrs(vc.as_ptr(), &mut mask) } != 0 {
                error(&[b"attest: --pcrs takes a comma separated list of 0..23"]);
                return 2;
            }
        } else if let Some(v) = value!(b"--output") {
            out_path = Some(v);
        } else if is_help(Some(a)) {
            attest_help();
            return 0;
        } else {
            error(&[b"attest: unknown option '", a, b"'"]);
            return 2;
        }
        i += 1;
    }
    if nonce_len == 0 {
        warn(&[b"attest: no --nonce; the evidence proves no freshness"]);
    }
    // SAFETY: an all-zero challenge is an empty one.
    let mut challenge: Box<AttestChallenge> = Box::new(unsafe { core::mem::zeroed() });
    if let Some(p) = challenge_path {
        let pc = message(&[p]);
        // SAFETY: a C string and room for the challenge.
        if unsafe { attest_challenge_read(pc.as_ptr(), &mut *challenge) } != 0 {
            error(&[b"attest: ", p, b" is not a shirudo credential challenge"]);
            return 2;
        }
    }
    let request: *const AttestChallenge = if challenge_path.is_some() {
        &*challenge
    } else {
        ptr::null()
    };
    let (mut doc, mut len, mut cap): (*mut c_char, usize, usize) = (ptr::null_mut(), 0, 0);
    // SAFETY: the nonce, the challenge or NULL, the runtime's journal and
    // rooms for the document.
    let ret = unsafe {
        attest_evidence_config(
            nonce.as_ptr(),
            nonce_len,
            mask,
            request,
            image_runtime::update_context().cast(),
            &mut doc,
            &mut len,
            &mut cap,
        )
    };
    match ret {
        0 => {}
        r if r == -ENXIO => {
            error(&[b"attest: no TPM answered (tpm_error)"]);
            return 1;
        }
        r if r == -ENODEV => {
            error(&[b"attest: register 0x01818E00 is not bound this boot (tpm_error); run shirudo init first"]);
            return 1;
        }
        r if r == -EKEYREJECTED => {
            error(&[b"attest: the TPM refused the challenge; the attestation key or the endorsement key is not this TPM's"]);
            return 1;
        }
        r => {
            error(&[b"attest: evidence failed: ", strerr(-r)]);
            return 1;
        }
    }
    // SAFETY: the document's len bytes.
    let body = unsafe { ffi::slice(doc.cast::<u8>(), len) };
    let ret = match out_path {
        Some(p) => {
            let path = message(&[p]);
            let mut out = SealOutput::closed();
            // SAFETY: the output to create and a C string.
            let e = unsafe { seal_output_create(&mut out, path.as_ptr(), 0o600) };
            if e != 0 {
                error(&[b"attest: open ", p, b": ", strerr(-e)]);
                e
            } else {
                // SAFETY: the output created above and the bytes.
                let e = unsafe { seal_output_commit(&mut out, body.as_ptr().cast(), body.len()) };
                if e != 0 {
                    error(&[b"attest: write ", p, b": ", strerr(-e)]);
                }
                e
            }
        }
        None => {
            // SAFETY: the bytes, to the C library's stdout.
            let n = unsafe { fwrite(body.as_ptr().cast(), 1, body.len(), stdout) };
            // SAFETY: a newline, to the C library's stdout.
            let nl = n == body.len()
                && unsafe { crate::sys::libc::fputc(c_int::from(b'\n'), stdout) } >= 0;
            if nl { 0 } else { -EIO }
        }
    };
    // SAFETY: the document's buffer of cap bytes.
    unsafe { xfree(doc.cast(), cap) };
    if ret != 0 { 1 } else { 0 }
}

/// `shirudo attest`.
///
/// # Safety
///
/// `argv` holds `argc` C strings.
unsafe fn attest(argc: c_int, argv: *const *const c_char) -> c_int {
    // SAFETY: the caller's arguments.
    let raw = unsafe { words(argc, argv) };
    // SAFETY: each a C string.
    let args: Vec<&[u8]> = raw.iter().map(|&a| unsafe { ffi::c_str(a) }).collect();

    if args.len() >= 2 && is_help(Some(args[1])) {
        attest_help();
        return 0;
    }
    if args.len() >= 2 && is_list_cmds(Some(args[1])) {
        // SAFETY: items whose names are C strings.
        unsafe { print_subcmd_list(&SUBCMDS) };
        return 0;
    }
    if args.len() >= 2 && args[1].first() != Some(&b'-') {
        // SAFETY: a label, the caller's word and items with names.
        let sub = unsafe { resolve_subcommand(c"attest".as_ptr(), raw[1], &SUBCMDS) };
        if sub.is_null() {
            return 2;
        }
        // SAFETY: the name of one of the items.
        return match unsafe { CStr::from_ptr(sub) }.to_bytes() {
            b"verify" => verify(&args),
            b"challenge" => challenge(&args),
            _ => predict(&args),
        };
    }
    evidence(&args)
}

pub(super) use capi::cmd_attest;

mod capi {
    use core::ffi::{c_char, c_int};

    /// # Safety
    ///
    /// `argv` holds `argc` C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cmd_attest(argc: c_int, argv: *const *const c_char) -> c_int {
        // SAFETY: the caller's arguments.
        unsafe { super::attest(argc, argv) }
    }
}
