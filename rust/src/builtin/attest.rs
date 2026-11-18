// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo attest`: on a target, a TPM-signed evidence document; on the
//! operator, verifying one, predicting the register a set of upatches
//! yields, and making a credential challenge for a target's key.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use std::ffi::CString;

use crate::errno::{EEXIST, EINVAL, EIO, EKEYREJECTED, ENODATA, ENODEV, ENXIO};
use crate::ffi;
use crate::heap::xfree;
use crate::sys::libc::{fwrite, stdout, strerror};
use crate::sys::tss2::NV_WRITTEN;
use crate::text::{cstr, parse_u64};
use crate::util::attest::{
    AttestChallenge, AttestChallengePolicy, AttestExpect, NONCE_MAX, PCR_DEFAULT,
    attest_challenge_make, attest_challenge_read, attest_evidence_config, attest_parse_name_digest,
    attest_parse_pcr_value, attest_parse_pcrs, attest_verify,
};
use crate::util::chain::{
    self, ANCHOR_MAX, MeasuredUpatch, PCR, PCR_MASK as CHAIN_PCR_MASK, PHASE_PCR,
};
use crate::util::config_measure::pcr_valid;
use crate::util::crypto_openssl::sha256_into;
use crate::util::eventlog::NV_INDEX;
use crate::util::help::{
    Help, HelpItem, HelpSection, is_help, is_list_cmds, print_help, print_subcmd_list,
    resolve_subcommand,
};
use crate::util::hex;
use crate::util::image_runtime;
use crate::util::io::read_file;
use crate::util::json::{JsonEmit, MAX_BYTES};
use crate::util::keys::{self, KEYS_MAX};
use crate::util::measured::{measured_set_add, measured_upatch_of};
use crate::util::options::{
    EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OPT_REPEAT, OptParser, OptSpec,
};
use crate::util::seal::{SealOutput, seal_output_commit, seal_output_create};
use crate::util::tpm::REGISTER_ATTRS;
use crate::util::tpm_wire::{
    CREDENTIAL_LEN, NAME_LEN, NV_RSA_BYTES, RegisterPolicy, nv_name, register_policy,
};
use crate::util::upatch::{self, Upatch, upatch_close, upatch_open};

const MEMBERS_MAX: usize = 256;
const REPORT_MAX: usize = 8192;
const EVENTS_MAX: usize = 256;
const KEYS_DER_MAX: usize = 1024 * 1024;
/// The register's PCRs, as the options and messages take them.
const CHAIN_PCR: u64 = PCR as u64;
const CHAIN_PHASE_PCR: u64 = PHASE_PCR as u64;

static SUBCMDS: [HelpItem; 3] = [
    HelpItem::new(
        c"verify",
        c"check an evidence document against the expected state",
    ),
    HelpItem::new(
        c"predict",
        c"compute the register value a set of upatches yields",
    ),
    HelpItem::new(
        c"challenge",
        c"make a credential challenge for a target's attestation key",
    ),
];

const EVIDENCE_NONCE: c_int = 0;
const EVIDENCE_PCRS: c_int = 1;
const EVIDENCE_CHALLENGE: c_int = 2;
const EVIDENCE_OUTPUT: c_int = 3;

static EVIDENCE_OPTS: [OptSpec; 4] = [
    OptSpec::new(
        c"--nonce",
        0,
        0,
        Some(c"<hex>"),
        c"freshness value from the verifier (up to 64 bytes)",
    ),
    OptSpec::new(
        c"--pcrs",
        0,
        0,
        Some(c"<list>"),
        c"PCRs to quote, comma separated (default 0-7,9,11-15)",
    ),
    OptSpec::new(
        c"--challenge",
        0,
        0,
        Some(c"<path>"),
        c"a challenge from the verifier to activate while attesting",
    ),
    OptSpec::new(
        c"--output",
        b'o',
        0,
        Some(c"<path>"),
        c"write the evidence there (0600) instead of stdout",
    ),
];

const VERIFY_EVIDENCE: c_int = 0;
const VERIFY_NONCE: c_int = 1;
const VERIFY_AK_NAME: c_int = 2;
const VERIFY_CERT: c_int = 3;
const VERIFY_UPATCH: c_int = 4;
const VERIFY_EXPECT: c_int = 5;
const VERIFY_TREE_ROOT: c_int = 6;
const VERIFY_EXPECT_CHAIN: c_int = 7;
const VERIFY_EXPECT_CONFIG_ROOT: c_int = 8;
const VERIFY_EXPECT_CONFIG_PCR: c_int = 9;
const VERIFY_EXPECT_PCR: c_int = 10;
const VERIFY_ALLOW_RUNTIME_EVENTS: c_int = 11;
const VERIFY_JSON: c_int = 12;
const VERIFY_STRICT_ANCHOR: c_int = 13;
const VERIFY_EXPECT_CREDENTIAL: c_int = 14;
const VERIFY_EK_NAME: c_int = 15;
const VERIFY_EXPECT_BIND_PCR: c_int = 16;
const VERIFY_REQUIRE_INITRD: c_int = 17;

static VERIFY_OPTS: [OptSpec; 18] = [
    OptSpec::new(
        c"--evidence",
        0,
        0,
        Some(c"<path>"),
        c"the document a target produced",
    ),
    OptSpec::new(
        c"--nonce",
        0,
        0,
        Some(c"<hex>"),
        c"the nonce that document was requested with",
    ),
    OptSpec::new(
        c"--ak-name",
        0,
        0,
        Some(c"<hex>"),
        c"the attestation key name pinned at enrollment",
    ),
    OptSpec::new(
        c"--cert",
        0,
        OPT_REPEAT,
        Some(c"<cert.der>"),
        c"a certificate the target enrols (repeatable)",
    ),
    OptSpec::new(
        c"--upatch",
        0,
        OPT_REPEAT,
        Some(c"<file>"),
        c"an installed artifact (repeatable)",
    ),
    OptSpec::new(
        c"--expect",
        0,
        OPT_REPEAT,
        Some(c"<name>=<hex>"),
        c"an installed upatch by name and payload digest",
    ),
    OptSpec::new(
        c"--tree-root",
        0,
        0,
        Some(c"<hex>"),
        c"the upatch tree projection root at boot",
    ),
    OptSpec::new(
        c"--expect-chain",
        0,
        0,
        Some(c"<hex>"),
        c"the register value after the expected events",
    ),
    OptSpec::new(
        c"--expect-config-root",
        0,
        0,
        Some(c"<hex>"),
        c"approved config image hash",
    ),
    OptSpec::new(
        c"--expect-config-pcr",
        0,
        0,
        Some(c"<n>"),
        c"reserved config PCR number",
    ),
    OptSpec::new(
        c"--expect-pcr",
        0,
        OPT_REPEAT,
        Some(c"<n>=<hex>"),
        c"a PCR value the quote must carry (repeatable)",
    ),
    OptSpec::new(
        c"--allow-runtime-events",
        0,
        0,
        None,
        c"accept loads, unloads and revocations after boot",
    ),
    OptSpec::new(
        c"--json",
        0,
        0,
        None,
        c"print the checks and the verdict as JSON",
    ),
    OptSpec::new(
        c"--strict-anchor",
        0,
        0,
        None,
        c"require the anchoring PCR to hold only the anchor",
    ),
    OptSpec::new(
        c"--expect-credential",
        0,
        0,
        Some(c"<hex>"),
        c"the credential the challenge given to the target carried",
    ),
    OptSpec::new(
        c"--ek-name",
        0,
        0,
        Some(c"<hex>"),
        c"the endorsement key name pinned at enrollment",
    ),
    OptSpec::new(
        c"--expect-bind-pcr",
        0,
        OPT_REPEAT,
        Some(c"<n>=<hex>"),
        c"a PCR value the register was bound under (repeatable)",
    ),
    OptSpec::new(
        c"--require-initrd",
        0,
        0,
        None,
        c"fail unless init bound the register from the initrd",
    ),
];

const CHALLENGE_EVIDENCE: c_int = 0;
const CHALLENGE_AK_NAME: c_int = 1;
const CHALLENGE_EK_CA: c_int = 2;
const CHALLENGE_EK_NAME: c_int = 3;
const CHALLENGE_TRUST_PRESENTED_EK: c_int = 4;
const CHALLENGE_OUTPUT: c_int = 5;

static CHALLENGE_OPTS: [OptSpec; 6] = [
    OptSpec::new(
        c"--evidence",
        0,
        0,
        Some(c"<path>"),
        c"a document the target produced, carrying its keys",
    ),
    OptSpec::new(
        c"--ak-name",
        0,
        0,
        Some(c"<hex>"),
        c"the attestation key name the challenge is for",
    ),
    OptSpec::new(
        c"--ek-ca",
        0,
        0,
        Some(c"<bundle>"),
        c"PEM issuers the endorsement certificate must chain to",
    ),
    OptSpec::new(
        c"--ek-name",
        0,
        0,
        Some(c"<hex>"),
        c"an endorsement key name known out of band",
    ),
    OptSpec::new(
        c"--trust-presented-ek",
        0,
        0,
        None,
        c"accept an endorsement key nothing vouches for",
    ),
    OptSpec::new(
        c"--output",
        b'o',
        0,
        Some(c"<path>"),
        c"write the challenge there (0600)",
    ),
];

const PREDICT_CERT: c_int = 0;
const PREDICT_UPATCH: c_int = 1;
const PREDICT_EXPECT: c_int = 2;
const PREDICT_TREE_ROOT: c_int = 3;
const PREDICT_EVENT: c_int = 4;
const PREDICT_BIND_PCR: c_int = 5;
const PREDICT_JSON: c_int = 6;
const PREDICT_WRITER_PUBLIC: c_int = 7;

static PREDICT_OPTS: [OptSpec; 8] = [
    OptSpec::new(
        c"--cert",
        0,
        OPT_REPEAT,
        Some(c"<cert.der>"),
        c"a certificate the target enrols (repeatable)",
    ),
    OptSpec::new(
        c"--upatch",
        0,
        OPT_REPEAT,
        Some(c"<file>"),
        c"an installed artifact (repeatable)",
    ),
    OptSpec::new(
        c"--expect",
        0,
        OPT_REPEAT,
        Some(c"<name>=<hex>"),
        c"an installed upatch by name and payload digest",
    ),
    OptSpec::new(
        c"--tree-root",
        0,
        0,
        Some(c"<hex>"),
        c"the upatch tree projection root at boot",
    ),
    OptSpec::new(
        c"--event",
        0,
        OPT_REPEAT,
        Some(c"<kind>:<name>=<hex>"),
        c"a load, unload, tree:<seq> or revoke:<fingerprint> event after boot",
    ),
    OptSpec::new(
        c"--bind-pcr",
        0,
        OPT_REPEAT,
        Some(c"<n>=<hex>"),
        c"PCR 9 and 11 values at binding, for the register name",
    ),
    OptSpec::new(c"--json", 0, 0, None, c"print the values as JSON"),
    OptSpec::new(
        c"--writer-public",
        0,
        0,
        Some(c"<hex>"),
        c"init record's 384-byte RSA modulus (with --bind-pcr)",
    ),
];

static SECTIONS: [HelpSection; 5] = [
    HelpSection::items(c"subcommands:", &SUBCMDS),
    HelpSection::options(c"evidence options (target):", &EVIDENCE_OPTS),
    HelpSection::options(c"verify options (operator):", &VERIFY_OPTS),
    HelpSection::options(c"predict options (operator):", &PREDICT_OPTS),
    HelpSection::options(c"challenge options (operator):", &CHALLENGE_OPTS),
];

static HELP: Help = Help::new(
    c"shirudo attest [--nonce=<hex>] [--pcrs=<list>] [--challenge=<path>] [--output=<path>]\n       \
      shirudo attest verify --evidence=<path> --nonce=<hex> --ak-name=<hex> [options]\n       \
      shirudo attest predict --cert=<cert.der> [options]\n       \
      shirudo attest challenge --evidence=<path> --output=<path> \
      --ek-ca=<bundle>|--ek-name=<hex>|--trust-presented-ek [options]",
    Some(
        c"Without a subcommand: emit a TPM-signed evidence document for this\n\
          target (quote over the PCRs, certification of the measurement register,\n\
          this boot's eventlog, the firmware and systemd measurement logs), activating\n\
          the verifier's challenge when given one.\n\
          verify, predict and challenge run on the operator and touch no TPM.",
    ),
    &SECTIONS,
    None,
);

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
    crate::log::err(msg.to_bytes());
}

fn warn(parts: &[&[u8]]) {
    let msg = message(parts);
    crate::log::warn(msg.to_bytes());
}

fn strerr(err: c_int) -> &'static [u8] {
    // SAFETY: strerror() gives a C string that outlives the message.
    unsafe { ffi::c_str(strerror(err)) }
}

/// The value of the option or argument `p` last returned, empty for a
/// flag.
fn value<'a>(p: &OptParser<'a>) -> &'a [u8] {
    p.value().map_or(&[], CStr::to_bytes)
}

/// Reports a usage error of `p`'s command, its message formatted.
fn usage(p: &OptParser<'_>, message: impl AsRef<[u8]>) -> c_int {
    p.usage(message.as_ref());
    EXIT_USAGE
}

/// The nonce of `v`: hex of 1 to NONCE_MAX bytes.
fn nonce_of(p: &OptParser<'_>, v: &[u8], nonce: &mut [u8; NONCE_MAX]) -> Result<usize, c_int> {
    match hex::decode_max(v, nonce) {
        Ok(n) if n > 0 => Ok(n),
        _ => Err(usage(
            p,
            format!("--nonce must be hex of up to {NONCE_MAX} bytes"),
        )),
    }
}

/// A key name of `v`, of the option `what`: 2 * NAME_LEN hex digits.
fn name_of(p: &OptParser<'_>, what: &str, v: &[u8], out: &mut [u8; NAME_LEN]) -> Result<(), c_int> {
    if hex::decode(v, out).is_ok() {
        return Ok(());
    }
    Err(usage(
        p,
        format!("{what} must be {} hex characters", 2 * NAME_LEN),
    ))
}

fn parse_hex32(what: &[u8], text: &[u8], out: &mut [u8; 32]) -> Result<(), c_int> {
    if hex::decode(text, out).is_ok() {
        return Ok(());
    }
    error(&[b"attest: ", what, b" must be 64 hex characters"]);
    Err(EXIT_USAGE)
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

    /// The members added so far.
    fn members(&mut self) -> &mut [MeasuredUpatch] {
        self.set.get_mut(..self.n).unwrap_or_default()
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

    fn add_file(&mut self, path: &[u8]) -> Result<(), c_int> {
        // SAFETY: an all-zero container is a closed one.
        let mut u: Upatch = unsafe { core::mem::zeroed() };
        // SAFETY: an all-zero member is an empty one.
        let mut e: MeasuredUpatch = unsafe { core::mem::zeroed() };
        let p = message(&[path]);

        // SAFETY: a C string and a container to fill.
        let ret = unsafe { upatch_open(p.as_ptr(), &mut u) };
        if ret != 0 {
            error(&[b"attest: open ", path, b": ", strerr(-ret)]);
            return Err(EXIT_USAGE);
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
            return Err(EXIT_USAGE);
        }
        Ok(())
    }

    fn add_spec(&mut self, spec: &[u8]) -> Result<(), c_int> {
        let mut name = [0u8; upatch::NAME_MAX + 1];
        let mut payload = [0u8; 32];
        let s = message(&[spec]);

        // SAFETY: a C string and the room for a name and a digest.
        let mut ret = unsafe {
            attest_parse_name_digest(s.as_ptr(), name.as_mut_ptr().cast(), payload.as_mut_ptr())
        };
        if ret == 0 {
            ret = self.add(
                &message(&[cstr(&name)]),
                &message(&[&hex::encode(&payload)]),
            );
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
            return Err(EXIT_USAGE);
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
fn cert_digest(path: &[u8]) -> Result<[u8; 32], c_int> {
    let mut out = [0; 32];
    let ret = match read(path, KEYS_DER_MAX) {
        Ok(der) if der.bytes().is_empty() => -ENODATA,
        Ok(der) => sha256_into(der.bytes(), &mut out),
        Err(err) => err,
    };

    if ret != 0 {
        error(&[b"attest: --cert ", path, b": ", strerr(-ret)]);
        return Err(EXIT_USAGE);
    }
    Ok(out)
}

/// The certificates of `--cert`: the digest of each, at most KEYS_MAX.
fn cert_add(p: &OptParser<'_>, v: &[u8], certs: &mut Vec<[u8; 32]>) -> Result<(), c_int> {
    if certs.len() >= KEYS_MAX {
        return Err(usage(p, format!("at most {KEYS_MAX} --cert")));
    }
    certs.push(cert_digest(v)?);
    Ok(())
}

/// Folds a `<kind>:<name>=<hex>` event into `register`.
fn apply_event(spec: &[u8], register: &mut [u8; 32]) -> Result<(), c_int> {
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
    let ret = match kind {
        b"load" => chain::upatch_event(c"shirudo-upatch", &name, &digest, &mut event),
        b"unload" => chain::upatch_event(c"shirudo-unload", &name, &digest, &mut event),
        b"tree" => {
            let seq = parse_u64(cstr(&name), i64::MAX as u64)
                .ok()
                .and_then(|s| i64::try_from(s).ok())
                .filter(|&s| s >= 1)
                .ok_or(-EINVAL)?;
            chain::tree_event(seq, &digest, &mut event)
        }
        b"revoke" => chain::key_event(c"shirudo-key-revoke", &digest, &mut event),
        _ => return Err(-EINVAL),
    };
    if ret != 0 || chain::fold(register, &event) != 0 {
        return Err(-EIO);
    }
    Ok(())
}

/// The values predict prints: `key: value` lines, or members of JSON.
struct Predicted<'a> {
    json: Option<JsonEmit<'a>>,
}

impl Predicted<'_> {
    fn kv(&mut self, key: &[u8], value: &[u8]) {
        match &mut self.json {
            Some(e) => e.kv_string(key, value),
            None => print(&[key, b": ", value, b"\n"].concat()),
        }
    }
}

/// The SHA-256 of the certificates a target enrols, as the init event
/// counts them.
fn anchor_digest(certs: &[[u8; 32]]) -> Option<[u8; 32]> {
    keys::anchor_digest(certs).ok()
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

/// A `<n>=<hex>` PCR value of the option `what` into `values`, once for
/// each PCR, which `mask` marks.
fn pcr_expect(
    p: &OptParser<'_>,
    what: &str,
    v: &[u8],
    values: &mut [[u8; 32]; 24],
    mask: &mut u32,
) -> Result<(), c_int> {
    let (n, value) = pcr_value(v).ok_or(EXIT_USAGE)?;

    parse_hex32(format!("{what} value").as_bytes(), value, &mut values[n])?;
    if *mask & (1 << n) != 0 {
        return Err(usage(p, format!("{what} {n} given twice")));
    }
    *mask |= 1 << n;
    Ok(())
}

fn predict(args: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"attest predict", &PREDICT_OPTS, Some(&HELP), args, 2);
    let mut writer_public = [0u8; NV_RSA_BYTES];
    let mut tree_root = [0u8; 32];
    let mut certs = Vec::new();
    let mut bind = [[0u8; 32]; 2];
    let mut have_bind = [false; 2];
    let mut have_writer = false;
    let mut events = Vec::new();
    let mut m = Members::new();
    let mut json = false;

    let parsed = (|| loop {
        let opt = p.next();
        let v = value(&p);
        match opt {
            OPT_END => return Ok(()),
            PREDICT_CERT => cert_add(&p, v, &mut certs)?,
            PREDICT_UPATCH => m.add_file(v)?,
            PREDICT_EXPECT => m.add_spec(v)?,
            PREDICT_TREE_ROOT => parse_hex32(b"--tree-root", v, &mut tree_root)?,
            PREDICT_EVENT => {
                if events.len() >= EVENTS_MAX {
                    return Err(usage(&p, format!("at most {EVENTS_MAX} --event")));
                }
                events.push(v);
            }
            PREDICT_WRITER_PUBLIC => {
                if hex::decode(v, &mut writer_public).is_err() {
                    return Err(usage(&p, "invalid RSA-3072 --writer-public"));
                }
                have_writer = true;
            }
            PREDICT_JSON => json = true,
            PREDICT_BIND_PCR => {
                let slot = pcr_value(v).and_then(|(n, value)| {
                    let s = [CHAIN_PCR, CHAIN_PHASE_PCR]
                        .iter()
                        .position(|&pcr| pcr == n as u64)?;
                    parse_hex32(b"--bind-pcr value", value, &mut bind[s]).ok()?;
                    Some((n, s))
                });
                let Some((n, s)) = slot else {
                    return Err(usage(
                        &p,
                        format!("--bind-pcr takes {CHAIN_PCR}=<hex> or {CHAIN_PHASE_PCR}=<hex>"),
                    ));
                };
                if have_bind[s] {
                    return Err(usage(&p, format!("--bind-pcr {n} given twice")));
                }
                have_bind[s] = true;
            }
            OPT_ARG => {
                p.usage_arg(b"unexpected argument ");
                return Err(EXIT_USAGE);
            }
            OPT_DONE => return Err(0),
            _ => return Err(EXIT_USAGE),
        }
    })();
    if let Err(code) = parsed {
        return code;
    }
    if certs.is_empty() {
        return usage(&p, "--cert is required");
    }
    let mut json_buf = vec![0u8; 4096];
    let mut out = Predicted {
        json: json.then(|| JsonEmit::fixed(&mut json_buf)),
    };
    if let Some(e) = &mut out.json {
        e.obj_open();
        e.kv_int(b"schema", 1);
    }
    let (mut set_digest, mut init, mut register) = ([0u8; 32], [0u8; 32], [0u8; 32]);
    let ok = anchor_digest(&certs).is_some_and(|cert_sha| {
        chain::init_event(
            &cert_sha,
            m.members(),
            &tree_root,
            &mut set_digest,
            &mut init,
        ) == 0
    });
    if !ok {
        error(&[b"attest predict: cannot hash the init event"]);
        return EXIT_USAGE;
    }
    out.kv(b"set_digest", &hex::encode(&set_digest));
    out.kv(b"init_event", &hex::encode(&init));
    if chain::fold(&mut register, &init) != 0 {
        error(&[b"attest predict: cannot hash the register at boot"]);
        return EXIT_USAGE;
    }
    out.kv(b"register_at_boot", &hex::encode(&register));
    for ev in &events {
        if apply_event(ev, &mut register).is_err() {
            error(&[b"attest predict: bad --event '", ev, b"'"]);
            return EXIT_USAGE;
        }
    }
    if !events.is_empty() {
        out.kv(b"register_after_events", &hex::encode(&register));
    }
    if have_bind[0] && have_bind[1] {
        let (mut written, mut initial, mut policy) = ([0u8; 32], [0u8; 32], [0u8; 32]);
        let mut name = [0u8; NAME_LEN];
        let mut anchor = [0u8; ANCHOR_MAX];
        let mut anchor_digest = [0u8; 32];

        if !have_writer {
            error(&[b"attest predict: --bind-pcr requires --writer-public"]);
            return EXIT_USAGE;
        }
        let ret = register_policy(
            CHAIN_PCR_MASK,
            bind.as_flattened(),
            &writer_public,
            RegisterPolicy {
                branch_written: &mut written,
                branch_init: &mut initial,
                policy: &mut policy,
            },
        );
        if ret != 0 {
            error(&[b"attest predict: cannot compute the signed write policy"]);
            return 1;
        }
        if nv_name(
            NV_INDEX,
            REGISTER_ATTRS | NV_WRITTEN,
            &policy,
            32,
            &mut name,
        ) != 0
        {
            error(&[b"attest predict: cannot compute the register name"]);
            return 1;
        }
        out.kv(b"register_name", &hex::encode(&name));
        if chain::anchor(&name, &mut anchor) != 0 {
            error(&[b"attest predict: the anchor does not fit"]);
            return EXIT_USAGE;
        }
        out.kv(b"anchor", cstr(&anchor));
        if sha256_into(cstr(&anchor), &mut anchor_digest) != 0 {
            error(&[b"attest predict: cannot hash the anchor"]);
            return EXIT_USAGE;
        }
        if chain::fold(&mut bind[0], &anchor_digest) != 0 {
            error(&[
                format!("attest predict: cannot hash PCR {CHAIN_PCR} after the anchor").as_bytes(),
            ]);
            return EXIT_USAGE;
        }
        out.kv(
            format!("pcr{CHAIN_PCR}_after_anchor").as_bytes(),
            &hex::encode(&bind[0]),
        );
    } else if have_bind[0] || have_bind[1] || have_writer {
        error(&[format!(
            "attest predict: --bind-pcr needs both {CHAIN_PCR} and {CHAIN_PHASE_PCR}"
        )
        .as_bytes()]);
        return EXIT_USAGE;
    }
    if let Some(e) = &mut out.json {
        e.obj_close();
        if e.err() != 0 {
            error(&[b"attest predict: json encode failed"]);
            return 1;
        }
        print(&[e.output(), b"\n"].concat());
    }
    0
}

/// The report as JSON: one check or note per line, OK, FAIL or NOTE then
/// the text.
fn report_json(report: &[u8], verdict: &[u8]) -> c_int {
    let mut buf = vec![0u8; 2 * REPORT_MAX];
    let mut e = JsonEmit::fixed(&mut buf);

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

fn read_evidence(path: &[u8]) -> Result<File, c_int> {
    let ret = match read(path, MAX_BYTES) {
        Ok(f) if f.bytes().is_empty() => Err(-ENODATA),
        r => r,
    };

    ret.map_err(|err| {
        error(&[b"attest: evidence ", path, b": ", strerr(-err)]);
        EXIT_USAGE
    })
}

fn verify(args: &[&CStr]) -> c_int {
    // SAFETY: an all-zero expectation expects nothing.
    let mut x: Box<AttestExpect> = Box::new(unsafe { core::mem::zeroed() });
    let ret = verify_against(args, &mut x).unwrap_or_else(|code| code);

    // SAFETY: the expectation, scrubbed before it goes.
    unsafe { ptr::write_bytes(&raw mut *x, 0, 1) };
    ret
}

/// attest verify with the expectation `x` its options fill.
fn verify_against(args: &[&CStr], x: &mut AttestExpect) -> Result<c_int, c_int> {
    let mut p = OptParser::new(c"attest verify", &VERIFY_OPTS, Some(&HELP), args, 2);
    let mut nonce = [0u8; NONCE_MAX];
    let mut nonce_len = 0;
    let mut certs = Vec::new();
    let mut tree_root = [0u8; 32];
    let mut evidence_path = None;
    let mut m = Members::new();
    let (mut json, mut have_tree_root) = (false, false);

    loop {
        let opt = p.next();
        let v = value(&p);
        match opt {
            OPT_END => break,
            VERIFY_EVIDENCE => evidence_path = Some(v),
            VERIFY_NONCE => nonce_len = nonce_of(&p, v, &mut nonce)?,
            VERIFY_AK_NAME => {
                name_of(&p, "--ak-name", v, &mut x.ak_name)?;
                x.have_ak_name = true;
            }
            VERIFY_CERT => cert_add(&p, v, &mut certs)?,
            VERIFY_UPATCH => m.add_file(v)?,
            VERIFY_EXPECT => m.add_spec(v)?,
            VERIFY_TREE_ROOT => {
                parse_hex32(b"--tree-root", v, &mut tree_root)?;
                have_tree_root = true;
            }
            VERIFY_EXPECT_CONFIG_ROOT => {
                parse_hex32(b"--expect-config-root", v, &mut x.config_root)?;
                x.have_config_root = true;
            }
            VERIFY_EXPECT_CONFIG_PCR => {
                let pcr = p.number(0, 15).map_err(|_| EXIT_USAGE)? as u32;
                if pcr_valid(pcr) != 0 {
                    return Err(usage(&p, "--expect-config-pcr cannot be 9 or 11"));
                }
                x.config_pcr = pcr;
                x.have_config_pcr = true;
            }
            VERIFY_EXPECT_CHAIN => {
                parse_hex32(b"--expect-chain", v, &mut x.chain)?;
                x.have_chain = true;
            }
            VERIFY_EXPECT_PCR => {
                pcr_expect(&p, "--expect-pcr", v, &mut x.pcrs, &mut x.pcr_expect_mask)?;
            }
            VERIFY_JSON => json = true,
            VERIFY_ALLOW_RUNTIME_EVENTS => x.allow_runtime_events = true,
            VERIFY_STRICT_ANCHOR => x.strict_anchor = true,
            VERIFY_EXPECT_CREDENTIAL => {
                parse_hex32(b"--expect-credential", v, &mut x.credential)?;
                x.have_credential = true;
            }
            VERIFY_EK_NAME => {
                name_of(&p, "--ek-name", v, &mut x.ek_name)?;
                x.have_ek_name = true;
            }
            VERIFY_EXPECT_BIND_PCR => {
                pcr_expect(
                    &p,
                    "--expect-bind-pcr",
                    v,
                    &mut x.bind_values,
                    &mut x.bind_expect_mask,
                )?;
            }
            VERIFY_REQUIRE_INITRD => x.require_initrd = true,
            OPT_ARG => {
                p.usage_arg(b"unexpected argument ");
                return Err(EXIT_USAGE);
            }
            OPT_DONE => return Ok(0),
            _ => return Err(EXIT_USAGE),
        }
    }
    if x.have_config_root && !x.have_config_pcr {
        return Err(usage(
            &p,
            "--expect-config-root requires --expect-config-pcr",
        ));
    }
    let Some(evidence_path) = evidence_path.filter(|_| nonce_len > 0) else {
        return Err(usage(&p, "--evidence and --nonce are required"));
    };
    if certs.is_empty() && (m.n != 0 || have_tree_root) {
        return Err(usage(
            &p,
            "--upatch, --expect and --tree-root describe the init event and need --cert",
        ));
    }
    // The credential proves that the pinned attestation key sits beside
    // the endorsement key; recovered on the target, its value says
    // nothing about which key signed the evidence.
    if x.have_credential && !x.have_ak_name {
        error(&[
            b"attest verify: --expect-credential needs the key the challenge was made for; give --ak-name",
        ]);
        return Err(EXIT_USAGE);
    }
    if !x.have_ak_name {
        warn(&[b"attest verify: no --ak-name; the signer is not pinned"]);
    }
    x.nonce = nonce.as_ptr();
    x.nonce_len = nonce_len;
    if !certs.is_empty() {
        let mut set_digest = [0u8; 32];
        let ok = anchor_digest(&certs).is_some_and(|cert_sha| {
            chain::init_event(
                &cert_sha,
                m.members(),
                &tree_root,
                &mut set_digest,
                &mut x.init_event,
            ) == 0
        });
        if !ok {
            error(&[b"attest verify: cannot hash the init event"]);
            return Err(EXIT_USAGE);
        }
        x.have_init = true;
    }
    let evidence = read_evidence(evidence_path)?;
    let mut report = vec![0u8; REPORT_MAX];
    let doc = evidence.bytes();
    // SAFETY: the evidence, the expectation and room for the report.
    let err = unsafe {
        attest_verify(
            doc.as_ptr().cast(),
            doc.len(),
            x,
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
            b"attest verify: ",
            evidence_path,
            b" is not a shirudo evidence document",
        ]);
        return Err(EXIT_USAGE);
    }
    let verdict: &[u8] = if err != 0 { b"fail" } else { b"ok" };
    if json {
        let ret = report_json(report, verdict);
        return Ok(if ret == 0 && err != 0 { 1 } else { ret });
    }
    print(report);
    print(&[b"verdict: ", verdict, b"\n"].concat());
    Ok(c_int::from(err != 0))
}

fn challenge(args: &[&CStr]) -> c_int {
    let mut credential = [0u8; CREDENTIAL_LEN];
    let ret = challenge_into(args, &mut credential).unwrap_or_else(|code| code);

    // SAFETY: the credential's bytes, scrubbed before they go.
    unsafe { ptr::write_volatile(&mut credential, [0; CREDENTIAL_LEN]) };
    ret
}

/// attest challenge, the credential it makes into `credential`.
fn challenge_into(args: &[&CStr], credential: &mut [u8; CREDENTIAL_LEN]) -> Result<c_int, c_int> {
    let mut p = OptParser::new(c"attest challenge", &CHALLENGE_OPTS, Some(&HELP), args, 2);
    let (mut ak_name, mut ek_name) = ([0u8; NAME_LEN], [0u8; NAME_LEN]);
    let (mut have_ak, mut have_ek, mut trust_presented) = (false, false, false);
    let mut ek_ca: Option<&CStr> = None;
    let (mut evidence_path, mut out_path) = (None, None);

    loop {
        let opt = p.next();
        let v = value(&p);
        match opt {
            OPT_END => break,
            CHALLENGE_EVIDENCE => evidence_path = Some(v),
            CHALLENGE_EK_CA => ek_ca = p.value(),
            CHALLENGE_AK_NAME => {
                name_of(&p, "--ak-name", v, &mut ak_name)?;
                have_ak = true;
            }
            CHALLENGE_EK_NAME => {
                name_of(&p, "--ek-name", v, &mut ek_name)?;
                have_ek = true;
            }
            CHALLENGE_TRUST_PRESENTED_EK => trust_presented = true,
            CHALLENGE_OUTPUT => out_path = Some(v),
            OPT_ARG => {
                p.usage_arg(b"unexpected argument ");
                return Err(EXIT_USAGE);
            }
            OPT_DONE => return Ok(0),
            _ => return Err(EXIT_USAGE),
        }
    }
    let (Some(evidence_path), Some(out_path)) = (evidence_path, out_path) else {
        return Err(usage(&p, "--evidence and --output are required"));
    };
    let evidence = read_evidence(evidence_path)?;
    let pol = AttestChallengePolicy {
        ek_ca: ek_ca.map_or(ptr::null(), CStr::as_ptr),
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
            error(&[
                b"attest challenge: ",
                evidence_path,
                b" carries no endorsement key",
            ]);
            return EXIT_USAGE;
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
            error(&[b"attest challenge: open ", out_path, b": ", strerr(-e)]);
            return 1;
        }
        // SAFETY: the output created above and the document's bytes.
        let e = unsafe { seal_output_commit(&mut out, doc.cast(), len) };
        if e != 0 {
            error(&[b"attest challenge: write ", out_path, b": ", strerr(-e)]);
            return 1;
        }
        print(
            &[
                b"challenge: ",
                out_path,
                b"\ncredential: ",
                &hex::encode(&credential[..]),
                b"\n",
            ]
            .concat(),
        );
        0
    })();
    // SAFETY: the document's buffer of cap bytes, or NULL.
    unsafe { xfree(doc.cast(), cap) };
    Ok(ret)
}

fn evidence(args: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"attest", &EVIDENCE_OPTS, Some(&HELP), args, 1);
    let mut nonce = [0u8; NONCE_MAX];
    let mut nonce_len = 0;
    let mut mask = PCR_DEFAULT;
    let (mut out_path, mut challenge_path) = (None, None);

    loop {
        let opt = p.next();
        let v = value(&p);
        match opt {
            OPT_END => break,
            EVIDENCE_CHALLENGE => challenge_path = Some(v),
            EVIDENCE_NONCE => match nonce_of(&p, v, &mut nonce) {
                Ok(n) => nonce_len = n,
                Err(code) => return code,
            },
            EVIDENCE_PCRS => {
                let list = p.value().map_or(ptr::null(), CStr::as_ptr);
                // SAFETY: a C string and room for the mask.
                if unsafe { attest_parse_pcrs(list, &mut mask) } != 0 {
                    return usage(&p, "--pcrs takes a comma separated list of 0..23");
                }
            }
            EVIDENCE_OUTPUT => out_path = Some(v),
            OPT_ARG => {
                p.usage_arg(b"unexpected argument ");
                return EXIT_USAGE;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    if nonce_len == 0 {
        warn(&[b"attest: no --nonce; the evidence proves no freshness"]);
    }
    // SAFETY: an all-zero challenge is an empty one.
    let mut challenge: Box<AttestChallenge> = Box::new(unsafe { core::mem::zeroed() });
    if let Some(path) = challenge_path {
        let pc = message(&[path]);
        // SAFETY: a C string and room for the challenge.
        if unsafe { attest_challenge_read(pc.as_ptr(), &mut *challenge) } != 0 {
            error(&[b"attest: ", path, b" is not a shirudo credential challenge"]);
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
            error(&[format!(
                "attest: register 0x{NV_INDEX:08X} is not bound this boot (tpm_error); \
                 run shirudo init first"
            )
            .as_bytes()]);
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
        Some(path) => {
            let c = message(&[path]);
            let mut out = SealOutput::closed();
            // SAFETY: the output to create and a C string.
            let e = unsafe { seal_output_create(&mut out, c.as_ptr(), 0o600) };
            if e != 0 {
                error(&[b"attest: open ", path, b": ", strerr(-e)]);
                e
            } else {
                // SAFETY: the output created above and the bytes.
                let e = unsafe { seal_output_commit(&mut out, body.as_ptr().cast(), body.len()) };
                if e != 0 {
                    error(&[b"attest: write ", path, b": ", strerr(-e)]);
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
    c_int::from(ret != 0)
}

/// `shirudo attest` on `args`, its name first.
pub(crate) fn cmd_attest(args: &[&CStr]) -> c_int {
    if let Some(word) = args.get(1) {
        let arg = word.to_bytes();

        if is_help(Some(arg)) {
            print_help(&HELP);
            return 0;
        }
        if is_list_cmds(Some(arg)) {
            print_subcmd_list(&SUBCMDS);
            return 0;
        }
        if arg.first() != Some(&b'-') {
            let Some(sub) = resolve_subcommand(c"attest", word, &SUBCMDS) else {
                return EXIT_USAGE;
            };
            return match sub.to_bytes() {
                b"verify" => verify(args),
                b"challenge" => challenge(args),
                _ => predict(args),
            };
        }
    }
    evidence(args)
}
