// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Attestation: the evidence a target emits, the
//! challenge an operator makes for its keys, and the verification the
//! operator runs against the evidence.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::mem::MaybeUninit;
use core::ptr;

use crate::errno::{
    E2BIG, EAGAIN, EBADMSG, EFBIG, EINTR, EINVAL, EIO, EKEYREJECTED, ENODEV, ENOMEM, ENOSPC, ENXIO,
    EUCLEAN,
};
use crate::ffi;
use crate::heap::{xcalloc, xfree, xmalloc};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    AT_FDCWD, O_CLOEXEC, O_RDONLY, STATX_BASIC_STATS, Statx, close, errno, explicit_bzero,
    getrandom, open, read, scrub, statx,
};
use crate::sys::tss2::NV_WRITTEN;
use crate::sys::version::shirudo_version_id;
use crate::text::capi::{digits, parse_u64, parse_x64, strscpy as c_strscpy};
use crate::text::{cstr, strscpy};
use crate::util::chain::{
    ANCHOR_MAX, PCR as CHAIN_PCR, PCR_MASK as CHAIN_PCR_MASK, PHASE_PCR as CHAIN_PHASE_PCR,
    chain_anchor, chain_fold, chain_key_event, chain_tree_event, chain_upatch_event,
    memneq_explicit,
};
use crate::util::config_attest::{
    Evidence, config_evidence_clear, config_evidence_collect, config_evidence_emit,
    config_evidence_parse, config_evidence_verify,
};
use crate::util::config_update::ConfigUpdate;
use crate::util::crypto_openssl::{
    Cert, CertPubkey, base64_decode, base64_encode, cert_free, cert_pubkey, cert_read_der,
    cert_verify_chain, ecdh_p256_ephemeral, rsa_oaep_encrypt, sha256, sha256_into,
};
use crate::util::eventlog::{
    NV_INDEX, eventlog_boot_id, eventlog_boot_lines, eventlog_path, eventlog_timestamp,
};
use crate::util::hex::{hex_decode, hex_decode_max, hex_encode, sha256_digest_decode};
use crate::util::io::read_file;
use crate::util::json::{JsonEmit, JsonField, MAX_BYTES as JSON_MAX_BYTES, parse_schema};
use crate::util::tpm::{
    ATTEST_MAX, EK_ATTRS, PUBLIC_MAX, REGISTER_ATTRS, SIGNATURE_MAX, Tpm, TpmAttestation, TpmKey,
    TpmNvInfo, tpm_activate_credential, tpm_ak_create, tpm_close, tpm_ek_certificate,
    tpm_ek_create, tpm_key_flush, tpm_nv_certify, tpm_nv_info, tpm_nv_read, tpm_open, tpm_pcr_read,
    tpm_quote,
};
use crate::util::tpm_wire::{
    ALG_ECC, ALG_RSA, CREDENTIAL_LEN, EK_POLICY, ID_OBJECT_LEN, NAME_LEN, NV_RSA_BYTES,
    ST_ATTEST_NV, ST_ATTEST_QUOTE, TpmAttest, TpmEccPublic, TpmPublic, attest_signer,
    attest_verify as signature_verify, tpm_attest_parse, tpm_credential_protect,
    tpm_ecc_public_parse, tpm_kdfe, tpm_nv_name, tpm_object_name, tpm_public_parse,
    tpm_register_policy,
};
use crate::util::upatch::{NAME_MAX as UPATCH_NAME_MAX, upatch_name_valid};

const FIRMWARE_LOG_PATH: &CStr = c"/sys/kernel/security/tpm0/binary_bios_measurements";
const SYSTEMD_LOG_PATH: &CStr = c"/run/log/systemd/tpm2-measure.log";
const LOG_MAX_BYTES: usize = 2 * 1024 * 1024;
const EK_CERT_MAX: usize = 4096;
const QUOTE_ATTEMPTS: u32 = 3;
const RECORDS_MAX: usize = 4096;
const EK_CERT_B64_MAX: usize = 4 * EK_CERT_MAX.div_ceil(3) + 1;
/// restricted | sign | fixedTPM | fixedParent | sensitiveDataOrigin
const AK_ATTRS_REQUIRED: u32 = 0x0005_0032;
/// The longest nonce.
pub(crate) const NONCE_MAX: usize = 64;
/// The PCRs a quote covers when
/// the operator names none.
pub(crate) const PCR_DEFAULT: u32 = 0x0000_FAFF;
/// The longest challenge.
const CHALLENGE_MAX: usize = 16 * 1024;
/// The label of a credential's seed, which the TPM takes with its NUL.
const IDENTITY: &CStr = c"IDENTITY";

/// `struct attest_challenge`: the blob and the encrypted seed
/// TPM2_ActivateCredential takes, for the attestation key of a name under
/// the endorsement key of a type.
#[repr(C)]
pub struct AttestChallenge {
    ek_rsa: bool,
    ak_name: [u8; NAME_LEN],
    blob: [u8; ID_OBJECT_LEN],
    blob_len: usize,
    secret: [u8; 256],
    secret_len: usize,
}

/// `struct attest_challenge_policy`: what the operator vouches for.
#[repr(C)]
pub struct AttestChallengePolicy {
    /// Issuer bundle, or NULL.
    pub(crate) ek_ca: *const c_char,
    /// Pinned attestation key, or NULL.
    pub(crate) ak_name: *const u8,
    /// Pinned endorsement key, or NULL.
    pub(crate) ek_name: *const u8,
    /// Accept an unvouched endorsement key.
    pub(crate) trust_presented: bool,
}

/// `struct attest_expect`: what the operator expects the evidence to
/// show.
#[repr(C)]
pub struct AttestExpect {
    pub(crate) nonce: *const u8,
    pub(crate) nonce_len: usize,
    pub(crate) have_ak_name: bool,
    pub(crate) ak_name: [u8; NAME_LEN],
    pub(crate) have_chain: bool,
    pub(crate) chain: [u8; 32],
    /// Cert, set and tree root known.
    pub(crate) have_init: bool,
    pub(crate) init_event: [u8; 32],
    pub(crate) allow_runtime_events: bool,
    pub(crate) strict_anchor: bool,
    pub(crate) pcr_expect_mask: u32,
    pub(crate) pcrs: [[u8; 32]; 24],
    pub(crate) have_credential: bool,
    pub(crate) credential: [u8; CREDENTIAL_LEN],
    pub(crate) have_ek_name: bool,
    pub(crate) ek_name: [u8; NAME_LEN],
    /// The binding must be the initrd's.
    pub(crate) require_initrd: bool,
    /// PCR values at binding time.
    pub(crate) bind_expect_mask: u32,
    pub(crate) bind_values: [[u8; 32]; 24],
    pub(crate) have_config_root: bool,
    pub(crate) config_root: [u8; 32],
    pub(crate) have_config_pcr: bool,
    pub(crate) config_pcr: u32,
}

const _: () = assert!(size_of::<AttestChallenge>() == 376);
const _: () = assert!(size_of::<AttestChallengePolicy>() == 32);
const _: () = assert!(size_of::<AttestExpect>() == 1776);

/// `struct record`: an eventlog record as the report names it.
#[repr(C)]
struct Record {
    ty: [u8; 16],
    label: [u8; UPATCH_NAME_MAX + 64],
    digest: [u8; 32],
    /// The digest follows from the record's fields.
    derived: bool,
}

/// `struct init_record`: the boot's last init record.
#[repr(C)]
struct InitRecord {
    writer_public: [u8; NV_RSA_BYTES],
    present: bool,
    have_reset_count: bool,
    initrd: bool,
    reset_count: u32,
    pcr: u32,
    phase_pcr: u32,
    digest: [u8; 32],
    pcr_before: [u8; 32],
    phase_before: [u8; 32],
    name: [u8; NAME_LEN],
    anchor_digest: [u8; 32],
    chain: [u8; 32],
    anchor: [u8; ANCHOR_MAX],
}

/// `struct parse`: what the evidence's schema reads into, laid out as
/// the C's, whose size it is allocated by.
#[repr(C)]
struct Parse {
    writer_public_hex: [u8; 2 * NV_RSA_BYTES + 1],
    nonce_hex: [u8; 2 * NONCE_MAX + 1],
    pcr_mask: i64,
    ak_public_hex: [u8; 2 * PUBLIC_MAX + 1],
    ak_name_hex: [u8; 2 * NAME_LEN + 1],
    quote_attest_hex: [u8; 2 * ATTEST_MAX + 1],
    quote_sig_hex: [u8; 2 * SIGNATURE_MAX + 1],
    ek_type: [u8; 8],
    ek_public_hex: [u8; 2 * PUBLIC_MAX + 1],
    ek_name_hex: [u8; 2 * NAME_LEN + 1],
    cred_hex: [u8; 2 * CREDENTIAL_LEN + 1],
    reg_index: [u8; 16],
    reg_pcr: i64,
    reg_name_hex: [u8; 2 * NAME_LEN + 1],
    reg_value_hex: [u8; 65],
    reg_attest_hex: [u8; 2 * ATTEST_MAX + 1],
    reg_sig_hex: [u8; 2 * SIGNATURE_MAX + 1],
    pcr_index: i64,
    pcr_value_hex: [u8; 65],
    pcr_have: u32,
    pcrs: [[u8; 32]; 24],
    ty: [u8; 16],
    digest_hex: [u8; 65],
    pcr_before_hex: [u8; 65],
    phase_before_hex: [u8; 65],
    bound_in: [u8; 8],
    nv_name_hex: [u8; 2 * NAME_LEN + 1],
    anchor: [u8; ANCHOR_MAX],
    anchor_digest_hex: [u8; 65],
    chain_hex: [u8; 65],
    rec_pcr: i64,
    rec_phase_pcr: i64,
    rec_reset: i64,
    upatch_name: [u8; UPATCH_NAME_MAX + 1],
    upatch_payload_hex: [u8; 65],
    tree_id: [u8; UPATCH_NAME_MAX + 1],
    tree_op: [u8; 16],
    /// `sizeof("sha256:") + 64`.
    tree_digest_hex: [u8; 8 + 64],
    tree_seq: i64,
    key_fingerprint: [u8; 65],
    key_sha_hex: [u8; 65],
    recs: *mut Record,
    n_recs: usize,
    /// Init records this boot.
    inits: u32,
    /// Those for the last reset count.
    inits_epoch: u32,
    init: InitRecord,
}

const _: () = assert!(size_of::<Record>() == 369);
const _: () = assert!(size_of::<InitRecord>() == 724);
const _: () = assert!(size_of::<Parse>() == 11064);

/// A structure all of whose bits zeroed are a value of it, as `= {}` and
/// memset() give it in C.
fn zeroed<T>() -> T {
    // SAFETY: called only for structures of integers, booleans, arrays
    // and pointers, for which all-zero bytes are a value.
    unsafe { MaybeUninit::zeroed().assume_init() }
}

/// The file at `path`, read to its end and at most LOG_MAX_BYTES, as
/// base64 into `*out`, xmalloc'd to `*out_cap` bytes. securityfs reports
/// a size of 0 for the firmware event log, so the log is read to its end
/// rather than for the size a stat gives.
fn read_file_base64(path: &CStr, out: &mut *mut c_char, out_cap: &mut usize) -> c_int {
    let mut len = 0usize;
    let mut ret = 0;

    *out = ptr::null_mut();
    *out_cap = 0;
    // SAFETY: a C string.
    let fd = unsafe { open(path.as_ptr(), O_RDONLY | O_CLOEXEC) };
    if fd < 0 {
        return -errno();
    }
    // SAFETY: an allocation, freed below by its size.
    let raw = unsafe { xmalloc(LOG_MAX_BYTES + 1) }.cast::<u8>();
    if raw.is_null() {
        // SAFETY: the file's descriptor, closed once.
        unsafe { close(fd) };
        return -ENOMEM;
    }
    while len <= LOG_MAX_BYTES {
        // SAFETY: the file's descriptor and the room left in the
        // allocation.
        let got = unsafe { read(fd, raw.add(len).cast(), LOG_MAX_BYTES + 1 - len) };

        if got < 0 && errno() == EINTR {
            continue;
        }
        if got < 0 {
            ret = -errno();
        }
        if got <= 0 {
            break;
        }
        len += got as usize;
    }
    // SAFETY: the file's descriptor, closed once.
    unsafe { close(fd) };
    if ret == 0 && (len == 0 || len > LOG_MAX_BYTES) {
        ret = -EFBIG;
    }
    if ret != 0 {
        // SAFETY: the allocation, by its size.
        unsafe { xfree(raw.cast(), LOG_MAX_BYTES + 1) };
        return ret;
    }
    let cap = 4 * len.div_ceil(3) + 1;
    // SAFETY: an allocation of cap bytes, the log's base64 into it, and
    // the log freed by its size.
    unsafe {
        *out = xmalloc(cap).cast();
        ret = if (*out).is_null() {
            -ENOMEM
        } else {
            base64_encode(raw, len, *out, cap)
        };
        xfree(raw.cast(), LOG_MAX_BYTES + 1);
    }
    if ret != 0 {
        // SAFETY: the allocation, or NULL, by its size.
        unsafe { xfree((*out).cast(), cap) };
        *out = ptr::null_mut();
        return ret;
    }
    *out_cap = cap;
    0
}

/// What the eventlog's walk calls with each line: the line as it stands,
/// into the evidence's array.
///
/// # Safety
///
/// `ctx` is the emitter and `line` holds `len` bytes.
unsafe extern "C" fn emit_line(line: *const c_char, len: usize, ctx: *mut c_void) -> c_int {
    // SAFETY: the walk passes back the emitter, which nothing else
    // touches during it, and the line.
    unsafe { (*ctx.cast::<JsonEmit>()).raw(ffi::slice(line.cast(), len)) };
    0
}

/// `data` as hex under `key`; more than an attestation's worth stops the
/// emitter with -E2BIG.
fn emit_hex(e: &mut JsonEmit, key: &[u8], data: &[u8]) {
    let mut hex = [0u8; 2 * ATTEST_MAX + 1];

    if data.len() > ATTEST_MAX {
        e.set_err(-E2BIG);
        return;
    }
    // SAFETY: the bytes, and room for their hex and a NUL.
    unsafe { hex_encode(data.as_ptr(), data.len(), hex.as_mut_ptr().cast()) };
    e.kv_string(key, &hex[..2 * data.len()]);
}

/// The digest a quote over `mask` carries: SHA-256 of the PCR values
/// it selects, in index order. None where the hash fails, which the
/// target and the operator alike take as a digest that does not match.
fn pcr_values_digest(mask: u32, values: &[[u8; 32]; 24]) -> Option<[u8; 32]> {
    let selected: Vec<u8> = (0..values.len())
        .filter(|&i| mask & (1 << i) != 0)
        .flat_map(|i| values[i])
        .collect();

    sha256(&selected).ok()
}

/// Whether the quote covers the PCR values read beside it, which alone
/// makes it acceptable.
fn quote_covers(quote: &TpmAttestation, mask: u32, values: &[[u8; 32]; 24]) -> bool {
    let mut a: TpmAttest = zeroed();

    // SAFETY: the quote's bytes, and room for what they hold.
    if unsafe { tpm_attest_parse(quote.attest.as_ptr(), quote.attest_len, &mut a) } != 0
        || a.ty != ST_ATTEST_QUOTE
        || a.pcr_mask != mask
    {
        return false;
    }
    pcr_values_digest(mask, values).is_some_and(|d| !memneq_explicit(&d, &a.pcr_digest))
}

/// What attest_evidence_config() holds across its steps, freed and wiped
/// after them.
struct Evidencing {
    tpm: *mut Tpm,
    ak: TpmKey,
    ek: TpmKey,
    ak_copy: TpmKey,
    ek_copy: TpmKey,
    cred: [u8; CREDENTIAL_LEN],
    cred_len: usize,
    ek_cert: *mut u8,
    ek_b64: *mut c_char,
    ek_b64_cap: usize,
    fw: *mut c_char,
    fw_cap: usize,
    sd: *mut c_char,
    sd_cap: usize,
}

/// memzero_explicit() of a key, every byte of it.
fn scrub_key(k: &mut TpmKey) {
    // SAFETY: the key's bytes, which it owns whole.
    unsafe { explicit_bzero(ptr::from_mut(k).cast(), size_of::<TpmKey>()) };
}

/// attest_evidence_config(): the target's register, its quoted PCRs, its
/// keys and logs, and the config it runs, as a NUL-terminated document
/// into `*out`, xmalloc'd to `*cap` bytes.
///
/// # Safety
///
/// `nonce` holds `nonce_len` bytes, `c` is NULL or a challenge, and
/// `update` NULL or a journal.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn evidence_config(
    nonce: *const u8,
    nonce_len: usize,
    pcr_mask: u32,
    c: *const AttestChallenge,
    update: *mut ConfigUpdate,
    out: &mut *mut c_char,
    len: &mut usize,
    cap: &mut usize,
) -> c_int {
    let mut config: Evidence = zeroed();

    *out = ptr::null_mut();
    *len = 0;
    *cap = 0;
    if nonce_len > NONCE_MAX || pcr_mask == 0 || pcr_mask & !0x00FF_FFFF != 0 {
        return -EINVAL;
    }
    // SAFETY: the caller's journal or NULL, and the view.
    let ret = unsafe { config_evidence_collect(update, &mut config) };
    if ret != 0 {
        return ret;
    }
    let mut s: Evidencing = zeroed();
    // SAFETY: the caller's nonce and challenge.
    let ret = unsafe {
        evidence(
            &mut s,
            &config,
            nonce,
            nonce_len,
            pcr_mask,
            c.as_ref(),
            out,
            len,
            cap,
        )
    };

    // SAFETY: what the steps left: the keys and the connection while it
    // is open, the view, and the allocations by their sizes.
    unsafe {
        if !s.tpm.is_null() {
            tpm_key_flush(s.tpm, &mut s.ek);
            tpm_key_flush(s.tpm, &mut s.ak);
            tpm_close(s.tpm);
        }
        config_evidence_clear(&mut config);
        let ek_cert_size = if s.ek_cert.is_null() { 0 } else { EK_CERT_MAX };
        xfree(s.ek_cert.cast(), ek_cert_size);
        xfree(s.ek_b64.cast(), s.ek_b64_cap);
        xfree(s.fw.cast(), s.fw_cap);
        xfree(s.sd.cast(), s.sd_cap);
    }
    scrub(&mut s.cred);
    scrub_key(&mut s.ak);
    scrub_key(&mut s.ek);
    scrub_key(&mut s.ak_copy);
    scrub_key(&mut s.ek_copy);
    if ret != 0 && !(*out).is_null() {
        // SAFETY: the document, by its size.
        unsafe { xfree((*out).cast(), *cap) };
        *out = ptr::null_mut();
        *cap = 0;
    }
    ret
}

/// The steps of attest_evidence_config() once the config is collected.
///
/// # Safety
///
/// `nonce` holds `nonce_len` bytes.
#[allow(clippy::too_many_arguments)]
unsafe fn evidence(
    s: &mut Evidencing,
    config: &Evidence,
    nonce: *const u8,
    nonce_len: usize,
    mut pcr_mask: u32,
    challenge: Option<&AttestChallenge>,
    out: &mut *mut c_char,
    len: &mut usize,
    cap: &mut usize,
) -> c_int {
    let mut quote: TpmAttestation = zeroed();
    let mut certify: TpmAttestation = zeroed();
    let mut nv: TpmNvInfo = zeroed();
    let mut values = [[0u8; 32]; 24];
    let mut reg = [0u8; 32];
    let mut ek_cert_len = 0usize;
    let mut ek_cert_rsa = false;
    let mut ts = [0u8; 32];
    let mut boot_id = [0u8; 64];
    let mut nv_index = [0u8; 16];
    let mut nonce_hex = [0u8; 2 * 64 + 1];
    let mut st = Statx::zeroed();

    if config.present {
        pcr_mask |= 1 << config.pcr;
    }
    // SAFETY: where the connection goes.
    if unsafe { tpm_open(&mut s.tpm) } != 0 {
        return -ENXIO;
    }
    let tpm = s.tpm;
    // SAFETY: the connection, and room for the index's state.
    let ret = unsafe { tpm_nv_info(tpm, NV_INDEX, &mut nv) };
    if ret != 0 {
        return ret;
    }
    if !nv.defined || !nv.written {
        return -ENODEV;
    }
    // SAFETY: the connection, and room for the value.
    let ret = unsafe { tpm_nv_read(tpm, NV_INDEX, reg.as_mut_ptr()) };
    if ret != 0 {
        return ret;
    }
    // SAFETY: the connection, and room for the key.
    let ret = unsafe { tpm_ak_create(tpm, &mut s.ak) };
    if ret != 0 {
        return ret;
    }
    let mut attempt = 0;
    while attempt < QUOTE_ATTEMPTS {
        for (i, value) in values.iter_mut().enumerate() {
            if pcr_mask & (1 << i) == 0 {
                continue;
            }
            // SAFETY: the connection, and room for the value.
            let ret = unsafe { tpm_pcr_read(tpm, i as u32, value.as_mut_ptr()) };
            if ret != 0 {
                return ret;
            }
        }
        // SAFETY: the connection, the key, the caller's nonce, and room
        // for the quote.
        let ret = unsafe { tpm_quote(tpm, &s.ak, nonce, nonce_len, pcr_mask, &mut quote) };
        if ret != 0 {
            return ret;
        }
        if quote_covers(&quote, pcr_mask, &values) {
            break;
        }
        attempt += 1;
    }
    if attempt == QUOTE_ATTEMPTS {
        crate::log::err(b"attest: PCRs kept changing while quoting");
        return -EAGAIN;
    }
    if config.present {
        let mut quoted: TpmAttest = zeroed();

        // SAFETY: the quote's bytes, and room for what they hold.
        if unsafe { tpm_attest_parse(quote.attest.as_ptr(), quote.attest_len, &mut quoted) } != 0
            || quoted.reset_count != config.reset_count
            || quoted.restart_count != config.restart_count
            || values[config.pcr as usize] != config.value
        {
            return -EUCLEAN;
        }
    }
    // SAFETY: the connection, the key, the caller's nonce, and room for
    // the certification.
    let ret = unsafe { tpm_nv_certify(tpm, &s.ak, NV_INDEX, nonce, nonce_len, &mut certify) };
    if ret != 0 {
        return ret;
    }
    // SAFETY: an allocation, which the caller frees by its size.
    s.ek_cert = unsafe { xmalloc(EK_CERT_MAX) }.cast();
    if s.ek_cert.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the connection, room for a certificate, and its length and
    // kind.
    if unsafe {
        tpm_ek_certificate(
            tpm,
            s.ek_cert,
            EK_CERT_MAX,
            &mut ek_cert_len,
            &mut ek_cert_rsa,
        )
    } == 0
    {
        s.ek_b64_cap = 4 * ek_cert_len.div_ceil(3) + 1;
        // SAFETY: an allocation, which the caller frees by its size, and
        // the certificate's base64 into it.
        unsafe {
            s.ek_b64 = xmalloc(s.ek_b64_cap).cast();
            if s.ek_b64.is_null()
                || base64_encode(s.ek_cert, ek_cert_len, s.ek_b64, s.ek_b64_cap) != 0
            {
                xfree(s.ek_b64.cast(), s.ek_b64_cap);
                s.ek_b64 = ptr::null_mut();
                s.ek_b64_cap = 0;
            }
        }
    }
    // The endorsement key the certificate describes, or the one the
    // challenge was made for; a TPM without a certificate yields its ECC
    // key, which the operator pins by name.
    let ek_rsa = challenge.map_or(ek_cert_rsa, |c| c.ek_rsa);
    // SAFETY: the connection, and room for the key.
    let ret = unsafe { tpm_ek_create(tpm, ek_rsa, &mut s.ek) };
    if ret != 0 {
        return ret;
    }
    if let Some(c) = challenge {
        if s.ak.name_len != NAME_LEN || c.ak_name != s.ak.name {
            crate::log::err(b"attest: the challenge was made for another attestation key");
            return -EKEYREJECTED;
        }
        // SAFETY: the connection, the keys, the challenge's blob and
        // secret, and room for the credential.
        let ret = unsafe {
            tpm_activate_credential(
                tpm,
                &s.ak,
                &s.ek,
                c.blob.as_ptr(),
                c.blob_len,
                c.secret.as_ptr(),
                c.secret_len,
                s.cred.as_mut_ptr(),
                s.cred.len(),
                &mut s.cred_len,
            )
        };
        if ret != 0 {
            crate::log::err(b"attest: the TPM refused the challenge: not made for this attestation key under this endorsement key");
            return ret;
        }
    }
    // The keys are flushed before the file work; keep their public parts.
    s.ak_copy = s.ak;
    s.ek_copy = s.ek;
    // SAFETY: the connection and its keys, flushed and closed once.
    unsafe {
        tpm_key_flush(tpm, &mut s.ek);
        tpm_key_flush(tpm, &mut s.ak);
        tpm_close(tpm);
    }
    s.tpm = ptr::null_mut();

    read_file_base64(FIRMWARE_LOG_PATH, &mut s.fw, &mut s.fw_cap);
    read_file_base64(SYSTEMD_LOG_PATH, &mut s.sd, &mut s.sd_cap);
    let mut need = (64 * 1024usize)
        .wrapping_add(s.fw_cap)
        .wrapping_add(s.sd_cap)
        .wrapping_add(s.ek_b64_cap)
        .wrapping_add(config.n_events.wrapping_mul(160));
    // SAFETY: the eventlog's path, and room for its state.
    if unsafe { statx(AT_FDCWD, eventlog_path(), 0, STATX_BASIC_STATS, &mut st) } == 0
        && st.stx_size as i64 > 0
    {
        need = need.saturating_add(2usize.saturating_mul(st.stx_size as usize));
    }
    if need > JSON_MAX_BYTES {
        need = JSON_MAX_BYTES;
    }
    // SAFETY: an allocation, which the caller frees by its size.
    *out = unsafe { xmalloc(need) }.cast();
    if (*out).is_null() {
        return -ENOMEM;
    }
    *cap = need;

    // SAFETY: rooms of their sizes.
    unsafe {
        eventlog_timestamp(ts.as_mut_ptr().cast(), ts.len());
        eventlog_boot_id(boot_id.as_mut_ptr().cast(), boot_id.len());
    }
    // SAFETY: the room, and the C's format with its argument.
    if unsafe {
        crate::text::csprintf!(
            nv_index.as_mut_ptr().cast(),
            nv_index.len(),
            c"0x%08X".as_ptr(),
            NV_INDEX,
        )
    } < 0
    {
        return -E2BIG;
    }
    // SAFETY: the caller's nonce, and room for its hex and a NUL.
    unsafe { hex_encode(nonce, nonce_len, nonce_hex.as_mut_ptr().cast()) };

    // SAFETY: the need bytes xmalloc() gave at *out, which nothing else
    // touches until the emitter is done.
    let mut e = unsafe { JsonEmit::fixed_raw(*out, need) };
    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"kind", b"shirudo-attestation");
    // SAFETY: the build's version ID, a C string.
    let version_id = unsafe { CStr::from_ptr(&raw const shirudo_version_id) };
    e.kv_string(b"version_id", version_id.to_bytes());
    e.kv_string(b"ts", cstr(&ts));
    e.kv_string(b"boot_id", cstr(&boot_id));
    e.kv_string(b"nonce", cstr(&nonce_hex));
    e.kv_string(b"pcr_bank", b"sha256");
    e.kv_int(b"pcr_mask", i64::from(pcr_mask));
    e.arr_open(b"pcrs");
    for (i, value) in values.iter().enumerate() {
        if pcr_mask & (1 << i) == 0 {
            continue;
        }
        e.obj_open();
        e.kv_int(b"index", i as i64);
        emit_hex(&mut e, b"value", value);
        e.obj_close();
    }
    e.arr_close();
    e.obj_open_key(b"ak");
    emit_hex(&mut e, b"public", &s.ak_copy.public[..s.ak_copy.public_len]);
    emit_hex(&mut e, b"name", &s.ak_copy.name[..s.ak_copy.name_len]);
    e.obj_close();
    e.obj_open_key(b"ek");
    e.kv_string(b"type", if ek_rsa { b"rsa" } else { b"ecc" });
    emit_hex(&mut e, b"public", &s.ek_copy.public[..s.ek_copy.public_len]);
    emit_hex(&mut e, b"name", &s.ek_copy.name[..s.ek_copy.name_len]);
    e.obj_close();
    e.obj_open_key(b"quote");
    emit_hex(&mut e, b"attest", &quote.attest[..quote.attest_len]);
    emit_hex(
        &mut e,
        b"signature",
        &quote.signature[..quote.signature_len],
    );
    e.obj_close();
    e.obj_open_key(b"register");
    e.kv_string(b"nv_index", cstr(&nv_index));
    e.kv_int(b"pcr", i64::from(CHAIN_PCR));
    emit_hex(&mut e, b"name", &nv.name[..nv.name_len]);
    emit_hex(&mut e, b"value", &reg);
    emit_hex(&mut e, b"attest", &certify.attest[..certify.attest_len]);
    emit_hex(
        &mut e,
        b"signature",
        &certify.signature[..certify.signature_len],
    );
    e.obj_close();
    e.arr_open(b"eventlog");
    // SAFETY: the callback, and the emitter it takes, which only the
    // callback touches during the walk.
    unsafe { eventlog_boot_lines(Some(emit_line), (&raw mut e).cast()) };
    e.arr_close();
    // SAFETY: the emitter and the view.
    let ret = unsafe { config_evidence_emit(&mut e, config) };
    if ret != 0 {
        return ret;
    }
    if s.cred_len != 0 {
        e.obj_open_key(b"credential");
        emit_hex(&mut e, b"value", &s.cred[..s.cred_len]);
        e.obj_close();
    } else {
        e.kv_null(b"credential");
    }
    if s.ek_b64.is_null() {
        e.kv_null(b"ek_certificate");
    } else {
        // SAFETY: the certificate's base64, a C string.
        e.kv_string(b"ek_certificate", unsafe { ffi::c_str(s.ek_b64) });
    }
    e.obj_open_key(b"logs");
    if s.fw.is_null() {
        e.kv_null(b"firmware");
    } else {
        // SAFETY: the log's base64, a C string.
        e.kv_string(b"firmware", unsafe { ffi::c_str(s.fw) });
    }
    if s.sd.is_null() {
        e.kv_null(b"systemd");
    } else {
        // SAFETY: the log's base64, a C string.
        e.kv_string(b"systemd", unsafe { ffi::c_str(s.sd) });
    }
    e.obj_close();
    e.obj_close();
    if e.err() != 0 {
        return e.err();
    }
    // SAFETY: the document's room, past what the emitter wrote.
    unsafe { *(*out).add(e.written()) = 0 };
    *len = e.written();
    0
}

/* ---- verification ---------------------------------------------------- */

/// What the array of PCRs calls with each: its value, under its index.
fn on_pcr(p: &mut Parse) -> Result<(), c_int> {
    if !(0..24).contains(&p.pcr_index)
        || !hex_into(&p.pcr_value_hex, &mut p.pcrs[p.pcr_index as usize])
    {
        return Err(-EINVAL);
    }
    p.pcr_have |= 1u32 << p.pcr_index;
    Ok(())
}

/// Whether the report may print `s` as it stands. The report prints a
/// record's type and label as they stand, and the target writes them:
/// only the words its writers use may pass, or an escape sequence would
/// rewrite what the operator reads.
fn record_word(s: &[u8]) -> bool {
    s.iter().all(|&c| c.is_ascii_lowercase() || c == b'_')
}

/// hex_decode() of the C string in `hex` into all of `out`.
fn hex_into(hex: &[u8], out: &mut [u8]) -> bool {
    // SAFETY: a C string the parser wrote, and room for out.len() bytes.
    unsafe { hex_decode(hex.as_ptr().cast(), out.as_mut_ptr(), out.len()) == 0 }
}

/// What the eventlog's array calls with each record.
fn on_record(p: &mut Parse) -> Result<(), c_int> {
    if p.n_recs >= RECORDS_MAX {
        return Err(-E2BIG);
    }
    if !record_word(cstr(&p.ty)) {
        return Err(-EINVAL);
    }
    // SAFETY: a record of the parse's RECORDS_MAX, apart from the parse.
    let mut r = unsafe { &mut *p.recs.add(p.n_recs) };
    *r = zeroed();
    let _ = strscpy(&mut r.ty, cstr(&p.ty));
    if !hex_into(&p.digest_hex, &mut r.digest) {
        return Err(-EINVAL);
    }
    let ty = cstr(&p.ty);
    if ty == b"init" {
        let inr = &mut p.init;
        let prev_reset = inr.reset_count;
        let prev_have = inr.have_reset_count;

        *inr = zeroed();
        if p.rec_pcr < 0
            || p.rec_pcr >= 24
            || p.rec_phase_pcr <= p.rec_pcr
            || p.rec_phase_pcr >= 24
            || p.rec_reset > i64::from(u32::MAX)
            || cstr(&p.nv_name_hex).len() != 2 * NAME_LEN
            || !hex_into(&p.pcr_before_hex, &mut inr.pcr_before)
            || !hex_into(&p.phase_before_hex, &mut inr.phase_before)
            || !hex_into(&p.nv_name_hex, &mut inr.name)
            || !hex_into(&p.anchor_digest_hex, &mut inr.anchor_digest)
            || !hex_into(&p.chain_hex, &mut inr.chain)
            || !hex_into(&p.writer_public_hex, &mut inr.writer_public)
        {
            return Err(-EINVAL);
        }
        inr.digest = r.digest;
        inr.pcr = p.rec_pcr as u32;
        inr.phase_pcr = p.rec_phase_pcr as u32;
        inr.initrd = cstr(&p.bound_in) == b"initrd";
        inr.have_reset_count = p.rec_reset >= 0;
        inr.reset_count = p.rec_reset as u32;
        let _ = strscpy(&mut inr.anchor, cstr(&p.anchor));
        inr.present = true;
        // Records are of one TPM reset unless both carry a count and the
        // counts differ; a second record for one reset is a register
        // bound again after boot.
        p.inits = p.inits.wrapping_add(1);
        if p.inits == 1 || (inr.have_reset_count && prev_have && inr.reset_count != prev_reset) {
            p.inits_epoch = 1;
        } else {
            p.inits_epoch = p.inits_epoch.wrapping_add(1);
        }
        // This boot's register starts here.
        p.n_recs = 0;
        // SAFETY: the parse's first record.
        r = unsafe { &mut *p.recs };
        *r = zeroed();
        let _ = strscpy(&mut r.ty, b"init");
        r.digest = p.init.digest;
    } else if ty == b"upatch_load" || ty == b"upatch_unload" {
        let tag = if ty[7] == b'l' {
            c"shirudo-upatch"
        } else {
            c"shirudo-unload"
        };
        let mut payload = [0u8; 32];
        let mut event = [0u8; 32];

        // SAFETY: a C string the parser wrote.
        if !unsafe { upatch_name_valid(p.upatch_name.as_ptr().cast()) } {
            return Err(-EINVAL);
        }
        let _ = strscpy(&mut r.label, cstr(&p.upatch_name));
        if hex_into(&p.upatch_payload_hex, &mut payload)
            // SAFETY: the tag, a C string the parser wrote, the payload's
            // digest and room for the event.
            && unsafe {
                chain_upatch_event(
                    tag.as_ptr(),
                    p.upatch_name.as_ptr().cast(),
                    payload.as_ptr(),
                    event.as_mut_ptr(),
                )
            } == 0
        {
            r.derived = !memneq_explicit(&event, &r.digest);
        }
    } else if ty == b"tree_op" {
        let mut operation = [0u8; 32];
        let mut event = [0u8; 32];

        // verify cannot tie op and id to the digest: leave them out.
        // SAFETY: the label's room, and the C's format with its argument.
        if unsafe {
            crate::text::csprintf!(
                r.label.as_mut_ptr().cast(),
                r.label.len(),
                c"seq %lld".as_ptr(),
                p.tree_seq,
            )
        } < 0
        {
            return Err(-E2BIG);
        }
        if p.tree_seq > 0
            // SAFETY: a C string the parser wrote, and room for a digest.
            && unsafe {
                sha256_digest_decode(p.tree_digest_hex.as_ptr().cast(), operation.as_mut_ptr())
            } == 0
            // SAFETY: the operation's digest, and room for the event.
            && unsafe { chain_tree_event(p.tree_seq, operation.as_ptr(), event.as_mut_ptr()) } == 0
        {
            r.derived = !memneq_explicit(&event, &r.digest);
            // SAFETY: the label's room, and the C's format with its
            // arguments: the digest's hex after its "sha256:".
            if unsafe {
                crate::text::csprintf!(
                    r.label.as_mut_ptr().cast(),
                    r.label.len(),
                    c"seq %lld operation %.12s".as_ptr(),
                    p.tree_seq,
                    p.tree_digest_hex.as_ptr().add(7),
                )
            } < 0
            {
                return Err(-E2BIG);
            }
        }
    } else if ty == b"key_revoke" {
        let mut sha = [0u8; 32];
        let mut event = [0u8; 32];

        // Nor the fingerprint: name the measured certificate.
        if hex_into(&p.key_sha_hex, &mut sha)
            // SAFETY: the tag, the certificate's digest and room for the
            // event.
            && unsafe {
                chain_key_event(c"shirudo-key-revoke".as_ptr(), sha.as_ptr(), event.as_mut_ptr())
            } == 0
        {
            r.derived = !memneq_explicit(&event, &r.digest);
            // SAFETY: the label's room, and the C's format with its
            // argument.
            if unsafe {
                crate::text::csprintf!(
                    r.label.as_mut_ptr().cast(),
                    r.label.len(),
                    c"certificate %.12s".as_ptr(),
                    p.key_sha_hex.as_ptr(),
                )
            } < 0
            {
                return Err(-E2BIG);
            }
        }
    }
    p.n_recs += 1;
    // Reset the per-element scratch the next element may not set.
    p.ty[0] = 0;
    p.upatch_name[0] = 0;
    p.upatch_payload_hex[0] = 0;
    p.tree_id[0] = 0;
    p.tree_op[0] = 0;
    p.tree_digest_hex[0] = 0;
    p.key_fingerprint[0] = 0;
    p.key_sha_hex[0] = 0;
    p.anchor[0] = 0;
    p.writer_public_hex[0] = 0;
    p.bound_in[0] = 0;
    p.tree_seq = 0;
    p.rec_pcr = -1;
    p.rec_phase_pcr = -1;
    p.rec_reset = -1;
    Ok(())
}

/// `struct reporter`: the caller's report, its room, what it holds, and
/// how many checks failed.
struct Reporter {
    buf: *mut c_char,
    cap: usize,
    len: usize,
    failed: c_int,
}

impl Reporter {
    /// A report into the `cap` bytes at `buf`.
    fn new(buf: *mut c_char, cap: usize) -> Self {
        Reporter {
            buf,
            cap,
            len: 0,
            failed: 0,
        }
    }

    /// A line of the report: its tag, then what `text` writes into the
    /// room left and says it wrote, then a line feed, all as room allows.
    fn line(&mut self, tag: &CStr, text: impl FnOnce(*mut c_char, usize) -> c_int) {
        if self.len + 8 >= self.cap {
            return;
        }
        // SAFETY: the room left in the caller's report, and a C string.
        let n = unsafe { c_strscpy(self.buf.add(self.len), tag.as_ptr(), self.cap - self.len) };
        if n > 0 {
            self.len += n as usize;
        }
        // SAFETY: as above.
        let n = text(unsafe { self.buf.add(self.len) }, self.cap - self.len);
        if n > 0 {
            self.len += n as usize;
        }
        if self.len + 1 < self.cap {
            // SAFETY: two bytes within the caller's report.
            unsafe {
                *self.buf.add(self.len) = b'\n' as c_char;
                self.len += 1;
                *self.buf.add(self.len) = 0;
            }
        }
    }

    /// say(): a check, which counts when it failed.
    fn say(&mut self, ok: bool, text: impl FnOnce(*mut c_char, usize) -> c_int) {
        if !ok {
            self.failed += 1;
        }
        self.line(if ok { c"  OK    " } else { c"  FAIL  " }, text);
    }

    /// note(): a remark, which is no check.
    fn note(&mut self, text: impl FnOnce(*mut c_char, usize) -> c_int) {
        self.line(c"  NOTE  ", text);
    }
}

/// A check of the report, in a format of the C's with the arguments it
/// takes, which strsprintf() formats as the C's say() did.
macro_rules! say {
    ($rep:expr, $ok:expr, $fmt:expr $(, $arg:expr)* $(,)?) => {
        $rep.say($ok, |buf, room| {
            // SAFETY: the room left in the report, and a format with the
            // arguments it converts.
            unsafe { crate::text::csprintf!(buf, room, $fmt.as_ptr() $(, $arg)*) }
        })
    };
}

/// A remark of the report, likewise.
macro_rules! note {
    ($rep:expr, $fmt:expr $(, $arg:expr)* $(,)?) => {
        $rep.note(|buf, room| {
            // SAFETY: the room left in the report, and a format with the
            // arguments it converts.
            unsafe { crate::text::csprintf!(buf, room, $fmt.as_ptr() $(, $arg)*) }
        })
    };
}

/// The attestation in `attest_hex`, which `sig_hex` signs, checked against
/// the attestation key `ak` of the name `ak_name` and the nonce: its
/// bytes into `attest`, what they hold into `parsed`. -EINVAL for hex
/// that does not decode, -EKEYREJECTED for a structure that does not
/// parse, else 0 and the checks in the report.
#[allow(clippy::too_many_arguments)]
fn check_signed(
    rep: &mut Reporter,
    what: &CStr,
    attest_hex: &[u8],
    sig_hex: &[u8],
    ak: &TpmEccPublic,
    ak_name: &[u8; NAME_LEN],
    nonce: &[u8],
    attest: &mut [u8; ATTEST_MAX],
    attest_len: &mut usize,
    parsed: &mut TpmAttest,
) -> c_int {
    let mut sig = [0u8; SIGNATURE_MAX];
    let mut sig_len = 0usize;
    let what = what.as_ptr();

    // SAFETY: C strings the parser wrote, and the rooms with their sizes.
    if unsafe {
        hex_decode_max(
            attest_hex.as_ptr().cast(),
            attest.as_mut_ptr(),
            attest.len(),
            attest_len,
        ) != 0
            || hex_decode_max(
                sig_hex.as_ptr().cast(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut sig_len,
            ) != 0
    } {
        return -EINVAL;
    }
    // SAFETY: the attestation's bytes, and room for what they hold.
    if unsafe { tpm_attest_parse(attest.as_ptr(), *attest_len, parsed) } != 0 {
        say!(rep, false, c"%s: attestation structure unparseable", what);
        return -EKEYREJECTED;
    }
    let ret = signature_verify(&attest[..*attest_len], &sig[..sig_len], &ak.x, &ak.y);
    if ret == -EBADMSG {
        say!(rep, false, c"%s: signature structure unparseable", what);
        return -EKEYREJECTED;
    }
    say!(
        rep,
        ret == 0,
        c"%s: ECDSA signature by the attestation key",
        what
    );
    say!(
        rep,
        attest_signer(parsed, ak_name) == Ok(true),
        c"%s: signed by the key as an endorsement primary",
        what
    );
    let carried = parsed.extra_len == nonce.len()
        && (nonce.is_empty()
            // SAFETY: the extra data, extra_len bytes of the attestation.
            || !memneq_explicit(unsafe { ffi::slice(parsed.extra, parsed.extra_len) }, nonce));
    say!(rep, carried, c"%s: carries the nonce", what);
    0
}

/// parse_schema() of the evidence into the parse: whether it carries an
/// endorsement key and a credential, or -EINVAL.
fn parse_evidence(p: &mut Parse, evidence: &[u8]) -> Result<(bool, bool), c_int> {
    let pcr_sub = [
        JsonField::int(c"index", |p: &mut Parse| &mut p.pcr_index),
        JsonField::string(c"value", |p| &mut p.pcr_value_hex),
    ];
    let ak_sub = [
        JsonField::string(c"public", |p: &mut Parse| &mut p.ak_public_hex),
        JsonField::string(c"name", |p| &mut p.ak_name_hex),
    ];
    let quote_sub = [
        JsonField::string(c"attest", |p: &mut Parse| &mut p.quote_attest_hex),
        JsonField::string(c"signature", |p| &mut p.quote_sig_hex),
    ];
    let ek_sub = [
        JsonField::string(c"type", |p: &mut Parse| &mut p.ek_type),
        JsonField::string(c"public", |p| &mut p.ek_public_hex),
        JsonField::string(c"name", |p| &mut p.ek_name_hex),
    ];
    let cred_sub = [JsonField::string(c"value", |p: &mut Parse| &mut p.cred_hex)];
    let reg_sub = [
        JsonField::string(c"nv_index", |p: &mut Parse| &mut p.reg_index),
        JsonField::int(c"pcr", |p| &mut p.reg_pcr),
        JsonField::string(c"name", |p| &mut p.reg_name_hex),
        JsonField::string(c"value", |p| &mut p.reg_value_hex),
        JsonField::string(c"attest", |p| &mut p.reg_attest_hex),
        JsonField::string(c"signature", |p| &mut p.reg_sig_hex),
    ];
    let upatch_sub = [
        JsonField::string(c"name", |p: &mut Parse| &mut p.upatch_name),
        JsonField::string(c"payload_sha256", |p| &mut p.upatch_payload_hex),
    ];
    let key_sub = [
        JsonField::string(c"fingerprint", |p: &mut Parse| &mut p.key_fingerprint),
        JsonField::string(c"cert_sha256", |p| &mut p.key_sha_hex),
    ];
    let tree_sub = [
        JsonField::int(c"seq", |p: &mut Parse| &mut p.tree_seq),
        JsonField::string(c"op", |p| &mut p.tree_op),
        JsonField::string(c"id", |p| &mut p.tree_id),
        JsonField::string(c"operation_digest", |p| &mut p.tree_digest_hex),
    ];
    let rec_sub = [
        JsonField::string(c"type", |p: &mut Parse| &mut p.ty),
        JsonField::string(c"digest", |p| &mut p.digest_hex),
        JsonField::int(c"pcr", |p| &mut p.rec_pcr),
        JsonField::int(c"tpm_reset_count", |p| &mut p.rec_reset),
        JsonField::string(c"pcr_before", |p| &mut p.pcr_before_hex),
        JsonField::int(c"phase_pcr", |p| &mut p.rec_phase_pcr),
        JsonField::string(c"phase_before", |p| &mut p.phase_before_hex),
        JsonField::string(c"bound_in", |p| &mut p.bound_in),
        JsonField::string(c"nv_name", |p| &mut p.nv_name_hex),
        JsonField::string(c"nv_writer_public", |p| &mut p.writer_public_hex),
        JsonField::string(c"anchor", |p| &mut p.anchor),
        JsonField::string(c"anchor_digest", |p| &mut p.anchor_digest_hex),
        JsonField::string(c"chain", |p| &mut p.chain_hex),
        JsonField::object(c"upatch", &upatch_sub),
        JsonField::object(c"tree", &tree_sub),
        JsonField::object(c"key", &key_sub),
    ];
    let top = [
        JsonField::string(c"nonce", |p: &mut Parse| &mut p.nonce_hex),
        JsonField::int(c"pcr_mask", |p| &mut p.pcr_mask),
        JsonField::array(c"pcrs", &pcr_sub, &on_pcr),
        JsonField::object(c"ak", &ak_sub),
        JsonField::object(c"quote", &quote_sub),
        JsonField::object(c"register", &reg_sub),
        JsonField::array(c"eventlog", &rec_sub, &on_record),
        JsonField::object(c"ek", &ek_sub),
        JsonField::object(c"credential", &cred_sub),
    ];

    if parse_schema(evidence, &top, p).is_err() || !top[..7].iter().all(JsonField::seen) {
        return Err(-EINVAL);
    }
    Ok((ek_sub.iter().all(JsonField::seen), cred_sub[0].seen()))
}

/// attest_verify(): the evidence checked against what the operator
/// expects, every check into the report. 0 when each passed,
/// -EKEYREJECTED when one failed, -EINVAL for a malformed document.
///
/// # Safety
///
/// `evidence` holds `len` bytes and `report` has room for `report_cap`.
unsafe fn verify(
    evidence: *const c_char,
    len: usize,
    expect: &AttestExpect,
    report: *mut c_char,
    report_cap: usize,
) -> c_int {
    let mut rep = Reporter::new(report, report_cap);
    let mut config: Evidence = zeroed();
    let mut cred = [0u8; CREDENTIAL_LEN];

    if report_cap != 0 {
        // SAFETY: the caller's report.
        unsafe { *report = 0 };
    }
    // SAFETY: an allocation of the parse, freed below by its size.
    let p = unsafe { xcalloc(1, size_of::<Parse>()) }.cast::<Parse>();
    if p.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the parse, zeroed, which is a value of it, and the records'
    // allocation, freed below by its size.
    unsafe {
        (*p).recs = xcalloc(RECORDS_MAX, size_of::<Record>()).cast();
        if (*p).recs.is_null() {
            xfree(p.cast(), size_of::<Parse>());
            return -ENOMEM;
        }
        (*p).rec_pcr = -1;
        (*p).rec_phase_pcr = -1;
        (*p).rec_reset = -1;
    }
    // SAFETY: the caller's evidence, len bytes of it.
    let doc = unsafe { ffi::slice(evidence.cast::<u8>(), len) };
    // SAFETY: the parse, and the caller's evidence.
    let ret = unsafe { verify_parsed(&mut rep, p, &mut config, &mut cred, evidence, doc, expect) };

    // SAFETY: the view, the records and the parse, each freed once.
    unsafe {
        config_evidence_clear(&mut config);
        xfree((*p).recs.cast(), RECORDS_MAX * size_of::<Record>());
        xfree(p.cast(), size_of::<Parse>());
    }
    scrub(&mut cred);
    ret
}

/// The checks of attest_verify(), with the parse allocated.
///
/// # Safety
///
/// `p` is the parse, and `doc` the `evidence` the caller passed.
unsafe fn verify_parsed(
    rep: &mut Reporter,
    p: *mut Parse,
    config: &mut Evidence,
    cred: &mut [u8; CREDENTIAL_LEN],
    evidence: *const c_char,
    doc: &[u8],
    expect: &AttestExpect,
) -> c_int {
    let mut quote: TpmAttest = zeroed();
    let mut certify: TpmAttest = zeroed();
    let mut ak_pub: TpmEccPublic = zeroed();
    let mut ak_public = [0u8; PUBLIC_MAX];
    let mut ak_name = [0u8; NAME_LEN];
    let mut reg_name = [0u8; NAME_LEN];
    let mut reg_value = [0u8; 32];
    let mut attest = [0u8; ATTEST_MAX];
    let mut nonce = [0u8; NONCE_MAX];
    let mut chain = [0u8; 32];
    let mut branch_written = [0u8; 32];
    let mut branch_init = [0u8; 32];
    let mut policy = [0u8; 32];
    let mut bind = [0u8; 64];
    let mut expected_name = [0u8; NAME_LEN];
    let mut anchor_digest = [0u8; 32];
    let mut ak_public_len = 0usize;
    let mut nonce_len = 0usize;
    let mut attest_len = 0usize;
    let mut cred_len = 0usize;
    let mut reg_index = 0u64;
    let mut runtime = 0usize;
    let mut replayed = true;

    // SAFETY: the caller's parse, which nothing else touches.
    let p = unsafe { &mut *p };
    let (have_ek, have_cred) = match parse_evidence(p, doc) {
        Ok(found) => found,
        Err(ret) => return ret,
    };

    // SAFETY: the caller's evidence, and the view.
    let ret = unsafe { config_evidence_parse(evidence, doc.len(), config) };
    if ret == -EKEYREJECTED {
        say!(
            rep,
            false,
            c"config: the events are one boot event followed by updates in sequence"
        );
    }
    // What json_parse() refuses past a bound is a malformed document.
    if ret == -E2BIG || ret == -ENOSPC {
        return -EINVAL;
    }
    if ret != 0 {
        return ret;
    }

    // Freshness: the document must answer this request.
    // SAFETY: a C string the parser wrote, and the room with its size.
    if unsafe {
        hex_decode_max(
            p.nonce_hex.as_ptr().cast(),
            nonce.as_mut_ptr(),
            nonce.len(),
            &mut nonce_len,
        )
    } != 0
    {
        return -EINVAL;
    }
    let fresh = expect.nonce_len == nonce_len
        && (nonce_len == 0
            // SAFETY: the caller's nonce, nonce_len bytes of it.
            || !memneq_explicit(&nonce[..nonce_len], unsafe {
                ffi::slice(expect.nonce, nonce_len)
            }));
    say!(rep, fresh, c"nonce matches the request");

    // SAFETY: a C string the parser wrote, and the room with its size.
    if unsafe {
        hex_decode_max(
            p.ak_public_hex.as_ptr().cast(),
            ak_public.as_mut_ptr(),
            ak_public.len(),
            &mut ak_public_len,
        )
    } != 0
        || !hex_into(&p.ak_name_hex, &mut ak_name)
    {
        return -EINVAL;
    }
    // SAFETY: the key's public area, and room for what it holds.
    if unsafe { tpm_ecc_public_parse(ak_public.as_ptr(), ak_public_len, &mut ak_pub) } != 0 {
        say!(
            rep,
            false,
            c"attestation key: public area is not a P-256 ECDSA key"
        );
        return -EKEYREJECTED;
    }
    say!(
        rep,
        ak_pub.attrs & AK_ATTRS_REQUIRED == AK_ATTRS_REQUIRED,
        c"attestation key: restricted, fixed to this TPM"
    );
    {
        let mut computed = [0u8; NAME_LEN];
        // SAFETY: the public area, and room for its name.
        let named =
            unsafe { tpm_object_name(ak_public.as_ptr(), ak_public_len, computed.as_mut_ptr()) }
                == 0;

        say!(
            rep,
            named && !memneq_explicit(&computed, &ak_name),
            c"attestation key: name matches its public area"
        );
    }
    if expect.have_ak_name {
        say!(
            rep,
            !memneq_explicit(&ak_name, &expect.ak_name),
            c"attestation key: the pinned key"
        );
    } else {
        note!(
            rep,
            c"attestation key not pinned: name %s",
            p.ak_name_hex.as_ptr()
        );
    }

    if have_ek {
        let mut ek_public = [0u8; PUBLIC_MAX];
        let mut ek_name = [0u8; NAME_LEN];
        let mut computed = [0u8; NAME_LEN];
        let mut ek_pub = TpmPublic::zeroed();
        let mut ek_public_len = 0usize;

        // SAFETY: a C string the parser wrote, and the room with its size.
        if unsafe {
            hex_decode_max(
                p.ek_public_hex.as_ptr().cast(),
                ek_public.as_mut_ptr(),
                ek_public.len(),
                &mut ek_public_len,
            )
        } != 0
            || !hex_into(&p.ek_name_hex, &mut ek_name)
        {
            return -EINVAL;
        }
        // SAFETY: the public area, and room for what it holds.
        let parsed =
            unsafe { tpm_public_parse(ek_public.as_ptr(), ek_public_len, &mut ek_pub) } == 0;
        let named = parsed
            // SAFETY: the public area, and room for its name.
            && unsafe { tpm_object_name(ek_public.as_ptr(), ek_public_len, computed.as_mut_ptr()) }
                == 0
            && !memneq_explicit(&computed, &ek_name);
        say!(rep, named, c"endorsement key: name matches its public area");
        say!(
            rep,
            parsed
                && ek_pub.attrs == EK_ATTRS
                && ek_pub.policy_len == 32
                && !memneq_explicit(&ek_pub.policy, &EK_POLICY),
            c"endorsement key: TCG default template under the endorsement policy"
        );
    } else {
        note!(rep, c"no endorsement key in the evidence");
    }
    if expect.have_ek_name {
        let mut ek_name = [0u8; NAME_LEN];
        let pinned = have_ek
            && hex_into(&p.ek_name_hex, &mut ek_name)
            && !memneq_explicit(&ek_name, &expect.ek_name);

        say!(rep, pinned, c"endorsement key: the pinned key");
    }
    if have_cred
        // SAFETY: a C string the parser wrote, and the room with its size.
        && unsafe {
            hex_decode_max(
                p.cred_hex.as_ptr().cast(),
                cred.as_mut_ptr(),
                cred.len(),
                &mut cred_len,
            )
        } != 0
    {
        return -EINVAL;
    }
    if expect.have_credential {
        say!(
            rep,
            have_cred && cred_len == CREDENTIAL_LEN && !memneq_explicit(cred, &expect.credential),
            c"attestation key: activated the credential made for it under the endorsement key"
        );
    } else if have_cred {
        note!(
            rep,
            c"a credential was activated but none is expected (--expect-credential)"
        );
    }

    let qrc = check_signed(
        rep,
        c"quote",
        &p.quote_attest_hex,
        &p.quote_sig_hex,
        &ak_pub,
        &ak_name,
        &nonce[..nonce_len],
        &mut attest,
        &mut attest_len,
        &mut quote,
    );
    if qrc == -EINVAL {
        return qrc;
    }
    if qrc == 0 {
        let complete = quote.ty == ST_ATTEST_QUOTE
            && p.pcr_mask == i64::from(quote.pcr_mask)
            && p.pcr_have == quote.pcr_mask;

        say!(rep, complete, c"quote: covers the PCRs the document lists");
        let vouched = complete
            && pcr_values_digest(quote.pcr_mask, &p.pcrs)
                .is_some_and(|d| !memneq_explicit(&d, &quote.pcr_digest));
        say!(rep, vouched, c"quote: PCR digest matches the listed values");
        if !vouched {
            p.pcr_have = 0;
        }
    } else {
        p.pcr_have = 0;
    }

    let crc = check_signed(
        rep,
        c"register",
        &p.reg_attest_hex,
        &p.reg_sig_hex,
        &ak_pub,
        &ak_name,
        &nonce[..nonce_len],
        &mut attest,
        &mut attest_len,
        &mut certify,
    );
    if crc == -EINVAL {
        return crc;
    }
    let index = cstr(&p.reg_index);
    if !hex_into(&p.reg_name_hex, &mut reg_name)
        || !hex_into(&p.reg_value_hex, &mut reg_value)
        || !index.starts_with(b"0x")
        // SAFETY: the index's digits after its 0x, and room for their
        // value.
        || unsafe {
            parse_x64(
                p.reg_index.as_ptr().add(2).cast(),
                index.len() - 2,
                0xffff_ffff,
                &mut reg_index,
            )
        } != 0
        || !(0..24).contains(&p.reg_pcr)
    {
        return -EINVAL;
    }
    if crc == 0 {
        say!(
            rep,
            certify.ty == ST_ATTEST_NV
                && certify.index_name_len == NAME_LEN
                && !memneq_explicit(&certify.index_name, &reg_name),
            c"register: certification names the listed index"
        );
        let contents = certify.ty == ST_ATTEST_NV
            && certify.offset == 0
            && certify.nv_len == 32
            // SAFETY: the certified contents, nv_len bytes of the
            // attestation.
            && !memneq_explicit(unsafe { ffi::slice(certify.nv_data, 32) }, &reg_value);
        say!(
            rep,
            contents,
            c"register: certified contents match the listed value"
        );
    }
    // A restart clears the register as a reset does.
    if qrc == 0 && crc == 0 {
        say!(
            rep,
            quote.reset_count == certify.reset_count
                && quote.restart_count == certify.restart_count
                && quote.firmware_version == certify.firmware_version,
            c"quote and certification are of one TPM boot"
        );
    }

    if config.present || expect.have_config_root || expect.have_config_pcr {
        let root = if expect.have_config_root {
            expect.config_root.as_ptr()
        } else {
            ptr::null()
        };
        let pcr = if expect.have_config_pcr {
            expect.config_pcr as c_int
        } else {
            -1
        };
        let mut reason: *const c_char = ptr::null();

        // SAFETY: the view, the quoted PCRs, the root or NULL, and where
        // the reason goes.
        let ret = unsafe {
            config_evidence_verify(
                config,
                quote.pcr_mask,
                quote.reset_count,
                p.pcrs.as_ptr(),
                ptr::null(),
                root,
                pcr,
                &mut reason,
            )
        };
        say!(rep, ret == 0, c"config: %s", reason);
        if config.present && !expect.have_config_root {
            note!(
                rep,
                c"config root has no operator approval; use --expect-config-root with --expect-config-pcr"
            );
        }
        if config.present {
            note!(
                rep,
                c"config records a selection; direct TPM writer protection is deferred"
            );
        }
    }

    // The binding: the certified index must have the public area a
    // register bound to the recorded PCR values has, which is what makes
    // a recreation impossible to pass off, and those values are what the
    // operator pins to tell an initrd binding from a later one. The
    // handle and the PCRs are the register's, never the document's: taken
    // from the record, a target could certify an index of its own under a
    // policy over PCRs it can extend and reset at will.
    say!(
        rep,
        p.init.present,
        c"eventlog: this boot has an init record"
    );
    if !p.init.present {
        return -EKEYREJECTED;
    }
    say!(
        rep,
        reg_index == u64::from(NV_INDEX)
            && p.reg_pcr as u32 == CHAIN_PCR
            && p.init.pcr == CHAIN_PCR
            && p.init.phase_pcr == CHAIN_PHASE_PCR,
        c"register: the document names index 0x%08X and PCRs %u and %u",
        NV_INDEX,
        CHAIN_PCR,
        CHAIN_PHASE_PCR
    );
    bind[..32].copy_from_slice(&p.init.pcr_before);
    bind[32..].copy_from_slice(&p.init.phase_before);
    // SAFETY: two values, the writer's modulus, and rooms for three
    // digests.
    let ret = unsafe {
        tpm_register_policy(
            CHAIN_PCR_MASK,
            bind.as_ptr(),
            2,
            p.init.writer_public.as_ptr(),
            branch_written.as_mut_ptr(),
            branch_init.as_mut_ptr(),
            policy.as_mut_ptr(),
        )
    };
    if ret != 0 {
        say!(
            rep,
            false,
            c"register: cannot compute the signed write policy"
        );
        // Malformed recorded values are the document's failure, not a
        // parse error.
        return if ret == -EINVAL { -EKEYREJECTED } else { ret };
    }
    // SAFETY: the policy, and room for the name.
    let ret = unsafe {
        tpm_nv_name(
            NV_INDEX,
            REGISTER_ATTRS | NV_WRITTEN,
            policy.as_ptr(),
            32,
            expected_name.as_mut_ptr(),
        )
    };
    if ret != 0 {
        say!(rep, false, c"register: cannot compute the index name");
        return ret;
    }
    say!(
        rep,
        !memneq_explicit(&expected_name, &reg_name)
            && !memneq_explicit(&expected_name, &p.init.name),
        c"register: public area is bound to PCRs %u and %u as recorded",
        CHAIN_PCR,
        CHAIN_PHASE_PCR
    );
    for bit in 0..24u32 {
        if expect.bind_expect_mask & (1 << bit) == 0 {
            continue;
        }
        let held = if bit == CHAIN_PCR {
            Some(&p.init.pcr_before)
        } else if bit == CHAIN_PHASE_PCR {
            Some(&p.init.phase_before)
        } else {
            None
        };
        say!(
            rep,
            held.is_some_and(|h| !memneq_explicit(h, &expect.bind_values[bit as usize])),
            c"binding: PCR %u held the expected value",
            bit
        );
    }
    if expect.require_initrd {
        say!(rep, p.init.initrd, c"binding: made while the initrd ran");
    } else {
        let place = if p.init.initrd {
            c"initrd"
        } else {
            c"root file system"
        };

        note!(rep, c"binding: made in the %s", place.as_ptr());
    }

    // The epoch: one binding per TPM reset, and the one on record is of
    // the reset the TPM certifies in, so no register bound again after
    // boot can pass as the boot's.
    say!(
        rep,
        p.inits_epoch == 1,
        c"eventlog: one init record for this TPM reset (%u this boot)",
        p.inits
    );
    if crc == 0 {
        say!(
            rep,
            p.init.have_reset_count && p.init.reset_count == certify.reset_count,
            c"register: init record is of the TPM's current reset count"
        );
    }

    // SAFETY: the records the parse holds.
    let recs = unsafe { ffi::slice(p.recs, p.n_recs) };
    for (i, r) in recs.iter().enumerate() {
        // SAFETY: the register replayed so far, and a record's digest.
        if unsafe { chain_fold(chain.as_mut_ptr(), r.digest.as_ptr()) } != 0 {
            replayed = false;
        }
        if i != 0 {
            runtime += 1;
        }
    }
    let plural = if recs.len() == 1 { c"" } else { c"s" };
    say!(
        rep,
        replayed && !memneq_explicit(&chain, &reg_value),
        c"eventlog: %zu record%s replay to the certified value",
        recs.len(),
        plural.as_ptr()
    );
    // A digest the record's own fields do not produce is a record
    // relabelled after the fact: the replay still closes, but what the
    // events say happened is not what was measured.
    for (i, r) in recs.iter().enumerate().skip(1) {
        if !r.derived {
            say!(
                rep,
                false,
                c"eventlog: event %zu (%s %s) digest does not derive from its fields",
                i,
                r.ty.as_ptr(),
                r.label.as_ptr()
            );
        }
    }

    {
        let mut anchor = [0u8; ANCHOR_MAX];
        // SAFETY: the recorded name, and the anchor's room.
        let mut named = unsafe {
            chain_anchor(
                p.init.name.as_ptr(),
                anchor.as_mut_ptr().cast(),
                anchor.len(),
            )
        } == 0
            && sha256_into(cstr(&anchor), &mut anchor_digest) == 0;

        say!(
            rep,
            named && !memneq_explicit(&anchor_digest, &p.init.anchor_digest),
            c"anchor: record digest matches the index name"
        );
        let mut pcr_expected = p.init.pcr_before;
        // SAFETY: the value, and the anchor's digest folded into it.
        named =
            unsafe { chain_fold(pcr_expected.as_mut_ptr(), anchor_digest.as_ptr()) } == 0 && named;
        if p.pcr_have & (1 << CHAIN_PCR) != 0 {
            let exact = named && !memneq_explicit(&pcr_expected, &p.pcrs[CHAIN_PCR as usize]);

            if exact || expect.strict_anchor {
                say!(
                    rep,
                    exact,
                    c"anchor: PCR %u equals the recorded value extended by the anchor",
                    CHAIN_PCR
                );
            } else {
                note!(
                    rep,
                    c"anchor: PCR %u carries further measurements after the anchor; replay the logs to confirm it",
                    CHAIN_PCR
                );
            }
        } else {
            say!(rep, false, c"anchor: PCR %u is not in the quote", CHAIN_PCR);
        }
    }

    if expect.have_init {
        say!(
            rep,
            !memneq_explicit(&p.init.digest, &expect.init_event),
            c"state: init event covers the expected certificate, set and tree root"
        );
    }
    if expect.have_chain {
        say!(
            rep,
            !memneq_explicit(&reg_value, &expect.chain),
            c"state: register equals the expected value"
        );
    } else if expect.have_init {
        let mut predicted = [0u8; 32];
        // SAFETY: the value, and the expected init event folded into it.
        let folded = unsafe { chain_fold(predicted.as_mut_ptr(), expect.init_event.as_ptr()) } == 0;

        if runtime == 0 {
            say!(
                rep,
                folded && !memneq_explicit(&reg_value, &predicted),
                c"state: register equals the value predicted for the set at boot"
            );
        } else {
            let plural = if runtime == 1 { c"" } else { c"s" };

            say!(
                rep,
                expect.allow_runtime_events,
                c"state: %zu event%s after boot change the register",
                runtime,
                plural.as_ptr()
            );
        }
    } else {
        note!(
            rep,
            c"no expected state given; the register value is %s",
            p.reg_value_hex.as_ptr()
        );
    }
    for r in recs.iter().skip(1) {
        note!(
            rep,
            c"event after boot: %s %s",
            r.ty.as_ptr(),
            r.label.as_ptr()
        );
    }
    for bit in 0..24u32 {
        if expect.pcr_expect_mask & (1 << bit) == 0 {
            continue;
        }
        let i = bit as usize;
        say!(
            rep,
            p.pcr_have & (1 << bit) != 0 && !memneq_explicit(&p.pcrs[i], &expect.pcrs[i]),
            c"PCR %u matches the expected value",
            bit
        );
    }
    if rep.failed != 0 { -EKEYREJECTED } else { 0 }
}

/// What a challenge's document gives, in hex.
struct ChallengeJson {
    blob_hex: [u8; 2 * ID_OBJECT_LEN + 1],
    secret_hex: [u8; 2 * 256 + 1],
    ak_hex: [u8; 2 * NAME_LEN + 1],
    kind: [u8; 32],
    ty: [u8; 8],
}

/// attest_challenge_read(): the challenge an operator made, from the
/// file at `path`.
///
/// # Safety
///
/// `path` is a C string and `out` room for a challenge.
unsafe fn challenge_read(path: *const c_char, out: *mut AttestChallenge) -> c_int {
    let mut challenge = ChallengeJson {
        blob_hex: [0; 2 * ID_OBJECT_LEN + 1],
        secret_hex: [0; 2 * 256 + 1],
        ak_hex: [0; 2 * NAME_LEN + 1],
        kind: [0; 32],
        ty: [0; 8],
    };
    let ek_sub = [JsonField::string(c"type", |c: &mut ChallengeJson| {
        &mut c.ty
    })];
    let top = [
        JsonField::string(c"kind", |c: &mut ChallengeJson| &mut c.kind),
        JsonField::object(c"ek", &ek_sub),
        JsonField::string(c"ak_name", |c| &mut c.ak_hex),
        JsonField::string(c"credential_blob", |c| &mut c.blob_hex),
        JsonField::string(c"secret", |c| &mut c.secret_hex),
    ];
    let mut doc: *mut c_char = ptr::null_mut();
    let mut len = 0usize;

    // SAFETY: the caller's room, padding too, as memset() zeroes it.
    let out = unsafe {
        out.write_bytes(0, 1);
        &mut *out
    };
    // SAFETY: the caller's C string, and where the document goes.
    let ret = unsafe { read_file(path, CHALLENGE_MAX, (&raw mut doc).cast(), &mut len) };
    if ret != 0 {
        return ret;
    }
    // SAFETY: the document's len bytes.
    let parsed = parse_schema(unsafe { ffi::slice(doc.cast(), len) }, &top, &mut challenge);
    // SAFETY: the document, freed once by its size.
    unsafe { xfree(doc.cast(), len + 1) };
    let ChallengeJson {
        blob_hex,
        secret_hex,
        ak_hex,
        kind,
        ty,
    } = challenge;
    if parsed.is_err()
        || !top[0].seen()
        || cstr(&kind) != b"shirudo-credential"
        || !ek_sub[0].seen()
        || !top[2].seen()
        || !top[3].seen()
        || !top[4].seen()
    {
        return -EINVAL;
    }
    match cstr(&ty) {
        b"rsa" => out.ek_rsa = true,
        b"ecc" => {}
        _ => return -EINVAL,
    }
    if !hex_into(&ak_hex, &mut out.ak_name)
        // SAFETY: a C string the parser wrote, and the challenge's room
        // with its size.
        || unsafe {
            hex_decode_max(
                blob_hex.as_ptr().cast(),
                out.blob.as_mut_ptr(),
                out.blob.len(),
                &mut out.blob_len,
            )
        } != 0
        || out.blob_len != ID_OBJECT_LEN
        // SAFETY: as above.
        || unsafe {
            hex_decode_max(
                secret_hex.as_ptr().cast(),
                out.secret.as_mut_ptr(),
                out.secret.len(),
                &mut out.secret_len,
            )
        } != 0
        || out.secret_len == 0
    {
        return -EINVAL;
    }
    0
}

/// Whether the certificate's key is the endorsement key of the evidence.
fn cert_describes(key: &CertPubkey, public: &TpmPublic) -> bool {
    let rsa = public.ty == ALG_RSA;

    if key.rsa != rsa {
        return false;
    }
    if key.rsa {
        let e = if public.rsa_exponent != 0 {
            public.rsa_exponent
        } else {
            65537
        };

        return key.n_len == public.n_len
            && !memneq_explicit(&key.n[..public.n_len], &public.n[..public.n_len])
            && key.e == e;
    }
    !memneq_explicit(&key.x, &public.x) && !memneq_explicit(&key.y, &public.y)
}

/// What attest_challenge_make() holds across its steps, freed and wiped
/// after them.
struct Making {
    seed: [u8; 32],
    z: [u8; 32],
    cert: Cert,
    der: *mut u8,
    cert_b64: *mut c_char,
}

/// attest_challenge_make(): after the checks the policy asks for, into
/// the report, a credential the target recovers only with the
/// attestation key the evidence names under its endorsement key, and the
/// challenge that carries it, into `*out`, xmalloc'd to `*cap` bytes.
///
/// # Safety
///
/// `evidence` holds `len` bytes, `credential` has room for a credential
/// and `report` for `report_cap` bytes.
#[allow(clippy::too_many_arguments)]
unsafe fn challenge_make(
    evidence: *const c_char,
    len: usize,
    pol: &AttestChallengePolicy,
    credential: *mut u8,
    out: &mut *mut c_char,
    out_len: &mut usize,
    cap: &mut usize,
    report: *mut c_char,
    report_cap: usize,
) -> c_int {
    let mut rep = Reporter::new(report, report_cap);
    let mut s = Making {
        seed: [0; 32],
        z: [0; 32],
        cert: Cert::new(),
        der: ptr::null_mut(),
        // SAFETY: an allocation, freed below by its size.
        cert_b64: unsafe { xmalloc(EK_CERT_B64_MAX) }.cast(),
    };

    *out = ptr::null_mut();
    *out_len = 0;
    *cap = 0;
    if report_cap != 0 {
        // SAFETY: the caller's report.
        unsafe { *report = 0 };
    }
    if s.cert_b64.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the caller's evidence and credential's room.
    let ret = unsafe {
        make(
            &mut rep, &mut s, evidence, len, pol, credential, out, out_len, cap,
        )
    };

    scrub(&mut s.seed);
    scrub(&mut s.z);
    // SAFETY: the certificate, and the allocations by their sizes, each
    // freed once.
    unsafe {
        cert_free(&mut s.cert);
        let der_size = if s.der.is_null() { 0 } else { EK_CERT_MAX };
        xfree(s.der.cast(), der_size);
        xfree(s.cert_b64.cast(), EK_CERT_B64_MAX);
    }
    if ret != 0 {
        // SAFETY: the caller's room for the credential.
        unsafe { explicit_bzero(credential.cast(), CREDENTIAL_LEN) };
        if !(*out).is_null() {
            // SAFETY: the challenge, by its size.
            unsafe { xfree((*out).cast(), *cap) };
            *out = ptr::null_mut();
            *cap = 0;
        }
    }
    ret
}

/// What the evidence gives of its keys, in hex, and its EK certificate
/// into the allocation for it.
struct KeysJson<'c> {
    ek_public_hex: [u8; 2 * PUBLIC_MAX + 1],
    ak_hex: [u8; 2 * NAME_LEN + 1],
    ek_type: [u8; 8],
    ek_name_hex: [u8; 2 * NAME_LEN + 1],
    cert_b64: &'c mut [u8],
}

/// The steps of attest_challenge_make() once its buffer is allocated.
///
/// # Safety
///
/// As challenge_make().
#[allow(clippy::too_many_arguments)]
unsafe fn make(
    rep: &mut Reporter,
    s: &mut Making,
    evidence: *const c_char,
    len: usize,
    pol: &AttestChallengePolicy,
    credential: *mut u8,
    out: &mut *mut c_char,
    out_len: &mut usize,
    cap: &mut usize,
) -> c_int {
    let vouched = !pol.ek_name.is_null() || pol.trust_presented;
    let mut hex = [0u8; 2 * 256 + 1];
    let mut ak_name = [0u8; NAME_LEN];
    let mut ek_name = [0u8; NAME_LEN];
    let mut ek_public = [0u8; PUBLIC_MAX];
    let mut computed = [0u8; NAME_LEN];
    let mut eph_x = [0u8; 32];
    let mut eph_y = [0u8; 32];
    let mut secret = [0u8; 256];
    let mut blob = [0u8; ID_OBJECT_LEN];
    let mut cert_key: CertPubkey = zeroed();
    let mut public = TpmPublic::zeroed();
    let mut ek_public_len = 0usize;
    let mut secret_len = 0usize;
    let mut der_len = 0usize;
    let mut reason: *const c_char = c"".as_ptr();
    let ak_sub = [JsonField::string(c"name", |k: &mut KeysJson| &mut k.ak_hex)];
    let ek_sub = [
        JsonField::string(c"type", |k: &mut KeysJson| &mut k.ek_type),
        JsonField::string(c"public", |k| &mut k.ek_public_hex),
        JsonField::string(c"name", |k| &mut k.ek_name_hex),
    ];
    let top = [
        JsonField::object(c"ak", &ak_sub),
        JsonField::object(c"ek", &ek_sub),
        JsonField::string(c"ek_certificate", |k: &mut KeysJson| &mut *k.cert_b64),
    ];

    // SAFETY: the allocation's first byte.
    unsafe { *s.cert_b64 = 0 };
    let mut keys = KeysJson {
        ek_public_hex: [0; 2 * PUBLIC_MAX + 1],
        ak_hex: [0; 2 * NAME_LEN + 1],
        ek_type: [0; 8],
        ek_name_hex: [0; 2 * NAME_LEN + 1],
        // SAFETY: the allocation of EK_CERT_B64_MAX bytes, which only the
        // parse touches until it ends.
        cert_b64: unsafe { ffi::bytes_mut(s.cert_b64.cast(), EK_CERT_B64_MAX) },
    };
    // SAFETY: the caller's evidence.
    let parsed = parse_schema(unsafe { ffi::slice(evidence.cast(), len) }, &top, &mut keys);
    let KeysJson {
        ek_public_hex,
        ak_hex,
        ek_type,
        ek_name_hex,
        ..
    } = keys;
    if parsed.is_err()
        || !ak_sub[0].seen()
        || !ek_sub[0].seen()
        || !ek_sub[1].seen()
        || !ek_sub[2].seen()
        || !hex_into(&ak_hex, &mut ak_name)
        // SAFETY: a C string the parser wrote, and the room with its size.
        || unsafe {
            hex_decode_max(
                ek_public_hex.as_ptr().cast(),
                ek_public.as_mut_ptr(),
                ek_public.len(),
                &mut ek_public_len,
            )
        } != 0
        || !hex_into(&ek_name_hex, &mut ek_name)
    {
        return -EINVAL;
    }
    let rsa = match cstr(&ek_type) {
        b"rsa" => true,
        b"ecc" => false,
        _ => return -EINVAL,
    };
    // SAFETY: the public area, and room for what it holds.
    if unsafe { tpm_public_parse(ek_public.as_ptr(), ek_public_len, &mut public) } != 0
        || public.ty != if rsa { ALG_RSA } else { ALG_ECC }
    {
        return -EINVAL;
    }

    // The operator's pins come first: the challenge is for the key the
    // operator enrolled, not for whatever the document names.
    if !pol.ak_name.is_null() {
        // SAFETY: the caller's pinned name.
        let pinned = unsafe { ffi::slice(pol.ak_name, NAME_LEN) };

        say!(
            rep,
            !memneq_explicit(&ak_name, pinned),
            c"attestation key: the pinned key"
        );
    }
    if !pol.ek_name.is_null() {
        // SAFETY: the caller's pinned name.
        let pinned = unsafe { ffi::slice(pol.ek_name, NAME_LEN) };

        say!(
            rep,
            !memneq_explicit(&ek_name, pinned),
            c"endorsement key: the pinned key"
        );
    }

    // The key must be an endorsement key, not any decryption key.
    // SAFETY: the public area, and room for its name.
    let named =
        unsafe { tpm_object_name(ek_public.as_ptr(), ek_public_len, computed.as_mut_ptr()) } == 0;
    say!(
        rep,
        named && !memneq_explicit(&computed, &ek_name),
        c"endorsement key: name matches its public area"
    );
    say!(
        rep,
        public.attrs == EK_ATTRS
            && public.policy_len == 32
            && !memneq_explicit(&public.policy, &EK_POLICY),
        c"endorsement key: TCG default template under the endorsement policy"
    );
    if top[2].seen() {
        // SAFETY: an allocation, which the caller frees by its size.
        s.der = unsafe { xmalloc(EK_CERT_MAX) }.cast();
        if s.der.is_null() {
            return -ENOMEM;
        }
        // SAFETY: the certificate's base64, a C string, room for its DER,
        // and the certificate and key to fill.
        let unreadable = unsafe {
            base64_decode(
                s.cert_b64,
                ffi::c_str(s.cert_b64).len(),
                s.der,
                EK_CERT_MAX,
                &mut der_len,
            ) != 0
                || cert_read_der(s.der, der_len, &mut s.cert) != 0
                || cert_pubkey(&s.cert, &mut cert_key) != 0
        };
        if unreadable {
            say!(
                rep,
                false,
                c"endorsement certificate: parseable with a P-256 or RSA-2048 key"
            );
        } else {
            say!(
                rep,
                cert_describes(&cert_key, &public),
                c"endorsement certificate: describes the endorsement key"
            );
            if !pol.ek_ca.is_null() {
                // SAFETY: the certificate, the caller's bundle path, and
                // where the reason goes.
                let vrc = unsafe { cert_verify_chain(&s.cert, pol.ek_ca, &mut reason) };

                if vrc == -EINVAL {
                    say!(
                        rep,
                        false,
                        c"endorsement certificate: issuer bundle %s unreadable",
                        pol.ek_ca
                    );
                } else {
                    let (sep, why) = if vrc != 0 {
                        (c": ".as_ptr(), reason)
                    } else {
                        (c"".as_ptr(), c"".as_ptr())
                    };

                    say!(
                        rep,
                        vrc == 0,
                        c"endorsement certificate: chains to %s%s%s",
                        pol.ek_ca,
                        sep,
                        why
                    );
                }
            } else if vouched {
                note!(
                    rep,
                    c"endorsement certificate: not checked against an issuer bundle (--ek-ca)"
                );
            } else {
                say!(
                    rep,
                    false,
                    c"endorsement certificate: not checked against an issuer bundle; pass --ek-ca, pin the key with --ek-name or waive with --trust-presented-ek"
                );
            }
        }
    } else if vouched {
        note!(
            rep,
            c"no endorsement certificate: the endorsement key is trusted as presented"
        );
    } else {
        say!(
            rep,
            false,
            c"no endorsement certificate: pin the key with --ek-name or waive with --trust-presented-ek"
        );
    }
    if rep.failed != 0 {
        return -EKEYREJECTED;
    }

    // SAFETY: the caller's room for the credential.
    if unsafe { getrandom(credential.cast(), CREDENTIAL_LEN, 0) } != CREDENTIAL_LEN as isize {
        return -EIO;
    }
    if rsa {
        // SAFETY: room for the seed.
        if unsafe { getrandom(s.seed.as_mut_ptr().cast(), s.seed.len(), 0) }
            != s.seed.len() as isize
            // SAFETY: the key's modulus, the label with its NUL, the
            // seed, and room for the secret.
            || unsafe {
                rsa_oaep_encrypt(
                    public.n.as_ptr(),
                    public.n_len,
                    public.rsa_exponent,
                    IDENTITY.as_ptr().cast(),
                    IDENTITY.to_bytes_with_nul().len(),
                    s.seed.as_ptr(),
                    s.seed.len(),
                    secret.as_mut_ptr(),
                    secret.len(),
                    &mut secret_len,
                )
            } != 0
        {
            return -EIO;
        }
    } else {
        if ecdh_p256_ephemeral(&public.x, &public.y, &mut eph_x, &mut eph_y, &mut s.z) != 0
            // SAFETY: the shared secret, the label, the two parties' x,
            // and room for the seed.
            || unsafe {
                tpm_kdfe(
                    s.z.as_ptr(),
                    IDENTITY.as_ptr(),
                    eph_x.as_ptr(),
                    32,
                    public.x.as_ptr(),
                    32,
                    s.seed.as_mut_ptr(),
                )
            } != 0
        {
            return -EIO;
        }
        secret[0] = 0;
        secret[1] = 32;
        secret[2..34].copy_from_slice(&eph_x);
        secret[34] = 0;
        secret[35] = 32;
        secret[36..68].copy_from_slice(&eph_y);
        secret_len = 68;
    }
    // SAFETY: the seed, the key's name, the caller's credential, and room
    // for the blob.
    if unsafe {
        tpm_credential_protect(
            s.seed.as_ptr(),
            ak_name.as_ptr(),
            credential,
            blob.as_mut_ptr(),
        )
    } != 0
    {
        return -EIO;
    }

    *cap = 4096;
    // SAFETY: an allocation, which the caller frees by its size.
    *out = unsafe { xmalloc(*cap) }.cast();
    if (*out).is_null() {
        return -ENOMEM;
    }
    // SAFETY: the *cap bytes xmalloc() gave at *out, which nothing else
    // touches until the emitter is done.
    let mut e = unsafe { JsonEmit::fixed_raw(*out, *cap) };
    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"kind", b"shirudo-credential");
    e.obj_open_key(b"ek");
    e.kv_string(b"type", if rsa { b"rsa" } else { b"ecc" });
    e.kv_string(b"name", cstr(&ek_name_hex));
    e.obj_close();
    e.kv_string(b"ak_name", cstr(&ak_hex));
    // SAFETY: the blob, and room for its hex and a NUL.
    unsafe { hex_encode(blob.as_ptr(), blob.len(), hex.as_mut_ptr().cast()) };
    e.kv_string(b"credential_blob", cstr(&hex));
    // SAFETY: the secret, and room for its hex and a NUL.
    unsafe { hex_encode(secret.as_ptr(), secret_len, hex.as_mut_ptr().cast()) };
    e.kv_string(b"secret", cstr(&hex));
    e.obj_close();
    if e.err() != 0 {
        return e.err();
    }
    // SAFETY: the challenge's room, past what the emitter wrote.
    unsafe { *(*out).add(e.written()) = 0 };
    *out_len = e.written();
    0
}

/// attest_parse_pcrs(): PCRs 0 to 23 apart by commas, into a mask.
///
/// # Safety
///
/// `list` is a C string.
unsafe fn parse_pcrs(list: *const c_char, mask: &mut u32) -> c_int {
    let mut p = list;

    *mask = 0;
    // SAFETY: the caller's C string, walked up to its NUL.
    unsafe {
        while *p != 0 {
            let len = digits(p, ffi::c_str(p).len());
            let mut n = 0u64;

            if parse_u64(p, len, 23, &mut n) != 0 {
                return -EINVAL;
            }
            *mask |= 1 << n;
            p = p.add(len);
            if *p == b',' as c_char && *p.add(1) != 0 {
                p = p.add(1);
            } else if *p != 0 {
                return -EINVAL;
            }
        }
    }
    if *mask != 0 { 0 } else { -EINVAL }
}

/// attest_parse_pcr_value(): "<pcr>=<value>", the PCR, below 24, and
/// where its value starts.
///
/// # Safety
///
/// `arg` is a C string and `pcr` room for a number.
unsafe fn parse_pcr_value(arg: *const c_char, pcr: *mut u64, value: &mut *const c_char) -> c_int {
    // SAFETY: the caller's C string, and room for the number.
    unsafe {
        let len = digits(arg, ffi::c_str(arg).len());

        if *arg.add(len) != b'=' as c_char || parse_u64(arg, len, 23, pcr) != 0 {
            return -EINVAL;
        }
        *value = arg.add(len + 1);
    }
    0
}

/// attest_parse_name_digest(): "<name>=<digest>", a name of 1 to
/// UPATCH_NAME_MAX bytes up to the first equals sign, then 64 hex digits.
///
/// # Safety
///
/// `spec` is a C string, `name` room for UPATCH_NAME_MAX + 1 bytes and
/// `digest` for a digest.
unsafe fn parse_name_digest(spec: *const c_char, name: *mut c_char, digest: *mut u8) -> c_int {
    // SAFETY: the caller's C string.
    let s = unsafe { ffi::c_str(spec) };
    let Some(len) = s.iter().position(|&c| c == b'=') else {
        return -EINVAL;
    };

    if len == 0
        || len > UPATCH_NAME_MAX
        // SAFETY: the C string after the sign, and the caller's room.
        || unsafe { hex_decode(spec.add(len + 1), digest, 32) } != 0
    {
        return -EINVAL;
    }
    // SAFETY: the caller's room for the name and its NUL.
    unsafe {
        ptr::copy_nonoverlapping(spec, name, len);
        *name.add(len) = 0;
    }
    0
}

pub(crate) use capi::{
    attest_challenge_make, attest_challenge_read, attest_evidence_config, attest_parse_name_digest,
    attest_parse_pcr_value, attest_parse_pcrs, attest_verify,
};

#[cfg(shirudo_fuzz)]
mod fuzz;
#[cfg(test)]
mod tests;

mod capi {
    use core::ffi::{c_char, c_int};

    use super::{AttestChallenge, AttestChallengePolicy, AttestExpect};
    use crate::util::config_update::ConfigUpdate;

    /// # Safety
    ///
    /// `path` is a C string and `out` room for a challenge.
    pub unsafe extern "C" fn attest_challenge_read(
        path: *const c_char,
        out: *mut AttestChallenge,
    ) -> c_int {
        // SAFETY: the caller passes a C string and the room.
        unsafe { super::challenge_read(path, out) }
    }

    /// # Safety
    ///
    /// `nonce` holds `nonce_len` bytes, `c` is NULL or a challenge,
    /// `update` NULL or a journal, and `out`, `len` and `cap` rooms.
    #[allow(clippy::too_many_arguments)]
    pub unsafe extern "C" fn attest_evidence_config(
        nonce: *const u8,
        nonce_len: usize,
        pcr_mask: u32,
        c: *const AttestChallenge,
        update: *mut ConfigUpdate,
        out: *mut *mut c_char,
        len: *mut usize,
        cap: *mut usize,
    ) -> c_int {
        // SAFETY: the caller passes the nonce, the challenge, the journal
        // and the rooms.
        unsafe {
            super::evidence_config(
                nonce, nonce_len, pcr_mask, c, update, &mut *out, &mut *len, &mut *cap,
            )
        }
    }

    /// # Safety
    ///
    /// `evidence` holds `len` bytes, `pol` is a policy, `credential` room
    /// for a credential, `out`, `out_len` and `cap` rooms, and `report`
    /// room for `report_cap` bytes.
    #[allow(clippy::too_many_arguments)]
    pub unsafe extern "C" fn attest_challenge_make(
        evidence: *const c_char,
        len: usize,
        pol: *const AttestChallengePolicy,
        credential: *mut u8,
        out: *mut *mut c_char,
        out_len: *mut usize,
        cap: *mut usize,
        report: *mut c_char,
        report_cap: usize,
    ) -> c_int {
        // SAFETY: the caller passes the evidence, the policy and the
        // rooms.
        unsafe {
            super::challenge_make(
                evidence,
                len,
                &*pol,
                credential,
                &mut *out,
                &mut *out_len,
                &mut *cap,
                report,
                report_cap,
            )
        }
    }

    /// # Safety
    ///
    /// `evidence` holds `len` bytes, `expect` is an expectation, and
    /// `report` has room for `report_cap` bytes.
    pub unsafe extern "C" fn attest_verify(
        evidence: *const c_char,
        len: usize,
        expect: *const AttestExpect,
        report: *mut c_char,
        report_cap: usize,
    ) -> c_int {
        // SAFETY: the caller passes the evidence, the expectation and the
        // report's room.
        unsafe { super::verify(evidence, len, &*expect, report, report_cap) }
    }

    /// # Safety
    ///
    /// `list` is a C string and `mask` room for a mask.
    pub unsafe extern "C" fn attest_parse_pcrs(list: *const c_char, mask: *mut u32) -> c_int {
        // SAFETY: the caller passes a C string and the room.
        unsafe { super::parse_pcrs(list, &mut *mask) }
    }

    /// # Safety
    ///
    /// `arg` is a C string, and `pcr` and `value` rooms.
    pub unsafe extern "C" fn attest_parse_pcr_value(
        arg: *const c_char,
        pcr: *mut u64,
        value: *mut *const c_char,
    ) -> c_int {
        // SAFETY: the caller passes a C string and the rooms.
        unsafe { super::parse_pcr_value(arg, pcr, &mut *value) }
    }

    /// # Safety
    ///
    /// `spec` is a C string, `name` room for UPATCH_NAME_MAX + 1 bytes
    /// and `digest` for a digest.
    pub unsafe extern "C" fn attest_parse_name_digest(
        spec: *const c_char,
        name: *mut c_char,
        digest: *mut u8,
    ) -> c_int {
        // SAFETY: the caller passes a C string and the rooms.
        unsafe { super::parse_name_digest(spec, name, digest) }
    }
}
