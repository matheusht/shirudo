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
use crate::heap::{xfree, xmalloc};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    AT_FDCWD, O_CLOEXEC, O_RDONLY, STATX_BASIC_STATS, Statx, close, errno, explicit_bzero,
    getrandom, open, read, scrub, statx,
};
use crate::sys::tss2::NV_WRITTEN;
use crate::sys::version::shirudo_version_id;
use crate::text::{cstr, digits, parse_u64, parse_x64};
use crate::util::bpm_tree::digest_bytes;
use crate::util::chain::{
    self, ANCHOR_MAX, PCR as CHAIN_PCR, PCR_MASK as CHAIN_PCR_MASK, PHASE_PCR as CHAIN_PHASE_PCR,
    memneq_explicit,
};
use crate::util::config_attest::{self, Evidence, Quote};
use crate::util::config_update::ConfigUpdate;
use crate::util::crypto_openssl::{
    Cert, CertPubkey, base64_decode, base64_encode, cert_free, cert_pubkey, cert_read_der,
    cert_verify_chain, ecdh_p256_ephemeral, rsa_oaep_encrypt, sha256, sha256_into,
};
use crate::util::eventlog::{
    NV_INDEX, eventlog_boot_id, eventlog_boot_lines, eventlog_path, eventlog_timestamp,
};
use crate::util::hex::{decode, decode_max, encode, hex_encode};
use crate::util::io;
use crate::util::json::{JsonEmit, JsonField, MAX_BYTES as JSON_MAX_BYTES, parse_schema};
use crate::util::tpm::{
    ATTEST_MAX, EK_ATTRS, PUBLIC_MAX, REGISTER_ATTRS, SIGNATURE_MAX, Tpm, TpmAttestation, TpmKey,
    TpmNvInfo, tpm_activate_credential, tpm_ak_create, tpm_close, tpm_ek_certificate,
    tpm_ek_create, tpm_key_flush, tpm_nv_certify, tpm_nv_info, tpm_nv_read, tpm_open, tpm_pcr_read,
    tpm_quote,
};
use crate::util::tpm_wire::{
    ALG_ECC, ALG_RSA, CREDENTIAL_LEN, EK_POLICY, ID_OBJECT_LEN, NAME_LEN, NV_RSA_BYTES,
    RegisterPolicy, ST_ATTEST_NV, ST_ATTEST_QUOTE, TpmAttest, TpmEccPublic, TpmPublic,
    attest_parse, attest_signer, attest_verify as signature_verify, credential_protect,
    ecc_public_parse, kdfe, nv_name, object_name, public_parse, register_policy,
};
use crate::util::upatch::{self, NAME_MAX as UPATCH_NAME_MAX};

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
/// The longest challenge made.
const CHALLENGE_DOC_MAX: usize = 4096;
/// The longest secret of a challenge, an RSA-2048 key's OAEP.
const SECRET_MAX: usize = 256;
/// The label of a credential's seed, which the TPM takes with its NUL.
const IDENTITY: &CStr = c"IDENTITY";

/// A credential challenge: the blob and the encrypted seed
/// TPM2_ActivateCredential takes, for the attestation key of a name under
/// the endorsement key of a type.
pub(crate) struct AttestChallenge {
    ek_rsa: bool,
    ak_name: [u8; NAME_LEN],
    blob: [u8; ID_OBJECT_LEN],
    secret: Vec<u8>,
}

/// What the operator vouches for when making a challenge.
#[derive(Default)]
pub(crate) struct AttestChallengePolicy<'a> {
    /// The issuer bundle the EK certificate must chain to.
    pub(crate) ek_ca: Option<&'a CStr>,
    pub(crate) ak_name: Option<[u8; NAME_LEN]>,
    pub(crate) ek_name: Option<[u8; NAME_LEN]>,
    /// Accept an unvouched endorsement key.
    pub(crate) trust_presented: bool,
}

/// What the operator expects the evidence to show.
#[derive(Default)]
pub(crate) struct AttestExpect {
    /// The nonce the evidence was requested with.
    pub(crate) nonce: Vec<u8>,
    pub(crate) ak_name: Option<[u8; NAME_LEN]>,
    /// The register's value after the expected events.
    pub(crate) chain: Option<[u8; 32]>,
    /// The init event of the certificates, set and tree root known.
    pub(crate) init_event: Option<[u8; 32]>,
    pub(crate) allow_runtime_events: bool,
    pub(crate) strict_anchor: bool,
    /// The PCRs whose values the quote must carry, and the values.
    pub(crate) pcr_expect_mask: u32,
    pub(crate) pcrs: [[u8; 32]; 24],
    pub(crate) credential: Option<[u8; CREDENTIAL_LEN]>,
    pub(crate) ek_name: Option<[u8; NAME_LEN]>,
    /// The binding must be the initrd's.
    pub(crate) require_initrd: bool,
    /// The PCRs whose values at binding time are pinned, and the values.
    pub(crate) bind_expect_mask: u32,
    pub(crate) bind_values: [[u8; 32]; 24],
    pub(crate) config_root: Option<[u8; 32]>,
    pub(crate) config_pcr: Option<u32>,
}

/// An eventlog record as the report names it.
struct Record {
    ty: Vec<u8>,
    label: Vec<u8>,
    digest: [u8; 32],
    /// The digest follows from the record's fields.
    derived: bool,
}

/// The boot's last init record.
struct InitRecord {
    writer_public: [u8; NV_RSA_BYTES],
    present: bool,
    initrd: bool,
    reset_count: Option<u32>,
    pcr: u32,
    phase_pcr: u32,
    digest: [u8; 32],
    pcr_before: [u8; 32],
    phase_before: [u8; 32],
    name: [u8; NAME_LEN],
    anchor_digest: [u8; 32],
}

impl InitRecord {
    const fn new() -> Self {
        InitRecord {
            writer_public: [0; NV_RSA_BYTES],
            present: false,
            initrd: false,
            reset_count: None,
            pcr: 0,
            phase_pcr: 0,
            digest: [0; 32],
            pcr_before: [0; 32],
            phase_before: [0; 32],
            name: [0; NAME_LEN],
            anchor_digest: [0; 32],
        }
    }
}

/// What the evidence's schema reads into: the text of each value, in
/// room that bounds it, and what its arrays of PCRs and records give.
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
    recs: Vec<Record>,
    /// Init records this boot.
    inits: u32,
    /// Those for the last reset count.
    inits_epoch: u32,
    init: InitRecord,
}

impl Parse {
    /// Nothing parsed yet, a record's numbers not given.
    const fn new() -> Self {
        Parse {
            writer_public_hex: [0; 2 * NV_RSA_BYTES + 1],
            nonce_hex: [0; 2 * NONCE_MAX + 1],
            pcr_mask: 0,
            ak_public_hex: [0; 2 * PUBLIC_MAX + 1],
            ak_name_hex: [0; 2 * NAME_LEN + 1],
            quote_attest_hex: [0; 2 * ATTEST_MAX + 1],
            quote_sig_hex: [0; 2 * SIGNATURE_MAX + 1],
            ek_type: [0; 8],
            ek_public_hex: [0; 2 * PUBLIC_MAX + 1],
            ek_name_hex: [0; 2 * NAME_LEN + 1],
            cred_hex: [0; 2 * CREDENTIAL_LEN + 1],
            reg_index: [0; 16],
            reg_pcr: 0,
            reg_name_hex: [0; 2 * NAME_LEN + 1],
            reg_value_hex: [0; 65],
            reg_attest_hex: [0; 2 * ATTEST_MAX + 1],
            reg_sig_hex: [0; 2 * SIGNATURE_MAX + 1],
            pcr_index: 0,
            pcr_value_hex: [0; 65],
            pcr_have: 0,
            pcrs: [[0; 32]; 24],
            ty: [0; 16],
            digest_hex: [0; 65],
            pcr_before_hex: [0; 65],
            phase_before_hex: [0; 65],
            bound_in: [0; 8],
            nv_name_hex: [0; 2 * NAME_LEN + 1],
            anchor: [0; ANCHOR_MAX],
            anchor_digest_hex: [0; 65],
            chain_hex: [0; 65],
            rec_pcr: -1,
            rec_phase_pcr: -1,
            rec_reset: -1,
            upatch_name: [0; UPATCH_NAME_MAX + 1],
            upatch_payload_hex: [0; 65],
            tree_id: [0; UPATCH_NAME_MAX + 1],
            tree_op: [0; 16],
            tree_digest_hex: [0; 8 + 64],
            tree_seq: 0,
            key_fingerprint: [0; 65],
            key_sha_hex: [0; 65],
            recs: Vec::new(),
            inits: 0,
            inits_epoch: 0,
            init: InitRecord::new(),
        }
    }
}

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
    let mut a = TpmAttest::zeroed();

    if quote
        .attest
        .get(..quote.attest_len)
        .is_none_or(|bytes| attest_parse(bytes, &mut a) != 0)
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
    *out = ptr::null_mut();
    *len = 0;
    *cap = 0;
    if nonce_len > NONCE_MAX || pcr_mask == 0 || pcr_mask & !0x00FF_FFFF != 0 {
        return -EINVAL;
    }
    // SAFETY: the caller's journal or NULL.
    let config = match config_attest::collect(unsafe { update.as_ref() }) {
        Ok(config) => config,
        Err(ret) => return ret,
    };
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
    // is open, and the allocations by their sizes.
    unsafe {
        if !s.tpm.is_null() {
            tpm_key_flush(s.tpm, &mut s.ek);
            tpm_key_flush(s.tpm, &mut s.ak);
            tpm_close(s.tpm);
        }
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
        let mut quoted = TpmAttest::zeroed();

        if quote
            .attest
            .get(..quote.attest_len)
            .is_none_or(|bytes| attest_parse(bytes, &mut quoted) != 0)
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
                c.blob.len(),
                c.secret.as_ptr(),
                c.secret.len(),
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
        .wrapping_add(config.n_events().wrapping_mul(160));
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
    if let Err(ret) = config_attest::emit(&mut e, config) {
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
    let index = usize::try_from(p.pcr_index)
        .ok()
        .filter(|&i| i < p.pcrs.len())
        .ok_or(-EINVAL)?;

    if !hex_into(&p.pcr_value_hex, &mut p.pcrs[index]) {
        return Err(-EINVAL);
    }
    p.pcr_have |= 1u32 << index;
    Ok(())
}

/// Whether the report may print `s` as it stands. The report prints a
/// record's type and label as they stand, and the target writes them:
/// only the words its writers use may pass, or an escape sequence would
/// rewrite what the operator reads.
fn record_word(s: &[u8]) -> bool {
    s.iter().all(|&c| c.is_ascii_lowercase() || c == b'_')
}

/// The hex of the C string in `hex` decoded into all of `out`.
fn hex_into(hex: &[u8], out: &mut [u8]) -> bool {
    decode(cstr(hex), out).is_ok()
}

/// The bytes the hex of the C string in `hex` spells, as the start of
/// `room`: -EINVAL for more than it holds or for what is not hex.
fn hex_text<'a>(hex: &[u8], room: &'a mut [u8]) -> Result<&'a [u8], c_int> {
    let n = decode_max(cstr(hex), room)?;

    room.get(..n).ok_or(-EINVAL)
}

/// At most the first `n` bytes of `s`, as `%.<n>s` prints them.
fn first(s: &[u8], n: usize) -> &[u8] {
    s.get(..n).unwrap_or(s)
}

/// The init record the parse holds, of the digest `digest`, as the
/// boot's last: -EINVAL for a field out of range or not hex.
fn take_init(p: &mut Parse, digest: &[u8; 32]) -> Result<(), c_int> {
    let prev_reset = p.init.reset_count;
    let mut init = InitRecord::new();
    // Checked, as the record must carry it, but not used.
    let mut chain = [0u8; 32];

    let (Ok(pcr), Ok(phase_pcr)) = (u32::try_from(p.rec_pcr), u32::try_from(p.rec_phase_pcr))
    else {
        return Err(-EINVAL);
    };
    if pcr >= 24
        || phase_pcr <= pcr
        || phase_pcr >= 24
        || p.rec_reset > i64::from(u32::MAX)
        || !hex_into(&p.pcr_before_hex, &mut init.pcr_before)
        || !hex_into(&p.phase_before_hex, &mut init.phase_before)
        || !hex_into(&p.nv_name_hex, &mut init.name)
        || !hex_into(&p.anchor_digest_hex, &mut init.anchor_digest)
        || !hex_into(&p.chain_hex, &mut chain)
        || !hex_into(&p.writer_public_hex, &mut init.writer_public)
    {
        return Err(-EINVAL);
    }
    init.digest = *digest;
    init.pcr = pcr;
    init.phase_pcr = phase_pcr;
    init.initrd = cstr(&p.bound_in) == b"initrd";
    init.reset_count = u32::try_from(p.rec_reset).ok();
    init.present = true;
    // Records are of one TPM reset unless both carry a count and the
    // counts differ; a second record for one reset is a register bound
    // again after boot.
    p.inits = p.inits.wrapping_add(1);
    let reset_changed =
        matches!((init.reset_count, prev_reset), (Some(now), Some(before)) if now != before);
    if p.inits == 1 || reset_changed {
        p.inits_epoch = 1;
    } else {
        p.inits_epoch = p.inits_epoch.wrapping_add(1);
    }
    p.init = init;
    Ok(())
}

/// Whether the digest of the load or unload `r` follows from its name
/// and payload, which the tag `tag` measures: -EINVAL for a name that is
/// not an upatch's.
fn derive_upatch(p: &Parse, tag: &CStr, r: &mut Record) -> Result<(), c_int> {
    let name = cstr(&p.upatch_name);
    let mut payload = [0u8; 32];
    let mut event = [0u8; 32];

    if !upatch::name_valid(Some(name)) {
        return Err(-EINVAL);
    }
    r.label = name.to_vec();
    if hex_into(&p.upatch_payload_hex, &mut payload)
        && chain::upatch_event(tag, name, &payload, &mut event) == 0
    {
        r.derived = !memneq_explicit(&event, &r.digest);
    }
    Ok(())
}

/// Whether the digest of the tree operation `r` follows from its
/// sequence and operation digest.
fn derive_tree_op(p: &Parse, r: &mut Record) {
    let mut event = [0u8; 32];

    // verify cannot tie op and id to the digest: leave them out.
    r.label = format!("seq {}", p.tree_seq).into_bytes();
    if p.tree_seq > 0
        && let Some(operation) = digest_bytes(&p.tree_digest_hex)
        && chain::tree_event(p.tree_seq, &operation, &mut event) == 0
    {
        r.derived = !memneq_explicit(&event, &r.digest);
        // The digest's hex after its "sha256:".
        let hex = cstr(&p.tree_digest_hex).get(7..).unwrap_or_default();
        r.label = [
            format!("seq {} operation ", p.tree_seq).as_bytes(),
            first(hex, 12),
        ]
        .concat();
    }
}

/// Whether the digest of the revocation `r` follows from the
/// certificate's digest.
fn derive_key_revoke(p: &Parse, r: &mut Record) {
    let mut sha = [0u8; 32];
    let mut event = [0u8; 32];

    // Nor the fingerprint: name the measured certificate.
    if hex_into(&p.key_sha_hex, &mut sha)
        && chain::key_event(c"shirudo-key-revoke", &sha, &mut event) == 0
    {
        r.derived = !memneq_explicit(&event, &r.digest);
        r.label = [b"certificate ", first(cstr(&p.key_sha_hex), 12)].concat();
    }
}

/// What the eventlog's array calls with each record.
fn on_record(p: &mut Parse) -> Result<(), c_int> {
    if p.recs.len() >= RECORDS_MAX {
        return Err(-E2BIG);
    }
    let ty = cstr(&p.ty).to_vec();
    if !record_word(&ty) {
        return Err(-EINVAL);
    }
    let mut r = Record {
        ty: ty.clone(),
        label: Vec::new(),
        digest: [0; 32],
        derived: false,
    };
    if !hex_into(&p.digest_hex, &mut r.digest) {
        return Err(-EINVAL);
    }
    match ty.as_slice() {
        b"init" => {
            take_init(p, &r.digest)?;
            // This boot's register starts here.
            p.recs.clear();
        }
        b"upatch_load" => derive_upatch(p, c"shirudo-upatch", &mut r)?,
        b"upatch_unload" => derive_upatch(p, c"shirudo-unload", &mut r)?,
        b"tree_op" => derive_tree_op(p, &mut r),
        b"key_revoke" => derive_key_revoke(p, &mut r),
        _ => {}
    }
    p.recs.push(r);
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

/// The tag of a line of the report, as long as each tag.
const TAG_LEN: usize = 8;
const TAG_OK: &[u8; TAG_LEN] = b"  OK    ";
const TAG_FAIL: &[u8; TAG_LEN] = b"  FAIL  ";
const TAG_NOTE: &[u8; TAG_LEN] = b"  NOTE  ";

/// A report of checks and notes, a line each, in at most `cap` bytes
/// and the NUL after them, as the C's buffer of that size held it, and
/// how many of the checks failed.
pub(crate) struct Report {
    text: Vec<u8>,
    cap: usize,
    failed: u32,
}

impl Report {
    /// A report of at most `cap` bytes, its NUL included.
    pub(crate) fn new(cap: usize) -> Self {
        Report {
            text: Vec::new(),
            cap,
            failed: 0,
        }
    }

    /// The lines of the report.
    pub(crate) fn text(&self) -> &[u8] {
        &self.text
    }

    /// A line: its tag, then `text` where it fits whole with a NUL after
    /// it, then a line feed where room is left, and nothing once the
    /// room left would not hold a tag and its NUL.
    fn line(&mut self, tag: &[u8; TAG_LEN], text: &[u8]) {
        if self.text.len() + TAG_LEN >= self.cap {
            return;
        }
        self.text.extend_from_slice(tag);
        if self.text.len() + text.len() < self.cap {
            self.text.extend_from_slice(text);
        }
        if self.text.len() + 1 < self.cap {
            self.text.push(b'\n');
        }
    }

    /// A check, which counts when it failed.
    fn check(&mut self, ok: bool, text: &[u8]) {
        if !ok {
            self.failed = self.failed.saturating_add(1);
        }
        self.line(if ok { TAG_OK } else { TAG_FAIL }, text);
    }

    /// A remark, which is no check.
    fn note(&mut self, text: &[u8]) {
        self.line(TAG_NOTE, text);
    }
}

/// The attestation key that signs the evidence's attestations, its name,
/// and the nonce they must carry.
struct Signer<'a> {
    key: &'a TpmEccPublic,
    name: &'a [u8; NAME_LEN],
    nonce: &'a [u8],
}

/// An attestation of the evidence: its bytes, and what they hold as far
/// as they parse.
struct Signed {
    bytes: Vec<u8>,
    attest: TpmAttest,
    /// The attestation and its signature parse, and were checked.
    checked: bool,
}

/// The attestation in `attest_hex`, which `sig_hex` signs, checked
/// against the signer, every check into the report as `what`'s: -EINVAL
/// for hex that does not decode.
fn check_signed(
    rep: &mut Report,
    signer: &Signer,
    what: &[u8],
    attest_hex: &[u8],
    sig_hex: &[u8],
) -> Result<Signed, c_int> {
    let mut bytes = vec![0u8; ATTEST_MAX];
    let mut sig = [0u8; SIGNATURE_MAX];
    let mut attest = TpmAttest::zeroed();

    let attest_len = decode_max(cstr(attest_hex), &mut bytes)?;
    let sig = hex_text(sig_hex, &mut sig)?;
    bytes.truncate(attest_len);
    let checked = check_attest(rep, signer, what, &bytes, sig, &mut attest);
    Ok(Signed {
        bytes,
        attest,
        checked,
    })
}

/// The checks of check_signed() on the attestation `bytes`, parsed into
/// `attest`, and its signature `sig`: whether they parse.
fn check_attest(
    rep: &mut Report,
    signer: &Signer,
    what: &[u8],
    bytes: &[u8],
    sig: &[u8],
    attest: &mut TpmAttest,
) -> bool {
    if attest_parse(bytes, attest) != 0 {
        rep.check(
            false,
            &[what, b": attestation structure unparseable"].concat(),
        );
        return false;
    }
    let ret = signature_verify(bytes, sig, &signer.key.x, &signer.key.y);
    if ret == -EBADMSG {
        rep.check(
            false,
            &[what, b": signature structure unparseable"].concat(),
        );
        return false;
    }
    rep.check(
        ret == 0,
        &[what, b": ECDSA signature by the attestation key"].concat(),
    );
    rep.check(
        attest_signer(attest, signer.name) == Ok(true),
        &[what, b": signed by the key as an endorsement primary"].concat(),
    );
    let nonce = signer.nonce;
    let carried = attest.extra_in(bytes).is_some_and(|extra| {
        extra.len() == nonce.len() && (nonce.is_empty() || !memneq_explicit(extra, nonce))
    });
    rep.check(carried, &[what, b": carries the nonce"].concat());
    true
}

/// Whether `public` is an endorsement key of the TCG default template.
fn endorsement_template(public: &TpmPublic) -> bool {
    public.attrs == EK_ATTRS
        && public.policy_len == 32
        && !memneq_explicit(&public.policy, &EK_POLICY)
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

/// attest verify: the evidence checked against what the operator
/// expects, every check into the report: -EKEYREJECTED when one failed,
/// -EINVAL for a malformed document.
pub(crate) fn verify(
    evidence: &[u8],
    expect: &AttestExpect,
    rep: &mut Report,
) -> Result<(), c_int> {
    let mut p = Box::new(Parse::new());

    p.recs.try_reserve_exact(RECORDS_MAX).map_err(|_| -ENOMEM)?;
    let (have_ek, have_cred) = parse_evidence(&mut p, evidence)?;
    let config = parse_config(rep, evidence)?;

    // Freshness: the document must answer this request.
    let mut nonce = [0u8; NONCE_MAX];
    let nonce = hex_text(&p.nonce_hex, &mut nonce)?;
    let fresh = expect.nonce.len() == nonce.len()
        && (nonce.is_empty() || !memneq_explicit(nonce, &expect.nonce));
    rep.check(fresh, b"nonce matches the request");

    let (ak_pub, ak_name) = check_ak(rep, &p, expect)?;
    check_ek(rep, &p, expect, have_ek)?;
    check_credential(rep, &p, expect, have_cred)?;

    let signer = Signer {
        key: &ak_pub,
        name: &ak_name,
        nonce,
    };
    let quote = check_signed(
        rep,
        &signer,
        b"quote",
        &p.quote_attest_hex,
        &p.quote_sig_hex,
    )?;
    check_quote(rep, &mut p, &quote);
    let certify = check_signed(rep, &signer, b"register", &p.reg_attest_hex, &p.reg_sig_hex)?;
    let register = read_register(&p)?;
    check_certify(rep, &register, &certify);
    // A restart clears the register as a reset does.
    if quote.checked && certify.checked {
        let (q, c) = (&quote.attest, &certify.attest);
        rep.check(
            q.reset_count == c.reset_count
                && q.restart_count == c.restart_count
                && q.firmware_version == c.firmware_version,
            b"quote and certification are of one TPM boot",
        );
    }
    check_config(rep, &p, expect, &config, &quote.attest);

    check_binding(rep, &p, expect, &register)?;
    check_epoch(rep, &p, &certify);
    check_replay(rep, &p, &register.value);
    check_anchor(rep, &p, expect);
    check_state(rep, &p, expect, &register.value);
    for bit in 0..24u32 {
        if expect.pcr_expect_mask & (1 << bit) == 0 {
            continue;
        }
        let i = bit as usize;
        rep.check(
            p.pcr_have & (1 << bit) != 0 && !memneq_explicit(&p.pcrs[i], &expect.pcrs[i]),
            format!("PCR {bit} matches the expected value").as_bytes(),
        );
    }
    if rep.failed != 0 {
        return Err(-EKEYREJECTED);
    }
    Ok(())
}

/// The config's history the evidence carries, the failure of a history
/// out of order into the report.
fn parse_config(rep: &mut Report, evidence: &[u8]) -> Result<Evidence, c_int> {
    config_attest::parse(evidence).map_err(|ret| {
        if ret == -EKEYREJECTED {
            rep.check(
                false,
                b"config: the events are one boot event followed by updates in sequence",
            );
        }
        // What json_parse() refuses past a bound is a malformed document.
        if ret == -E2BIG || ret == -ENOSPC {
            return -EINVAL;
        }
        ret
    })
}

/// The attestation key the evidence names, checked: its public area and
/// its name, or -EKEYREJECTED for a key that is not a P-256 ECDSA key.
fn check_ak(
    rep: &mut Report,
    p: &Parse,
    expect: &AttestExpect,
) -> Result<(TpmEccPublic, [u8; NAME_LEN]), c_int> {
    let mut ak_public = [0u8; PUBLIC_MAX];
    let mut ak_name = [0u8; NAME_LEN];
    let mut ak_pub = TpmEccPublic::zeroed();
    let mut computed = [0u8; NAME_LEN];

    let ak_public = hex_text(&p.ak_public_hex, &mut ak_public)?;
    if !hex_into(&p.ak_name_hex, &mut ak_name) {
        return Err(-EINVAL);
    }
    if ecc_public_parse(ak_public, &mut ak_pub) != 0 {
        rep.check(
            false,
            b"attestation key: public area is not a P-256 ECDSA key",
        );
        return Err(-EKEYREJECTED);
    }
    rep.check(
        ak_pub.attrs & AK_ATTRS_REQUIRED == AK_ATTRS_REQUIRED,
        b"attestation key: restricted, fixed to this TPM",
    );
    let named = object_name(ak_public, &mut computed) == 0;
    rep.check(
        named && !memneq_explicit(&computed, &ak_name),
        b"attestation key: name matches its public area",
    );
    match &expect.ak_name {
        Some(pinned) => rep.check(
            !memneq_explicit(&ak_name, pinned),
            b"attestation key: the pinned key",
        ),
        None => rep.note(&[b"attestation key not pinned: name ", cstr(&p.ak_name_hex)].concat()),
    }
    Ok((ak_pub, ak_name))
}

/// The endorsement key the evidence carries, if any, checked, and
/// against the one pinned.
fn check_ek(
    rep: &mut Report,
    p: &Parse,
    expect: &AttestExpect,
    have_ek: bool,
) -> Result<(), c_int> {
    if have_ek {
        let mut ek_public = [0u8; PUBLIC_MAX];
        let mut ek_name = [0u8; NAME_LEN];
        let mut computed = [0u8; NAME_LEN];
        let mut ek_pub = TpmPublic::zeroed();

        let ek_public = hex_text(&p.ek_public_hex, &mut ek_public)?;
        if !hex_into(&p.ek_name_hex, &mut ek_name) {
            return Err(-EINVAL);
        }
        let parsed = public_parse(ek_public, &mut ek_pub) == 0;
        let named = parsed
            && object_name(ek_public, &mut computed) == 0
            && !memneq_explicit(&computed, &ek_name);
        rep.check(named, b"endorsement key: name matches its public area");
        rep.check(
            parsed && endorsement_template(&ek_pub),
            b"endorsement key: TCG default template under the endorsement policy",
        );
    } else {
        rep.note(b"no endorsement key in the evidence");
    }
    if let Some(pinned) = &expect.ek_name {
        let mut ek_name = [0u8; NAME_LEN];
        let ok =
            have_ek && hex_into(&p.ek_name_hex, &mut ek_name) && !memneq_explicit(&ek_name, pinned);

        rep.check(ok, b"endorsement key: the pinned key");
    }
    Ok(())
}

/// The credential the target activated, if any, against the one the
/// challenge carried.
fn check_credential(
    rep: &mut Report,
    p: &Parse,
    expect: &AttestExpect,
    have_cred: bool,
) -> Result<(), c_int> {
    // On the heap, so that it is scrubbed when it goes.
    let mut room = vec![0u8; CREDENTIAL_LEN];
    let cred = if have_cred {
        hex_text(&p.cred_hex, &mut room)?
    } else {
        &[]
    };

    match &expect.credential {
        Some(want) => rep.check(
            have_cred && cred.len() == CREDENTIAL_LEN && !memneq_explicit(cred, want),
            b"attestation key: activated the credential made for it under the endorsement key",
        ),
        None if have_cred => {
            rep.note(b"a credential was activated but none is expected (--expect-credential)")
        }
        None => {}
    }
    Ok(())
}

/// The quote's checks against the PCRs the document lists, which stand
/// as quoted only when they pass.
fn check_quote(rep: &mut Report, p: &mut Parse, quote: &Signed) {
    if !quote.checked {
        p.pcr_have = 0;
        return;
    }
    let q = &quote.attest;
    let complete =
        q.ty == ST_ATTEST_QUOTE && p.pcr_mask == i64::from(q.pcr_mask) && p.pcr_have == q.pcr_mask;
    rep.check(complete, b"quote: covers the PCRs the document lists");
    let vouched = complete
        && pcr_values_digest(q.pcr_mask, &p.pcrs)
            .is_some_and(|d| !memneq_explicit(&d, &q.pcr_digest));
    rep.check(vouched, b"quote: PCR digest matches the listed values");
    if !vouched {
        p.pcr_have = 0;
    }
}

/// The register as the document lists it.
struct Register {
    index: u64,
    name: [u8; NAME_LEN],
    value: [u8; 32],
}

/// The register the document lists: -EINVAL for a field malformed.
fn read_register(p: &Parse) -> Result<Register, c_int> {
    let mut register = Register {
        index: 0,
        name: [0; NAME_LEN],
        value: [0; 32],
    };

    if !hex_into(&p.reg_name_hex, &mut register.name)
        || !hex_into(&p.reg_value_hex, &mut register.value)
        || !(0..24).contains(&p.reg_pcr)
    {
        return Err(-EINVAL);
    }
    let digits = cstr(&p.reg_index).strip_prefix(b"0x").ok_or(-EINVAL)?;
    register.index = parse_x64(digits, 0xffff_ffff).map_err(|_| -EINVAL)?;
    Ok(register)
}

/// The certification's checks against the register the document lists.
fn check_certify(rep: &mut Report, register: &Register, certify: &Signed) {
    if !certify.checked {
        return;
    }
    let c = &certify.attest;
    rep.check(
        c.ty == ST_ATTEST_NV
            && c.index_name_len == NAME_LEN
            && !memneq_explicit(&c.index_name, &register.name),
        b"register: certification names the listed index",
    );
    let contents = c.ty == ST_ATTEST_NV
        && c.offset == 0
        && c.nv_len == 32
        && c.nv_data_in(&certify.bytes)
            .is_some_and(|data| !memneq_explicit(data, &register.value));
    rep.check(
        contents,
        b"register: certified contents match the listed value",
    );
}

/// The config's history against the quote, where the evidence carries
/// one or the operator expects one.
fn check_config(
    rep: &mut Report,
    p: &Parse,
    expect: &AttestExpect,
    config: &Evidence,
    quote: &TpmAttest,
) {
    if !config.present && expect.config_root.is_none() && expect.config_pcr.is_none() {
        return;
    }
    let quoted = Quote {
        mask: quote.pcr_mask,
        reset: quote.reset_count,
        pcrs: &p.pcrs,
        nvpcr: None,
    };
    let (ret, reason) = config_attest::verify(
        config,
        &quoted,
        expect.config_root.as_ref(),
        expect.config_pcr,
    );

    rep.check(ret == 0, &[b"config: ", reason.to_bytes()].concat());
    if config.present && expect.config_root.is_none() {
        rep.note(
            b"config root has no operator approval; use --expect-config-root with --expect-config-pcr",
        );
    }
    if config.present {
        rep.note(b"config records a selection; direct TPM writer protection is deferred");
    }
}

/// The binding of the register: -EKEYREJECTED without an init record or
/// for recorded values its policy cannot be computed of.
fn check_binding(
    rep: &mut Report,
    p: &Parse,
    expect: &AttestExpect,
    register: &Register,
) -> Result<(), c_int> {
    let init = &p.init;
    let mut branch_written = [0u8; 32];
    let mut branch_init = [0u8; 32];
    let mut policy = [0u8; 32];
    let mut bind = [0u8; 64];
    let mut expected_name = [0u8; NAME_LEN];

    // The binding: the certified index must have the public area a
    // register bound to the recorded PCR values has, which is what makes
    // a recreation impossible to pass off, and those values are what the
    // operator pins to tell an initrd binding from a later one. The
    // handle and the PCRs are the register's, never the document's: taken
    // from the record, a target could certify an index of its own under a
    // policy over PCRs it can extend and reset at will.
    rep.check(init.present, b"eventlog: this boot has an init record");
    if !init.present {
        return Err(-EKEYREJECTED);
    }
    rep.check(
        register.index == u64::from(NV_INDEX)
            && p.reg_pcr == i64::from(CHAIN_PCR)
            && init.pcr == CHAIN_PCR
            && init.phase_pcr == CHAIN_PHASE_PCR,
        format!(
            "register: the document names index 0x{NV_INDEX:08X} and PCRs {CHAIN_PCR} and {CHAIN_PHASE_PCR}"
        )
        .as_bytes(),
    );
    bind[..32].copy_from_slice(&init.pcr_before);
    bind[32..].copy_from_slice(&init.phase_before);
    let ret = register_policy(
        CHAIN_PCR_MASK,
        &bind,
        &init.writer_public,
        RegisterPolicy {
            branch_written: &mut branch_written,
            branch_init: &mut branch_init,
            policy: &mut policy,
        },
    );
    if ret != 0 {
        rep.check(false, b"register: cannot compute the signed write policy");
        // Malformed recorded values are the document's failure, not a
        // parse error.
        return Err(if ret == -EINVAL { -EKEYREJECTED } else { ret });
    }
    let ret = nv_name(
        NV_INDEX,
        REGISTER_ATTRS | NV_WRITTEN,
        &policy,
        32,
        &mut expected_name,
    );
    if ret != 0 {
        rep.check(false, b"register: cannot compute the index name");
        return Err(ret);
    }
    rep.check(
        !memneq_explicit(&expected_name, &register.name)
            && !memneq_explicit(&expected_name, &init.name),
        format!(
            "register: public area is bound to PCRs {CHAIN_PCR} and {CHAIN_PHASE_PCR} as recorded"
        )
        .as_bytes(),
    );
    for bit in 0..24u32 {
        if expect.bind_expect_mask & (1 << bit) == 0 {
            continue;
        }
        let held = match bit {
            CHAIN_PCR => Some(&init.pcr_before),
            CHAIN_PHASE_PCR => Some(&init.phase_before),
            _ => None,
        };
        rep.check(
            held.is_some_and(|h| !memneq_explicit(h, &expect.bind_values[bit as usize])),
            format!("binding: PCR {bit} held the expected value").as_bytes(),
        );
    }
    if expect.require_initrd {
        rep.check(init.initrd, b"binding: made while the initrd ran");
    } else {
        let place: &[u8] = if init.initrd {
            b"initrd"
        } else {
            b"root file system"
        };

        rep.note(&[b"binding: made in the ", place].concat());
    }
    Ok(())
}

/// The epoch: one binding per TPM reset, and the one on record is of
/// the reset the TPM certifies in, so no register bound again after
/// boot can pass as the boot's.
fn check_epoch(rep: &mut Report, p: &Parse, certify: &Signed) {
    rep.check(
        p.inits_epoch == 1,
        format!(
            "eventlog: one init record for this TPM reset ({} this boot)",
            p.inits
        )
        .as_bytes(),
    );
    if certify.checked {
        rep.check(
            p.init.reset_count == Some(certify.attest.reset_count),
            b"register: init record is of the TPM's current reset count",
        );
    }
}

/// The records replayed to the certified value, and each one after the
/// init record whose digest its fields do not give.
fn check_replay(rep: &mut Report, p: &Parse, value: &[u8; 32]) {
    let mut register = [0u8; 32];
    let mut replayed = true;

    for r in &p.recs {
        if chain::fold(&mut register, &r.digest) != 0 {
            replayed = false;
        }
    }
    let n = p.recs.len();
    let plural = if n == 1 { "" } else { "s" };
    rep.check(
        replayed && !memneq_explicit(&register, value),
        format!("eventlog: {n} record{plural} replay to the certified value").as_bytes(),
    );
    // A digest the record's own fields do not produce is a record
    // relabelled after the fact: the replay still closes, but what the
    // events say happened is not what was measured.
    for (i, r) in p.recs.iter().enumerate().skip(1) {
        if !r.derived {
            rep.check(
                false,
                &[
                    format!("eventlog: event {i} (").as_bytes(),
                    &r.ty,
                    b" ",
                    &r.label,
                    b") digest does not derive from its fields",
                ]
                .concat(),
            );
        }
    }
}

/// The anchor: the init record's digest of it and the anchoring PCR.
fn check_anchor(rep: &mut Report, p: &Parse, expect: &AttestExpect) {
    let mut anchor = [0u8; ANCHOR_MAX];
    let mut anchor_digest = [0u8; 32];

    let mut named = chain::anchor(&p.init.name, &mut anchor) == 0
        && sha256_into(cstr(&anchor), &mut anchor_digest) == 0;
    rep.check(
        named && !memneq_explicit(&anchor_digest, &p.init.anchor_digest),
        b"anchor: record digest matches the index name",
    );
    let mut pcr_expected = p.init.pcr_before;
    named = chain::fold(&mut pcr_expected, &anchor_digest) == 0 && named;
    if p.pcr_have & (1 << CHAIN_PCR) == 0 {
        rep.check(
            false,
            format!("anchor: PCR {CHAIN_PCR} is not in the quote").as_bytes(),
        );
        return;
    }
    let exact = named && !memneq_explicit(&pcr_expected, &p.pcrs[CHAIN_PCR as usize]);
    if exact || expect.strict_anchor {
        rep.check(
            exact,
            format!("anchor: PCR {CHAIN_PCR} equals the recorded value extended by the anchor")
                .as_bytes(),
        );
    } else {
        rep.note(
            format!(
                "anchor: PCR {CHAIN_PCR} carries further measurements after the anchor; replay the logs to confirm it"
            )
            .as_bytes(),
        );
    }
}

/// The register's state against the one expected, and the events after
/// boot named.
fn check_state(rep: &mut Report, p: &Parse, expect: &AttestExpect, value: &[u8; 32]) {
    let runtime = p.recs.len().saturating_sub(1);

    if let Some(init_event) = &expect.init_event {
        rep.check(
            !memneq_explicit(&p.init.digest, init_event),
            b"state: init event covers the expected certificate, set and tree root",
        );
    }
    if let Some(chain_value) = &expect.chain {
        rep.check(
            !memneq_explicit(value, chain_value),
            b"state: register equals the expected value",
        );
    } else if let Some(init_event) = &expect.init_event {
        let mut predicted = [0u8; 32];
        let folded = chain::fold(&mut predicted, init_event) == 0;

        if runtime == 0 {
            rep.check(
                folded && !memneq_explicit(value, &predicted),
                b"state: register equals the value predicted for the set at boot",
            );
        } else {
            let plural = if runtime == 1 { "" } else { "s" };

            rep.check(
                expect.allow_runtime_events,
                format!("state: {runtime} event{plural} after boot change the register").as_bytes(),
            );
        }
    } else {
        rep.note(
            &[
                b"no expected state given; the register value is ",
                cstr(&p.reg_value_hex),
            ]
            .concat(),
        );
    }
    for r in p.recs.iter().skip(1) {
        rep.note(&[b"event after boot: ", &r.ty[..], b" ", &r.label].concat());
    }
}

/// What a challenge's document gives, in hex.
struct ChallengeJson {
    blob_hex: [u8; 2 * ID_OBJECT_LEN + 1],
    secret_hex: [u8; 2 * SECRET_MAX + 1],
    ak_hex: [u8; 2 * NAME_LEN + 1],
    kind: [u8; 32],
    ty: [u8; 8],
}

/// The challenge an operator made, from the file at `path`: -EINVAL for
/// a document that is not one, or the error of reading it.
pub(crate) fn challenge_read(path: &CStr) -> Result<AttestChallenge, c_int> {
    let mut json = ChallengeJson {
        blob_hex: [0; 2 * ID_OBJECT_LEN + 1],
        secret_hex: [0; 2 * SECRET_MAX + 1],
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
    let mut secret = [0u8; SECRET_MAX];

    let doc = io::read(path, CHALLENGE_MAX)?;
    let parsed = parse_schema(&doc, &top, &mut json);
    if parsed.is_err()
        || !top[0].seen()
        || cstr(&json.kind) != b"shirudo-credential"
        || !ek_sub[0].seen()
        || !top[2].seen()
        || !top[3].seen()
        || !top[4].seen()
    {
        return Err(-EINVAL);
    }
    let ek_rsa = match cstr(&json.ty) {
        b"rsa" => true,
        b"ecc" => false,
        _ => return Err(-EINVAL),
    };
    let mut challenge = AttestChallenge {
        ek_rsa,
        ak_name: [0; NAME_LEN],
        blob: [0; ID_OBJECT_LEN],
        secret: Vec::new(),
    };
    if !hex_into(&json.ak_hex, &mut challenge.ak_name)
        || !hex_into(&json.blob_hex, &mut challenge.blob)
    {
        return Err(-EINVAL);
    }
    let secret = hex_text(&json.secret_hex, &mut secret)?;
    if secret.is_empty() {
        return Err(-EINVAL);
    }
    challenge.secret = secret.to_vec();
    Ok(challenge)
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

        let (Some(key_n), Some(public_n)) = (key.n.get(..key.n_len), public.n.get(..public.n_len))
        else {
            return false;
        };
        return key.n_len == public.n_len && !memneq_explicit(key_n, public_n) && key.e == e;
    }
    !memneq_explicit(&key.x, &public.x) && !memneq_explicit(&key.y, &public.y)
}

/// A challenge made: the document that carries it, and the credential
/// the target recovers with it, on the heap so that it is scrubbed when
/// it goes.
pub(crate) struct MadeChallenge {
    pub(crate) document: Vec<u8>,
    pub(crate) credential: Box<[u8; CREDENTIAL_LEN]>,
}

/// The seed a credential is protected under, and the ECDH secret it is
/// derived from, on the heap so that they are scrubbed when they go.
struct Seed {
    seed: [u8; 32],
    z: [u8; 32],
}

/// What the evidence gives of its keys, in hex, and of its EK certificate
/// in base64.
struct KeysJson {
    ek_public_hex: [u8; 2 * PUBLIC_MAX + 1],
    ak_hex: [u8; 2 * NAME_LEN + 1],
    ek_type: [u8; 8],
    ek_name_hex: [u8; 2 * NAME_LEN + 1],
    cert_b64: Vec<u8>,
}

/// The keys of the evidence a challenge is made for.
struct ChallengeKeys {
    json: Box<KeysJson>,
    rsa: bool,
    ak_name: [u8; NAME_LEN],
    ek_name: [u8; NAME_LEN],
    ek_public: Vec<u8>,
    public: TpmPublic,
    /// The evidence carries an EK certificate.
    have_cert: bool,
}

/// The keys the evidence names: -EINVAL for a document without them
/// whole, or with an endorsement key not of the type it names.
fn challenge_keys(evidence: &[u8]) -> Result<ChallengeKeys, c_int> {
    let mut json = Box::new(KeysJson {
        ek_public_hex: [0; 2 * PUBLIC_MAX + 1],
        ak_hex: [0; 2 * NAME_LEN + 1],
        ek_type: [0; 8],
        ek_name_hex: [0; 2 * NAME_LEN + 1],
        cert_b64: vec![0; EK_CERT_B64_MAX],
    });
    let ak_sub = [JsonField::string(c"name", |k: &mut KeysJson| &mut k.ak_hex)];
    let ek_sub = [
        JsonField::string(c"type", |k: &mut KeysJson| &mut k.ek_type),
        JsonField::string(c"public", |k| &mut k.ek_public_hex),
        JsonField::string(c"name", |k| &mut k.ek_name_hex),
    ];
    let top = [
        JsonField::object(c"ak", &ak_sub),
        JsonField::object(c"ek", &ek_sub),
        JsonField::string(c"ek_certificate", |k: &mut KeysJson| {
            k.cert_b64.as_mut_slice()
        }),
    ];
    let mut ak_name = [0u8; NAME_LEN];
    let mut ek_name = [0u8; NAME_LEN];
    let mut ek_public = [0u8; PUBLIC_MAX];
    let mut public = TpmPublic::zeroed();

    let parsed = parse_schema(evidence, &top, &mut *json);
    if parsed.is_err()
        || !ak_sub[0].seen()
        || !ek_sub[0].seen()
        || !ek_sub[1].seen()
        || !ek_sub[2].seen()
        || !hex_into(&json.ak_hex, &mut ak_name)
    {
        return Err(-EINVAL);
    }
    let ek_public = hex_text(&json.ek_public_hex, &mut ek_public)?;
    if !hex_into(&json.ek_name_hex, &mut ek_name) {
        return Err(-EINVAL);
    }
    let rsa = match cstr(&json.ek_type) {
        b"rsa" => true,
        b"ecc" => false,
        _ => return Err(-EINVAL),
    };
    if public_parse(ek_public, &mut public) != 0 || public.ty != if rsa { ALG_RSA } else { ALG_ECC }
    {
        return Err(-EINVAL);
    }
    Ok(ChallengeKeys {
        rsa,
        ak_name,
        ek_name,
        ek_public: ek_public.to_vec(),
        public,
        have_cert: top[2].seen(),
        json,
    })
}

/// A certificate cert_read_der() reads into, freed when it goes.
struct HeldCert(Cert);

impl Drop for HeldCert {
    fn drop(&mut self) {
        // SAFETY: the certificate the guard holds, or none, freed once.
        unsafe { cert_free(&mut self.0) };
    }
}

/// The certificate in the base64 `b64` and its key: none when it does
/// not decode, parse or hold a key of the kinds a TPM's endorsement key
/// has.
fn ek_certificate(b64: &[u8]) -> Option<(HeldCert, CertPubkey)> {
    let mut der = vec![0u8; EK_CERT_MAX];
    let mut der_len = 0usize;
    let mut cert = HeldCert(Cert::new());
    let mut key = CertPubkey {
        rsa: false,
        n: [0; 512],
        n_len: 0,
        e: 0,
        x: [0; 32],
        y: [0; 32],
    };

    // SAFETY: the base64's bytes, room for the DER and for its length.
    let ret = unsafe {
        base64_decode(
            b64.as_ptr().cast(),
            b64.len(),
            der.as_mut_ptr(),
            der.len(),
            &mut der_len,
        )
    };
    let der = der.get(..der_len).filter(|_| ret == 0)?;
    // SAFETY: the DER's bytes, and the certificate to read them into.
    if unsafe { cert_read_der(der.as_ptr(), der.len(), &mut cert.0) } != 0 {
        return None;
    }
    // SAFETY: the certificate read above, and room for its key.
    if unsafe { cert_pubkey(&cert.0, &mut key) } != 0 {
        return None;
    }
    Some((cert, key))
}

/// Whether the certificate chains to the issuer bundle at `bundle`: 0,
/// -EKEYREJECTED with libcrypto's reason, or -EINVAL for a bundle that
/// cannot be loaded.
fn cert_chains(cert: &HeldCert, bundle: &CStr) -> (c_int, &'static [u8]) {
    let mut reason: *const c_char = c"".as_ptr();

    // SAFETY: the certificate, the bundle's path, a C string, and where
    // the reason goes.
    let ret = unsafe { cert_verify_chain(&cert.0, bundle.as_ptr(), &mut reason) };
    // SAFETY: a static C string of libcrypto's, or the empty one above.
    (ret, unsafe { ffi::c_str(reason) })
}

/// The checks of the EK certificate the evidence carries, if any, into
/// the report.
fn check_ek_certificate(rep: &mut Report, pol: &AttestChallengePolicy, keys: &ChallengeKeys) {
    let vouched = pol.ek_name.is_some() || pol.trust_presented;

    if !keys.have_cert {
        if vouched {
            rep.note(b"no endorsement certificate: the endorsement key is trusted as presented");
        } else {
            rep.check(
                false,
                b"no endorsement certificate: pin the key with --ek-name or waive with --trust-presented-ek",
            );
        }
        return;
    }
    let Some((cert, key)) = ek_certificate(cstr(&keys.json.cert_b64)) else {
        rep.check(
            false,
            b"endorsement certificate: parseable with a P-256 or RSA-2048 key",
        );
        return;
    };
    rep.check(
        cert_describes(&key, &keys.public),
        b"endorsement certificate: describes the endorsement key",
    );
    let Some(bundle) = pol.ek_ca else {
        if vouched {
            rep.note(b"endorsement certificate: not checked against an issuer bundle (--ek-ca)");
        } else {
            rep.check(
                false,
                b"endorsement certificate: not checked against an issuer bundle; pass --ek-ca, pin the key with --ek-name or waive with --trust-presented-ek",
            );
        }
        return;
    };
    let (ret, reason) = cert_chains(&cert, bundle);
    if ret == -EINVAL {
        rep.check(
            false,
            &[
                b"endorsement certificate: issuer bundle ",
                bundle.to_bytes(),
                b" unreadable",
            ]
            .concat(),
        );
        return;
    }
    let (sep, why): (&[u8], &[u8]) = if ret != 0 {
        (b": ", reason)
    } else {
        (b"", b"")
    };
    rep.check(
        ret == 0,
        &[
            b"endorsement certificate: chains to ",
            bundle.to_bytes(),
            sep,
            why,
        ]
        .concat(),
    );
}

/// `buf` filled from the kernel's random source: -EIO where it gives
/// less.
fn random(buf: &mut [u8]) -> Result<(), c_int> {
    // SAFETY: the room of buf, of its length.
    let got = unsafe { getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) };
    if usize::try_from(got) != Ok(buf.len()) {
        return Err(-EIO);
    }
    Ok(())
}

/// The secret that carries the seed to the endorsement key `public`,
/// the seed into `seed`: RSA-OAEP of a random seed, or the ephemeral
/// point of an ECDH whose secret the seed derives from.
fn seal_seed(rsa: bool, public: &TpmPublic, seed: &mut Seed) -> Result<Vec<u8>, c_int> {
    let mut secret = [0u8; 256];
    let mut secret_len = 0usize;

    if rsa {
        random(&mut seed.seed)?;
        // SAFETY: the key's modulus, the label with its NUL, the seed,
        // and room for the secret and its length.
        let ret = unsafe {
            rsa_oaep_encrypt(
                public.n.as_ptr(),
                public.n_len,
                public.rsa_exponent,
                IDENTITY.as_ptr().cast(),
                IDENTITY.to_bytes_with_nul().len(),
                seed.seed.as_ptr(),
                seed.seed.len(),
                secret.as_mut_ptr(),
                secret.len(),
                &mut secret_len,
            )
        };
        if ret != 0 {
            return Err(-EIO);
        }
        return secret.get(..secret_len).map(<[u8]>::to_vec).ok_or(-EIO);
    }
    let (mut eph_x, mut eph_y) = ([0u8; 32], [0u8; 32]);
    if ecdh_p256_ephemeral(&public.x, &public.y, &mut eph_x, &mut eph_y, &mut seed.z) != 0
        || kdfe(
            &seed.z,
            IDENTITY.to_bytes(),
            &eph_x,
            &public.x,
            &mut seed.seed,
        ) != 0
    {
        return Err(-EIO);
    }
    Ok([&[0, 32][..], &eph_x, &[0, 32], &eph_y].concat())
}

/// attest challenge: after the checks the policy asks for, into the
/// report, a credential the target recovers only with the attestation
/// key the evidence names under its endorsement key, and the challenge
/// that carries it: -EKEYREJECTED when a check failed, -EINVAL for
/// evidence without the keys.
pub(crate) fn challenge_make(
    evidence: &[u8],
    pol: &AttestChallengePolicy,
    rep: &mut Report,
) -> Result<MadeChallenge, c_int> {
    let mut computed = [0u8; NAME_LEN];
    let mut blob = [0u8; ID_OBJECT_LEN];
    let mut credential = Box::new([0u8; CREDENTIAL_LEN]);
    let mut seed = Box::new(Seed {
        seed: [0; 32],
        z: [0; 32],
    });

    let keys = challenge_keys(evidence)?;
    // The operator's pins come first: the challenge is for the key the
    // operator enrolled, not for whatever the document names.
    if let Some(pinned) = &pol.ak_name {
        rep.check(
            !memneq_explicit(&keys.ak_name, pinned),
            b"attestation key: the pinned key",
        );
    }
    if let Some(pinned) = &pol.ek_name {
        rep.check(
            !memneq_explicit(&keys.ek_name, pinned),
            b"endorsement key: the pinned key",
        );
    }

    // The key must be an endorsement key, not any decryption key.
    let named = object_name(&keys.ek_public, &mut computed) == 0;
    rep.check(
        named && !memneq_explicit(&computed, &keys.ek_name),
        b"endorsement key: name matches its public area",
    );
    rep.check(
        endorsement_template(&keys.public),
        b"endorsement key: TCG default template under the endorsement policy",
    );
    check_ek_certificate(rep, pol, &keys);
    if rep.failed != 0 {
        return Err(-EKEYREJECTED);
    }

    random(&mut credential[..])?;
    let secret = seal_seed(keys.rsa, &keys.public, &mut seed)?;
    if credential_protect(&seed.seed, &keys.ak_name, &credential, &mut blob) != 0 {
        return Err(-EIO);
    }
    let document = challenge_document(&keys, &blob, &secret)?;
    Ok(MadeChallenge {
        document,
        credential,
    })
}

/// The challenge's document: the keys as the evidence named them, the
/// credential's blob and the secret.
fn challenge_document(
    keys: &ChallengeKeys,
    blob: &[u8; ID_OBJECT_LEN],
    secret: &[u8],
) -> Result<Vec<u8>, c_int> {
    let mut room = [0u8; CHALLENGE_DOC_MAX];
    let mut e = JsonEmit::fixed(&mut room);

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"kind", b"shirudo-credential");
    e.obj_open_key(b"ek");
    e.kv_string(b"type", if keys.rsa { b"rsa" } else { b"ecc" });
    e.kv_string(b"name", cstr(&keys.json.ek_name_hex));
    e.obj_close();
    e.kv_string(b"ak_name", cstr(&keys.json.ak_hex));
    e.kv_string(b"credential_blob", &encode(blob));
    e.kv_string(b"secret", &encode(secret));
    e.obj_close();
    e.finish()
}

/// `--pcrs`: PCRs 0 to 23 apart by commas, as a mask; -EINVAL for
/// anything else, an empty list among it.
pub(crate) fn parse_pcrs(list: &[u8]) -> Result<u32, c_int> {
    let mut mask = 0u32;
    let mut rest = list;

    while !rest.is_empty() {
        let (number, after) = rest.split_at(digits(rest));
        let pcr = parse_u64(number, 23).map_err(|_| -EINVAL)?;

        mask |= 1 << pcr;
        rest = match after {
            [b',', next @ ..] if !next.is_empty() => next,
            [] => after,
            _ => return Err(-EINVAL),
        };
    }
    if mask == 0 {
        return Err(-EINVAL);
    }
    Ok(mask)
}

/// `<pcr>=<value>`: the PCR, below 24, and the text of its value after
/// the equals sign; -EINVAL for anything else.
pub(crate) fn parse_pcr_value(arg: &[u8]) -> Result<(usize, &[u8]), c_int> {
    let (number, rest) = arg.split_at(digits(arg));
    let (Some(value), Ok(pcr)) = (rest.strip_prefix(b"="), parse_u64(number, 23)) else {
        return Err(-EINVAL);
    };
    let pcr = usize::try_from(pcr).map_err(|_| -EINVAL)?;

    Ok((pcr, value))
}

/// `<name>=<digest>`: a name of 1 to UPATCH_NAME_MAX bytes up to the
/// first equals sign, then the 64 hex digits of the digest; -EINVAL for
/// anything else.
pub(crate) fn parse_name_digest(spec: &[u8]) -> Result<(&[u8], [u8; 32]), c_int> {
    let mut parts = spec.splitn(2, |&c| c == b'=');
    let mut digest = [0u8; 32];

    let (Some(name), Some(hex)) = (parts.next(), parts.next()) else {
        return Err(-EINVAL);
    };
    if name.is_empty() || name.len() > UPATCH_NAME_MAX || decode(hex, &mut digest).is_err() {
        return Err(-EINVAL);
    }
    Ok((name, digest))
}

pub(crate) use capi::attest_evidence_config;

#[cfg(shirudo_fuzz)]
mod fuzz;
#[cfg(test)]
mod tests;

mod capi {
    use core::ffi::{c_char, c_int};

    use super::AttestChallenge;
    use crate::util::config_update::ConfigUpdate;

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
}
