// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The packager: a BPF object into a signed `.upatch`. The object is
//! read as libbpf reads it and its loader program and data generated as
//! libbpf's gen_loader generates them (crate::bpf); the
//! attach metadata, the decoders, the policy labels and the name are
//! signed with the data, past the end the loader addresses; CMS signs
//! the loader and the data; and the container puts a header in front.
//! An unload directive is the embedded unload template so packaged,
//! naming the upatch and the payload it unloads. Re-signing takes a
//! package whose data differs from a signed one only in named .rodata
//! symbols, and signs it anew.

mod decoders;
mod meta;

use core::ffi::{CStr, c_int, c_void};
use std::ffi::CString;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use super::{KeyFiles, error, info, strerr};
use crate::bpf::object::{self, GenOpts, Object};
use crate::errno::{E2BIG, EBADMSG, EINVAL, EIO, ENAMETOOLONG, ENOENT, EOVERFLOW, EPERM};
use crate::sys::loader::unload_blob;
use crate::text::{digits, parse_u64};
use crate::util::bpm_package::verify_cms;
use crate::util::crypto_openssl::sha256_calc;
use crate::util::upatch::{
    self, DIRECTIVE_UNLOAD, FILE_MAX, HEADER_SIZE, MAGIC, MAPS_MAX, NAME_MAX, PAYLOAD_HASH_LEN,
    POLICY_LABEL_ENTRY, POLICY_LABEL_HEADER, POLICY_LABELS_MAGIC, POLICY_LABELS_VERSION,
    SECTION_ATTACH, SECTION_DECODERS, SECTION_NAME, SECTION_POLICY_LABELS, SECTION_UNLOAD,
    SIGNED_SECTION, SIGNED_SECTIONS_MAX, SIGNED_TRAILER, SIGNED_TRAILER_MAGIC, SIGNED_VERSION,
    TYPE_BPF, Upatch, VERSION, upatch_close, upatch_data, upatch_loader, upatch_metadata,
    upatch_open, upatch_signature,
};
use crate::util::upatch_rodata::{
    RodataRange, upatch_rodata_data_offset, upatch_rodata_symbol_range,
};

/// A detached CMS over an ML-DSA-87 signature is about 5 KiB (a
/// 4627-byte signature and its SignerInfo); the kernel caps
/// attr.signature_size at 64 KiB.
const MAX_SIG_SIZE: usize = 16384;
/// The verifier log the target gives a load.
const LOG_BUF_SZ: u32 = 1024 * 1024;
/// The symbols `upatch rewrite-rodata` may change.
const RESIGN_SYMBOLS: [&CStr; 2] = [c"obs_watch_v4", c"obs_watch_v6"];
const RANGES_MAX: usize = 16;
const BPF_MAP_TYPE_SK_STORAGE: u32 = 24;
const BPF_MAP_TYPE_TASK_STORAGE: u32 = 29;
const BPF_F_NO_PREALLOC: u32 = 1;
const BPF_F_CLONE: u32 = 1 << 9;
/// `NAME_MAX` of `<limits.h>`, which the name rule's message quotes.
const PIN_NAME_MAX: usize = 255;

fn errno_of(e: &std::io::Error) -> c_int {
    -e.raw_os_error().unwrap_or(EIO)
}

fn put32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// The fields of a container's header.
struct Header<'a> {
    name: &'a [u8],
    ty: u32,
    flags: u32,
    payload_sha256: &'a [u8; 32],
    loader: (u32, u32),
    signature: (u32, u32),
    metadata: (u32, u32),
    data: (u32, u32),
    log_buf_sz: u32,
    rodata_data_off: u32,
    nr_maps: u32,
    nr_progs: u32,
}

impl Header<'_> {
    /// `struct upatch_header`, little-endian.
    fn bytes(&self) -> [u8; HEADER_SIZE] {
        let mut h = [0u8; HEADER_SIZE];
        let name = &self.name[..self.name.len().min(NAME_MAX - 1)];

        h[0..8].copy_from_slice(&MAGIC.to_le_bytes());
        put32(&mut h, 8, VERSION);
        put32(&mut h, 12, self.flags);
        h[16..16 + name.len()].copy_from_slice(name);
        h[272..304].copy_from_slice(self.payload_sha256);
        let fields = [
            self.loader.0,
            self.loader.1,
            self.signature.0,
            self.signature.1,
            self.metadata.0,
            self.metadata.1,
            self.data.0,
            self.data.1,
            self.log_buf_sz,
            self.nr_maps,
            self.nr_progs,
            self.rodata_data_off,
            self.ty,
        ];
        for (i, v) in fields.into_iter().enumerate() {
            put32(&mut h, 304 + 4 * i, v);
        }
        h
    }
}

/// A signed section: its tag and its bytes.
struct Section<'a>(u32, &'a [u8]);

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// data || sections, each at an 8-byte boundary || directory || trailer.
/// The loader addresses nothing past its own data, so the sections are
/// invisible to it and the kernel signs them with the rest.
fn compose_signed_data(data: &[u8], sections: &[Section]) -> Result<Vec<u8>, c_int> {
    let n = sections.len();

    if n == 0 || n > SIGNED_SECTIONS_MAX as usize {
        return Err(-EINVAL);
    }
    let mut end = data.len();
    for s in sections {
        end = align8(end) + s.1.len();
    }
    let dir_off = align8(end);
    let total = dir_off + n * SIGNED_SECTION + SIGNED_TRAILER;
    if total > u32::MAX as usize {
        return Err(-EOVERFLOW);
    }
    let mut buf = vec![0u8; total];
    buf[..data.len()].copy_from_slice(data);
    let mut at = data.len();
    for (i, s) in sections.iter().enumerate() {
        at = align8(at);
        buf[at..at + s.1.len()].copy_from_slice(s.1);
        let d = dir_off + i * SIGNED_SECTION;
        put32(&mut buf, d, s.0);
        put32(&mut buf, d + 8, at as u32);
        put32(&mut buf, d + 12, s.1.len() as u32);
        at += s.1.len();
    }
    let t = dir_off + n * SIGNED_SECTION;
    put32(&mut buf, t, SIGNED_TRAILER_MAGIC);
    put32(&mut buf, t + 4, SIGNED_VERSION);
    put32(&mut buf, t + 8, dir_off as u32);
    put32(&mut buf, t + 12, n as u32);
    Ok(buf)
}

/// CMS over `insns` and `data`: the signature, and the SHA-256 of the
/// two the header carries.
fn sign(insns: &[u8], data: &[u8], keys: (&CStr, &CStr)) -> Result<(Vec<u8>, [u8; 32]), c_int> {
    super::sign::cms_sign(insns, data, MAX_SIG_SIZE, keys.0, keys.1)
}

/// The parts of an open container.
fn part(p: *const c_void, len: u32) -> &'static [u8] {
    if p.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: a part of a container that stays open while it is read.
    unsafe { crate::ffi::slice(p.cast::<u8>(), len as usize) }
}

/// A container opened, closed when it goes.
struct Opened(Box<Upatch>);

impl Opened {
    fn open(path: &CStr) -> Result<Self, c_int> {
        // SAFETY: an all-zero container is a closed one.
        let mut u: Box<Upatch> = Box::new(unsafe { core::mem::zeroed() });
        // SAFETY: a C string and the container to fill.
        match unsafe { upatch_open(path.as_ptr(), &mut *u) } {
            0 => Ok(Opened(u)),
            err => Err(err),
        }
    }

    fn loader(&self) -> &[u8] {
        // SAFETY: the open container.
        part(
            unsafe { upatch_loader(&*self.0) },
            self.0.hdr.loader_insns_len,
        )
    }

    fn data(&self) -> &[u8] {
        // SAFETY: the open container.
        part(unsafe { upatch_data(&*self.0) }, self.0.hdr.data_len)
    }

    fn signature(&self) -> &[u8] {
        // SAFETY: the open container.
        part(
            unsafe { upatch_signature(&*self.0) },
            self.0.hdr.signature_len,
        )
    }

    fn metadata(&self) -> &[u8] {
        // SAFETY: the open container.
        part(
            unsafe { upatch_metadata(&*self.0) },
            self.0.hdr.metadata_len,
        )
    }

    fn map(&self) -> &[u8] {
        part(self.0.map.cast(), self.0.map_size as u32)
    }

    fn is_unload(&self) -> bool {
        upatch::is_unload(&self.0)
    }

    fn symbol_range(&self, symbol: &CStr) -> Result<RodataRange, c_int> {
        // SAFETY: an all-zero range is room for one.
        let mut range: RodataRange = unsafe { core::mem::zeroed() };
        // SAFETY: the open container, a C string and the room.
        match unsafe { upatch_rodata_symbol_range(&*self.0, symbol.as_ptr(), &mut range) } {
            0 => Ok(range),
            err => Err(err),
        }
    }
}

impl Drop for Opened {
    fn drop(&mut self) {
        // SAFETY: the container opened.
        unsafe { upatch_close(&mut *self.0) };
    }
}

/// The CMS covers the loader and the data but not the header, whose
/// payload digest the target measures, so the digest is compared too.
fn verify_payload(u: &Opened, cert: &CStr) -> c_int {
    let payload = [u.loader(), u.data()].concat();
    let ret = verify_cms(&payload, u.signature(), cert);
    let mut digest = [0u8; 32];

    if ret != 0 {
        return ret;
    }
    if sha256_calc(&payload, &mut digest) != 0 || digest != u.0.hdr.payload_sha256 {
        return -EBADMSG;
    }
    0
}

/// An output that is one of the inputs, under whatever name, is refused
/// before it is truncated, so that a write that fails cannot take the
/// input with it.
fn output_is_input(out: &std::fs::File, original: &CStr, modified: &CStr) -> bool {
    let Ok(o) = out.metadata() else {
        return true;
    };
    [original, modified].iter().any(|p| {
        std::fs::metadata(super::path(p.to_bytes()))
            .is_ok_and(|i| i.dev() == o.dev() && i.ino() == o.ino())
    })
}

/// A data range a re-signed package may change.
#[derive(Clone, Copy)]
struct DataRange {
    offset: u32,
    length: u32,
}

/// Signs `modified` anew into `output`: it must be `original` but in the
/// data `ranges` cover, each the whole of a distinct one of `symbols`,
/// and `original` must verify against the certificate.
fn resign(
    original: &CStr,
    modified: &CStr,
    output: &CStr,
    ranges: &[DataRange],
    symbols: &[&CStr],
    keys: &KeyFiles,
) -> c_int {
    if ranges.is_empty()
        || ranges.len() > RANGES_MAX
        || symbols.len() != ranges.len()
        || original == output
        || modified == output
    {
        return -EINVAL;
    }
    let src = match Opened::open(original) {
        Ok(u) => u,
        Err(err) => return err,
    };
    let m = match Opened::open(modified) {
        Ok(u) => u,
        Err(err) => return err,
    };
    let (sh, mh) = (&src.0.hdr, &m.0.hdr);
    if src.is_unload()
        || m.is_unload()
        || src.map()[..HEADER_SIZE] != m.map()[..HEADER_SIZE]
        || sh.loader_insns_len != mh.loader_insns_len
        || sh.signature_len != mh.signature_len
        || sh.data_len != mh.data_len
        || sh.metadata_len != mh.metadata_len
        || src.loader() != m.loader()
        || src.signature() != m.signature()
        || src.metadata() != m.metadata()
    {
        return -EINVAL;
    }
    let data_len = sh.data_len;
    let mut prev_end = 0u64;
    for (i, r) in ranges.iter().enumerate() {
        if r.length == 0
            || r.offset > data_len
            || r.length > data_len - r.offset
            || (i > 0 && u64::from(r.offset) < prev_end)
        {
            return -EINVAL;
        }
        prev_end = u64::from(r.offset) + u64::from(r.length);
    }
    let covered = |at: usize| {
        ranges
            .iter()
            .any(|r| at >= r.offset as usize && at - (r.offset as usize) < r.length as usize)
    };
    if src
        .data()
        .iter()
        .zip(m.data())
        .enumerate()
        .any(|(i, (a, b))| a != b && !covered(i))
    {
        return -EPERM;
    }
    if !sh.name.contains(&0) {
        return -EINVAL;
    }
    let ret = verify_payload(&src, &keys.cert);
    if ret != 0 {
        return ret;
    }
    let mut expected = Vec::with_capacity(symbols.len());
    for s in symbols {
        match src.symbol_range(s) {
            Ok(r) => expected.push(r),
            Err(err) => return err,
        }
    }
    let mut found = vec![false; symbols.len()];
    for r in ranges {
        let hit = (0..symbols.len())
            .find(|&j| r.offset == expected[j].offset && r.length == expected[j].size && !found[j]);
        match hit {
            Some(j) => found[j] = true,
            None => return -EPERM,
        }
    }
    let (sig, digest) = match sign(m.loader(), m.data(), (&keys.pkey, &keys.cert)) {
        Ok(s) => s,
        Err(err) => return err,
    };
    let (insns_len, data, meta) = (m.loader().len(), m.data(), m.metadata());
    let loader_off = HEADER_SIZE;
    let sig_off = loader_off + insns_len;
    let data_off = sig_off + sig.len();
    let meta_off = data_off + data.len();
    if meta_off > u32::MAX as usize {
        return -EOVERFLOW;
    }
    if meta_off + meta.len() > FILE_MAX {
        return -E2BIG;
    }
    let mut name = [0u8; NAME_MAX + 1];
    upatch::header_name(&m.0, &mut name);
    let hdr = Header {
        name: crate::text::cstr(&name),
        ty: mh.ty,
        flags: mh.flags,
        payload_sha256: &digest,
        loader: (loader_off as u32, insns_len as u32),
        signature: (sig_off as u32, sig.len() as u32),
        metadata: (
            if meta.is_empty() { 0 } else { meta_off as u32 },
            meta.len() as u32,
        ),
        data: (
            if data.is_empty() { 0 } else { data_off as u32 },
            data.len() as u32,
        ),
        log_buf_sz: mh.log_buf_sz,
        rodata_data_off: mh.rodata_data_off,
        nr_maps: mh.nr_maps,
        nr_progs: mh.nr_progs,
    };
    let out_path = super::path(output.to_bytes());
    // Truncated only once it is known not to be one of the inputs.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o644)
        .open(out_path);
    let mut file = match file {
        Ok(f) => f,
        Err(e) => return errno_of(&e),
    };
    if output_is_input(&file, original, modified) {
        return -EINVAL;
    }
    if let Err(e) = file.set_len(0) {
        return errno_of(&e);
    }
    let written = [&hdr.bytes()[..], m.loader(), &sig, data, meta]
        .iter()
        .try_for_each(|b| file.write_all(b))
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written {
        let _ = std::fs::remove_file(out_path);
        return errno_of(&e);
    }
    0
}

/// A temporary file, removed when it goes.
struct Temp(CString);

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(super::path(self.0.to_bytes()));
    }
}

/// Sets `symbol` in the .rodata of the package at `input` to `value` and
/// signs the result into `output`.
pub(super) fn patch_rodata(
    input: &CStr,
    output: &CStr,
    symbol: &CStr,
    value: &[u8],
    keys: &KeyFiles,
) -> c_int {
    if value.is_empty() || input == output {
        return -EINVAL;
    }
    let src = match Opened::open(input) {
        Ok(u) => u,
        Err(err) => return err,
    };
    if src.is_unload() {
        return -EINVAL;
    }
    let ret = verify_payload(&src, &keys.cert);
    if ret != 0 {
        return ret;
    }
    let range = match src.symbol_range(symbol) {
        Ok(r) => r,
        Err(err) => return err,
    };
    let data_len = src.0.hdr.data_len as usize;
    if value.len() != range.size as usize
        || range.offset as usize > data_len
        || value.len() > data_len - range.offset as usize
    {
        return -EINVAL;
    }
    let mut candidate = src.map().to_vec();
    let at = src.0.hdr.data_off as usize + range.offset as usize;
    candidate[at..at + value.len()].copy_from_slice(value);
    let mut tmpl = *b"/tmp/shirudo-rodata-XXXXXX\0";
    // SAFETY: the template, which mkstemp() fills in.
    let fd = unsafe { crate::sys::libc::mkstemp(tmpl.as_mut_ptr().cast()) };
    if fd < 0 {
        return super::last_err();
    }
    let temp = Temp(CString::new(crate::text::cstr(&tmpl).to_vec()).unwrap_or_default());
    // SAFETY: the descriptor mkstemp() opened, the file's from here.
    let mut file = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    let mut ret = match file.write_all(&candidate).and_then(|()| file.sync_all()) {
        Ok(()) => 0,
        Err(e) => errno_of(&e),
    };
    // SAFETY: the descriptor the file gives up.
    if unsafe { crate::sys::libc::close(std::os::fd::IntoRawFd::into_raw_fd(file)) } != 0
        && ret == 0
    {
        ret = super::last_err();
    }
    if ret != 0 {
        return ret;
    }
    let allowed = [DataRange {
        offset: range.offset,
        length: range.size,
    }];
    resign(input, &temp.0, output, &allowed, &[symbol], keys)
}

pub(super) fn verify_package(input: &CStr, cert: &CStr) -> c_int {
    match Opened::open(input) {
        Ok(u) if u.is_unload() => -EINVAL,
        Ok(u) => verify_payload(&u, cert),
        Err(err) => err,
    }
}

/// `offset:length`, both decimal and within 32 bits, the length not 0.
fn parse_range(s: &[u8]) -> Option<DataRange> {
    let off_len = digits(s);
    if off_len == 0 || off_len >= s.len() || s[off_len] != b':' {
        return None;
    }
    let length = &s[off_len + 1..];
    let len_len = digits(length);
    let max = u64::from(u32::MAX);
    let (Ok(offset), Ok(len)) = (
        parse_u64(&s[..off_len], max),
        parse_u64(&length[..len_len], max),
    ) else {
        return None;
    };
    if len_len != length.len() || len == 0 {
        return None;
    }
    Some(DataRange {
        offset: offset as u32,
        length: len as u32,
    })
}

/// `shirudo-build upatch rewrite-rodata`, from `upatch` on.
pub(super) fn upatch_cli(args: &[&CStr]) -> c_int {
    let mut keys = KeyFiles::default();
    let (mut original, mut modified, mut output, mut keys_dir) = (None, None, None, None);
    let mut ranges: Vec<DataRange> = Vec::new();

    if args.get(1).map(|a| a.to_bytes()) != Some(b"rewrite-rodata") {
        super::print(false, b"usage: shirudo-build upatch rewrite-rodata <original.upatch> <modified.upatch> -o <output.upatch> --data-range <offset:length>... [--keys-dir <dir>] [--key <signing_key.pem>] [--cert <cert.der>]\n");
        return 2;
    }
    let mut i = 2;
    while i < args.len() {
        let a = args[i].to_bytes();
        let next = args.get(i + 1).copied();
        match (a, next) {
            (b"-o" | b"--output", Some(v)) => output = Some(v),
            (b"--data-range", Some(v)) => {
                if ranges.len() == RANGES_MAX {
                    return 2;
                }
                match parse_range(v.to_bytes()) {
                    Some(r) => ranges.push(r),
                    None => return 2,
                }
            }
            (b"--keys-dir", Some(v)) => keys_dir = Some(v),
            (b"--key", Some(v)) => keys.set_pkey(v),
            (b"--cert", Some(v)) => keys.set_cert(v),
            _ => {
                if a.first() == Some(&b'-') {
                    error(&[b"upatch rewrite-rodata: unknown option ", a].concat());
                    return 2;
                }
                if original.is_none() {
                    original = Some(args[i]);
                } else if modified.is_none() {
                    modified = Some(args[i]);
                } else {
                    error(&[b"upatch rewrite-rodata: unexpected argument ", a].concat());
                    return 2;
                }
                i += 1;
                continue;
            }
        }
        i += 2;
    }
    let (Some(original), Some(modified), Some(output), false) =
        (original, modified, output, ranges.is_empty())
    else {
        error(b"upatch rewrite-rodata requires two inputs, -o, and data ranges");
        return 2;
    };
    if keys.resolve(keys_dir).is_err() {
        return 2;
    }
    let ret = resign(original, modified, output, &ranges, &RESIGN_SYMBOLS, &keys);
    if ret != 0 {
        error(&[b"upatch rewrite-rodata: ", strerr(-ret)].concat());
    }
    if ret != 0 { 1 } else { 0 }
}

/// Every target refuses a name upatch_name_valid() does not take.
fn check_name(name: &[u8]) -> c_int {
    if upatch::name_valid(Some(name)) {
        return 0;
    }
    error(
        format!(
            "upatch name '{}' is not 1 to {PIN_NAME_MAX} characters of [A-Za-z0-9._-], each '.' counting as two, not starting with '.'",
            String::from_utf8_lossy(name)
        )
        .as_bytes(),
    );
    -EINVAL
}

/// What a package is made of besides its object.
struct Contents<'a> {
    name: &'a CStr,
    flags: u32,
    unload_payload: &'a [u8; 32],
    src_path: Option<&'a CStr>,
    policy_labels: &'a [u8],
}

/// The object as a signed package at `out`.
fn finalize(mut obj: Object, out: &CStr, c: &Contents, keys: (&CStr, &CStr)) -> c_int {
    // The loader writes map_fd/prog_fd back into descriptor arrays past
    // its ctx, in the order libbpf iterates the object; the target finds
    // prog_fd[] after BPF_PROG_TEST_RUN by these counts. The attach
    // metadata comes before the loader so that an unsupported section
    // fails with shirudo's diagnostic, not the generator's.
    let nr_maps = obj.maps.len() as u32;
    let nr_progs = obj.programs().count() as u32;
    let unloading = c.flags & DIRECTIVE_UNLOAD != 0;
    let name = c.name.to_bytes();
    let (mut attach_meta, mut decoder_blob, mut nr_decoders) = (Vec::new(), Vec::new(), 0);

    if !unloading {
        attach_meta = match meta::prog_metadata(&obj, nr_maps, nr_progs) {
            Ok(m) => m,
            Err(err) => return err,
        };
        (decoder_blob, nr_decoders) =
            match decoders::blob(&obj, c.src_path.map(CStr::to_bytes), name) {
                Ok(b) => b,
                Err(err) => return err,
            };
    }
    let mut opts = GenOpts {
        gen_hash: true,
        reuse_map_mask: 0,
    };
    if !c.policy_labels.is_empty() {
        let le = |off: usize| {
            u32::from_le_bytes(c.policy_labels[off..off + 4].try_into().unwrap_or_default())
        };
        let (map_idx, socket_idx) = (le(12), le(16));
        if map_idx >= nr_maps
            || map_idx >= MAPS_MAX
            || socket_idx >= nr_maps
            || socket_idx >= MAPS_MAX
            || map_idx == socket_idx
        {
            return -EINVAL;
        }
        opts.reuse_map_mask = (1u64 << map_idx) | (1u64 << socket_idx);
    }
    let (insns, data) = match obj.gen_loader(&opts) {
        Ok(l) => l,
        Err(err) => {
            error(format!("generate loader: {err}").as_bytes());
            return err;
        }
    };
    // The name the pin, the archive and the register event carry, the
    // attach sites, the unload target: signed with the data, since the
    // header is not.
    if name.len() >= NAME_MAX {
        return -ENAMETOOLONG;
    }
    let mut signed_name = [0u8; NAME_MAX];
    signed_name[..name.len()].copy_from_slice(name);
    let mut sections = vec![Section(SECTION_NAME, &signed_name)];
    if unloading {
        sections.push(Section(SECTION_UNLOAD, c.unload_payload));
    } else {
        sections.push(Section(SECTION_ATTACH, &attach_meta));
        if !decoder_blob.is_empty() {
            sections.push(Section(SECTION_DECODERS, &decoder_blob));
        }
        if !c.policy_labels.is_empty() {
            sections.push(Section(SECTION_POLICY_LABELS, c.policy_labels));
        }
    }
    let insns = &insns[..];
    let signed = match compose_signed_data(&data, &sections) {
        Ok(s) => s,
        Err(err) => return err,
    };
    let loader_data = [insns, &signed].concat();
    // SAFETY: an all-zero container, given the loader and its data.
    let mut view: Upatch = unsafe { core::mem::zeroed() };
    view.map = loader_data.as_ptr();
    view.hdr.loader_insns_len = insns.len() as u32;
    view.hdr.data_off = insns.len() as u32;
    view.hdr.data_len = signed.len() as u32;
    let mut rodata_data_off = 0;
    // SAFETY: the view of the loader and data, and room for the offset.
    match unsafe { upatch_rodata_data_offset(&view, &mut rodata_data_off) } {
        0 => {}
        err if err == -ENOENT => rodata_data_off = 0,
        err => return err,
    }
    let (sig, digest) = match sign(insns, &signed, keys) {
        Ok(s) => s,
        Err(err) => {
            error(format!("cms_sign: {err}").as_bytes());
            return err;
        }
    };
    let sig_off = HEADER_SIZE + insns.len();
    let data_off = sig_off + sig.len();
    if data_off > FILE_MAX || signed.len() > FILE_MAX - data_off {
        return -E2BIG;
    }
    let hdr = Header {
        name,
        ty: TYPE_BPF,
        flags: c.flags,
        payload_sha256: &digest,
        loader: (HEADER_SIZE as u32, insns.len() as u32),
        signature: (sig_off as u32, sig.len() as u32),
        metadata: (0, 0),
        data: (data_off as u32, signed.len() as u32),
        log_buf_sz: LOG_BUF_SZ,
        rodata_data_off,
        nr_maps,
        nr_progs,
    };
    let out_path = super::path(out.to_bytes());
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(out_path);
    let mut file = match file {
        Ok(f) => f,
        Err(e) => {
            let err = errno_of(&e);
            error(&[b"open ", out.to_bytes(), b": ", strerr(-err)].concat());
            return err;
        }
    };
    let written = [&hdr.bytes()[..], insns, &sig, &signed]
        .iter()
        .try_for_each(|b| file.write_all(b))
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written {
        let _ = std::fs::remove_file(out_path);
        return errno_of(&e);
    }
    let directive = if unloading { " UNLOAD" } else { "" };
    let msg = format!(
        "wrote {} (insns={} sig={} data={} sections={} maps={nr_maps} progs={nr_progs} decoders={nr_decoders} name={}{directive})",
        String::from_utf8_lossy(out.to_bytes()),
        insns.len(),
        sig.len(),
        signed.len(),
        sections.len(),
        String::from_utf8_lossy(name),
    );
    info(msg.as_bytes());
    0
}

/// The policy labels a package signs: their header and the entries,
/// with the maps that hold the policy found in the object.
fn policy_labels(obj: &Object, policies: &[u8], nr: u32) -> Result<Vec<u8>, c_int> {
    let index = |name: &[u8]| obj.maps.iter().position(|m| m.name == name);
    let (task, sock) = (index(b"shirudo_task_policy"), index(b"shirudo_sock_policy"));
    let task_ok = task.is_some_and(|i| {
        let m = &obj.maps[i];
        m.map_type() == BPF_MAP_TYPE_TASK_STORAGE
            && m.key_size() == 4
            && m.value_size() == 16
            && m.map_flags() == BPF_F_NO_PREALLOC
    });
    if !task_ok {
        error(b"policy labels require a compatible shirudo_task_policy map");
        return Err(-EINVAL);
    }
    let sock_ok = sock.is_some_and(|i| {
        let m = &obj.maps[i];
        m.map_type() == BPF_MAP_TYPE_SK_STORAGE
            && m.key_size() == 4
            && m.value_size() == 8
            && m.map_flags() == (BPF_F_NO_PREALLOC | BPF_F_CLONE)
    });
    if !sock_ok {
        error(b"policy labels require a compatible shirudo_sock_policy map");
        return Err(-EINVAL);
    }
    let policy_idx = task.filter(|&i| i < MAPS_MAX as usize).ok_or(-E2BIG)?;
    let socket_idx = sock
        .filter(|&i| i < MAPS_MAX as usize && i != policy_idx)
        .ok_or(-E2BIG)?;
    let total = (nr as usize)
        .checked_mul(POLICY_LABEL_ENTRY)
        .and_then(|n| n.checked_add(POLICY_LABEL_HEADER));
    let Some(total) = total.filter(|&t| t <= u32::MAX as usize) else {
        return Err(-EOVERFLOW);
    };
    let mut blob = vec![0u8; POLICY_LABEL_HEADER];
    put32(&mut blob, 0, POLICY_LABELS_MAGIC);
    put32(&mut blob, 4, POLICY_LABELS_VERSION);
    put32(&mut blob, 8, nr);
    put32(&mut blob, 12, policy_idx as u32);
    put32(&mut blob, 16, socket_idx as u32);
    blob.extend_from_slice(policies);
    debug_assert_eq!(blob.len(), total);
    Ok(blob)
}

/// Packages the object at `bpf_o` as upatch `name` at `out`.
pub(super) fn load(
    bpf_o: &CStr,
    src_path: Option<&CStr>,
    out: &CStr,
    name: &CStr,
    policies: &[u8],
    nr: u32,
    keys: (&CStr, &CStr),
) -> c_int {
    let err = check_name(name.to_bytes());
    if err != 0 {
        return err;
    }
    let path = bpf_o.to_bytes();
    let obj = std::fs::read(super::path(path))
        .map_err(|e| errno_of(&e))
        .and_then(|data| Object::open(&data, object::object_name(path)));
    let obj = match obj {
        Ok(o) => o,
        Err(err) => {
            error(format!("open {}: {err}", String::from_utf8_lossy(bpf_o.to_bytes())).as_bytes());
            return err;
        }
    };
    let labels = if nr != 0 {
        match policy_labels(&obj, policies, nr) {
            Ok(l) => l,
            Err(err) => return err,
        }
    } else {
        Vec::new()
    };
    let contents = Contents {
        name,
        flags: 0,
        unload_payload: &[0; 32],
        src_path,
        policy_labels: &labels,
    };
    finalize(obj, out, &contents, keys)
}

/// `struct unload_params` of the unload template: the name and the
/// payload it unloads.
const UNLOAD_PARAMS: usize = NAME_MAX + PAYLOAD_HASH_LEN;

/// Signs the directive that unloads upatch `name`, whose payload has
/// the digest `payload`, at `out`.
pub(super) fn unload(name: &CStr, payload: &[u8; 32], out: &CStr, keys: (&CStr, &CStr)) -> c_int {
    let err = check_name(name.to_bytes());
    if err != 0 {
        return err;
    }
    // SAFETY: the embedded unload template, static.
    let blob = unsafe { unload_blob() };
    // SAFETY: NULL or the static blob.
    let Some(b) = (unsafe { blob.as_ref() }).filter(|b| !b.data.is_null() && b.size != 0) else {
        error(b"embedded unload template missing");
        return -ENOENT;
    };
    // SAFETY: the static blob's `size` bytes.
    let data = unsafe { crate::ffi::slice(b.data.cast::<u8>(), b.size) };
    // Named as libbpf names it opened from unload.bpf.o: from memory,
    // libbpf would name it from its address, and its .rodata map so.
    let mut obj = match Object::open(data, b"unload") {
        Ok(o) => o,
        Err(err) => {
            error(format!("open embedded unload template: {err}").as_bytes());
            return err;
        }
    };
    let Some(rodata) = obj.rodata_mut() else {
        error(b"unload template has no .rodata map");
        return -EINVAL;
    };
    let n = name.to_bytes();
    if n.len() >= NAME_MAX {
        return -ENAMETOOLONG;
    }
    let mut params = [0u8; UNLOAD_PARAMS];
    params[..n.len()].copy_from_slice(n);
    params[NAME_MAX..].copy_from_slice(payload);
    if let Err(err) = rodata.set_initial_value(&params) {
        error(format!("set_initial_value(.rodata): {err}").as_bytes());
        return err;
    }
    // The target reads the name and the expected payload from the signed
    // sections, not from the loader's .rodata, which it has no portable
    // way to locate in the data blob.
    let contents = Contents {
        name,
        flags: DIRECTIVE_UNLOAD,
        unload_payload: payload,
        src_path: None,
        policy_labels: &[],
    };
    finalize(obj, out, &contents, keys)
}

/// Packages the object at `bpf_o` as upatch `name` at `out`, with no
/// policy labels, signed with the key and certificate at `pkey` and
/// `cert`.
pub(super) fn load_object(
    bpf_o: &CStr,
    src_path: Option<&CStr>,
    out: &CStr,
    name: &CStr,
    pkey: &CStr,
    cert: &CStr,
) -> c_int {
    load(bpf_o, src_path, out, name, &[], 0, (pkey, cert))
}

/// Signs the directive that unloads upatch `name` at `out`.
pub(super) fn unload_directive(
    name: &CStr,
    payload: &[u8; 32],
    out: &CStr,
    pkey: &CStr,
    cert: &CStr,
) -> c_int {
    unload(name, payload, out, (pkey, cert))
}
