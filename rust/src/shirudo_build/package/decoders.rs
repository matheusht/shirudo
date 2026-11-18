// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The decoders a package carries: the manifests a source declares in
//! its .rodata, each naming a Lua source beside the `.bpf.c`, read and
//! signed with the package so the target runs only what the operator
//! built.

use core::ffi::c_int;
use std::ffi::CString;

use super::{error, strerr};
use crate::bpf::object::Object;
use crate::errno::{EEXIST, EINVAL, EOPNOTSUPP, EOVERFLOW};
use crate::text::cstr;
use crate::util::upatch::{DECODER_BLOB, DECODER_ENTRY, DECODER_MAGIC, DECODER_VERSION};

/// DECODER_MANIFEST_MAGIC: "DECD", little-endian.
const MANIFEST_MAGIC: u32 = 0x4443_4544;
/// sizeof(struct decoder_manifest).
const MANIFEST: usize = 192;
const LANG_LUA: u32 = 1;
const INPUT_MAP_V1: u32 = 1;
const EXPORT_LOG: u32 = 1;
const EXPORT_METRIC: u32 = 2;
/// The largest decoder source a package takes.
const SOURCE_MAX: usize = 16 * 1024 * 1024;

/// A manifest, its strings as the fields hold them up to their NULs.
struct Manifest {
    language: u32,
    api_version: u32,
    input_format: u32,
    export_signal: u32,
    upatch: Vec<u8>,
    map: Vec<u8>,
    source: Vec<u8>,
    entrypoint: Vec<u8>,
}

fn le16(b: &[u8], off: usize) -> u32 {
    u16::from_le_bytes([b[off], b[off + 1]]).into()
}

/// A fixed string field: not empty, and NUL-terminated within it.
fn field(b: &[u8], off: usize, len: usize) -> Option<Vec<u8>> {
    let f = &b[off..off + len];
    (f[0] != 0 && f.contains(&0)).then(|| cstr(f).to_vec())
}

fn parse_manifest(b: &[u8]) -> Option<Manifest> {
    if b.len() < MANIFEST
        || u32::from_le_bytes([b[0], b[1], b[2], b[3]]) != MANIFEST_MAGIC
        || le16(b, 4) != DECODER_VERSION
    {
        return None;
    }
    let (upatch, map, source, entrypoint) = (
        field(b, 16, 64)?,
        field(b, 80, 16)?,
        field(b, 96, 64)?,
        field(b, 160, 32)?,
    );
    let m = Manifest {
        language: le16(b, 6),
        api_version: le16(b, 8),
        input_format: le16(b, 10),
        export_signal: le16(b, 12),
        upatch,
        map,
        source,
        entrypoint,
    };
    let zero = [m.language, m.api_version, m.input_format, m.export_signal].contains(&0);
    (!zero && le16(b, 14) == 0).then_some(m)
}

/// A relative path that stays below its directory: no leading '/', no
/// '\', no empty, '.' or '..' component.
fn relpath_unsafe(path: &[u8]) -> bool {
    path.is_empty()
        || path[0] == b'/'
        || path.contains(&b'\\')
        || path
            .split(|&c| c == b'/')
            .any(|c| c.is_empty() || c == b"." || c == b"..")
}

/// A decoder and its source.
struct Decoder {
    manifest: Manifest,
    source: Vec<u8>,
}

/// Reads the source a manifest names, beside `src_path`.
fn read_source(m: &Manifest, src_path: Option<&[u8]>) -> Result<Vec<u8>, c_int> {
    let shown = String::from_utf8_lossy(&m.source);

    if relpath_unsafe(&m.source) {
        error(format!("decoder source path '{shown}' is invalid").as_bytes());
        return Err(-EINVAL);
    }
    let dir = src_path
        .and_then(|s| s.iter().rposition(|&c| c == b'/').map(|slash| &s[..=slash]))
        .unwrap_or_default();
    let path = CString::new([dir, &m.source].concat()).map_err(|_| -EINVAL)?;
    let (source, mut err) = match crate::util::io::read(&path, SOURCE_MAX) {
        Ok(source) => (source, 0),
        Err(err) => (Vec::new(), err),
    };
    if err == 0 && source.is_empty() {
        err = -EINVAL;
    }
    if err != 0 {
        let p = String::from_utf8_lossy(path.to_bytes());
        error(
            format!(
                "read decoder source {p}: {}",
                String::from_utf8_lossy(strerr(-err))
            )
            .as_bytes(),
        );
        return Err(err);
    }
    Ok(source)
}

/// The decoders of `obj`'s .rodata, every 4 bytes a candidate manifest.
fn collect(
    obj: &Object,
    src_path: Option<&[u8]>,
    upatch_name: &[u8],
) -> Result<Vec<Decoder>, c_int> {
    let Some(rodata) = obj.rodata() else {
        return Ok(Vec::new());
    };
    let data = &rodata.initial[..];
    let mut out: Vec<Decoder> = Vec::new();
    let mut off = 0;

    while off + MANIFEST <= data.len() {
        let at = off;
        off += 4;
        let Some(m) = parse_manifest(&data[at..]) else {
            continue;
        };
        let (u, map) = (
            String::from_utf8_lossy(&m.upatch),
            String::from_utf8_lossy(&m.map),
        );
        let abi = m.language == LANG_LUA
            && m.api_version == 1
            && m.input_format == INPUT_MAP_V1
            && (m.export_signal == EXPORT_LOG || m.export_signal == EXPORT_METRIC);
        let failure = if !abi {
            Some((
                format!("unsupported decoder ABI for '{u}/{map}'"),
                -EOPNOTSUPP,
            ))
        } else if m.upatch != upatch_name {
            let name = String::from_utf8_lossy(upatch_name);
            Some((
                format!("decoder upatch '{u}' does not match package name '{name}'"),
                -EINVAL,
            ))
        } else if obj.map(&m.map).is_none() {
            Some((format!("decoder manifest for missing map '{map}'"), -EINVAL))
        } else if out
            .iter()
            .any(|d| d.manifest.upatch == m.upatch && d.manifest.map == m.map)
        {
            Some((format!("duplicate decoder for '{u}/{map}'"), -EEXIST))
        } else {
            None
        };
        if let Some((msg, err)) = failure {
            error(msg.as_bytes());
            return Err(err);
        }
        let source = read_source(&m, src_path)?;
        out.push(Decoder {
            manifest: m,
            source,
        });
    }
    Ok(out)
}

fn put_str(buf: &mut [u8], s: &[u8]) {
    let n = s.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&s[..n]);
    buf[n] = 0;
}

/// The decoder blob a package signs, and how many decoders it holds;
/// empty without any.
pub(super) fn blob(
    obj: &Object,
    src_path: Option<&[u8]>,
    upatch_name: &[u8],
) -> Result<(Vec<u8>, u32), c_int> {
    let decoders = collect(obj, src_path, upatch_name)?;
    let n = decoders.len();

    if n == 0 {
        return Ok((Vec::new(), 0));
    }
    let entries_end = DECODER_BLOB + n * DECODER_ENTRY;
    let total = entries_end + decoders.iter().map(|d| d.source.len()).sum::<usize>();
    if total > u32::MAX as usize {
        return Err(-EOVERFLOW);
    }
    let mut blob = vec![0u8; entries_end];
    blob[0..4].copy_from_slice(&DECODER_MAGIC.to_le_bytes());
    blob[4..8].copy_from_slice(&DECODER_VERSION.to_le_bytes());
    blob[8..12].copy_from_slice(&(n as u32).to_le_bytes());
    let mut source_off = entries_end;
    for (i, d) in decoders.iter().enumerate() {
        let e = &mut blob[DECODER_BLOB + i * DECODER_ENTRY..][..DECODER_ENTRY];
        let m = &d.manifest;
        for (at, v) in [
            (0, m.language),
            (4, m.api_version),
            (8, m.input_format),
            (12, m.export_signal),
        ] {
            e[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        put_str(&mut e[16..80], &m.upatch);
        put_str(&mut e[80..96], &m.map);
        put_str(&mut e[96..160], &m.source);
        put_str(&mut e[160..192], &m.entrypoint);
        e[192..196].copy_from_slice(&(source_off as u32).to_le_bytes());
        e[196..200].copy_from_slice(&(d.source.len() as u32).to_le_bytes());
        source_off += d.source.len();
    }
    for d in &decoders {
        blob.extend_from_slice(&d.source);
    }
    Ok((blob, n as u32))
}
