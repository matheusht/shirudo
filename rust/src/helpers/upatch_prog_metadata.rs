// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-upatch-prog-metadata: the signed program metadata of a .upatch
//! checked offline against what a test built it for. Prints ok, and for
//! a single uprobe its first file offset, which the caller cannot know
//! beforehand.
//!
//!   test-upatch-prog-metadata <file.upatch> [serializer]
//!   test-upatch-prog-metadata <file.upatch> cgroup-ingress|cgroup-egress|kprobe-override|fmod-ret|netfilter-ipv6-pre-routing|policy-labels
//!   test-upatch-prog-metadata <file.upatch> xdp <device classes>
//!   test-upatch-prog-metadata <file.upatch> uprobe|uretprobe|uprobe-multi|uretprobe-multi <path> <pattern> <offset or count>

use core::ffi::{CStr, c_int};

use super::{err, helper_main, out};
use crate::text::{cstr, parse_u64};
use crate::util::upatch::{
    ATTACH_CGROUP_SKB_EGRESS, ATTACH_CGROUP_SKB_INGRESS, ATTACH_FMOD_RET, ATTACH_KPROBE,
    ATTACH_NETFILTER_IPV6_PRE_ROUTING, ATTACH_UPROBE, ATTACH_UPROBE_MULTI, ATTACH_URETPROBE,
    ATTACH_URETPROBE_MULTI, ATTACH_XDP, BUILD_ID_MAX, Opened, POLICY_LABEL_ENTRY,
    POLICY_LABEL_HEADER, POLICY_LABELS_MAGIC, POLICY_LABELS_VERSION, PROG_ENTRY, PROG_MAGIC,
    PROG_METADATA, PROG_VERSION, ProgSpec, ROLE_ATTACH, ROLE_SERIALIZER, UPROBE_TARGET,
    UPROBE_TARGET_MAGIC, UPROBE_TARGET_VERSION, UPROBE_TARGETS, Upatch, XDP_ALL, specs_free,
    specs_parse,
};

helper_main!(shirudo_helper_test_upatch_prog_metadata, run);

const KPROBE_TARGET_MAGIC: u32 = 0x534b_5055;
const KPROBE_TARGET_VERSION: u32 = 1;
const ATTACH_KPROBE_MULTI: u32 = 12;
const ATTACH_KRETPROBE_MULTI: u32 = 13;

type Check = Result<(), &'static str>;

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap_or_default())
}

fn le64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap_or_default())
}

/// The NUL-terminated name in `field`, or None when it fills the field.
fn name(field: &[u8]) -> Option<&[u8]> {
    field.iter().position(|&c| c == 0).map(|n| &field[..n])
}

/// `struct upatch_prog_entry` at the start of `b`.
struct Entry<'a> {
    role: u32,
    kind: u32,
    offset: u64,
    target: &'a [u8],
    map: &'a [u8],
}

fn entry(b: &[u8]) -> Entry<'_> {
    Entry {
        role: le32(b, 0),
        kind: le32(b, 4),
        offset: le64(b, 8),
        target: &b[16..16 + 128],
        map: &b[16 + 128..PROG_ENTRY],
    }
}

/// The metadata's header and its `n` entries, its length `PROG_METADATA`
/// and the entries' exactly when `exact`, at least that when not.
fn metadata(raw: &[u8], n: usize, exact: bool) -> Result<Vec<Entry<'_>>, ()> {
    let need = PROG_METADATA + n * PROG_ENTRY;
    if (exact && raw.len() != need) || raw.len() < need {
        return Err(());
    }
    Ok((0..n)
        .map(|i| entry(&raw[PROG_METADATA + i * PROG_ENTRY..]))
        .collect())
}

fn header_ok(raw: &[u8], nr_progs: u32) -> bool {
    le32(raw, 0) == PROG_MAGIC && le32(raw, 4) == PROG_VERSION && le32(raw, 8) == nr_progs
}

fn signed_attach(u: &Upatch) -> &[u8] {
    u.signed_attach().unwrap_or_default()
}

fn expect_attach(u: &Upatch, kind: u32, target: Option<&[u8]>, offset: u64) -> Check {
    if u.hdr.nr_progs != 1 {
        return Err("unexpected metadata prog count");
    }
    let raw = signed_attach(u);
    if raw.is_empty() {
        return Err("missing signed metadata");
    }
    let progs = metadata(raw, 1, true).map_err(|()| "unexpected metadata length")?;
    if le32(raw, 0) != PROG_MAGIC || le32(raw, 4) != PROG_VERSION {
        return Err("unexpected metadata magic/version");
    }
    if le32(raw, 8) != 1 {
        return Err("unexpected metadata prog count");
    }
    let prog = &progs[0];
    if prog.role != ROLE_ATTACH {
        return Err("program is not an attach program");
    }
    if prog.kind != kind {
        return Err("attach kind mismatch");
    }
    if prog.offset != offset {
        return Err("unexpected attach offset");
    }
    let got = name(prog.target).ok_or("unterminated attach target")?;
    match target {
        Some(t) if got != t => return Err("attach target mismatch"),
        None if !got.is_empty() => return Err("unexpected attach target"),
        _ => {}
    }
    if prog.map[0] != 0 {
        return Err("unexpected attach map");
    }
    Ok(())
}

fn expect_serializer(u: &Upatch) -> Check {
    if u.hdr.nr_maps != 4 || u.hdr.nr_progs != 2 {
        return Err("unexpected map/prog counts");
    }
    let raw = signed_attach(u);
    if raw.is_empty() {
        return Err("missing signed metadata");
    }
    let progs = metadata(raw, 2, true).map_err(|()| "unexpected metadata length")?;
    if !header_ok(raw, 2) || le32(raw, 12) != 4 {
        return Err("unexpected metadata header");
    }
    let (mut arena, mut error) = (false, false);
    for prog in &progs {
        let map = name(prog.map)
            .filter(|_| prog.role == ROLE_SERIALIZER)
            .ok_or("program is not a named serializer")?;
        match map {
            b"tree_arena" => arena = true,
            b"tree_error" => error = true,
            _ => return Err("unexpected serializer target map"),
        }
    }
    if arena && error {
        Ok(())
    } else {
        Err("serializer map mismatch")
    }
}

/// The one program attaches as `kind` to `pattern` in `path` at
/// `expected_offsets` file offsets, of which it gives the first;
/// `entry_offset` is the offset the entry records inside the function.
fn expect_uprobe(
    u: &Upatch,
    kind: u32,
    path: &[u8],
    pattern: &[u8],
    entry_offset: u64,
    expected_offsets: u32,
) -> Result<u64, &'static str> {
    if u.hdr.nr_progs != 1 {
        return Err("unexpected metadata prog count");
    }
    let raw = signed_attach(u);
    let progs = match metadata(raw, 1, false) {
        Ok(p) if raw.len() >= PROG_METADATA + PROG_ENTRY + UPROBE_TARGETS + UPROBE_TARGET => p,
        _ => return Err("missing uprobe metadata"),
    };
    if !header_ok(raw, 1) {
        return Err("unexpected metadata header");
    }
    let prog = &progs[0];
    if prog.role != ROLE_ATTACH
        || prog.kind != kind
        || prog.offset != entry_offset
        || name(prog.target) != Some(pattern)
    {
        return Err("uprobe program entry mismatch");
    }
    let targets = &raw[PROG_METADATA + PROG_ENTRY..];
    if le32(targets, 0) != UPROBE_TARGET_MAGIC
        || le32(targets, 4) != UPROBE_TARGET_VERSION
        || le32(targets, 8) != 1
        || le32(targets, 12) != 0
    {
        return Err("uprobe target header mismatch");
    }
    let record = &targets[UPROBE_TARGETS..];
    let (path_len, build_id_len, nr_offsets) = (le32(record, 4), le32(record, 8), le32(record, 12));
    if le32(record, 0) != 0
        || path_len as usize != path.len()
        || build_id_len == 0
        || build_id_len as usize > BUILD_ID_MAX
        || nr_offsets != expected_offsets
    {
        return Err("uprobe target record mismatch");
    }
    let rest = &record[UPROBE_TARGET..];
    let (path_len, build_id_len) = (path_len as usize, build_id_len as usize);
    if rest.len() != path_len + build_id_len + nr_offsets as usize * 8 || &rest[..path_len] != path
    {
        return Err("uprobe path or metadata length mismatch");
    }
    let offsets: Vec<u64> = rest[path_len + build_id_len..]
        .chunks_exact(8)
        .map(|c| le64(c, 0))
        .collect();
    if offsets.windows(2).any(|w| w[1] <= w[0]) {
        return Err("uprobe offsets are not sorted and unique");
    }
    Ok(offsets.first().copied().unwrap_or(0))
}

fn kprobe_block(raw: &[u8], program_index: u32, names: &[u8]) -> Check {
    let mut want = names.to_vec();
    let count = 1 + want.iter().filter(|&&b| b == b',').count();
    for byte in &mut want {
        if *byte == b',' {
            *byte = 0;
        }
    }
    want.push(0);
    if raw.len() != 16 + 12 + want.len() {
        return Err("kprobe multi metadata length mismatch");
    }
    if le32(raw, 0) != KPROBE_TARGET_MAGIC
        || le32(raw, 4) != KPROBE_TARGET_VERSION
        || le32(raw, 8) != 1
        || le32(raw, 12) != 0
    {
        return Err("kprobe multi target header mismatch");
    }
    if le32(raw, 16) != program_index
        || le32(raw, 20) != count as u32
        || le32(raw, 24) != want.len() as u32
    {
        return Err("kprobe multi target record mismatch");
    }
    if raw[28..] != want {
        return Err("kprobe multi names mismatch");
    }
    Ok(())
}

fn expect_kprobe_multi(u: &Upatch, kind: u32, names: &[u8]) -> Check {
    if u.hdr.nr_progs != 1 {
        return Err("unexpected metadata prog count");
    }
    let raw = signed_attach(u);
    let progs = metadata(raw, 1, false).map_err(|()| "kprobe multi metadata length mismatch")?;
    if !header_ok(raw, 1) {
        return Err("unexpected metadata header");
    }
    let prog = &progs[0];
    if prog.role != ROLE_ATTACH || prog.kind != kind || prog.offset != 0 || prog.target[0] != 0 {
        return Err("kprobe multi program entry mismatch");
    }
    kprobe_block(&raw[PROG_METADATA + PROG_ENTRY..], 0, names)
}

fn expect_uprobe_and_kprobe_multi(u: &Upatch, path: &[u8], names: &[u8]) -> Check {
    if u.hdr.nr_progs != 2 {
        return Err("unexpected metadata prog count");
    }
    let raw = signed_attach(u);
    let progs = metadata(raw, 2, false).map_err(|()| "missing signed metadata")?;
    if !header_ok(raw, 2) {
        return Err("unexpected metadata header");
    }
    let uprobe = progs
        .iter()
        .position(|p| p.kind == ATTACH_UPROBE || p.kind == ATTACH_URETPROBE)
        .ok_or("uprobe target mismatch")?;
    let kprobe = progs
        .iter()
        .position(|p| p.kind == ATTACH_KPROBE_MULTI || p.kind == ATTACH_KRETPROBE_MULTI)
        .ok_or("kprobe multi names mismatch")?;
    if uprobe == kprobe || progs.iter().any(|p| p.role != ROLE_ATTACH) {
        return Err("the reader refuses the metadata");
    }
    let mut pos = PROG_METADATA + 2 * PROG_ENTRY;
    if raw.len() < pos + UPROBE_TARGETS + UPROBE_TARGET {
        return Err("the reader refuses the metadata");
    }
    if le32(raw, pos) != UPROBE_TARGET_MAGIC
        || le32(raw, pos + 4) != UPROBE_TARGET_VERSION
        || le32(raw, pos + 8) != 1
        || le32(raw, pos + 12) != 0
    {
        return Err("the reader refuses the metadata");
    }
    pos += UPROBE_TARGETS;
    let record = &raw[pos..pos + UPROBE_TARGET];
    let (path_len, build_id_len, nr_offsets) = (
        le32(record, 4) as usize,
        le32(record, 8) as usize,
        le32(record, 12) as usize,
    );
    if le32(record, 0) != uprobe as u32
        || build_id_len == 0
        || build_id_len > BUILD_ID_MAX
        || nr_offsets != 1
    {
        return Err("the reader refuses the metadata");
    }
    pos += UPROBE_TARGET;
    let end = pos
        .checked_add(path_len)
        .and_then(|n| n.checked_add(build_id_len))
        .and_then(|n| n.checked_add(nr_offsets * 8))
        .ok_or("the reader refuses the metadata")?;
    if end > raw.len() || raw[pos..pos + path_len] != *path {
        return Err("uprobe target mismatch");
    }
    kprobe_block(&raw[end..], kprobe as u32, names)
}

fn expect_policy_labels(u: &Upatch) -> Check {
    const POLICIES: [&[u8]; 5] = [
        b"executable",
        b"ordinary-a",
        b"ordinary-b",
        b"socket-check",
        b"matched",
    ];
    const PATHS: [&[u8]; 5] = [
        b"/tmp/shirudo-policy-label-test/executable",
        b"/tmp/shirudo-policy-label-test/ordinary",
        b"/tmp/shirudo-policy-label-test/ordinary",
        b"/tmp/shirudo-policy-label-test/socket-executable",
        b"/tmp/shirudo-policy-label-test/match-*",
    ];
    const BITS: [u64; 5] = [1, 2, 4, 16, 32];
    let raw = u.policy_labels().map_or(&[][..], |p| p.labels);
    if raw.is_empty() || raw.len() != POLICY_LABEL_HEADER + BITS.len() * POLICY_LABEL_ENTRY {
        return Err("policy label section length mismatch");
    }
    if le32(raw, 0) != POLICY_LABELS_MAGIC
        || le32(raw, 4) != POLICY_LABELS_VERSION
        || le32(raw, 8) as usize != BITS.len()
        || le32(raw, 12) != 0
        || le32(raw, 16) != 1
    {
        return Err("policy label header mismatch");
    }
    for (i, e) in raw[POLICY_LABEL_HEADER..]
        .chunks_exact(POLICY_LABEL_ENTRY)
        .enumerate()
    {
        if le64(e, 0) != BITS[i]
            || cstr(&e[8..8 + 64]) != POLICIES[i]
            || cstr(&e[8 + 64..]) != PATHS[i]
        {
            return Err("policy label entry mismatch");
        }
    }
    Ok(())
}

fn expect_xdp(u: &Upatch, classes: &CStr) -> Check {
    let mask =
        parse_u64(classes.to_bytes(), u64::from(XDP_ALL)).map_err(|_| "XDP metadata mismatch")?;
    let raw = signed_attach(u);
    let mut specs: *mut ProgSpec = core::ptr::null_mut();
    // SAFETY: the signed metadata, of its length, and room for the specs,
    // freed after.
    let ret = unsafe {
        specs_parse(
            raw.as_ptr().cast(),
            raw.len() as u32,
            u.hdr.nr_maps,
            u.hdr.nr_progs,
            &mut specs,
        )
    };
    if ret != 0 {
        return Err("XDP metadata mismatch");
    }
    // SAFETY: the specs parsed, one per program.
    let ok = unsafe {
        let ok = u.hdr.nr_progs == 1
            && (*specs).kind == ATTACH_XDP
            && u64::from((*specs).device_classes) == mask;
        specs_free(specs, u.hdr.nr_progs);
        ok
    };
    if ok {
        Ok(())
    } else {
        Err("XDP metadata mismatch")
    }
}

fn check(u: &Upatch, args: &[&CStr]) -> Result<Option<u64>, &'static str> {
    let mode = args.get(2).map_or(&b"serializer"[..], |m| m.to_bytes());
    let attach = |kind, target| expect_attach(u, kind, target, 0).map(|()| None);
    match (mode, args.len()) {
        (b"serializer", _) => expect_serializer(u).map(|()| None),
        (b"cgroup-ingress", _) => attach(ATTACH_CGROUP_SKB_INGRESS, None),
        (b"cgroup-egress", _) => attach(ATTACH_CGROUP_SKB_EGRESS, None),
        (b"kprobe-override", _) => attach(ATTACH_KPROBE, Some(&b"bpf_modify_return_test"[..])),
        (b"fmod-ret", _) => attach(ATTACH_FMOD_RET, None),
        (b"netfilter-ipv6-pre-routing", _) => attach(ATTACH_NETFILTER_IPV6_PRE_ROUTING, None),
        (b"xdp", 4) => expect_xdp(u, args[3]).map(|()| None),
        (b"uprobe-multi" | b"uretprobe-multi", 6) => {
            let kind = if mode == b"uretprobe-multi" {
                ATTACH_URETPROBE_MULTI
            } else {
                ATTACH_UPROBE_MULTI
            };
            let count = parse_u64(args[5].to_bytes(), u64::from(u32::MAX))
                .map_err(|_| "invalid expected uprobe offset count")?;
            expect_uprobe(
                u,
                kind,
                args[3].to_bytes(),
                args[4].to_bytes(),
                0,
                count as u32,
            )
            .map(|_| None)
        }
        (b"uprobe" | b"uretprobe", 6) => {
            let kind = if mode == b"uretprobe" {
                ATTACH_URETPROBE
            } else {
                ATTACH_UPROBE
            };
            let entry = parse_u64(args[5].to_bytes(), u64::MAX)
                .map_err(|_| "invalid expected uprobe entry offset")?;
            expect_uprobe(u, kind, args[3].to_bytes(), args[4].to_bytes(), entry, 1).map(Some)
        }
        (b"kprobe-multi", 4) => {
            expect_kprobe_multi(u, ATTACH_KPROBE_MULTI, args[3].to_bytes()).map(|()| None)
        }
        (b"kretprobe-multi", 4) => {
            expect_kprobe_multi(u, ATTACH_KRETPROBE_MULTI, args[3].to_bytes()).map(|()| None)
        }
        (b"uprobe-kprobe-multi", 5) => {
            expect_uprobe_and_kprobe_multi(u, args[3].to_bytes(), args[4].to_bytes()).map(|()| None)
        }
        (b"policy-labels", 3) => expect_policy_labels(u).map(|()| None),
        _ => Err("unknown metadata check mode"),
    }
}

fn run(args: &[&CStr]) -> c_int {
    let fail = |msg: &str| {
        err(&format!("{msg}\n"));
        1
    };
    if !(2..=6).contains(&args.len()) {
        return fail("usage: test-upatch-prog-metadata <file.upatch> [mode [path pattern count]]");
    }
    let Ok(u) = Opened::open(args[1]) else {
        return fail("open upatch failed");
    };
    match check(&u, args) {
        Err(msg) => fail(msg),
        Ok(first) => {
            if let Some(first) = first {
                out(&format!("{first}\n"));
            }
            out("ok\n");
            0
        }
    }
}
