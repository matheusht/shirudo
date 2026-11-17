// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The attach metadata a package signs: for each program, in the order
//! libbpf iterates them, its role, how the target attaches it and to
//! what, and the uprobe targets resolved on the operator; refusing a
//! section the target cannot attach with shirudo's own diagnostic rather
//! than the target kernel's.

use core::ffi::c_int;
use std::ffi::CString;

use super::bpf::{Object, Prog};
use super::{error, strerr};
use crate::errno::{EINVAL, ENAMETOOLONG, ENOENT, EOPNOTSUPP, EOVERFLOW};
use crate::text::{parse_u64, parse_x64};
use crate::util::elf_target::{ElfTarget, elf_target_free, elf_target_resolve};
use crate::util::upatch::{
    ATTACH_CGROUP_SKB_EGRESS, ATTACH_CGROUP_SKB_INGRESS, ATTACH_FMOD_RET, ATTACH_KPROBE,
    ATTACH_KRETPROBE, ATTACH_NETFILTER_IPV6_PRE_ROUTING, ATTACH_RAW_TRACEPOINT, ATTACH_TARGET_MAX,
    ATTACH_UPROBE_MULTI, PROG_ENTRY, PROG_MAGIC, PROG_MAP_MAX, PROG_METADATA, PROG_VERSION,
    ROLE_ATTACH, ROLE_SERIALIZER, ROLE_TEST_RUN, UPROBE_PATH_MAX, UPROBE_TARGET,
    UPROBE_TARGET_MAGIC, UPROBE_TARGET_VERSION, UPROBE_TARGETS,
};

const SERIALIZER_PREFIX: &[u8] = b"shirudo_serialize__";
const TEST_RUN_PREFIX: &[u8] = b"shirudo_test__";
/// SERIAL_MAP_NAME of bpf/lib/serializer.h: the serializers' output.
const SERIAL_MAP_NAME: &[u8] = b"shirudo_ser";
/// sizeof(struct serial_chunk) and SERIAL_MAX_CHUNKS.
const SERIAL_CHUNK: u32 = 4096;
const SERIAL_MAX_CHUNKS: u32 = 256;
const BPF_MAP_TYPE_ARRAY: u32 = 2;

/// The section without the `?` that marks it optional.
fn bare(sec: Option<&[u8]>) -> Option<&[u8]> {
    sec.map(|s| s.strip_prefix(b"?").unwrap_or(s))
}

/// `s` starts with `prefix` and goes on after it.
fn after<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    s.strip_prefix(prefix).filter(|rest| !rest.is_empty())
}

fn unsupported_kprobe(sec: &[u8]) -> bool {
    matches!(sec, b"kprobe" | b"kretprobe" | b"kprobe/" | b"kretprobe/")
        || sec.starts_with(b"kprobe.multi")
        || sec.starts_with(b"kretprobe.multi")
}

fn unsupported_uprobe(sec: &[u8]) -> bool {
    if after(sec, b"uprobe.multi/").is_some() {
        return false;
    }
    sec == b"uprobe"
        || sec.starts_with(b"uprobe/")
        || sec.starts_with(b"uprobe.")
        || sec == b"uretprobe"
        || sec.starts_with(b"uretprobe/")
        || sec.starts_with(b"uretprobe.")
}

fn unsupported_sk_skb(sec: &[u8]) -> bool {
    sec == b"sk_skb" || sec.starts_with(b"sk_skb/")
}

fn unsupported_socket_filter(sec: &[u8]) -> bool {
    matches!(sec, b"socket" | b"socket_filter")
        || sec.starts_with(b"socket/")
        || sec.starts_with(b"socket_filter/")
}

fn unsupported_cgroup_skb(sec: &[u8]) -> bool {
    if matches!(sec, b"cgroup_skb/ingress" | b"cgroup_skb/egress") {
        return false;
    }
    matches!(sec, b"cgroup/skb" | b"cgroup_skb") || sec.starts_with(b"cgroup_skb/")
}

fn unsupported_fmod_ret(sec: &[u8]) -> bool {
    matches!(
        sec,
        b"fmod_ret" | b"fmod_ret/" | b"fmod_ret.s" | b"fmod_ret.s/"
    )
}

/// The sections the target attaches by their BTF target alone, through
/// BPF_RAW_TRACEPOINT_OPEN or a BPF_LSM_MAC link; every other type fails
/// there.
fn default_attach(sec: &[u8]) -> bool {
    [
        b"fentry/".as_slice(),
        b"fentry.s/",
        b"fexit/",
        b"fexit.s/",
        b"lsm/",
        b"lsm.s/",
        b"tp_btf/",
    ]
    .iter()
    .any(|p| after(sec, p).is_some())
}

/// How the target attaches the program of `sec`, and to what.
fn attach_kind(sec: &[u8]) -> (u32, Option<&[u8]>) {
    if let Some(t) = after(sec, b"kprobe/") {
        return (ATTACH_KPROBE, Some(t));
    }
    if let Some(t) = after(sec, b"kretprobe/") {
        return (ATTACH_KRETPROBE, Some(t));
    }
    if let Some(t) = after(sec, b"uprobe.multi/") {
        return (ATTACH_UPROBE_MULTI, Some(t));
    }
    let kind = match sec {
        b"cgroup_skb/ingress" => ATTACH_CGROUP_SKB_INGRESS,
        b"cgroup_skb/egress" => ATTACH_CGROUP_SKB_EGRESS,
        b"netfilter" => ATTACH_NETFILTER_IPV6_PRE_ROUTING,
        _ if after(sec, b"fmod_ret/").is_some() || after(sec, b"fmod_ret.s/").is_some() => {
            ATTACH_FMOD_RET
        }
        _ => ATTACH_RAW_TRACEPOINT,
    };
    (kind, None)
}

/// `/absolute/path:function_glob` into the path and the pattern.
fn split_uprobe_target(src: &[u8]) -> Result<(&[u8], &[u8]), c_int> {
    if src.first() != Some(&b'/') {
        return Err(-EINVAL);
    }
    let colon = src.iter().position(|&c| c == b':').ok_or(-EINVAL)?;
    let (path, pattern) = (&src[..colon], &src[colon + 1..]);
    if colon == 0 || pattern.is_empty() {
        return Err(-EINVAL);
    }
    if path.len() >= UPROBE_PATH_MAX as usize || pattern.len() >= ATTACH_TARGET_MAX {
        return Err(-ENAMETOOLONG);
    }
    if pattern.iter().any(|&c| c == b',' || c == b'|') {
        return Err(-EOPNOTSUPP);
    }
    Ok((path, pattern))
}

/// "<symbol>[+<offset>]", the offset in decimal or 0x hexadecimal; a
/// leading zero is refused rather than read as octal.
fn split_probe_target(src: &[u8]) -> Result<(&[u8], u64), c_int> {
    let mut offset = 0u64;

    if src.is_empty() {
        return Err(-EINVAL);
    }
    let symbol = match src.iter().rposition(|&c| c == b'+') {
        Some(0) => return Err(-EINVAL),
        Some(plus) => {
            let num = &src[plus + 1..];
            let parsed = if num.len() > 2 && (num.starts_with(b"0x") || num.starts_with(b"0X")) {
                parse_x64(&num[2..], u64::MAX)
            } else if num.len() > 1 && num[0] == b'0' {
                Err(-EINVAL)
            } else {
                parse_u64(num, u64::MAX)
            };
            offset = parsed.map_err(|_| -EINVAL)?;
            &src[..plus]
        }
        None => src,
    };
    if symbol.is_empty() || symbol.len() >= ATTACH_TARGET_MAX {
        return Err(-EINVAL);
    }
    Ok((symbol, offset))
}

fn serializer_map<'a>(p: &Prog<'a>) -> Option<&'a [u8]> {
    p.name()?.strip_prefix(SERIALIZER_PREFIX)
}

fn is_syscall(sec: Option<&[u8]>) -> bool {
    sec == Some(b"syscall")
}

/// A section for a message: as printf prints a NULL one.
fn shown(sec: Option<&[u8]>) -> &[u8] {
    sec.unwrap_or(b"(null)")
}

fn validate_serializer_output_map(obj: &Object) -> c_int {
    let name = String::from_utf8_lossy(SERIAL_MAP_NAME);
    let Some(m) = obj.maps().find(|m| m.name() == SERIAL_MAP_NAME) else {
        error(format!("serializer upatch requires {name} output map").as_bytes());
        return -EINVAL;
    };
    let why = if m.ty() != BPF_MAP_TYPE_ARRAY {
        format!("{name} must be BPF_MAP_TYPE_ARRAY")
    } else if m.key_size() != 4 {
        format!("{name} must use a u32 key")
    } else if m.value_size() != SERIAL_CHUNK {
        format!("{name} value must be struct serial_chunk")
    } else if m.max_entries() == 0 || m.max_entries() > SERIAL_MAX_CHUNKS {
        format!("{name} max_entries must be 1..{SERIAL_MAX_CHUNKS}")
    } else {
        return 0;
    };
    error(why.as_bytes());
    -EINVAL
}

fn put32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// `s` into the fixed field at `buf`, NUL-terminated, as strscpy() does.
fn put_str(buf: &mut [u8], s: &[u8]) {
    let n = s.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&s[..n]);
    buf[n] = 0;
}

/// A uprobe.multi program's target, resolved against its ELF.
struct UprobeTarget {
    prog_idx: u32,
    path: Vec<u8>,
    elf: ElfTarget,
}

impl Drop for UprobeTarget {
    fn drop(&mut self) {
        // SAFETY: the target elf_target_resolve() filled.
        unsafe { elf_target_free(&mut self.elf) };
    }
}

impl UprobeTarget {
    fn offsets(&self) -> &[u64] {
        if self.elf.offsets.is_null() {
            return &[];
        }
        // SAFETY: the target's offsets.
        unsafe { crate::ffi::slice(self.elf.offsets, self.elf.nr_offsets as usize) }
    }
}

/// The entry of one attaching program: its kind, and its target and
/// offset, or its uprobe target, which it records into `uprobes`.
fn attach_entry(
    sec: Option<&[u8]>,
    i: usize,
    entry: &mut [u8],
    uprobes: &mut Vec<UprobeTarget>,
) -> c_int {
    let s = bare(sec);
    let unsupported: [Rule; 6] = [
        (
            unsupported_kprobe,
            "unsupported kprobe section '{}'; use kprobe/<symbol> or kretprobe/<symbol>",
        ),
        (
            unsupported_uprobe,
            "unsupported uprobe section '{}'; use uprobe.multi//absolute/path:function_glob (entry probes only)",
        ),
        (
            unsupported_sk_skb,
            "unsupported sk_skb section '{}'; supported network packet sections are cgroup_skb/ingress, cgroup_skb/egress, and netfilter",
        ),
        (
            unsupported_socket_filter,
            "unsupported socket filter section '{}'; shirudo upatches require a pinnable bpf_link lifecycle",
        ),
        (
            unsupported_cgroup_skb,
            "unsupported cgroup_skb section '{}'; use cgroup_skb/ingress or cgroup_skb/egress",
        ),
        (
            unsupported_fmod_ret,
            "unsupported fmod_ret section '{}'; use fmod_ret/<symbol> or fmod_ret.s/<symbol>",
        ),
    ];
    let shown_sec = String::from_utf8_lossy(shown(sec)).into_owned();

    for (test, msg) in unsupported {
        if s.is_some_and(test) {
            error(msg.replace("{}", &shown_sec).as_bytes());
            return -EOPNOTSUPP;
        }
    }
    let (kind, target) = s.map_or((ATTACH_RAW_TRACEPOINT, None), attach_kind);
    if kind == ATTACH_RAW_TRACEPOINT && !s.is_some_and(default_attach) {
        error(format!("unsupported section '{shown_sec}'; supported are fentry, fexit, fmod_ret, lsm, tp_btf, kprobe, kretprobe, uprobe.multi, cgroup_skb and netfilter").as_bytes());
        return -EOPNOTSUPP;
    }
    put32(entry, 0, ROLE_ATTACH);
    put32(entry, 4, kind);
    let mut offset = 0;
    if kind == ATTACH_UPROBE_MULTI {
        let (path, pattern) = match split_uprobe_target(target.unwrap_or_default()) {
            Ok(t) => t,
            Err(err) => {
                let msg = if err == -EOPNOTSUPP {
                    format!(
                        "invalid uprobe.multi section '{shown_sec}': ',' and '|' alternation are unsupported; use one '*'/'?' glob"
                    )
                } else {
                    format!(
                        "invalid uprobe.multi section '{shown_sec}'; expected uprobe.multi//absolute/path:function_glob"
                    )
                };
                error(msg.as_bytes());
                return err;
            }
        };
        put_str(&mut entry[16..16 + ATTACH_TARGET_MAX], pattern);
        // SAFETY: an all-zero target is an empty one.
        let elf = unsafe { core::mem::zeroed() };
        let mut t = UprobeTarget {
            prog_idx: i as u32,
            path: path.to_vec(),
            elf,
        };
        let (p, pat) = (
            CString::new(path).unwrap_or_default(),
            CString::new(pattern).unwrap_or_default(),
        );
        // SAFETY: two C strings and the target to fill.
        let err = unsafe { elf_target_resolve(p.as_ptr(), pat.as_ptr(), &mut t.elf) };
        uprobes.push(t);
        if err != 0 {
            let (pattern, path) = (
                String::from_utf8_lossy(pattern),
                String::from_utf8_lossy(path),
            );
            let msg = if err == -ENOENT {
                format!(
                    "uprobe.multi pattern '{pattern}' matched no functions in {path} (or the ELF has no GNU build ID)"
                )
            } else {
                format!(
                    "cannot resolve uprobe.multi target {path}:{pattern}: {}",
                    String::from_utf8_lossy(strerr(-err))
                )
            };
            error(msg.as_bytes());
            return err;
        }
    } else if let Some(target) = target {
        let (symbol, off) = match split_probe_target(target) {
            Ok(t) => t,
            Err(err) => {
                error(format!("invalid kprobe target in section '{shown_sec}'").as_bytes());
                return err;
            }
        };
        if kind == ATTACH_KRETPROBE && off != 0 {
            error(format!("kretprobe offsets are unsupported in section '{shown_sec}'").as_bytes());
            return -EINVAL;
        }
        put_str(&mut entry[16..16 + ATTACH_TARGET_MAX], symbol);
        offset = off;
    }
    entry[8..16].copy_from_slice(&offset.to_le_bytes());
    0
}

/// A section the target cannot attach, and what to use instead.
type Rule = (fn(&[u8]) -> bool, &'static str);

/// The uprobe targets that follow the program entries.
fn append_uprobes(md: &mut Vec<u8>, uprobes: &[UprobeTarget]) -> c_int {
    let mut len = md.len() + UPROBE_TARGETS;

    for t in uprobes {
        len += UPROBE_TARGET + t.path.len() + t.elf.build_id_len as usize + 8 * t.offsets().len();
    }
    if len > u32::MAX as usize {
        return -EOVERFLOW;
    }
    let mut head = [0u8; UPROBE_TARGETS];
    put32(&mut head, 0, UPROBE_TARGET_MAGIC);
    put32(&mut head, 4, UPROBE_TARGET_VERSION);
    put32(&mut head, 8, uprobes.len() as u32);
    md.extend_from_slice(&head);
    for t in uprobes {
        let mut rec = [0u8; UPROBE_TARGET];
        put32(&mut rec, 0, t.prog_idx);
        put32(&mut rec, 4, t.path.len() as u32);
        put32(&mut rec, 8, t.elf.build_id_len);
        put32(&mut rec, 12, t.offsets().len() as u32);
        md.extend_from_slice(&rec);
        md.extend_from_slice(&t.path);
        md.extend_from_slice(&t.elf.build_id[..t.elf.build_id_len as usize]);
        for off in t.offsets() {
            md.extend_from_slice(&off.to_le_bytes());
        }
    }
    0
}

/// The attach metadata of `obj`, of `nr_maps` maps and `nr_progs`
/// programs.
pub(super) fn prog_metadata(obj: &Object, nr_maps: u32, nr_progs: u32) -> Result<Vec<u8>, c_int> {
    if obj.programs().any(|p| serializer_map(&p).is_some()) {
        let err = validate_serializer_output_map(obj);
        if err != 0 {
            return Err(err);
        }
    }
    let base = PROG_METADATA + nr_progs as usize * PROG_ENTRY;
    if base > u32::MAX as usize {
        return Err(-EOVERFLOW);
    }
    let mut md = vec![0u8; base];
    put32(&mut md, 0, PROG_MAGIC);
    put32(&mut md, 4, PROG_VERSION);
    put32(&mut md, 8, nr_progs);
    put32(&mut md, 12, nr_maps);
    let mut seen: Vec<&[u8]> = Vec::new();
    let mut uprobes = Vec::new();
    let mut test_run = false;

    for (i, p) in obj.programs().enumerate() {
        let sec = p.section();
        let at = PROG_METADATA + i * PROG_ENTRY;
        let entry = &mut md[at..at + PROG_ENTRY];
        let name = || String::from_utf8_lossy(p.name().unwrap_or(b"?")).into_owned();

        if let Some(map) = serializer_map(&p) {
            let shown_map = String::from_utf8_lossy(map);
            let why = if !is_syscall(sec) {
                Some(format!("serializer '{}' must use SEC(\"syscall\")", name()))
            } else if map.is_empty() || map.len() >= PROG_MAP_MAX {
                Some(format!(
                    "serializer '{}' has invalid target map '{shown_map}'",
                    name()
                ))
            } else if map == SERIAL_MAP_NAME {
                Some(format!(
                    "serializer cannot target reserved map {}",
                    String::from_utf8_lossy(SERIAL_MAP_NAME)
                ))
            } else if !obj.has_map(map) {
                Some(format!(
                    "serializer '{}' targets missing map '{shown_map}'",
                    name()
                ))
            } else if seen.contains(&map) {
                Some(format!("duplicate serializer for map '{shown_map}'"))
            } else {
                None
            };
            if let Some(why) = why {
                error(why.as_bytes());
                return Err(-EINVAL);
            }
            seen.push(map);
            put32(entry, 0, ROLE_SERIALIZER);
            put_str(&mut entry[16 + ATTACH_TARGET_MAX..], map);
            continue;
        }
        if is_syscall(sec) {
            let named = p
                .name()
                .and_then(|n| n.strip_prefix(TEST_RUN_PREFIX))
                .is_some_and(|id| !id.is_empty());
            let prefix = String::from_utf8_lossy(TEST_RUN_PREFIX);
            if !named {
                error(
                    format!(
                        "SEC(\"syscall\") program '{}' must be named {prefix}<id>",
                        name()
                    )
                    .as_bytes(),
                );
                return Err(-EINVAL);
            }
            if test_run {
                error(format!("only one {prefix} test-run program is supported").as_bytes());
                return Err(-EINVAL);
            }
            test_run = true;
            put32(entry, 0, ROLE_TEST_RUN);
            continue;
        }
        let err = attach_entry(sec, i, entry, &mut uprobes);
        if err != 0 {
            return Err(err);
        }
    }
    if !uprobes.is_empty() {
        let err = append_uprobes(&mut md, &uprobes);
        if err != 0 {
            return Err(err);
        }
    }
    Ok(md)
}
