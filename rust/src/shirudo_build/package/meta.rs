// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The attach metadata a package signs: for each program, in the order
//! libbpf iterates them, its role, how the target attaches it and to
//! what, the uprobe targets resolved on the operator and the classes of
//! device an XDP program attaches to; refusing a
//! section the target cannot attach with shirudo's own diagnostic rather
//! than the target kernel's.

use core::ffi::c_int;

use super::{error, strerr};
use crate::bpf::MAP_ARRAY;
use crate::bpf::object::{Object, Prog};
use crate::errno::{E2BIG, EEXIST, EINVAL, ENAMETOOLONG, ENOENT, EOPNOTSUPP, EOVERFLOW, ERANGE};
use crate::text::{parse_u64, parse_x64};
use crate::util::elf_target::{self, Target};
use crate::util::upatch::{
    ATTACH_CGROUP_SKB_EGRESS, ATTACH_CGROUP_SKB_INGRESS, ATTACH_FMOD_RET, ATTACH_KPROBE,
    ATTACH_KPROBE_MULTI, ATTACH_KRETPROBE, ATTACH_KRETPROBE_MULTI,
    ATTACH_NETFILTER_IPV6_PRE_ROUTING, ATTACH_RAW_TRACEPOINT, ATTACH_TARGET_MAX, ATTACH_UPROBE,
    ATTACH_UPROBE_MULTI, ATTACH_URETPROBE, ATTACH_URETPROBE_MULTI, ATTACH_XDP, KPROBE_SYM_MAX,
    KPROBE_SYMS_MAX, KPROBE_TARGET, KPROBE_TARGET_MAGIC, KPROBE_TARGET_VERSION, KPROBE_TARGETS,
    PROG_ENTRY, PROG_MAGIC, PROG_MAP_MAX, PROG_METADATA, PROG_VERSION, ROLE_ATTACH,
    ROLE_SERIALIZER, ROLE_TEST_RUN, UPROBE_PATH_MAX, UPROBE_TARGET, UPROBE_TARGET_MAGIC,
    UPROBE_TARGET_VERSION, UPROBE_TARGETS, XDP_ALL, kprobe_sym_valid,
};

const SERIALIZER_PREFIX: &[u8] = b"shirudo_serialize__";
const TEST_RUN_PREFIX: &[u8] = b"shirudo_test__";
/// SERIAL_MAP_NAME of bpf/lib/serializer.h: the serializers' output.
const SERIAL_MAP_NAME: &[u8] = b"shirudo_ser";
/// sizeof(struct serial_chunk) and SERIAL_MAX_CHUNKS.
const SERIAL_CHUNK: u32 = 4096;
const SERIAL_MAX_CHUNKS: u32 = 256;

/// The section without the `?` that marks it optional.
fn bare(sec: &[u8]) -> &[u8] {
    sec.strip_prefix(b"?").unwrap_or(sec)
}

/// `s` starts with `prefix` and goes on after it.
fn after<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    s.strip_prefix(prefix).filter(|rest| !rest.is_empty())
}

/// The kprobe multi forms of a section, and their comma-separated names.
fn kprobe_multi_section(sec: &[u8]) -> Option<(u32, &[u8])> {
    after(sec, b"kprobe.multi/")
        .map(|target| (ATTACH_KPROBE_MULTI, target))
        .or_else(|| after(sec, b"kretprobe.multi/").map(|target| (ATTACH_KRETPROBE_MULTI, target)))
}

fn unsupported_kprobe(sec: &[u8]) -> bool {
    if kprobe_multi_section(sec).is_some() {
        return false;
    }
    matches!(sec, b"kprobe" | b"kretprobe" | b"kprobe/" | b"kretprobe/")
        || sec.starts_with(b"kprobe.multi")
        || sec.starts_with(b"kretprobe.multi")
}

/// The uprobe forms of a section, and the kind each attaches as. A
/// sleepable form takes its plain form's kind: BPF_F_SLEEPABLE is a load
/// flag, which the signed loader carries, not part of the link.
const UPROBE_FORMS: [(&[u8], u32); 8] = [
    (b"uprobe/", ATTACH_UPROBE),
    (b"uprobe.s/", ATTACH_UPROBE),
    (b"uretprobe/", ATTACH_URETPROBE),
    (b"uretprobe.s/", ATTACH_URETPROBE),
    (b"uprobe.multi/", ATTACH_UPROBE_MULTI),
    (b"uprobe.multi.s/", ATTACH_UPROBE_MULTI),
    (b"uretprobe.multi/", ATTACH_URETPROBE_MULTI),
    (b"uretprobe.multi.s/", ATTACH_URETPROBE_MULTI),
];

/// The kind of a uprobe section and what follows its form.
fn uprobe_section(sec: &[u8]) -> Option<(u32, &[u8])> {
    UPROBE_FORMS
        .iter()
        .find_map(|&(form, kind)| after(sec, form).map(|target| (kind, target)))
}

fn unsupported_uprobe(sec: &[u8]) -> bool {
    if uprobe_section(sec).is_some() {
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
    if let Some((kind, t)) = kprobe_multi_section(sec) {
        return (kind, Some(t));
    }
    if let Some((kind, t)) = uprobe_section(sec) {
        return (kind, Some(t));
    }
    if let Some(t) = after(sec, b"xdp/") {
        return (ATTACH_XDP, Some(t));
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

fn serializer_map(p: &Prog) -> Option<&[u8]> {
    p.name.strip_prefix(SERIALIZER_PREFIX)
}

fn is_syscall(sec: &[u8]) -> bool {
    sec == b"syscall"
}

fn validate_serializer_output_map(obj: &Object) -> Result<(), c_int> {
    let name = String::from_utf8_lossy(SERIAL_MAP_NAME);
    let Some(m) = obj.map(SERIAL_MAP_NAME) else {
        error(format!("serializer upatch requires {name} output map").as_bytes());
        return Err(-EINVAL);
    };
    let why = if m.map_type() != MAP_ARRAY {
        format!("{name} must be BPF_MAP_TYPE_ARRAY")
    } else if m.key_size() != 4 {
        format!("{name} must use a u32 key")
    } else if m.value_size() != SERIAL_CHUNK {
        format!("{name} value must be struct serial_chunk")
    } else if m.max_entries() == 0 || m.max_entries() > SERIAL_MAX_CHUNKS {
        format!("{name} max_entries must be 1..{SERIAL_MAX_CHUNKS}")
    } else {
        return Ok(());
    };
    error(why.as_bytes());
    Err(-EINVAL)
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

/// A uprobe program's target, resolved against its ELF.
struct UprobeTarget {
    prog_idx: u32,
    path: Vec<u8>,
    elf: Target,
}

/// A kprobe multi program's sorted, distinct function names.
struct KprobeTarget {
    prog_idx: u32,
    syms: Vec<Vec<u8>>,
}

/// What the attaching programs of one object gather: the uprobe
/// targets, kprobe multi targets, and the XDP device classes taken so
/// far, as a device takes one native XDP program at a time.
#[derive(Default)]
struct Attach {
    uprobes: Vec<UprobeTarget>,
    kprobes: Vec<KprobeTarget>,
    xdp_classes: u32,
}

fn lossy(s: &[u8]) -> String {
    String::from_utf8_lossy(s).into_owned()
}

/// A comma-separated kprobe multi target into distinct names in signed
/// lexical order.
fn split_kprobe_multi_target(src: &[u8]) -> Result<Vec<Vec<u8>>, c_int> {
    if src.iter().any(|&c| c == b'*' || c == b'?') {
        return Err(-EOPNOTSUPP);
    }
    let nr_syms = 1usize + src.iter().filter(|&&c| c == b',').count();
    if nr_syms > KPROBE_SYMS_MAX as usize
        || src
            .len()
            .checked_add(1)
            .is_none_or(|n| n > u32::MAX as usize)
    {
        return Err(-E2BIG);
    }
    let mut syms = Vec::new();
    syms.try_reserve_exact(nr_syms)
        .map_err(|_| -crate::errno::ENOMEM)?;
    for sym in src.split(|&c| c == b',') {
        if !kprobe_sym_valid(sym) {
            return Err(-EINVAL);
        }
        syms.push(sym.to_vec());
    }
    syms.sort_unstable();
    if syms.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(-EEXIST);
    }
    Ok(syms)
}

/// The device classes of an `xdp/<mask>` section into `entry`, each
/// class to one program of the object.
fn xdp_entry(shown_sec: &str, mask: &[u8], entry: &mut [u8], a: &mut Attach) -> Result<(), c_int> {
    let all = u64::from(XDP_ALL);
    let Some(mask) = parse_u64(mask, all)
        .ok()
        .filter(|&m| m != 0 && m & !all == 0)
    else {
        error(format!("invalid XDP device class mask in section '{shown_sec}'; use xdp/<decimal-mask>, a sum of 1, 2, 8 and 16").as_bytes());
        return Err(-EINVAL);
    };
    let mask = u32::try_from(mask).map_err(|_| -EINVAL)?;
    if mask & a.xdp_classes != 0 {
        error(format!("XDP section '{shown_sec}' selects a device class another XDP program of this upatch selects; give each class to one program").as_bytes());
        return Err(-EINVAL);
    }
    a.xdp_classes |= mask;
    put32(entry, 8, mask);
    Ok(())
}

/// `<path>:<function>[+<offset>]` or `<path>:0x<file offset>` of a
/// uprobe or uretprobe section into `entry`'s target and offset and one
/// file offset of the target it records.
fn single_uprobe_entry(
    shown_sec: &str,
    kind: u32,
    src: &[u8],
    i: usize,
    entry: &mut [u8],
    a: &mut Attach,
) -> Result<(), c_int> {
    let invalid = || {
        error(format!("invalid uprobe section '{shown_sec}'; expected uprobe[.s]//absolute/path:function[+offset], uretprobe[.s]//absolute/path:function or a 0x file offset in place of the function").as_bytes());
        Err(-EINVAL)
    };
    let Ok((path, loc)) = split_uprobe_target(src) else {
        return invalid();
    };
    let (target, func, offset) = match loc {
        [b'0', b'x' | b'X', hex @ ..] => match parse_x64(hex, u64::MAX) {
            Ok(off) => (loc, None, off),
            Err(_) => return invalid(),
        },
        _ => match split_probe_target(loc) {
            Ok((symbol, off)) => {
                if kind == ATTACH_URETPROBE && off != 0 {
                    error(
                        format!("uretprobe offsets are unsupported in section '{shown_sec}'")
                            .as_bytes(),
                    );
                    return Err(-EINVAL);
                }
                entry[8..16].copy_from_slice(&off.to_le_bytes());
                (symbol, Some(symbol), off)
            }
            Err(_) => return invalid(),
        },
    };
    put_str(&mut entry[16..16 + ATTACH_TARGET_MAX], target);
    let (shown_path, shown_target) = (lossy(path), lossy(target));
    let elf = match elf_target::resolve_func(path, func, offset) {
        Ok(elf) => elf,
        Err(err) => {
            let msg = if err == -ENOENT {
                format!(
                    "uprobe function '{shown_target}' not found in {shown_path} (or the ELF has no GNU build ID)"
                )
            } else if err == -ERANGE {
                format!("uprobe offset in section '{shown_sec}' lies outside {shown_path}")
            } else {
                format!(
                    "cannot resolve uprobe target {shown_path}:{shown_target}: {}",
                    lossy(strerr(-err))
                )
            };
            error(msg.as_bytes());
            return Err(err);
        }
    };
    // The kernel reports a uprobe link's offset in 32 bits.
    if elf.offsets[0] > u64::from(u32::MAX) {
        error(
            format!("uprobe offset in section '{shown_sec}' is beyond 4 GiB of {shown_path}")
                .as_bytes(),
        );
        return Err(-ERANGE);
    }
    a.uprobes.push(UprobeTarget {
        prog_idx: u32::try_from(i).map_err(|_| -EOVERFLOW)?,
        path: path.to_vec(),
        elf,
    });
    Ok(())
}

/// The entry of one attaching program: its kind, and its target and
/// offset, its uprobe target, which it records, or its XDP device
/// classes.
fn attach_entry(sec: &[u8], i: usize, entry: &mut [u8], a: &mut Attach) -> Result<(), c_int> {
    let s = bare(sec);
    let unsupported: [Rule; 6] = [
        (
            unsupported_kprobe,
            "unsupported kprobe section '{}'; use kprobe/<symbol>, kretprobe/<symbol>, kprobe.multi/<symbol>[,<symbol>...] or kretprobe.multi/<symbol>[,<symbol>...]",
        ),
        (
            unsupported_uprobe,
            "unsupported uprobe section '{}'; use uprobe[.s]//absolute/path:function[+offset], uretprobe[.s]//absolute/path:function, uprobe.multi[.s]//absolute/path:function_glob or uretprobe.multi[.s]//absolute/path:function_glob",
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
    let shown_sec = String::from_utf8_lossy(sec).into_owned();

    for (test, msg) in unsupported {
        if test(s) {
            error(msg.replace("{}", &shown_sec).as_bytes());
            return Err(-EOPNOTSUPP);
        }
    }
    let (kind, target) = attach_kind(s);
    if kind == ATTACH_RAW_TRACEPOINT && !default_attach(s) {
        error(format!("unsupported section '{shown_sec}'; supported are fentry, fexit, fmod_ret, lsm, tp_btf, kprobe, kretprobe, kprobe.multi, kretprobe.multi, uprobe[.s], uretprobe[.s], uprobe.multi[.s], uretprobe.multi[.s], cgroup_skb, netfilter and xdp/<mask>").as_bytes());
        return Err(-EOPNOTSUPP);
    }
    put32(entry, 0, ROLE_ATTACH);
    put32(entry, 4, kind);
    let target_of = target.unwrap_or_default();
    match kind {
        ATTACH_XDP => return xdp_entry(&shown_sec, target_of, entry, a),
        ATTACH_UPROBE | ATTACH_URETPROBE => {
            return single_uprobe_entry(&shown_sec, kind, target_of, i, entry, a);
        }
        _ => {}
    }
    let mut offset = 0;
    if kind == ATTACH_UPROBE_MULTI || kind == ATTACH_URETPROBE_MULTI {
        let (path, pattern) = match split_uprobe_target(target.unwrap_or_default()) {
            Ok(t) => t,
            Err(err) => {
                let msg = if err == -EOPNOTSUPP {
                    format!(
                        "invalid uprobe multi section '{shown_sec}': ',' and '|' alternation are unsupported; use one '*'/'?' glob"
                    )
                } else {
                    format!(
                        "invalid uprobe multi section '{shown_sec}'; expected uprobe.multi[.s]//absolute/path:function_glob or uretprobe.multi[.s]//absolute/path:function_glob"
                    )
                };
                error(msg.as_bytes());
                return Err(err);
            }
        };
        put_str(&mut entry[16..16 + ATTACH_TARGET_MAX], pattern);
        let (elf, err) = match elf_target::resolve(path, pattern) {
            Ok(t) => (t, 0),
            Err(err) => (Target::default(), err),
        };
        a.uprobes.push(UprobeTarget {
            prog_idx: u32::try_from(i).map_err(|_| -EOVERFLOW)?,
            path: path.to_vec(),
            elf,
        });
        if err != 0 {
            let (pattern, path) = (
                String::from_utf8_lossy(pattern),
                String::from_utf8_lossy(path),
            );
            let msg = if err == -ENOENT {
                format!(
                    "uprobe multi pattern '{pattern}' matched no functions in {path} (or the ELF has no GNU build ID)"
                )
            } else {
                format!(
                    "cannot resolve uprobe multi target {path}:{pattern}: {}",
                    String::from_utf8_lossy(strerr(-err))
                )
            };
            error(msg.as_bytes());
            return Err(err);
        }
    } else if matches!(kind, ATTACH_KPROBE_MULTI | ATTACH_KRETPROBE_MULTI) {
        let syms = match split_kprobe_multi_target(target.unwrap_or_default()) {
            Ok(syms) => syms,
            Err(err) => {
                let msg = if err == -EOPNOTSUPP {
                    format!(
                        "invalid kprobe multi section '{shown_sec}': globs are unsupported; name each function"
                    )
                } else if err == -EEXIST {
                    format!("invalid kprobe multi section '{shown_sec}': a function is named twice")
                } else {
                    format!(
                        "invalid kprobe multi section '{shown_sec}'; expected a comma-separated list of 1 to {KPROBE_SYMS_MAX} function names of at most {} bytes",
                        KPROBE_SYM_MAX - 1
                    )
                };
                error(msg.as_bytes());
                return Err(err);
            }
        };
        a.kprobes.push(KprobeTarget {
            prog_idx: u32::try_from(i).map_err(|_| -EOVERFLOW)?,
            syms,
        });
    } else if let Some(target) = target {
        let (symbol, off) = match split_probe_target(target) {
            Ok(t) => t,
            Err(err) => {
                error(format!("invalid kprobe target in section '{shown_sec}'").as_bytes());
                return Err(err);
            }
        };
        if kind == ATTACH_KRETPROBE && off != 0 {
            error(format!("kretprobe offsets are unsupported in section '{shown_sec}'").as_bytes());
            return Err(-EINVAL);
        }
        put_str(&mut entry[16..16 + ATTACH_TARGET_MAX], symbol);
        offset = off;
    }
    entry[8..16].copy_from_slice(&offset.to_le_bytes());
    Ok(())
}

/// A section the target cannot attach, and what to use instead.
type Rule = (fn(&[u8]) -> bool, &'static str);

/// The uprobe targets that follow the program entries.
fn append_uprobes(md: &mut Vec<u8>, uprobes: &[UprobeTarget]) -> Result<(), c_int> {
    let mut len = md.len() + UPROBE_TARGETS;

    for t in uprobes {
        len += UPROBE_TARGET + t.path.len() + t.elf.build_id.len() + 8 * t.elf.offsets.len();
    }
    if len > u32::MAX as usize {
        return Err(-EOVERFLOW);
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
        put32(&mut rec, 8, t.elf.build_id.len() as u32);
        put32(&mut rec, 12, t.elf.offsets.len() as u32);
        md.extend_from_slice(&rec);
        md.extend_from_slice(&t.path);
        md.extend_from_slice(&t.elf.build_id);
        for off in &t.elf.offsets {
            md.extend_from_slice(&off.to_le_bytes());
        }
    }
    Ok(())
}

/// The UPKS block after any UPUT block: one sorted NUL-terminated name
/// list for every kprobe multi program.
fn append_kprobes(md: &mut Vec<u8>, kprobes: &[KprobeTarget]) -> Result<(), c_int> {
    let mut added = KPROBE_TARGETS;
    for target in kprobes {
        let syms_len = target
            .syms
            .iter()
            .try_fold(0usize, |n, sym| n.checked_add(sym.len() + 1))
            .ok_or(-EOVERFLOW)?;
        added = added
            .checked_add(KPROBE_TARGET)
            .and_then(|n| n.checked_add(syms_len))
            .ok_or(-EOVERFLOW)?;
    }
    if md
        .len()
        .checked_add(added)
        .is_none_or(|len| len > u32::MAX as usize)
    {
        return Err(-EOVERFLOW);
    }
    md.try_reserve_exact(added)
        .map_err(|_| -crate::errno::ENOMEM)?;
    let mut head = [0u8; KPROBE_TARGETS];
    put32(&mut head, 0, KPROBE_TARGET_MAGIC);
    put32(&mut head, 4, KPROBE_TARGET_VERSION);
    put32(&mut head, 8, kprobes.len() as u32);
    md.extend_from_slice(&head);
    for target in kprobes {
        let syms_len = target.syms.iter().map(|sym| sym.len() + 1).sum::<usize>();
        let mut record = [0u8; KPROBE_TARGET];
        put32(&mut record, 0, target.prog_idx);
        put32(&mut record, 4, target.syms.len() as u32);
        put32(&mut record, 8, syms_len as u32);
        md.extend_from_slice(&record);
        for sym in &target.syms {
            md.extend_from_slice(sym);
            md.push(0);
        }
    }
    Ok(())
}

/// The attach metadata of `obj`, of `nr_maps` maps and `nr_progs`
/// programs.
pub(super) fn prog_metadata(obj: &Object, nr_maps: u32, nr_progs: u32) -> Result<Vec<u8>, c_int> {
    if obj.programs().any(|p| serializer_map(p).is_some()) {
        validate_serializer_output_map(obj)?;
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
    let mut attach = Attach::default();
    let mut test_run = false;

    for (i, p) in obj.programs().enumerate() {
        let sec = &p.sec_name[..];
        let at = PROG_METADATA + i * PROG_ENTRY;
        let entry = &mut md[at..at + PROG_ENTRY];
        let name = || String::from_utf8_lossy(&p.name).into_owned();

        if let Some(map) = serializer_map(p) {
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
            } else if obj.map(map).is_none() {
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
                .name
                .strip_prefix(TEST_RUN_PREFIX)
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
        attach_entry(sec, i, entry, &mut attach)?;
    }
    if !attach.uprobes.is_empty() {
        append_uprobes(&mut md, &attach.uprobes)?;
    }
    if !attach.kprobes.is_empty() {
        append_kprobes(&mut md, &attach.kprobes)?;
    }
    Ok(md)
}
