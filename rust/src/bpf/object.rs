// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! A BPF object opened and loaded as libbpf opens it and loads it into a
//! gen_loader: its programs, maps, externs and relocations collected, its
//! BTF fixed up, and its subprograms appended and its references
//! relocated program by program. What libbpf would ask the running
//! kernel or the host, and what the generated loader cannot carry, is
//! refused: kconfig and typeless externs, struct_ops, pinned, inner and
//! per-CPU maps, arena globals, pointers in data and jump tables.

use core::ffi::c_int;

use super::btf::{self, Btf};
use super::btf_ext::{self, BtfExt};
use super::elf::{self, Elf, Symbol};
use super::loader::{ExternRelo, Gen, MapCreate, ProgLoad};
use super::*;
use crate::errno::{E2BIG, EINVAL, ENOENT, EOPNOTSUPP, ESRCH};

/// The section definitions of the programs shirudo builds, as libbpf's
/// section_defs lists them, in its order: a prefix with a `+` matches the
/// name itself or the name and a `/`; one with a `/` at its end matches
/// any name it starts; any other the name itself.
struct SecDef {
    sec: &'static [u8],
    prog_type: u32,
    attach: u32,
    flags: u32,
}

const SEC_NONE: u32 = 0;
const SEC_ATTACHABLE_OPT: u32 = 3;
const SEC_ATTACH_BTF: u32 = 4;
const SEC_SLEEPABLE: u32 = 8;

const fn def(sec: &'static [u8], prog_type: u32, attach: u32, flags: u32) -> SecDef {
    SecDef {
        sec,
        prog_type,
        attach,
        flags,
    }
}

static SEC_DEFS: &[SecDef] = &[
    def(b"kprobe+", PROG_KPROBE, 0, SEC_NONE),
    def(b"uprobe+", PROG_KPROBE, 0, SEC_NONE),
    def(b"uprobe.s+", PROG_KPROBE, 0, SEC_SLEEPABLE),
    def(b"kretprobe+", PROG_KPROBE, 0, SEC_NONE),
    def(b"uretprobe+", PROG_KPROBE, 0, SEC_NONE),
    def(b"uretprobe.s+", PROG_KPROBE, 0, SEC_SLEEPABLE),
    def(b"kprobe.multi+", PROG_KPROBE, TRACE_KPROBE_MULTI, SEC_NONE),
    def(
        b"kretprobe.multi+",
        PROG_KPROBE,
        TRACE_KPROBE_MULTI,
        SEC_NONE,
    ),
    def(
        b"kprobe.session+",
        PROG_KPROBE,
        TRACE_KPROBE_SESSION,
        SEC_NONE,
    ),
    def(b"uprobe.multi+", PROG_KPROBE, TRACE_UPROBE_MULTI, SEC_NONE),
    def(
        b"uretprobe.multi+",
        PROG_KPROBE,
        TRACE_UPROBE_MULTI,
        SEC_NONE,
    ),
    def(
        b"uprobe.session+",
        PROG_KPROBE,
        TRACE_UPROBE_SESSION,
        SEC_NONE,
    ),
    def(
        b"uprobe.multi.s+",
        PROG_KPROBE,
        TRACE_UPROBE_MULTI,
        SEC_SLEEPABLE,
    ),
    def(
        b"uretprobe.multi.s+",
        PROG_KPROBE,
        TRACE_UPROBE_MULTI,
        SEC_SLEEPABLE,
    ),
    def(
        b"uprobe.session.s+",
        PROG_KPROBE,
        TRACE_UPROBE_SESSION,
        SEC_SLEEPABLE,
    ),
    def(b"ksyscall+", PROG_KPROBE, 0, SEC_NONE),
    def(b"kretsyscall+", PROG_KPROBE, 0, SEC_NONE),
    def(b"tracepoint+", PROG_TRACEPOINT, 0, SEC_NONE),
    def(b"tp+", PROG_TRACEPOINT, 0, SEC_NONE),
    def(b"tracepoint.s+", PROG_TRACEPOINT, 0, SEC_SLEEPABLE),
    def(b"tp.s+", PROG_TRACEPOINT, 0, SEC_SLEEPABLE),
    def(b"raw_tracepoint+", PROG_RAW_TRACEPOINT, 0, SEC_NONE),
    def(b"raw_tp+", PROG_RAW_TRACEPOINT, 0, SEC_NONE),
    def(b"raw_tracepoint.s+", PROG_RAW_TRACEPOINT, 0, SEC_SLEEPABLE),
    def(b"raw_tp.s+", PROG_RAW_TRACEPOINT, 0, SEC_SLEEPABLE),
    def(b"tp_btf+", PROG_TRACING, TRACE_RAW_TP, SEC_ATTACH_BTF),
    def(
        b"tp_btf.s+",
        PROG_TRACING,
        TRACE_RAW_TP,
        SEC_ATTACH_BTF | SEC_SLEEPABLE,
    ),
    def(b"fentry+", PROG_TRACING, TRACE_FENTRY, SEC_ATTACH_BTF),
    def(b"fmod_ret+", PROG_TRACING, MODIFY_RETURN, SEC_ATTACH_BTF),
    def(b"fexit+", PROG_TRACING, TRACE_FEXIT, SEC_ATTACH_BTF),
    def(
        b"fentry.s+",
        PROG_TRACING,
        TRACE_FENTRY,
        SEC_ATTACH_BTF | SEC_SLEEPABLE,
    ),
    def(
        b"fmod_ret.s+",
        PROG_TRACING,
        MODIFY_RETURN,
        SEC_ATTACH_BTF | SEC_SLEEPABLE,
    ),
    def(
        b"fexit.s+",
        PROG_TRACING,
        TRACE_FEXIT,
        SEC_ATTACH_BTF | SEC_SLEEPABLE,
    ),
    def(b"lsm+", PROG_LSM, LSM_MAC, SEC_ATTACH_BTF),
    def(b"lsm.s+", PROG_LSM, LSM_MAC, SEC_ATTACH_BTF | SEC_SLEEPABLE),
    def(b"syscall", PROG_SYSCALL, 0, SEC_SLEEPABLE),
    def(
        b"cgroup_skb/ingress",
        PROG_CGROUP_SKB,
        CGROUP_INET_INGRESS,
        SEC_ATTACHABLE_OPT,
    ),
    def(
        b"cgroup_skb/egress",
        PROG_CGROUP_SKB,
        CGROUP_INET_EGRESS,
        SEC_ATTACHABLE_OPT,
    ),
    def(b"netfilter", PROG_NETFILTER, NETFILTER, SEC_NONE),
];

/// sec_def_matches()
fn sec_def_matches(d: &SecDef, name: &[u8]) -> bool {
    match d.sec.split_last() {
        Some((b'/', _)) => name.starts_with(d.sec),
        Some((b'+', pfx)) => {
            name.starts_with(pfx) && matches!(name.get(pfx.len()), None | Some(b'/'))
        }
        _ => name == d.sec,
    }
}

fn find_sec_def(name: &[u8]) -> Option<&'static SecDef> {
    SEC_DEFS.iter().find(|d| sec_def_matches(d, name))
}

fn show(s: &[u8]) -> String {
    String::from_utf8_lossy(s).into_owned()
}

/// Logs `msg` as libbpf warns and fails with `err`.
fn fail<T>(err: c_int, msg: impl AsRef<str>) -> Result<T, c_int> {
    crate::log::warn(msg.as_ref().as_bytes());
    Err(err)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Strategy {
    Auto,
    Disabled,
    Manual,
}

/// The kinds of relocation, in libbpf's order, which sorts them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ReloKind {
    Ld64,
    Call,
    Data,
    ExternLd64,
    ExternCall,
    SubprogAddr,
    Core,
}

#[derive(Clone)]
struct Relo {
    kind: ReloKind,
    insn_idx: usize,
    map_idx: usize,
    sym_off: u32,
    ext_idx: usize,
    core: [u8; 16],
}

impl Relo {
    fn new(kind: ReloKind, insn_idx: usize) -> Self {
        Relo {
            kind,
            insn_idx,
            map_idx: 0,
            sym_off: 0,
            ext_idx: 0,
            core: [0; 16],
        }
    }
}

/// A program or, in .text, a subprogram.
pub(crate) struct Prog {
    pub(crate) name: Vec<u8>,
    pub(crate) sec_name: Vec<u8>,
    sec_idx: usize,
    sec_insn_off: usize,
    sec_insn_cnt: usize,
    insns: Vec<Insn>,
    strategy: Strategy,
    mark_btf_static: bool,
    def: Option<&'static SecDef>,
    pub(crate) prog_type: u32,
    pub(crate) attach: u32,
    prog_flags: u32,
    relos: Vec<Relo>,
}

impl Prog {
    fn contains(&self, insn_idx: usize) -> bool {
        insn_idx >= self.sec_insn_off && insn_idx < self.sec_insn_off + self.sec_insn_cnt
    }
}

/// Which libbpf map a map is: one of .maps, or the map of a global data
/// section.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MapKind {
    Btf,
    Data,
    Bss,
    Rodata,
}

/// A map, with what it is created with and, for a global data section,
/// its contents.
pub(crate) struct Map {
    pub(crate) name: Vec<u8>,
    kind: MapKind,
    sec_idx: usize,
    sec_offset: u64,
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    numa_node: u32,
    map_extra: u64,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    pub(crate) initial: Vec<u8>,
}

impl Map {
    /// A map of global data, which libbpf makes itself.
    pub(crate) fn is_internal(&self) -> bool {
        self.kind != MapKind::Btf
    }

    pub(crate) fn map_type(&self) -> u32 {
        self.map_type
    }

    pub(crate) fn map_flags(&self) -> u32 {
        self.map_flags
    }

    pub(crate) fn key_size(&self) -> u32 {
        self.key_size
    }

    /// The BTF types of a map of .maps' key and value, which
    /// tools/bpf-lskel writes Rust of.
    #[allow(dead_code)]
    pub(crate) fn key_type_id(&self) -> u32 {
        self.btf_key_type_id
    }

    #[allow(dead_code)]
    pub(crate) fn value_type_id(&self) -> u32 {
        self.btf_value_type_id
    }

    pub(crate) fn value_size(&self) -> u32 {
        self.value_size
    }

    pub(crate) fn max_entries(&self) -> u32 {
        self.max_entries
    }

    /// bpf_map__set_initial_value(): new contents for a map of global
    /// data, exactly its value's size.
    pub(crate) fn set_initial_value(&mut self, value: &[u8]) -> Result<(), c_int> {
        if !self.is_internal() || value.len() != self.value_size as usize {
            return Err(-EINVAL);
        }
        self.initial = value.to_vec();
        Ok(())
    }
}

/// The name libbpf gives an object it opens from `path`: the file's
/// name up to its first '.'.
pub(crate) fn object_name(path: &[u8]) -> &[u8] {
    let base = path.rsplit(|&c| c == b'/').next().unwrap_or(path);
    base.split(|&c| c == b'.').next().unwrap_or(base)
}

/// An extern of .ksyms: a kfunc or a typed kernel variable.
struct Extern {
    name: Vec<u8>,
    btf_id: u32,
    sym_idx: usize,
    is_weak: bool,
}

/// The .BTF.ext records of one kind with the ELF section of each group.
#[derive(Default)]
struct ExtInfo {
    rec_size: usize,
    groups: Vec<(usize, Vec<u8>)>,
}

impl ExtInfo {
    fn new(info: &btf_ext::Info<'_>, btf: &Btf, elf: &Elf<'_>) -> Self {
        let groups = info
            .groups
            .iter()
            .map(|g| {
                let sec = btf
                    .str_at(g.sec_name_off)
                    .filter(|n| !n.is_empty())
                    .and_then(|n| elf.section_by_name(n))
                    .unwrap_or(0);
                (sec, g.recs.to_vec())
            })
            .collect();
        ExtInfo {
            rec_size: info.rec_size,
            groups,
        }
    }

    fn records<'s>(&'s self, recs: &'s [u8]) -> impl Iterator<Item = &'s [u8]> {
        recs.chunks_exact(self.rec_size.max(1))
    }
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// What libbpf's object takes from a gen_loader's options.
pub(crate) struct GenOpts {
    pub(crate) gen_hash: bool,
    pub(crate) reuse_map_mask: u64,
}

/// The object, opened.
pub(crate) struct Object {
    name: Vec<u8>,
    license: Vec<u8>,
    btf: Btf,
    func_info: Option<ExtInfo>,
    line_info: Option<ExtInfo>,
    core_info: Option<ExtInfo>,
    progs: Vec<Prog>,
    pub(crate) maps: Vec<Map>,
    externs: Vec<Extern>,
    text_shndx: usize,
}

/// The name of the map of global data section `real_name`, as
/// internal_map_name() makes it.
fn internal_map_name(obj_name: &[u8], real_name: &[u8]) -> Vec<u8> {
    let sfx_len = real_name.len().clamp(7, 15);
    let pfx_len = if real_name.len() > 1 && real_name[1..].contains(&b'.') {
        0
    } else {
        (16 - sfx_len - 1).min(obj_name.len())
    };
    let mut name: Vec<u8> = obj_name[..pfx_len]
        .iter()
        .chain(&real_name[..real_name.len().min(sfx_len)])
        .copied()
        .take(15)
        .collect();
    for c in &mut name {
        if !c.is_ascii_alphanumeric() && *c != b'_' && *c != b'.' {
            *c = b'_';
        }
    }
    name
}

/// What each section is to the object.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SecType {
    None,
    Data,
    Rodata,
    Bss,
    Relo,
}

/// The ELF facts the open needs after elf_collect().
struct ElfCtx<'a> {
    elf: Elf<'a>,
    syms: Vec<Symbol>,
    symbols_shndx: usize,
    strtabidx: usize,
    secs: Vec<SecType>,
    btf_maps_shndx: Option<usize>,
}

impl<'a> ElfCtx<'a> {
    fn sym_name(&self, sym: &Symbol) -> Option<&'a [u8]> {
        self.elf.str_at(self.strtabidx, sym.name)
    }

    fn sec_name(&self, idx: usize) -> &'a [u8] {
        self.elf.section_name(idx).unwrap_or_default()
    }

    fn sec_size(&self, idx: usize) -> u64 {
        self.elf.sections.get(idx).map_or(0, |s| s.size)
    }
}

fn sym_is_extern(sym: &Symbol) -> bool {
    sym.shndx == elf::SHN_UNDEF
        && matches!(sym.bind(), elf::STB_GLOBAL | elf::STB_WEAK)
        && sym.ty() == 0
}

fn sym_is_subprog(sym: &Symbol, text_shndx: usize) -> bool {
    if usize::from(sym.shndx) != text_shndx {
        return false;
    }
    (sym.bind() == elf::STB_LOCAL && sym.ty() == elf::STT_SECTION)
        || (matches!(sym.bind(), elf::STB_GLOBAL | elf::STB_WEAK) && sym.ty() == elf::STT_FUNC)
}

fn is_dwarf(name: &[u8]) -> bool {
    name.starts_with(b".debug_")
}

/// ignore_elf_section()
fn ignore_section(s: &elf::Section, name: &[u8]) -> bool {
    if s.ty == elf::SHT_STRTAB || s.ty == elf::SHT_LLVM_ADDRSIG {
        return true;
    }
    if s.ty == elf::SHT_PROGBITS && s.size == 0 && name == b".text" {
        return true;
    }
    if is_dwarf(name) {
        return true;
    }
    if let Some(rest) = name.strip_prefix(b".rel") {
        return is_dwarf(rest) || rest == b".BTF" || rest == b".BTF.ext";
    }
    false
}

fn has_pfx_sec(name: &[u8], sec: &[u8]) -> bool {
    name == sec || (name.starts_with(sec) && name.get(sec.len()) == Some(&b'.'))
}

/// The main program being relocated: its instructions with the
/// subprograms it calls appended, its relocations and its function and
/// line info.
struct Linked {
    insns: Vec<Insn>,
    relos: Vec<Relo>,
    func_info: Option<Vec<u8>>,
    func_rec: usize,
    line_info: Option<Vec<u8>>,
    line_rec: usize,
}

/// glibc's bsearch() of `insn_idx` among relocations sorted by it.
fn find_insn_relo(relos: &[Relo], insn_idx: usize) -> Option<&Relo> {
    let (mut l, mut u) = (0, relos.len());
    while l < u {
        let idx = (l + u) / 2;
        match insn_idx.cmp(&relos[idx].insn_idx) {
            core::cmp::Ordering::Less => u = idx,
            core::cmp::Ordering::Greater => l = idx + 1,
            core::cmp::Ordering::Equal => return Some(&relos[idx]),
        }
    }
    None
}

/// bpf_object__add_programs(): the functions of the executable section
/// `sec_idx`, programs or, in .text, subprograms.
fn add_programs(
    progs: &mut Vec<Prog>,
    text_shndx: usize,
    cx: &ElfCtx<'_>,
    data: &[u8],
    sec_name: &[u8],
    sec_idx: usize,
) -> Result<(), c_int> {
    for sym in &cx.syms {
        if usize::from(sym.shndx) != sec_idx || sym.ty() != elf::STT_FUNC {
            continue;
        }
        let (sz, off) = (sym.size as usize, sym.value as usize);
        let name = cx.sym_name(sym).ok_or(-EINVAL)?;
        let end = off.checked_add(sz).filter(|&e| e <= data.len());
        let Some(end) = end else {
            return fail(
                -EINVAL,
                format!(
                    "sec '{}': program at offset {off} crosses section boundary",
                    show(sec_name)
                ),
            );
        };
        if sec_idx != text_shndx && sym.bind() == elf::STB_LOCAL {
            return fail(
                -EOPNOTSUPP,
                format!(
                    "sec '{}': program '{}' is static and not supported",
                    show(sec_name),
                    show(name)
                ),
            );
        }
        if sz == 0 || sz % INSN_SZ != 0 || off % INSN_SZ != 0 {
            return fail(
                -EINVAL,
                format!(
                    "sec '{}': corrupted program '{}'",
                    show(sec_name),
                    show(name)
                ),
            );
        }
        let (strategy, sec) = match sec_name.first() {
            Some(b'?') => (Strategy::Disabled, &sec_name[1..]),
            Some(b'!') => (Strategy::Manual, &sec_name[1..]),
            _ => (Strategy::Auto, sec_name),
        };
        let sym_global = sym.bind() != elf::STB_LOCAL;
        progs.push(Prog {
            name: name.to_vec(),
            sec_name: sec.to_vec(),
            sec_idx,
            sec_insn_off: off / INSN_SZ,
            sec_insn_cnt: sz / INSN_SZ,
            insns: data[off..end]
                .chunks_exact(INSN_SZ)
                .map(Insn::parse)
                .collect(),
            strategy,
            mark_btf_static: sym_global
                && matches!(sym.visibility(), elf::STV_HIDDEN | elf::STV_INTERNAL),
            def: None,
            prog_type: 0,
            attach: 0,
            prog_flags: 0,
            relos: Vec::new(),
        });
    }
    Ok(())
}

impl Object {
    /// bpf_object__open_mem() of `data` named `name`, as libbpf opens an
    /// object for a gen_loader.
    pub(crate) fn open(data: &[u8], name: &[u8]) -> Result<Self, c_int> {
        let elf = Elf::parse(data).or_else(|e| fail(e, "elf: not a valid eBPF object file"))?;
        // libbpf keeps a name of BPF_OBJ_NAME_LEN bytes with its NUL.
        let (mut obj, cx) = Self::elf_collect(elf, &name[..name.len().min(15)])?;
        obj.collect_externs(&cx)?;
        obj.fixup_btf(&cx)?;
        obj.init_maps(&cx)?;
        obj.init_progs();
        obj.collect_relos(&cx)?;
        Ok(obj)
    }

    /// bpf_object__elf_collect(): the symbols, the programs, the license,
    /// the sections of maps, data and relocations, and the BTF.
    fn elf_collect<'a>(elf: Elf<'a>, obj_name: &[u8]) -> Result<(Self, ElfCtx<'a>), c_int> {
        let n = elf.sections.len();
        let symtabs: Vec<usize> = (1..n)
            .filter(|&i| elf.sections[i].ty == elf::SHT_SYMTAB)
            .collect();
        let [symbols_shndx] = symtabs[..] else {
            return fail(-EINVAL, "elf: no single symbol table");
        };
        let syms = elf.symbols(symbols_shndx).ok_or(-EINVAL)?;
        let mut cx = ElfCtx {
            strtabidx: elf.sections[symbols_shndx].link as usize,
            elf,
            syms,
            symbols_shndx,
            secs: vec![SecType::None; n],
            btf_maps_shndx: None,
        };
        let (mut btf_data, mut btf_ext_data) = (None, None);
        let (mut license, mut progs, mut text_shndx) = (Vec::new(), Vec::new(), 0);
        for idx in 1..n {
            let s = cx.elf.sections[idx];
            let name = cx.elf.section_name(idx).ok_or(-EINVAL)?;
            if ignore_section(&s, name) {
                continue;
            }
            let data = cx.elf.section_data(idx).ok_or(-EINVAL)?;
            if name == b"license" {
                let n = data.len().min(63);
                let end = data[..n].iter().position(|&c| c == 0).unwrap_or(n);
                license = data[..end].to_vec();
            } else if name == b"version" {
                if data.len() != 4 {
                    return fail(-EINVAL, "invalid kver section");
                }
            } else if name == b"maps" {
                return fail(
                    -EOPNOTSUPP,
                    "elf: legacy map definitions in 'maps' section are not supported",
                );
            } else if name == b".maps" {
                cx.btf_maps_shndx = Some(idx);
            } else if name == b".BTF" || name == b".BTF.ext" {
                if s.ty != elf::SHT_PROGBITS {
                    return Err(-EINVAL);
                }
                *(if name == b".BTF" {
                    &mut btf_data
                } else {
                    &mut btf_ext_data
                }) = Some(data);
            } else if s.ty == elf::SHT_SYMTAB {
            } else if s.ty == elf::SHT_PROGBITS && s.size > 0 {
                if s.flags & elf::SHF_EXECINSTR != 0 {
                    if name == b".text" {
                        text_shndx = idx;
                    }
                    add_programs(&mut progs, text_shndx, &cx, data, name, idx)?;
                } else if has_pfx_sec(name, b".data") {
                    cx.secs[idx] = SecType::Data;
                } else if has_pfx_sec(name, b".rodata") {
                    cx.secs[idx] = SecType::Rodata;
                } else if has_pfx_sec(name, b".data.rel.ro")
                    || has_pfx_sec(name, b".percpu")
                    || matches!(
                        name,
                        b".struct_ops"
                            | b".struct_ops.link"
                            | b"?.struct_ops"
                            | b"?.struct_ops.link"
                    )
                    || name == b".addr_space.1"
                    || name == b".jumptables"
                {
                    return fail(
                        -EOPNOTSUPP,
                        format!("elf: section '{}' is not supported", show(name)),
                    );
                }
            } else if s.ty == elf::SHT_REL {
                let targ = s.info as usize;
                if s.entsize != elf::REL_SIZE as u64 || targ >= n {
                    return Err(-EINVAL);
                }
                if cx.elf.sections[targ].flags & elf::SHF_EXECINSTR != 0 {
                    cx.secs[idx] = SecType::Relo;
                } else if name.starts_with(b".rel.rodata")
                    || name.starts_with(b".rel.data.rel.ro")
                    || name.starts_with(b".rel.struct_ops")
                    || name.starts_with(b".rel?.struct_ops")
                    || name == b".rel.maps"
                {
                    return fail(
                        -EOPNOTSUPP,
                        format!("elf: relocations '{}' are not supported", show(name)),
                    );
                }
            } else if s.ty == elf::SHT_NOBITS && has_pfx_sec(name, b".bss") {
                cx.secs[idx] = SecType::Bss;
            }
        }
        if cx.strtabidx == 0 || cx.strtabidx >= n {
            return fail(-EINVAL, "elf: symbol strings section missing or invalid");
        }
        progs.sort_by_key(|p: &Prog| (p.sec_idx, p.sec_insn_off));
        let Some(btf_data) = btf_data else {
            return fail(-ENOENT, "elf: the object has no BTF");
        };
        let btf = Btf::parse(btf_data).or_else(|e| fail(e, "Error loading ELF section .BTF"))?;
        // An exception callback is appended to its program; libbpf finds
        // it by a declaration tag this does not look for.
        if (1..btf.type_cnt()).any(|id| {
            btf.kind(id) == btf::KIND_DECL_TAG && btf.name(id).starts_with(b"exception_callback:")
        }) {
            return fail(-EOPNOTSUPP, "exception callbacks are not supported");
        }
        let (mut func_info, mut line_info, mut core_info) = (None, None, None);
        if let Some(d) = btf_ext_data {
            if btf_ext::foreign(d) {
                return fail(
                    -EOPNOTSUPP,
                    "elf: .BTF.ext of the other byte order is not supported",
                );
            }
            match BtfExt::parse(d) {
                Ok(ext) => {
                    let mk = |i: &btf_ext::Info<'_>| Some(ExtInfo::new(i, &btf, &cx.elf));
                    (func_info, line_info, core_info) =
                        (mk(&ext.func), mk(&ext.line), mk(&ext.core));
                }
                // An object with maps needs its BTF whole, as libbpf_needs_btf()
                // says; any other goes on without the section.
                Err(e) if cx.btf_maps_shndx.is_some() => {
                    return fail(
                        e,
                        "Error loading ELF section .BTF.ext: BTF is required, but is corrupted.",
                    );
                }
                Err(_) => {
                    crate::log::warn(b"Error loading ELF section .BTF.ext. Ignored and continue.")
                }
            }
        }
        let obj = Object {
            name: obj_name.to_vec(),
            license,
            btf,
            func_info,
            line_info,
            core_info,
            progs,
            maps: Vec::new(),
            externs: Vec::new(),
            text_shndx,
        };
        Ok((obj, cx))
    }

    /// bpf_object__collect_externs(): the externs of .ksyms, each turned
    /// into a 4-byte variable of that section as the kernel wants it, a
    /// kfunc into a dummy one.
    fn collect_externs(&mut self, cx: &ElfCtx<'_>) -> Result<(), c_int> {
        if cx.elf.sections[cx.symbols_shndx].entsize != elf::SYM_SIZE as u64 {
            return Err(-EINVAL);
        }
        let btf = &mut self.btf;
        let ksyms_sec = btf.find_by_name_kind(b".ksyms", btf::KIND_DATASEC);
        let int_id = (1..btf.type_cnt())
            .find(|&id| btf.kind(id) == btf::KIND_INT && btf.word(id, 0) & 0xff == 32)
            .unwrap_or(0);
        let has_func = ksyms_sec.is_some_and(|sec| {
            (0..btf.vlen(sec)).any(|i| btf.kind(btf.secinfo(sec, i).0) == btf::KIND_FUNC)
        });
        let dummy = has_func.then(|| btf.add_var(b"dummy_ksym", btf::VAR_GLOBAL_ALLOCATED, int_id));
        for (i, sym) in cx.syms.iter().enumerate() {
            if !sym_is_extern(sym) {
                continue;
            }
            let name = cx.sym_name(sym).ok_or(-EINVAL)?;
            if name.is_empty() {
                continue;
            }
            let btf_id = (1..btf.type_cnt()).find(|&id| {
                matches!(btf.kind(id), btf::KIND_VAR | btf::KIND_FUNC) && btf.name(id) == name
            });
            let Some(btf_id) = btf_id else {
                return fail(
                    -ENOENT,
                    format!("failed to find BTF for extern '{}'", show(name)),
                );
            };
            let linkage = match btf.kind(btf_id) {
                btf::KIND_VAR => btf.var_linkage(btf_id),
                _ => btf.vlen(btf_id),
            };
            if linkage != btf::VAR_GLOBAL_EXTERN {
                return fail(
                    -EINVAL,
                    format!("failed to find BTF for extern '{}'", show(name)),
                );
            }
            let sec = (1..btf.type_cnt()).find(|&s| {
                btf.kind(s) == btf::KIND_DATASEC
                    && (0..btf.vlen(s)).any(|j| btf.secinfo(s, j).0 == btf_id)
            });
            let Some(sec) = sec else {
                return fail(
                    -ENOENT,
                    format!("failed to find BTF for extern '{}' section", show(name)),
                );
            };
            if btf.name(sec) != b".ksyms" {
                return fail(
                    -EOPNOTSUPP,
                    format!(
                        "extern '{}' of section '{}' is not supported",
                        show(name),
                        show(btf.name(sec))
                    ),
                );
            }
            if btf.skip_mods_and_typedefs(btf.size_or_type(btf_id)) == 0 {
                return fail(
                    -EOPNOTSUPP,
                    format!("typeless ksym '{}' is not supported", show(name)),
                );
            }
            self.externs.push(Extern {
                name: btf.name(btf_id).to_vec(),
                btf_id,
                sym_idx: i,
                is_weak: sym.bind() == elf::STB_WEAK,
            });
        }
        self.externs.sort_by(|a, b| a.name.cmp(&b.name));
        let (Some(sec), false) = (ksyms_sec, self.externs.is_empty()) else {
            return Ok(());
        };
        let dummy_id = dummy.unwrap_or(0);
        let dummy_name = btf.name_off(dummy_id);
        let mut off = 0;
        for i in 0..btf.vlen(sec) {
            let vt = btf.secinfo(sec, i).0;
            let ext_name = btf.name(vt).to_vec();
            if !self.externs.iter().any(|e| e.name == ext_name) {
                return fail(
                    -ESRCH,
                    format!(
                        "failed to find extern definition for BTF '{}'",
                        show(&ext_name)
                    ),
                );
            }
            if btf.kind(vt) == btf::KIND_FUNC {
                let proto = btf.size_or_type(vt);
                for j in 0..btf.vlen(proto) as usize {
                    if btf.word(proto, 2 * j + 1) != 0 && btf.word(proto, 2 * j) == 0 {
                        btf.set_word(proto, 2 * j, dummy_name);
                    }
                }
                btf.set_word(sec, 3 * i as usize, dummy_id);
                btf.set_info(vt, (btf.info(vt) & !0xffff) | btf::FUNC_GLOBAL);
            } else {
                btf.set_var_linkage(vt, btf::VAR_GLOBAL_ALLOCATED);
                btf.set_size(vt, int_id);
            }
            btf.set_secinfo_offset(sec, i, off);
            btf.set_word(sec, 3 * i as usize + 2, 4);
            off += 4;
        }
        btf.set_size(sec, off);
        Ok(())
    }

    /// bpf_object_fixup_btf(): each DATASEC sized from its section, its
    /// variables placed at their symbols, the hidden ones made static,
    /// and sorted by offset.
    fn fixup_btf(&mut self, cx: &ElfCtx<'_>) -> Result<(), c_int> {
        let btf = &mut self.btf;
        for id in 1..btf.type_cnt() {
            if btf.kind(id) != btf::KIND_DATASEC {
                continue;
            }
            let sec_name = btf.name(id).to_vec();
            if sec_name != b".kconfig" && sec_name != b".ksyms" {
                let mut fixup_offsets = false;
                if btf.size_or_type(id) == 0 {
                    let size = cx
                        .elf
                        .section_by_name(&sec_name)
                        .map_or(0, |i| cx.sec_size(i));
                    if size == 0 || size > u64::from(u32::MAX) {
                        return fail(
                            -ENOENT,
                            format!(
                                "sec '{}': failed to determine size from ELF",
                                show(&sec_name)
                            ),
                        );
                    }
                    btf.set_size(id, size as u32);
                    fixup_offsets = true;
                }
                for i in 0..btf.vlen(id) {
                    let vt = btf.secinfo(id, i).0;
                    if btf.kind(vt) != btf::KIND_VAR {
                        return fail(
                            -EINVAL,
                            format!("sec '{}': unexpected non-VAR type found", show(&sec_name)),
                        );
                    }
                    if matches!(
                        btf.var_linkage(vt),
                        btf::VAR_STATIC | btf::VAR_GLOBAL_EXTERN
                    ) {
                        continue;
                    }
                    let var_name = btf.name(vt);
                    let sym = cx.syms.iter().find(|s| {
                        s.ty() == elf::STT_OBJECT
                            && matches!(s.bind(), elf::STB_GLOBAL | elf::STB_WEAK)
                            && cx.sym_name(s) == Some(var_name)
                    });
                    let Some(sym) = sym else {
                        return fail(
                            -ENOENT,
                            format!(
                                "sec '{}': failed to find ELF symbol for VAR '{}'",
                                show(&sec_name),
                                show(var_name)
                            ),
                        );
                    };
                    if fixup_offsets {
                        btf.set_secinfo_offset(id, i, sym.value as u32);
                    }
                    if matches!(sym.visibility(), elf::STV_HIDDEN | elf::STV_INTERNAL) {
                        btf.set_var_linkage(vt, btf::VAR_STATIC);
                    }
                }
            }
            btf.sort_secinfos(id);
        }
        Ok(())
    }

    /// bpf_object__init_maps(): the maps of .maps, then one per global
    /// data section.
    fn init_maps(&mut self, cx: &ElfCtx<'_>) -> Result<(), c_int> {
        if let Some(shndx) = cx.btf_maps_shndx {
            let data_sz = cx.sec_size(shndx);
            let Some(sec) = self.btf.find_by_name_kind(b".maps", btf::KIND_DATASEC) else {
                return fail(-ENOENT, "DATASEC '.maps' not found.");
            };
            for i in 0..self.btf.vlen(sec) {
                let map = self.init_user_btf_map(sec, i, shndx, data_sz)?;
                self.maps.push(map);
            }
            if self.maps.iter().filter(|m| m.map_type == MAP_ARENA).count() > 1 {
                return fail(-EINVAL, "only single ARENA map is supported");
            }
        }
        for idx in 1..cx.secs.len() {
            let size = cx.sec_size(idx);
            let kind = match cx.secs[idx] {
                SecType::Data => MapKind::Data,
                SecType::Rodata => MapKind::Rodata,
                SecType::Bss => MapKind::Bss,
                _ => continue,
            };
            if size == 0 {
                continue;
            }
            if size > u64::from(u32::MAX) {
                return fail(
                    -E2BIG,
                    format!("sec '{}': too large for a map", show(cx.sec_name(idx))),
                );
            }
            let real_name = cx.sec_name(idx);
            let initial = match kind {
                MapKind::Bss => vec![0; size as usize],
                _ => cx.elf.section_data(idx).ok_or(-EINVAL)?.to_vec(),
            };
            let btf_value_type_id = (1..self.btf.type_cnt())
                .find(|&id| self.btf.name(id) == real_name)
                .unwrap_or(0);
            let mmapable = btf_value_type_id != 0
                && self.btf.kind(btf_value_type_id) == btf::KIND_DATASEC
                && (0..self.btf.vlen(btf_value_type_id)).any(|i| {
                    let vt = self.btf.secinfo(btf_value_type_id, i).0;
                    self.btf.kind(vt) == btf::KIND_VAR
                        && self.btf.var_linkage(vt) != btf::VAR_STATIC
                });
            let mut map_flags = if kind == MapKind::Rodata {
                F_RDONLY_PROG
            } else {
                0
            };
            if mmapable {
                map_flags |= F_MMAPABLE;
            }
            self.maps.push(Map {
                name: internal_map_name(&self.name, real_name),
                kind,
                sec_idx: idx,
                sec_offset: 0,
                map_type: MAP_ARRAY,
                key_size: 4,
                value_size: size as u32,
                max_entries: 1,
                map_flags,
                numa_node: 0,
                map_extra: 0,
                btf_key_type_id: 0,
                btf_value_type_id,
                initial,
            });
        }
        Ok(())
    }

    /// get_map_field_int(): the dimension of the array a member points to.
    fn field_int(&self, map: &[u8], m: u32) -> Result<u32, c_int> {
        let btf = &self.btf;
        let t = btf.skip_mods_and_typedefs(m);
        let arr = btf.size_or_type(t);
        if btf.kind(t) != btf::KIND_PTR || btf.kind(arr) != btf::KIND_ARRAY {
            return fail(
                -EINVAL,
                format!("map '{}': attr: expected PTR to ARRAY", show(map)),
            );
        }
        Ok(btf.word(arr, 2))
    }

    /// bpf_object__init_user_btf_map() with parse_btf_map_def(): the map
    /// a variable of .maps defines.
    fn init_user_btf_map(
        &self,
        sec: u32,
        i: u32,
        shndx: usize,
        data_sz: u64,
    ) -> Result<Map, c_int> {
        let btf = &self.btf;
        let (var, voff, vsize) = btf.secinfo(sec, i);
        let name = btf.name(var).to_vec();
        if name.is_empty() {
            return fail(-EINVAL, format!("map #{i}: empty name."));
        }
        if u64::from(voff) + u64::from(vsize) > data_sz {
            return fail(
                -EINVAL,
                format!("map '{}' BTF data is corrupted.", show(&name)),
            );
        }
        if btf.kind(var) != btf::KIND_VAR {
            return fail(
                -EINVAL,
                format!("map '{}': unexpected var kind.", show(&name)),
            );
        }
        if btf.var_linkage(var) != btf::VAR_GLOBAL_ALLOCATED {
            return fail(
                -EOPNOTSUPP,
                format!("map '{}': unsupported map linkage.", show(&name)),
            );
        }
        let def = btf.skip_mods_and_typedefs(btf.size_or_type(var));
        if btf.kind(def) != btf::KIND_STRUCT {
            return fail(
                -EINVAL,
                format!("map '{}': unexpected def kind.", show(&name)),
            );
        }
        if btf.size_or_type(def) > vsize {
            return fail(-EINVAL, format!("map '{}': invalid def size.", show(&name)));
        }
        let mut map = Map {
            name: name.clone(),
            kind: MapKind::Btf,
            sec_idx: shndx,
            sec_offset: u64::from(voff),
            map_type: 0,
            key_size: 0,
            value_size: 0,
            max_entries: 0,
            map_flags: 0,
            numa_node: 0,
            map_extra: 0,
            btf_key_type_id: 0,
            btf_value_type_id: 0,
            initial: Vec::new(),
        };
        let conflict = |what: &str, old: u32, new: u32| -> Result<(), c_int> {
            if old != 0 && old != new {
                return fail(
                    -EINVAL,
                    format!(
                        "map '{}': conflicting {what} size {old} != {new}.",
                        show(&name)
                    ),
                );
            }
            Ok(())
        };
        for j in 0..btf.vlen(def) as usize {
            let (name_off, mtype) = (btf.word(def, 3 * j), btf.word(def, 3 * j + 1));
            let Some(field) = btf.str_at(name_off) else {
                return fail(
                    -EINVAL,
                    format!("map '{}': invalid field #{j}.", show(&name)),
                );
            };
            match field {
                b"type" => map.map_type = self.field_int(&name, mtype)?,
                b"max_entries" => map.max_entries = self.field_int(&name, mtype)?,
                b"map_flags" => map.map_flags = self.field_int(&name, mtype)?,
                b"numa_node" => map.numa_node = self.field_int(&name, mtype)?,
                b"key_size" | b"value_size" => {
                    let sz = self.field_int(&name, mtype)?;
                    let cur = if field == b"key_size" {
                        &mut map.key_size
                    } else {
                        &mut map.value_size
                    };
                    conflict(if field == b"key_size" { "key" } else { "value" }, *cur, sz)?;
                    *cur = sz;
                }
                b"key" | b"value" => {
                    if btf.kind(mtype) != btf::KIND_PTR {
                        return fail(
                            -EINVAL,
                            format!("map '{}': key/value spec is not PTR.", show(&name)),
                        );
                    }
                    let target = btf.size_or_type(mtype);
                    let sz = btf.resolve_size(target)?;
                    let (cur, id) = if field == b"key" {
                        (&mut map.key_size, &mut map.btf_key_type_id)
                    } else {
                        (&mut map.value_size, &mut map.btf_value_type_id)
                    };
                    conflict(if field == b"key" { "key" } else { "value" }, *cur, sz)?;
                    *cur = sz;
                    *id = target;
                }
                b"pinning" => {
                    if self.field_int(&name, mtype)? != 0 {
                        return fail(
                            -EOPNOTSUPP,
                            format!("map '{}': pinning is not supported.", show(&name)),
                        );
                    }
                }
                b"map_extra" => {
                    let t = btf.skip_mods_and_typedefs(mtype);
                    map.map_extra = match btf.kind(t) {
                        btf::KIND_PTR => u64::from(self.field_int(&name, mtype)?),
                        btf::KIND_ENUM if btf.vlen(t) == 1 => btf.word(t, 1) as i32 as i64 as u64,
                        btf::KIND_ENUM64 if btf.vlen(t) == 1 => {
                            u64::from(btf.word(t, 1)) | (u64::from(btf.word(t, 2)) << 32)
                        }
                        _ => {
                            return fail(
                                -EINVAL,
                                format!("map '{}': attr 'map_extra': invalid.", show(&name)),
                            );
                        }
                    };
                }
                _ => {
                    return fail(
                        -EOPNOTSUPP,
                        format!(
                            "map '{}': field '{}' is not supported.",
                            show(&name),
                            show(field)
                        ),
                    );
                }
            }
        }
        if map.map_type == 0 {
            return fail(
                -EINVAL,
                format!("map '{}': map type isn't specified.", show(&name)),
            );
        }
        if matches!(map.map_type, MAP_RINGBUF | MAP_USER_RINGBUF) && map.max_entries != 0 {
            let page = page_size();
            let sz = u64::from(map.max_entries);
            if sz % page != 0 || !(sz / page).is_power_of_two() {
                let mut mul = 1u64;
                while mul * page <= sz && mul <= u64::from(u32::MAX) / page {
                    mul <<= 1;
                }
                if mul * page > sz && mul * page <= u64::from(u32::MAX) {
                    map.max_entries = (mul * page) as u32;
                }
            }
        }
        if matches!(
            map.map_type,
            MAP_PERF_EVENT_ARRAY | MAP_STRUCT_OPS | MAP_ARRAY_OF_MAPS | MAP_HASH_OF_MAPS
        ) {
            return fail(
                -EOPNOTSUPP,
                format!(
                    "map '{}': map type {} is not supported.",
                    show(&name),
                    map.map_type
                ),
            );
        }
        Ok(map)
    }

    /// bpf_object_init_progs(): each program's type, attach type and
    /// flags from its section. A program of a section shirudo does not
    /// build is refused when it is loaded, as libbpf refuses one it
    /// cannot type: until then the object stays open, for its caller to
    /// say what it supports.
    fn init_progs(&mut self) {
        for p in &mut self.progs {
            p.def = find_sec_def(&p.sec_name);
            if let Some(d) = p.def {
                p.prog_type = d.prog_type;
                p.attach = d.attach;
                if d.flags & SEC_SLEEPABLE != 0 {
                    p.prog_flags |= F_SLEEPABLE;
                }
            }
        }
    }

    fn find_prog_by_sec_insn(&self, sec_idx: usize, insn_idx: usize) -> Option<usize> {
        if self.progs.is_empty() {
            return None;
        }
        let (mut l, mut r) = (0, self.progs.len() - 1);
        while l < r {
            let m = l + (r - l).div_ceil(2);
            let p = &self.progs[m];
            if p.sec_idx < sec_idx || (p.sec_idx == sec_idx && p.sec_insn_off <= insn_idx) {
                l = m;
            } else {
                r = m - 1;
            }
        }
        let p = &self.progs[l];
        (p.sec_idx == sec_idx && p.contains(insn_idx)).then_some(l)
    }

    /// bpf_object__for_each_program(): the programs, subprograms left
    /// out, in the object's order.
    pub(crate) fn programs(&self) -> impl Iterator<Item = &Prog> {
        self.progs.iter().filter(|p| !self.is_subprog(p))
    }

    /// The programs a loader loads, in the order of its program
    /// descriptors: the object's, but those it leaves out. For
    /// tools/bpf-lskel, as is extern_names().
    #[allow(dead_code)]
    pub(crate) fn loaded_programs(&self) -> impl Iterator<Item = &Prog> {
        self.programs().filter(|p| p.strategy == Strategy::Auto)
    }

    /// The names of the kernel symbols of .ksyms the object uses.
    #[allow(dead_code)]
    pub(crate) fn extern_names(&self) -> impl Iterator<Item = &[u8]> {
        self.externs.iter().map(|e| &e.name[..])
    }

    pub(crate) fn btf(&self) -> &Btf {
        &self.btf
    }

    /// bpf_object__find_map_by_name()
    pub(crate) fn map(&self, name: &[u8]) -> Option<&Map> {
        self.maps.iter().find(|m| m.name == name)
    }

    /// The map of .rodata, "<object>.rodata" as libbpf names it.
    pub(crate) fn rodata_mut(&mut self) -> Option<&mut Map> {
        self.maps.iter_mut().find(|m| m.name.ends_with(b".rodata"))
    }

    pub(crate) fn rodata(&self) -> Option<&Map> {
        self.maps.iter().find(|m| m.name.ends_with(b".rodata"))
    }

    fn is_subprog(&self, p: &Prog) -> bool {
        p.sec_idx == self.text_shndx
    }

    /// bpf_object__collect_relos(): each relocation of each program, in
    /// the program's frame, sorted.
    fn collect_relos(&mut self, cx: &ElfCtx<'_>) -> Result<(), c_int> {
        for idx in 1..cx.secs.len() {
            if cx.secs[idx] != SecType::Relo {
                continue;
            }
            let sec_idx = cx.elf.sections[idx].info as usize;
            let sec_size = cx.sec_size(sec_idx);
            let rels = cx.elf.rels(idx).ok_or(-EINVAL)?;
            for (i, rel) in rels.iter().enumerate() {
                let Some(sym) = cx.syms.get(rel.sym as usize) else {
                    return fail(
                        -EINVAL,
                        format!("symbol #{} not found for relo #{i}", rel.sym),
                    );
                };
                if usize::from(sym.shndx) >= cx.secs.len() {
                    return fail(
                        -EINVAL,
                        format!("corrupted symbol #{} for relo #{i}", rel.sym),
                    );
                }
                if rel.offset % INSN_SZ as u64 != 0 || rel.offset >= sec_size {
                    return fail(
                        -EINVAL,
                        format!("invalid offset 0x{:x} for relo #{i}", rel.offset),
                    );
                }
                let insn_idx = (rel.offset / INSN_SZ as u64) as usize;
                let Some(p) = self.find_prog_by_sec_insn(sec_idx, insn_idx) else {
                    continue;
                };
                let insn_idx = insn_idx - self.progs[p].sec_insn_off;
                let relo = self.record_reloc(cx, p, insn_idx, sym, rel.sym as usize)?;
                self.progs[p].relos.push(relo);
            }
        }
        for p in &mut self.progs {
            p.relos.sort_by_key(|r| (r.insn_idx, r.kind));
        }
        Ok(())
    }

    /// bpf_program__record_reloc()
    fn record_reloc(
        &self,
        cx: &ElfCtx<'_>,
        p: usize,
        insn_idx: usize,
        sym: &Symbol,
        sym_idx: usize,
    ) -> Result<Relo, c_int> {
        let prog = &self.progs[p];
        let insn = prog.insns[insn_idx];
        let pname = show(&prog.name);
        let shndx = usize::from(sym.shndx);
        if !insn.is_call() && !insn.is_ldimm64() {
            return fail(
                -EINVAL,
                format!(
                    "prog '{pname}': invalid relo for insns[{insn_idx}].code 0x{:x}",
                    insn.code
                ),
            );
        }
        if sym_is_extern(sym) {
            let Some(ext_idx) = self.externs.iter().position(|e| e.sym_idx == sym_idx) else {
                return fail(
                    -EINVAL,
                    format!("prog '{pname}': extern relo failed to find extern"),
                );
            };
            let kind = if insn.is_call() {
                ReloKind::ExternCall
            } else {
                ReloKind::ExternLd64
            };
            return Ok(Relo {
                ext_idx,
                ..Relo::new(kind, insn_idx)
            });
        }
        if insn.is_call() {
            if insn.src() != PSEUDO_CALL {
                return fail(
                    -EINVAL,
                    format!("prog '{pname}': incorrect bpf_call opcode"),
                );
            }
            if shndx == 0 || shndx != self.text_shndx || sym.value % INSN_SZ as u64 != 0 {
                return fail(-EINVAL, format!("prog '{pname}': bad call relo"));
            }
            return Ok(Relo {
                sym_off: sym.value as u32,
                ..Relo::new(ReloKind::Call, insn_idx)
            });
        }
        if shndx == 0 || sym.shndx >= 0xff00 {
            return fail(
                -EINVAL,
                format!("prog '{pname}': invalid relo in special section 0x{shndx:x}"),
            );
        }
        if sym_is_subprog(sym, self.text_shndx) {
            if sym.value % INSN_SZ as u64 != 0 || insn.imm % INSN_SZ as i32 != 0 {
                return fail(-EINVAL, format!("prog '{pname}': bad subprog addr relo"));
            }
            return Ok(Relo {
                sym_off: sym.value as u32,
                ..Relo::new(ReloKind::SubprogAddr, insn_idx)
            });
        }
        let kind = match cx.secs[shndx] {
            _ if shndx == cx.symbols_shndx => None,
            SecType::Data => Some(MapKind::Data),
            SecType::Rodata => Some(MapKind::Rodata),
            SecType::Bss => Some(MapKind::Bss),
            _ => Some(MapKind::Btf),
        };
        match kind {
            Some(MapKind::Btf) => {
                if Some(shndx) != cx.btf_maps_shndx {
                    return fail(
                        -EINVAL,
                        format!(
                            "prog '{pname}': bad map relo in section '{}'",
                            show(cx.sec_name(shndx))
                        ),
                    );
                }
                let map_idx = self.maps.iter().position(|m| {
                    m.kind == MapKind::Btf && m.sec_idx == shndx && m.sec_offset == sym.value
                });
                let Some(map_idx) = map_idx else {
                    return fail(
                        -EINVAL,
                        format!("prog '{pname}': map relo failed to find map"),
                    );
                };
                Ok(Relo {
                    map_idx,
                    ..Relo::new(ReloKind::Ld64, insn_idx)
                })
            }
            Some(kind) => {
                let Some(map_idx) = self
                    .maps
                    .iter()
                    .position(|m| m.kind == kind && m.sec_idx == shndx)
                else {
                    return fail(
                        -EINVAL,
                        format!("prog '{pname}': data relo failed to find map"),
                    );
                };
                Ok(Relo {
                    map_idx,
                    sym_off: sym.value as u32,
                    ..Relo::new(ReloKind::Data, insn_idx)
                })
            }
            None => fail(-EINVAL, format!("prog '{pname}': bad data relo")),
        }
    }

    /// bpf_object__relocate_core() as a gen_loader does it: each CO-RE
    /// relocation recorded for the program it is in, for the kernel.
    fn relocate_core(&mut self) -> Result<(), c_int> {
        let Some(core) = self.core_info.take() else {
            return Ok(());
        };
        for (sec_idx, recs) in &core.groups {
            for rec in core.records(recs) {
                let insn_off = le32(rec) as usize;
                if insn_off % INSN_SZ != 0 {
                    return Err(-EINVAL);
                }
                let insn_idx = insn_off / INSN_SZ;
                let Some(p) = self.find_prog_by_sec_insn(*sec_idx, insn_idx) else {
                    continue;
                };
                let prog = &mut self.progs[p];
                if prog.strategy == Strategy::Disabled {
                    continue;
                }
                let insn_idx = insn_idx - prog.sec_insn_off;
                if insn_idx >= prog.insns.len() {
                    return Err(-EINVAL);
                }
                if prog.insns[insn_idx].is_ldimm64() && insn_idx + 1 >= prog.insns.len() {
                    return fail(
                        -EINVAL,
                        format!(
                            "prog '{}': insn #{insn_idx} (LDIMM64) is truncated",
                            show(&prog.name)
                        ),
                    );
                }
                let mut r = Relo::new(ReloKind::Core, insn_idx);
                r.core.copy_from_slice(&rec[..16]);
                prog.relos.push(r);
            }
        }
        self.core_info = Some(core);
        for p in &mut self.progs {
            p.relos.sort_by_key(|r| (r.insn_idx, r.kind));
        }
        Ok(())
    }

    /// adjust_prog_btf_ext_info(): the records of `info` for program
    /// `p`, its instruction offsets in the main program's frame.
    fn adjust_ext_info(
        &self,
        info: &ExtInfo,
        p: usize,
        sub_insn_off: usize,
    ) -> Result<Vec<u8>, c_int> {
        let prog = &self.progs[p];
        let Some((_, recs)) = info.groups.iter().find(|(sec, _)| *sec == prog.sec_idx) else {
            return Err(-ENOENT);
        };
        let mut out = Vec::new();
        let (mut start, mut end) = (None, 0);
        for (i, rec) in info.records(recs).enumerate() {
            let insn_off = le32(rec) as usize / INSN_SZ;
            if insn_off < prog.sec_insn_off {
                continue;
            }
            if insn_off >= prog.sec_insn_off + prog.sec_insn_cnt {
                break;
            }
            start.get_or_insert(i);
            end = i + 1;
        }
        let Some(start) = start else {
            return Err(-ENOENT);
        };
        let adj = sub_insn_off as i64 - prog.sec_insn_off as i64;
        for rec in info.records(recs).take(end).skip(start) {
            let off = (i64::from(le32(rec) / INSN_SZ as u32) + adj) as u32;
            out.extend_from_slice(&off.to_le_bytes());
            out.extend_from_slice(&rec[4..]);
        }
        Ok(out)
    }

    /// reloc_prog_func_and_line_info()
    fn reloc_func_and_line_info(
        &self,
        l: &mut Linked,
        main: usize,
        p: usize,
        sub_insn_off: usize,
    ) -> Result<(), c_int> {
        let name = show(&self.progs[p].name);
        for (info, line) in [(&self.func_info, false), (&self.line_info, true)] {
            let Some(info) = info else {
                return Ok(());
            };
            let (dst, rec) = if line {
                (&mut l.line_info, &mut l.line_rec)
            } else {
                (&mut l.func_info, &mut l.func_rec)
            };
            if main != p && dst.is_none() {
                continue;
            }
            match self.adjust_ext_info(info, p, sub_insn_off) {
                Ok(recs) => {
                    dst.get_or_insert_with(Vec::new).extend_from_slice(&recs);
                    *rec = info.rec_size;
                }
                Err(e) if e != -ENOENT || dst.is_some() => {
                    return fail(e, format!("prog '{name}': missing .BTF.ext info."));
                }
                Err(_) => crate::log::warn(
                    format!("prog '{name}': missing .BTF.ext info for the main program, skipping all of it.")
                        .as_bytes(),
                ),
            }
        }
        Ok(())
    }

    /// bpf_object__reloc_code(): the calls and subprogram addresses of
    /// program `p` within main program `main`, each subprogram appended
    /// the first time it is called.
    fn reloc_code(
        &self,
        l: &mut Linked,
        sub_off: &mut [usize],
        main: usize,
        p: usize,
    ) -> Result<(), c_int> {
        let p_off = if p == main { 0 } else { sub_off[p] };
        self.reloc_func_and_line_info(l, main, p, p_off)?;
        let prog = &self.progs[p];
        for insn_idx in 0..prog.sec_insn_cnt {
            let insn = l.insns[p_off + insn_idx];
            if !insn.is_subprog_call() && !insn.is_pseudo_func() {
                continue;
            }
            let relos = if p == main {
                &l.relos[..]
            } else {
                &prog.relos[..]
            };
            let relo = find_insn_relo(relos, insn_idx).map(|r| (r.kind, r.sym_off));
            let sub_insn_idx = match relo {
                Some((ReloKind::ExternCall, _)) => continue,
                Some((ReloKind::Call, sym_off)) => i64::from(sym_off / 8) + i64::from(insn.imm) + 1,
                Some((ReloKind::SubprogAddr, sym_off)) => {
                    (i64::from(sym_off) + i64::from(insn.imm)) / 8
                }
                Some((kind, _)) => {
                    return fail(
                        -EINVAL,
                        format!(
                            "prog '{}': unexpected relo for insn #{insn_idx}, type {kind:?}",
                            show(&prog.name)
                        ),
                    );
                }
                None if insn.is_pseudo_func() => {
                    return fail(
                        -EINVAL,
                        format!(
                            "prog '{}': missing subprog addr relo for insn #{insn_idx}",
                            show(&prog.name)
                        ),
                    );
                }
                None => (prog.sec_insn_off + insn_idx) as i64 + i64::from(insn.imm) + 1,
            };
            let sub = usize::try_from(sub_insn_idx)
                .ok()
                .and_then(|i| self.find_prog_by_sec_insn(self.text_shndx, i));
            let Some(sub) = sub else {
                return fail(
                    -EINVAL,
                    format!(
                        "prog '{}': no .text section found yet sub-program call exists",
                        show(&prog.name)
                    ),
                );
            };
            if sub_off[sub] == 0 {
                sub_off[sub] = l.insns.len();
                l.insns.extend_from_slice(&self.progs[sub].insns);
                if sub != main {
                    l.relos.extend(self.progs[sub].relos.iter().map(|r| Relo {
                        insn_idx: r.insn_idx + sub_off[sub],
                        ..r.clone()
                    }));
                }
                self.reloc_code(l, sub_off, main, sub)?;
            }
            l.insns[p_off + insn_idx].imm =
                (sub_off[sub] as i64 - (p_off + insn_idx) as i64 - 1) as i32;
        }
        Ok(())
    }

    /// bpf_object__relocate_data() as a gen_loader does it: maps and
    /// global data by their index, externs left for the loader.
    fn relocate_data(&self, l: &mut Linked) -> Result<(), c_int> {
        for r in &l.relos {
            let i = r.insn_idx;
            let needs_next = matches!(r.kind, ReloKind::Data | ReloKind::ExternLd64);
            if i >= l.insns.len() || (needs_next && i + 1 >= l.insns.len()) {
                return Err(-EINVAL);
            }
            match r.kind {
                ReloKind::Ld64 => {
                    l.insns[i].set_src(PSEUDO_MAP_IDX);
                    l.insns[i].imm = r.map_idx as i32;
                }
                ReloKind::Data => {
                    l.insns[i + 1].imm = l.insns[i].imm.wrapping_add(r.sym_off as i32);
                    l.insns[i].set_src(PSEUDO_MAP_IDX_VALUE);
                    l.insns[i].imm = r.map_idx as i32;
                }
                ReloKind::ExternLd64 => {
                    l.insns[i].set_src(PSEUDO_BTF_ID);
                    l.insns[i].imm = 0;
                    l.insns[i + 1].imm = 0;
                }
                ReloKind::ExternCall => {
                    l.insns[i].set_src(PSEUDO_KFUNC_CALL);
                    l.insns[i].imm = 0;
                    l.insns[i].off = 0;
                }
                ReloKind::SubprogAddr if l.insns[i].src() != PSEUDO_FUNC => return Err(-EINVAL),
                _ => {}
            }
        }
        Ok(())
    }

    /// bpf_object__gen_loader() and bpf_object__load(): the loader's
    /// instructions and blob.
    pub(crate) fn gen_loader(&mut self, opts: &GenOpts) -> Result<(Vec<u8>, Vec<u8>), c_int> {
        if let Some(p) = self.progs.iter().find(|p| p.strategy == Strategy::Manual) {
            return fail(
                -EOPNOTSUPP,
                format!(
                    "prog '{}': gen_loader does not support manually-loaded programs",
                    show(&p.name)
                ),
            );
        }
        let mut ldr = Gen::new(
            opts.gen_hash,
            opts.reuse_map_mask,
            self.progs.len() as u32,
            self.maps.len() as u32,
        )?;
        // bpf_object__relocate()
        self.relocate_core()?;
        for p in &mut self.progs {
            for r in &p.relos {
                if r.kind == ReloKind::SubprogAddr {
                    p.insns[r.insn_idx].set_src(PSEUDO_FUNC);
                }
            }
        }
        let mut linked: Vec<(usize, Linked)> = Vec::new();
        for p in 0..self.progs.len() {
            if self.is_subprog(&self.progs[p]) || self.progs[p].strategy == Strategy::Disabled {
                continue;
            }
            let mut l = Linked {
                insns: self.progs[p].insns.clone(),
                relos: self.progs[p].relos.clone(),
                func_info: None,
                func_rec: 0,
                line_info: None,
                line_rec: 0,
            };
            let mut sub_off = vec![0; self.progs.len()];
            self.reloc_code(&mut l, &mut sub_off, p, p)?;
            linked.push((p, l));
        }
        for (_, l) in &mut linked {
            self.relocate_data(l)?;
        }
        // bpf_object__sanitize_and_load_btf()
        let text = self.text_shndx;
        for p in self
            .progs
            .iter()
            .filter(|p| p.mark_btf_static && p.sec_idx == text)
        {
            let btf = &mut self.btf;
            let f = (1..btf.type_cnt()).find(|&id| {
                btf.kind(id) == btf::KIND_FUNC
                    && btf.vlen(id) == btf::FUNC_GLOBAL
                    && btf.name(id) == p.name
            });
            if let Some(f) = f {
                btf.set_info(f, btf::KIND_FUNC << 24 | btf::FUNC_STATIC);
            }
        }
        ldr.load_btf(&self.btf.raw())?;
        // bpf_object__create_maps()
        for (i, m) in self.maps.iter().enumerate() {
            let no_btf = matches!(
                m.map_type,
                MAP_PERF_EVENT_ARRAY
                    | MAP_CGROUP_ARRAY
                    | MAP_STACK_TRACE
                    | MAP_ARRAY_OF_MAPS
                    | MAP_HASH_OF_MAPS
                    | MAP_DEVMAP
                    | MAP_DEVMAP_HASH
                    | MAP_CPUMAP
                    | MAP_XSKMAP
                    | MAP_SOCKMAP
                    | MAP_SOCKHASH
                    | MAP_QUEUE
                    | MAP_STACK
                    | MAP_ARENA
            );
            let create = MapCreate {
                map_type: m.map_type,
                name: &m.name,
                key_size: m.key_size,
                value_size: m.value_size,
                max_entries: m.max_entries,
                map_flags: m.map_flags,
                numa_node: m.numa_node,
                map_extra: m.map_extra,
                btf_key_type_id: if no_btf { 0 } else { m.btf_key_type_id },
                btf_value_type_id: if no_btf { 0 } else { m.btf_value_type_id },
            };
            ldr.map_create(&create, i as u32)?;
            if m.is_internal() {
                ldr.map_update_elem(i as u32, &m.initial, 0)?;
                if m.kind == MapKind::Rodata {
                    ldr.map_freeze(i as u32)?;
                }
            }
        }
        // bpf_object__load_progs()
        for (p, l) in &linked {
            let prog = &self.progs[*p];
            for r in &l.relos {
                match r.kind {
                    ReloKind::ExternLd64 | ReloKind::ExternCall => {
                        let ext = &self.externs[r.ext_idx];
                        let is_ld64 = r.kind == ReloKind::ExternLd64;
                        let kind = if is_ld64 && self.btf.kind(ext.btf_id) == btf::KIND_VAR {
                            btf::KIND_VAR
                        } else {
                            btf::KIND_FUNC
                        };
                        ldr.record_extern(ExternRelo {
                            name: ext.name.clone(),
                            is_weak: ext.is_weak,
                            is_ld64,
                            kind: kind as i32,
                            insn_idx: r.insn_idx as u32,
                        });
                    }
                    ReloKind::Core => ldr.record_relo_core((r.insn_idx * INSN_SZ) as u32, &r.core),
                    _ => {}
                }
            }
            if prog.def.is_none() {
                return fail(
                    -EOPNOTSUPP,
                    format!(
                        "prog '{}': section '{}' is not supported",
                        show(&prog.name),
                        show(&prog.sec_name)
                    ),
                );
            }
            let mut attach_btf_id = 0;
            if prog.def.is_some_and(|d| d.flags & SEC_ATTACH_BTF != 0) {
                let Some(slash) = prog.sec_name.iter().position(|&c| c == b'/') else {
                    return fail(
                        -EINVAL,
                        format!(
                            "prog '{}': no BTF-based attach target is specified",
                            show(&prog.name)
                        ),
                    );
                };
                ldr.record_attach_target(&prog.sec_name[slash + 1..], prog.attach)?;
                attach_btf_id = 1;
            }
            let insns: Vec<u8> = l.insns.iter().flat_map(|i| i.bytes()).collect();
            ldr.prog_load(&ProgLoad {
                prog_type: prog.prog_type,
                name: &prog.name,
                license: &self.license,
                insns: &insns,
                expected_attach_type: prog.attach,
                attach_btf_id,
                prog_flags: prog.prog_flags,
                func_info: l.func_info.as_deref().unwrap_or_default(),
                func_info_rec_size: l.func_rec as u32,
                line_info: l.line_info.as_deref().unwrap_or_default(),
                line_info_rec_size: l.line_rec as u32,
            })?;
        }
        ldr.finish(self.progs.len() as u32, self.maps.len() as u32)
    }
}
