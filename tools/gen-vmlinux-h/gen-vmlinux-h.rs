// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2019 Facebook
// Copyright (c) 2026 Authors of shirudo

//! Dumps a BTF blob as the C of vmlinux.h, as bpftool's `btf dump file
//! ... format c` does with libbpf's btf_dump (both dual-licensed; this
//! follows their BSD-2-Clause branch): every type, sorted so that BTF
//! which only reorders types dumps the same, then the kfunc prototypes.
//! Build-time tool only; never shipped.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::{OsString, c_char};
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::{env, fmt};

/// The errno values of the crate's BTF reader and of a missing .BTF.
mod errno {
    use core::ffi::c_int;

    pub(crate) const E2BIG: c_int = 7;
    pub(crate) const EINVAL: c_int = 22;
    pub(crate) const ENODATA: c_int = 61;
}

// The tool only reads BTF, so the module's writers go unused here.
#[allow(dead_code)]
#[path = "../../rust/src/bpf/btf.rs"]
mod btf;

use btf::{Btf, Member};

const DEFAULT_PATH: &str = "/sys/kernel/btf/vmlinux";

const HEADER: &str = "\
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

#ifndef __ksym
#define __ksym __attribute__((section(\".ksyms\")))
#endif

#ifndef __weak
#define __weak __attribute__((weak))
#endif

#ifndef __bpf_fastcall
#if __has_attribute(bpf_fastcall)
#define __bpf_fastcall __attribute__((bpf_fastcall))
#else
#define __bpf_fastcall
#endif
#endif

";

const FOOTER: &str = "\
#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
";

/// A type's BTF_KIND_*, void being type 0's.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Void,
    Int,
    Ptr,
    Array,
    Struct,
    Union,
    Enum,
    Fwd,
    Typedef,
    Volatile,
    Const,
    Restrict,
    Func,
    FuncProto,
    Var,
    Datasec,
    Float,
    DeclTag,
    TypeTag,
    Enum64,
    LocParam,
    LocProto,
    Locsec,
}

impl Kind {
    fn of(raw: u32) -> Option<Self> {
        Some(match raw {
            btf::KIND_INT => Self::Int,
            btf::KIND_PTR => Self::Ptr,
            btf::KIND_ARRAY => Self::Array,
            btf::KIND_STRUCT => Self::Struct,
            btf::KIND_UNION => Self::Union,
            btf::KIND_ENUM => Self::Enum,
            btf::KIND_FWD => Self::Fwd,
            btf::KIND_TYPEDEF => Self::Typedef,
            btf::KIND_VOLATILE => Self::Volatile,
            btf::KIND_CONST => Self::Const,
            btf::KIND_RESTRICT => Self::Restrict,
            btf::KIND_FUNC => Self::Func,
            btf::KIND_FUNC_PROTO => Self::FuncProto,
            btf::KIND_VAR => Self::Var,
            btf::KIND_DATASEC => Self::Datasec,
            btf::KIND_FLOAT => Self::Float,
            btf::KIND_DECL_TAG => Self::DeclTag,
            btf::KIND_TYPE_TAG => Self::TypeTag,
            btf::KIND_ENUM64 => Self::Enum64,
            btf::KIND_LOC_PARAM => Self::LocParam,
            btf::KIND_LOC_PROTO => Self::LocProto,
            btf::KIND_LOCSEC => Self::Locsec,
            _ => return None,
        })
    }

    /// The kinds that refer on to one other type and add nothing to its
    /// name but a qualifier, a pointer or a tag.
    fn is_ref(self) -> bool {
        matches!(
            self,
            Self::TypeTag
                | Self::Const
                | Self::Ptr
                | Self::Volatile
                | Self::Restrict
                | Self::Typedef
                | Self::DeclTag
        )
    }

    /// btf_is_mod()
    fn is_mod(self) -> bool {
        matches!(
            self,
            Self::Volatile | Self::Const | Self::Restrict | Self::TypeTag
        )
    }
}

/// A FUNC_PROTO's parameter.
struct Param {
    name_off: u32,
    ty: u32,
}

/// The BTF being dumped, its kinds decoded once.
struct Types {
    btf: Btf,
    kinds: Vec<Kind>,
}

impl Types {
    fn new(btf: Btf) -> io::Result<Self> {
        let kinds = (0..btf.type_cnt())
            .map(|id| match id {
                0 => Some(Kind::Void),
                _ => Kind::of(btf.kind(id)),
            })
            .collect::<Option<_>>()
            .ok_or_else(|| invalid_data("BTF type of an unknown kind"))?;
        Ok(Self { btf, kinds })
    }

    fn count(&self) -> u32 {
        self.btf.type_cnt()
    }

    fn kind(&self, id: u32) -> Kind {
        self.kinds[id as usize]
    }

    fn named(&self, id: u32) -> bool {
        self.btf.name_off(id) != 0
    }

    fn name(&self, id: u32) -> &[u8] {
        self.btf.name(id)
    }

    fn str(&self, off: u32) -> &[u8] {
        self.btf.str_at(off).unwrap_or_default()
    }

    /// The type a modifier, pointer, typedef, tag, FUNC or VAR refers to,
    /// or a FUNC_PROTO's return type.
    fn target(&self, id: u32) -> u32 {
        self.btf.size_or_type(id)
    }

    fn size(&self, id: u32) -> u32 {
        self.btf.size_or_type(id)
    }

    fn vlen(&self, id: u32) -> u32 {
        self.btf.vlen(id)
    }

    fn kflag(&self, id: u32) -> bool {
        self.btf.kflag(id)
    }

    fn ptr_size(&self) -> u32 {
        self.btf.ptr_size()
    }

    fn members(&self, id: u32) -> impl Iterator<Item = Member> + '_ {
        self.btf.members(id)
    }

    fn params(&self, id: u32) -> impl Iterator<Item = Param> + '_ {
        (0..self.vlen(id) as usize).map(move |i| Param {
            name_off: self.btf.word(id, 2 * i),
            ty: self.btf.word(id, 2 * i + 1),
        })
    }

    fn elem_type(&self, id: u32) -> u32 {
        self.btf.array(id).ty
    }

    fn index_type(&self, id: u32) -> u32 {
        self.btf.word(id, 1)
    }

    fn nelems(&self, id: u32) -> u32 {
        self.btf.array(id).nelems
    }

    /// An ENUM's or ENUM64's `i`th value: its name and value.
    fn enumerator(&self, id: u32, i: u32) -> (u32, u64) {
        self.btf.enum_value(id, i)
    }

    /// A DECL_TAG's member or parameter index, -1 for the type itself.
    fn component_idx(&self, id: u32) -> i32 {
        self.btf.word(id, 0) as i32
    }

    /// btf__resolve_size(), 0 where it fails, as btf_dump takes it.
    fn size_of(&self, id: u32) -> i64 {
        self.btf.resolve_size(id).map_or(0, i64::from)
    }

    /// btf__align_of() of the vendored libbpf, 0 where it fails. Not the
    /// crate reader's align_of(): that one gives up 32 types deep and
    /// counts members in 16 bits, as this libbpf no longer does.
    fn align_of(&self, id: u32) -> u32 {
        match self.kind(id) {
            Kind::Int | Kind::Enum | Kind::Enum64 | Kind::Float => {
                self.size(id).min(self.ptr_size())
            }
            Kind::Ptr => self.ptr_size(),
            Kind::Typedef | Kind::Volatile | Kind::Const | Kind::Restrict | Kind::TypeTag => {
                self.align_of(self.target(id))
            }
            Kind::Array => self.align_of(self.elem_type(id)),
            Kind::Struct | Kind::Union => {
                let mut max_align = 1;
                for m in self.members(id) {
                    let align = self.align_of(m.ty);
                    if align == 0 {
                        return 0;
                    }
                    max_align = max_align.max(align);
                    // A member off its natural alignment means packed.
                    if m.bitfield_size() == 0 && !m.offset.is_multiple_of(8 * align) {
                        return 1;
                    }
                }
                if self.size(id).is_multiple_of(max_align) {
                    max_align
                } else {
                    1
                }
            }
            _ => 0,
        }
    }

    /// Whether a struct needs __attribute__((packed)) to keep its layout:
    /// a member off its alignment, or a size no multiple of it.
    fn is_packed(&self, id: u32) -> bool {
        let mut max_align = 1;
        for m in self.members(id) {
            let align = self.align_of(m.ty);
            if align != 0 && m.bitfield_size() == 0 && !m.offset.is_multiple_of(8 * align) {
                return true;
            }
            max_align = max_align.max(align);
        }
        !self.size(id).is_multiple_of(max_align)
    }

    fn is_builtin_va_list(&self, id: u32) -> bool {
        self.named(id) && self.name(id) == b"__builtin_va_list"
    }

    /// bpftool's kind rank: named enums and constants first, then base
    /// types, structs and unions, function prototypes, and what has no
    /// name of its own to sort by last.
    fn rank(&self, id: u32, has_name: bool) -> u32 {
        const UNNAMED: u32 = 10;
        let has_name = has_name || self.named(id);
        match self.kind(id) {
            Kind::Enum | Kind::Enum64 => u32::from(has_name),
            Kind::Int | Kind::Float => 2,
            Kind::Struct | Kind::Union if has_name => 3,
            Kind::FuncProto if has_name => 4,
            Kind::Array if has_name => self.rank(self.elem_type(id), true),
            k if k.is_ref() && has_name => self.rank(self.target(id), true),
            _ => UNNAMED,
        }
    }

    /// The name a type sorts by: a reference's target's, and an anonymous
    /// enum's first value's.
    fn sort_name(&self, id: u32, from_ref: bool) -> &[u8] {
        match self.kind(id) {
            Kind::Enum | Kind::Enum64 if !from_ref && !self.named(id) && self.vlen(id) > 0 => {
                self.str(self.enumerator(id, 0).0)
            }
            Kind::Array => self.sort_name(self.elem_type(id), true),
            k if k.is_ref() => self.sort_name(self.target(id), true),
            _ => self.name(id),
        }
    }

    /// bpftool's tie-break between types of the same rank and names: a
    /// hash of their member and value names, members' types one level deep.
    fn disambig_hash(&self, id: u32, include_members: bool) -> u64 {
        let mut hash = self.name_hash(0, self.btf.name_off(id));
        match self.kind(id) {
            Kind::Enum | Kind::Enum64 => {
                for i in 0..self.vlen(id) {
                    hash = self.name_hash(hash, self.enumerator(id, i).0);
                }
            }
            Kind::Struct | Kind::Union if include_members => {
                for m in self.members(id) {
                    hash = self.name_hash(hash, m.name_off);
                    hash = mix(hash, self.disambig_hash(m.ty, false));
                }
            }
            Kind::Array => {
                hash = mix(hash, u64::from(self.nelems(id)));
                hash = mix(
                    hash,
                    self.disambig_hash(self.elem_type(id), include_members),
                );
            }
            k if k.is_ref() => {
                hash = mix(hash, self.disambig_hash(self.target(id), include_members));
            }
            _ => {}
        }
        hash
    }

    fn name_hash(&self, hash: u64, name_off: u32) -> u64 {
        if name_off == 0 {
            return hash;
        }
        mix(hash, str_hash(self.str(name_off)))
    }

    /// Every type id in the order the dump takes them.
    fn sorted_ids(&self) -> Vec<u32> {
        let mut keys: Vec<_> = (0..self.count())
            .map(|id| {
                (
                    self.rank(id, false),
                    self.sort_name(id, false),
                    self.name(id),
                    self.disambig_hash(id, true),
                    id,
                )
            })
            .collect();
        keys.sort_unstable();
        keys.into_iter().map(|k| k.4).collect()
    }
}

fn mix(hash: u64, val: u64) -> u64 {
    hash.wrapping_mul(31).wrapping_add(val)
}

/// libbpf's str_hash(), which adds each byte as a C char: signed on x86.
fn str_hash(s: &[u8]) -> u64 {
    s.iter()
        .fold(0, |h: u64, &c| mix(h, c as c_char as i64 as u64))
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Order {
    #[default]
    NotOrdered,
    Ordering,
    Ordered,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Emit {
    #[default]
    NotEmitted,
    Emitting,
    Emitted,
}

/// What the dump has done with one type.
#[derive(Clone, Copy, Default)]
struct State {
    order: Order,
    emit: Emit,
    /// Its forward declaration is out; for a typedef, its definition.
    fwd_emitted: bool,
    name_resolved: bool,
    /// Some type refers to it. An anonymous enum nothing refers to is a
    /// set of constants of its own; one that is referred to is inlined.
    referenced: bool,
}

/// C's two namespaces: struct, union and enum tags, and ordinary
/// identifiers, which typedefs and enumerators share.
#[derive(Clone, Copy)]
enum Space {
    Tag,
    Ident,
}

#[derive(Debug)]
enum DumpError {
    Io(io::Error),
    /// Types that embed each other, which no forward declaration breaks.
    Cycle(u32),
    /// Padding before a member of no alignment, where libbpf divides by 0.
    ZeroAlign,
}

impl From<io::Error> for DumpError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl fmt::Display for DumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Cycle(id) => write!(f, "unsatisfiable type cycle, id:[{id}]"),
            Self::ZeroAlign => f.write_str("padding before a member of unknown alignment"),
        }
    }
}

type Result<T = ()> = std::result::Result<T, DumpError>;

/// Tabs for an indent level; libbpf stops at 13.
fn pfx(lvl: usize) -> &'static [u8] {
    const TABS: &[u8] = b"\t\t\t\t\t\t\t\t\t\t\t\t\t";
    &TABS[..lvl.min(TABS.len())]
}

/// libbpf's btf_dump: emits types and what they need first in C, each
/// one once.
struct Dumper<'a, W> {
    btf: &'a Types,
    out: W,
    states: Vec<State>,
    /// A name with the ___N suffix that sets it apart from an earlier one.
    renamed: Vec<Option<Vec<u8>>>,
    /// Each DECL_TAG as (target, tag), sorted, so that a type's tags are
    /// one run in id order.
    decl_tags: Vec<(u32, u32)>,
    queue: Vec<u32>,
    /// How often each name was seen in each namespace.
    tag_names: HashMap<&'a [u8], usize>,
    ident_names: HashMap<&'a [u8], usize>,
}

impl<'a, W: Write> Dumper<'a, W> {
    fn new(btf: &'a Types, out: W) -> Self {
        let n = btf.count() as usize;
        let mut states = vec![State::default(); n];
        let mut decl_tags = Vec::new();
        // Void is always defined.
        states[0].order = Order::Ordered;
        states[0].emit = Emit::Emitted;
        for id in 1..btf.count() {
            let mut mark = |t: u32| states[t as usize].referenced = true;
            match btf.kind(id) {
                Kind::Volatile
                | Kind::Const
                | Kind::Restrict
                | Kind::Ptr
                | Kind::Typedef
                | Kind::Func
                | Kind::Var
                | Kind::DeclTag
                | Kind::TypeTag => mark(btf.target(id)),
                Kind::Array => {
                    mark(btf.index_type(id));
                    mark(btf.elem_type(id));
                }
                Kind::Struct | Kind::Union => btf.members(id).for_each(|m| mark(m.ty)),
                // Not the return type: an anonymous enum only returned is
                // still dumped as constants of its own.
                Kind::FuncProto => btf.params(id).for_each(|p| mark(p.ty)),
                Kind::Datasec => {
                    (0..btf.vlen(id)).for_each(|i| mark(btf.btf.secinfo(id, i).0));
                }
                _ => {}
            }
            if btf.kind(id) == Kind::DeclTag {
                decl_tags.push((btf.target(id), id));
            }
        }
        decl_tags.sort_unstable();
        Self {
            btf,
            out,
            states,
            renamed: vec![None; n],
            decl_tags,
            queue: Vec::new(),
            tag_names: HashMap::new(),
            ident_names: HashMap::new(),
        }
    }

    fn put(&mut self, s: &[u8]) -> io::Result<()> {
        self.out.write_all(s)
    }

    /// btf_dump__dump_type(): `id` and every type it needs that is not out
    /// yet, in an order C compiles.
    fn dump_type(&mut self, id: u32) -> Result {
        self.queue.clear();
        self.order_type(id, false)?;
        let queue = std::mem::take(&mut self.queue);
        for &id in &queue {
            self.emit_type(id, 0)?;
        }
        self.queue = queue;
        Ok(())
    }

    /// Queues the definitions `id` needs, those first, and tells whether
    /// what refers to `id` needs its full definition (a strong link) or
    /// does with a forward declaration, which only a pointer to a named
    /// type allows.
    fn order_type(&mut self, id: u32, through_ptr: bool) -> Result<bool> {
        let btf = self.btf;
        let i = id as usize;
        let named = btf.named(id);
        match self.states[i].order {
            Order::Ordered => return Ok(true),
            Order::Ordering => {
                let composite = matches!(btf.kind(id), Kind::Struct | Kind::Union);
                if composite && through_ptr && named {
                    return Ok(false);
                }
                return Err(DumpError::Cycle(id));
            }
            Order::NotOrdered => {}
        }
        match btf.kind(id) {
            Kind::Int | Kind::Float => {
                self.states[i].order = Order::Ordered;
                Ok(false)
            }
            Kind::Ptr => {
                let strong = self.order_type(btf.target(id), true);
                self.states[i].order = Order::Ordered;
                strong
            }
            Kind::Array => self.order_type(btf.elem_type(id), false),
            Kind::Struct | Kind::Union => {
                // Named and behind a pointer, a declaration will do.
                if through_ptr && named {
                    return Ok(false);
                }
                self.states[i].order = Order::Ordering;
                for m in btf.members(id) {
                    self.order_type(m.ty, false)?;
                }
                if named {
                    self.queue.push(id);
                }
                self.states[i].order = Order::Ordered;
                Ok(true)
            }
            Kind::Enum | Kind::Enum64 | Kind::Fwd => {
                if named || !self.states[i].referenced {
                    self.queue.push(id);
                }
                self.states[i].order = Order::Ordered;
                Ok(true)
            }
            Kind::Typedef => {
                let strong = self.order_type(btf.target(id), through_ptr)?;
                if through_ptr && !strong {
                    return Ok(false);
                }
                self.queue.push(id);
                self.states[i].order = Order::Ordered;
                Ok(true)
            }
            Kind::Volatile | Kind::Const | Kind::Restrict | Kind::TypeTag => {
                self.order_type(btf.target(id), through_ptr)
            }
            Kind::FuncProto => {
                let mut strong = self.order_type(btf.target(id), through_ptr)?;
                for p in btf.params(id) {
                    strong |= self.order_type(p.ty, through_ptr)?;
                }
                Ok(strong)
            }
            Kind::Func
            | Kind::Var
            | Kind::Datasec
            | Kind::DeclTag
            | Kind::LocParam
            | Kind::LocProto
            | Kind::Locsec
            | Kind::Void => {
                self.states[i].order = Order::Ordered;
                Ok(false)
            }
        }
    }

    /// Emits `id`, or for a reference what it refers to, with forward
    /// declarations for what it reaches but need not define yet.
    /// `cont_id` is the named struct or union being defined, 0 at the top.
    fn emit_type(&mut self, id: u32, cont_id: u32) -> Result {
        let btf = self.btf;
        let i = id as usize;
        match self.states[i].emit {
            Emit::Emitted => return Ok(()),
            Emit::Emitting => return self.emit_while_emitting(id, cont_id),
            Emit::NotEmitted => {}
        }
        let top_level = cont_id == 0;
        match btf.kind(id) {
            Kind::Int => {
                self.emit_missing_aliases(id)?;
                self.states[i].emit = Emit::Emitted;
            }
            Kind::Enum | Kind::Enum64 => {
                if top_level {
                    self.emit_enum_def(id, 0)?;
                    self.put(b";\n\n")?;
                }
                self.states[i].emit = Emit::Emitted;
            }
            Kind::Ptr | Kind::Volatile | Kind::Const | Kind::Restrict | Kind::TypeTag => {
                self.emit_type(btf.target(id), cont_id)?;
            }
            Kind::Array => self.emit_type(btf.elem_type(id), cont_id)?,
            Kind::Fwd => {
                self.emit_fwd_def(id)?;
                self.put(b";\n\n")?;
                self.states[i].emit = Emit::Emitted;
            }
            Kind::Typedef => {
                self.states[i].emit = Emit::Emitting;
                self.emit_type(btf.target(id), id)?;
                // Unless a pointer to it already made the typedef come first.
                if !self.states[i].fwd_emitted && !btf.is_builtin_va_list(id) {
                    self.emit_typedef_def(id, 0)?;
                    self.put(b";\n\n")?;
                }
                self.states[i].emit = Emit::Emitted;
            }
            Kind::Struct | Kind::Union => {
                self.states[i].emit = Emit::Emitting;
                let named = btf.named(id);
                // A definition spells out its members, an anonymous type
                // inline too, so what they need goes first.
                if top_level || !named {
                    let cont = if named { id } else { cont_id };
                    for m in btf.members(id) {
                        self.emit_type(m.ty, cont)?;
                    }
                } else if !self.states[i].fwd_emitted && id != cont_id {
                    self.emit_struct_fwd(id)?;
                    self.put(b";\n\n")?;
                    self.states[i].fwd_emitted = true;
                }
                if top_level {
                    self.emit_struct_def(id, 0)?;
                    self.put(b";\n\n")?;
                    self.states[i].emit = Emit::Emitted;
                } else {
                    self.states[i].emit = Emit::NotEmitted;
                }
            }
            Kind::FuncProto => {
                self.emit_type(btf.target(id), cont_id)?;
                for p in btf.params(id) {
                    self.emit_type(p.ty, cont_id)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// `id` is reached again while it is being emitted: through a pointer,
    /// so a forward declaration does, which for a typedef is its definition.
    fn emit_while_emitting(&mut self, id: u32, cont_id: u32) -> Result {
        let btf = self.btf;
        let i = id as usize;
        if self.states[i].fwd_emitted {
            return Ok(());
        }
        match btf.kind(id) {
            Kind::Struct | Kind::Union => {
                // Inside its own definition it needs no declaration.
                if id == cont_id {
                    return Ok(());
                }
                if !btf.named(id) {
                    eprintln!("anonymous struct/union loop, id:[{id}]");
                    return Ok(());
                }
                self.emit_struct_fwd(id)?;
                self.put(b";\n\n")?;
                self.states[i].fwd_emitted = true;
            }
            Kind::Typedef => {
                if !btf.is_builtin_va_list(id) {
                    self.emit_typedef_def(id, 0)?;
                    self.put(b";\n\n")?;
                }
                self.states[i].fwd_emitted = true;
            }
            _ => {}
        }
        Ok(())
    }

    /// The name C knows `id` by: its own, or with a ___N suffix if an
    /// earlier type of the namespace took it. Settled the first time asked.
    fn resolve_name(&mut self, id: u32, space: Space) -> Cow<'a, [u8]> {
        let btf = self.btf;
        if !btf.named(id) {
            return Cow::Borrowed(b"");
        }
        let i = id as usize;
        let orig = btf.name(id);
        if !self.states[i].name_resolved {
            self.states[i].name_resolved = true;
            // Declarations only: they may repeat the name they declare.
            let decl = btf.kind(id) == Kind::Fwd || btf.kind(id) == Kind::Enum && btf.vlen(id) == 0;
            if !decl {
                let seen = self.count_name(space, orig);
                if seen > 1 {
                    self.renamed[i] = Some(suffixed(orig, seen));
                }
            }
        }
        match &self.renamed[i] {
            Some(name) => Cow::Owned(name.clone()),
            None => Cow::Borrowed(orig),
        }
    }

    /// Counts one more use of `name` in `space`, the count after it.
    fn count_name(&mut self, space: Space, name: &'a [u8]) -> usize {
        let names = match space {
            Space::Tag => &mut self.tag_names,
            Space::Ident => &mut self.ident_names,
        };
        let seen = names.entry(name).or_default();
        *seen += 1;
        *seen
    }

    fn type_name(&mut self, id: u32) -> Cow<'a, [u8]> {
        self.resolve_name(id, Space::Tag)
    }

    fn ident_name(&mut self, id: u32) -> Cow<'a, [u8]> {
        self.resolve_name(id, Space::Ident)
    }

    /// GCC's typedefs to its __PolyX_t of Arm SIMD, which no other
    /// compiler knows, as the base types they are.
    fn emit_missing_aliases(&mut self, id: u32) -> Result {
        const ALIASES: [(&[u8], &[u8]); 4] = [
            (b"__Poly8_t", b"unsigned char"),
            (b"__Poly16_t", b"unsigned short"),
            (b"__Poly64_t", b"unsigned long long"),
            (b"__Poly128_t", b"unsigned __int128"),
        ];
        let name = self.type_name(id);
        if let Some((_, base)) = ALIASES.iter().find(|(alias, _)| **alias == *name) {
            self.put(b"typedef ")?;
            self.put(base)?;
            self.put(b" ")?;
            self.put(&name)?;
            self.put(b";\n\n")?;
        }
        Ok(())
    }

    fn emit_struct_fwd(&mut self, id: u32) -> Result {
        let btf = self.btf;
        let keyword: &[u8] = if btf.kind(id) == Kind::Struct {
            b"struct"
        } else {
            b"union"
        };
        self.put(keyword)?;
        if btf.named(id) {
            self.put(b" ")?;
        }
        let name = self.type_name(id);
        self.put(&name)?;
        Ok(())
    }

    fn emit_struct_def(&mut self, id: u32, lvl: usize) -> Result {
        let btf = self.btf;
        let is_struct = btf.kind(id) == Kind::Struct;
        let align = btf.align_of(id);
        let packed = is_struct && btf.is_packed(id);
        self.emit_struct_fwd(id)?;
        self.put(b" {")?;
        let mut off: i64 = 0;
        let mut prev_bitfield = false;
        for (i, m) in btf.members(id).enumerate() {
            let bits = i64::from(m.bitfield_size());
            let m_off = i64::from(m.bit_offset());
            let m_align = if packed { 1 } else { btf.align_of(m.ty) };
            let in_bitfield = prev_bitfield && bits != 0;
            self.emit_bit_padding(off, m_off, m_align, in_bitfield, lvl + 1)?;
            self.put(b"\n")?;
            self.put(pfx(lvl + 1))?;
            self.emit_type_decl(m.ty, btf.str(m.name_off), lvl + 1)?;
            if bits != 0 {
                write!(self.out, ": {bits}")?;
                off = m_off + bits;
            } else {
                off = m_off + btf.size_of(m.ty) * 8;
            }
            prev_bitfield = bits != 0;
            self.emit_decl_tags(id, i as i32)?;
            self.put(b";")?;
        }
        if is_struct {
            let end = i64::from(btf.size(id)) * 8;
            self.emit_bit_padding(off, end, align, false, lvl + 1)?;
        }
        // An empty struct stays on one line.
        if btf.vlen(id) != 0 || btf.size(id) != 0 {
            self.put(b"\n")?;
            self.put(pfx(lvl))?;
        }
        self.put(b"}")?;
        if packed {
            self.put(b" __attribute__((packed))")?;
        }
        self.emit_decl_tags(id, -1)
    }

    /// Fills the bits from `cur` to `next` with anonymous bitfields, the
    /// fewest that make the compiler put the next member at `next`: `type:
    /// 0` to align to a type where the member's own alignment would not
    /// get there, then whole types, then the smallest type for the rest.
    fn emit_bit_padding(
        &mut self,
        mut cur: i64,
        next: i64,
        next_align: u32,
        in_bitfield: bool,
        lvl: usize,
    ) -> Result {
        let pads: [(&str, i64); 4] = [
            ("long", i64::from(self.btf.ptr_size()) * 8),
            ("int", 32),
            ("short", 16),
            ("char", 8),
        ];
        if cur >= next {
            return Ok(());
        }
        let (mut pad_type, mut pad_bits, new_off) = pads
            .iter()
            .map(|&(name, bits)| (name, bits, roundup(cur, bits)))
            .find(|&(_, _, off)| off <= next)
            .unwrap_or_else(|| ("char", 8, roundup(cur, 8)));
        if new_off > cur && new_off <= next {
            // `type: 0` where the next member's own alignment stops short
            // of `next`, or where `type: X` would fit the hole and do nothing.
            let mark = if in_bitfield {
                true
            } else if new_off == next {
                let align_bits = i64::from(next_align) * 8;
                if align_bits == 0 {
                    return Err(DumpError::ZeroAlign);
                }
                roundup(cur, align_bits) != new_off
            } else {
                next - new_off <= new_off - cur
            };
            if mark {
                let width = if in_bitfield { new_off - cur } else { 0 };
                self.emit_pad(pad_type, width, lvl)?;
            }
            cur = new_off;
        }
        while cur != next {
            let bits = (next - cur).min(pad_bits);
            if bits < pad_bits {
                // The remainder, in the smallest type that holds it.
                (pad_type, pad_bits) = *pads
                    .iter()
                    .rev()
                    .find(|&&(_, b)| b >= bits)
                    .unwrap_or(&pads[0]);
            }
            self.emit_pad(pad_type, bits, lvl)?;
            cur += bits;
        }
        Ok(())
    }

    fn emit_pad(&mut self, pad_type: &str, bits: i64, lvl: usize) -> Result {
        self.put(b"\n")?;
        self.put(pfx(lvl))?;
        write!(self.out, "{pad_type}: {bits};")?;
        Ok(())
    }

    fn emit_decl_tag(&mut self, tag: u32) -> Result {
        let btf = self.btf;
        let name = btf.name(tag);
        if !btf.kflag(tag) {
            self.put(b" __attribute__((btf_decl_tag(\"")?;
            self.put(name)?;
            self.put(b"\")))")?;
        } else if name.starts_with(b"__attribute__(") {
            self.put(b" ")?;
            self.put(name)?;
        } else {
            self.put(b" __attribute__((")?;
            self.put(name)?;
            self.put(b"))")?;
        }
        Ok(())
    }

    /// The decl tags on `id`'s member or parameter `comp_idx`, or on `id`
    /// itself for -1.
    fn emit_decl_tags(&mut self, id: u32, comp_idx: i32) -> Result {
        let start = self.decl_tags.partition_point(|&(target, _)| target < id);
        for k in start..self.decl_tags.len() {
            let (target, tag) = self.decl_tags[k];
            if target != id {
                break;
            }
            if self.btf.component_idx(tag) == comp_idx {
                self.emit_decl_tag(tag)?;
            }
        }
        Ok(())
    }

    fn emit_enum_fwd(&mut self, id: u32) -> Result {
        self.put(b"enum ")?;
        let name = self.type_name(id);
        self.put(&name)?;
        Ok(())
    }

    fn emit_enum_def(&mut self, id: u32, lvl: usize) -> Result {
        let btf = self.btf;
        self.put(b"enum")?;
        if btf.named(id) {
            self.put(b" ")?;
        }
        let name = self.type_name(id);
        self.put(&name)?;
        let vlen = btf.vlen(id);
        if vlen == 0 {
            return Ok(());
        }
        self.put(b" {")?;
        let enum64 = btf.kind(id) == Kind::Enum64;
        let signed = btf.kflag(id);
        for i in 0..vlen {
            let (name_off, val) = btf.enumerator(id, i);
            let name = btf.str(name_off);
            // Enumerators share the namespace of typedef names.
            let seen = self.count_name(Space::Ident, name);
            self.put(b"\n")?;
            self.put(pfx(lvl + 1))?;
            self.put(name)?;
            if seen > 1 {
                write!(self.out, "___{seen}")?;
            }
            match (enum64, signed) {
                (false, false) => write!(self.out, " = {},", val as u32)?,
                (false, true) => write!(self.out, " = {},", val as u32 as i32)?,
                (true, false) => write!(self.out, " = {val}ULL,")?,
                (true, true) => write!(self.out, " = {}LL,", val as i64)?,
            }
        }
        self.put(b"\n")?;
        self.put(pfx(lvl))?;
        self.put(b"}")?;
        // Sizes no enumerator implies need a mode to keep.
        let size = btf.size(id);
        if size == 1 {
            self.put(b" __attribute__((mode(byte)))")?;
        } else if size == 8 && btf.ptr_size() == 8 {
            // An enum64 with a value past 32 bits is 8 bytes without help.
            let wide = enum64 && (0..vlen).any(|i| btf.enumerator(id, i).1 >> 32 != 0);
            if !wide {
                self.put(b" __attribute__((mode(word)))")?;
            }
        }
        Ok(())
    }

    fn emit_fwd_def(&mut self, id: u32) -> Result {
        let keyword: &[u8] = if self.btf.kflag(id) {
            b"union "
        } else {
            b"struct "
        };
        self.put(keyword)?;
        let name = self.type_name(id);
        self.put(&name)?;
        Ok(())
    }

    fn emit_typedef_def(&mut self, id: u32, lvl: usize) -> Result {
        let btf = self.btf;
        let name = self.ident_name(id);
        // Old GCC typedefs __gnuc_va_list to void.
        if btf.target(id) == 0 && *name == *b"__gnuc_va_list" {
            self.put(b"typedef __builtin_va_list __gnuc_va_list")?;
            return Ok(());
        }
        self.put(b"typedef ")?;
        self.emit_type_decl(btf.target(id), &name, lvl)?;
        self.emit_decl_tags(id, -1)
    }

    /// Declares `fname` of type `id` in C syntax: the chain of types from
    /// `id` down to a named one, stacked, then unwound innermost first.
    fn emit_type_decl(&mut self, mut id: u32, fname: &[u8], lvl: usize) -> Result {
        let btf = self.btf;
        let mut decls = Vec::new();
        loop {
            decls.push(id);
            if id == 0 {
                break;
            }
            match btf.kind(id) {
                Kind::Ptr
                | Kind::Volatile
                | Kind::Const
                | Kind::Restrict
                | Kind::FuncProto
                | Kind::TypeTag => id = btf.target(id),
                Kind::Array => id = btf.elem_type(id),
                Kind::Int
                | Kind::Enum
                | Kind::Enum64
                | Kind::Fwd
                | Kind::Struct
                | Kind::Union
                | Kind::Typedef
                | Kind::Float => break,
                _ => {
                    warn_unexpected(btf, id);
                    break;
                }
            }
        }
        self.emit_type_chain(&mut decls, fname, lvl)
    }

    /// The qualifiers on top of `decls`, written before a type they apply to.
    fn emit_mods(&mut self, decls: &mut Vec<u32>) -> Result {
        while let Some(&id) = decls.last() {
            let word: &[u8] = match self.btf.kind(id) {
                Kind::Volatile => b"volatile ",
                Kind::Const => b"const ",
                Kind::Restrict => b"restrict ",
                _ => break,
            };
            self.put(word)?;
            decls.pop();
        }
        Ok(())
    }

    /// Drops qualifiers C cannot put on an array or a function: GCC emits
    /// them for const element types and noreturn function pointers.
    fn drop_mods(&self, decls: &mut Vec<u32>) {
        while decls.last().is_some_and(|&id| self.btf.kind(id).is_mod()) {
            decls.pop();
        }
    }

    fn emit_name(&mut self, name: &[u8], last_was_ptr: bool) -> Result {
        if !name.is_empty() && !last_was_ptr {
            self.put(b" ")?;
        }
        self.put(name)?;
        Ok(())
    }

    /// Unwinds a declaration stack. Pointers and qualifiers go right of
    /// what they point to, so `int ***p`; an array or function nested
    /// under a pointer takes parentheses, so `int (*p)[2]`.
    fn emit_type_chain(&mut self, decls: &mut Vec<u32>, fname: &[u8], lvl: usize) -> Result {
        let btf = self.btf;
        // True at the start for the lone pointer of `(*fname)`.
        let mut last_was_ptr = true;
        while let Some(id) = decls.pop() {
            if id == 0 {
                self.emit_mods(decls)?;
                self.put(b"void")?;
                last_was_ptr = false;
                continue;
            }
            let kind = btf.kind(id);
            match kind {
                Kind::Int | Kind::Float => {
                    self.emit_mods(decls)?;
                    self.put(btf.name(id))?;
                }
                Kind::Struct | Kind::Union => {
                    self.emit_mods(decls)?;
                    if btf.named(id) {
                        self.emit_struct_fwd(id)?;
                    } else {
                        self.emit_struct_def(id, lvl)?;
                    }
                }
                Kind::Enum | Kind::Enum64 => {
                    self.emit_mods(decls)?;
                    if btf.named(id) {
                        self.emit_enum_fwd(id)?;
                    } else {
                        self.emit_enum_def(id, lvl)?;
                    }
                }
                Kind::Fwd => {
                    self.emit_mods(decls)?;
                    self.emit_fwd_def(id)?;
                }
                Kind::Typedef => {
                    self.emit_mods(decls)?;
                    let name = self.ident_name(id);
                    self.put(&name)?;
                }
                Kind::Ptr => {
                    let star: &[u8] = if last_was_ptr { b"*" } else { b" *" };
                    self.put(star)?;
                }
                Kind::Volatile => self.put(b" volatile")?,
                Kind::Const => self.put(b" const")?,
                Kind::Restrict => self.put(b" restrict")?,
                Kind::TypeTag => {
                    self.emit_mods(decls)?;
                    self.emit_type_tag(id)?;
                }
                Kind::Array => {
                    self.drop_mods(decls);
                    let nelems = btf.nelems(id);
                    let Some(&next) = decls.last() else {
                        self.emit_name(fname, last_was_ptr)?;
                        write!(self.out, "[{nelems}]")?;
                        return Ok(());
                    };
                    let multidim = btf.kind(next) == Kind::Array;
                    if !fname.is_empty() && !last_was_ptr {
                        self.put(b" ")?;
                    }
                    if !multidim {
                        self.put(b"(")?;
                    }
                    self.emit_type_chain(decls, fname, lvl)?;
                    if !multidim {
                        self.put(b")")?;
                    }
                    write!(self.out, "[{nelems}]")?;
                    return Ok(());
                }
                Kind::FuncProto => {
                    return self.emit_func_proto(id, decls, fname, lvl, last_was_ptr);
                }
                _ => {
                    warn_unexpected(btf, id);
                    return Ok(());
                }
            }
            last_was_ptr = kind == Kind::Ptr;
        }
        self.emit_name(fname, last_was_ptr)
    }

    fn emit_type_tag(&mut self, id: u32) -> Result {
        let btf = self.btf;
        let name = btf.name(id);
        if btf.kflag(id) {
            if name.starts_with(b"__attribute__(") {
                self.put(b" ")?;
                self.put(name)?;
            } else {
                self.put(b" __attribute__((")?;
                self.put(name)?;
                self.put(b"))")?;
            }
        } else if name == b"arena" {
            // A pointer into the BPF arena's address space.
            self.put(
                b" __attribute__((address_space(1))) __attribute__((btf_type_tag(\"arena\")))",
            )?;
        } else {
            self.put(b" __attribute__((btf_type_tag(\"")?;
            self.put(name)?;
            self.put(b"\")))")?;
        }
        Ok(())
    }

    /// The function part of a declaration, what is left of `decls`
    /// (a pointer to it, say) in parentheses before the parameters.
    fn emit_func_proto(
        &mut self,
        id: u32,
        decls: &mut Vec<u32>,
        fname: &[u8],
        lvl: usize,
        last_was_ptr: bool,
    ) -> Result {
        let btf = self.btf;
        self.drop_mods(decls);
        if decls.is_empty() {
            self.emit_name(fname, last_was_ptr)?;
        } else {
            self.put(b" (")?;
            self.emit_type_chain(decls, fname, lvl)?;
            self.put(b")")?;
        }
        self.put(b"(")?;
        let params: Vec<Param> = btf.params(id).collect();
        // Clang writes no parameters as one void parameter.
        if params.is_empty() || params.len() == 1 && params[0].ty == 0 {
            self.put(b"void)")?;
            return Ok(());
        }
        for (i, p) in params.iter().enumerate() {
            if i > 0 {
                self.put(b", ")?;
            }
            // A trailing void parameter stands for varargs.
            if i == params.len() - 1 && p.ty == 0 {
                self.put(b"...")?;
                break;
            }
            self.emit_type_decl(p.ty, btf.str(p.name_off), lvl)?;
        }
        self.put(b")")?;
        Ok(())
    }

    /// Every function the bpf_kfunc decl tag marks, as an extern weak ksym
    /// sorted by name; bpf_fastcall tagged ones keep that convention.
    fn dump_kfuncs(&mut self) -> Result {
        let btf = self.btf;
        self.put(b"\n/* BPF kfuncs */\n#ifndef BPF_NO_KFUNC_PROTOTYPES\n")?;
        let mut kfuncs = Vec::new();
        let mut fastcalls = Vec::new();
        for id in 1..btf.count() {
            if btf.kind(id) != Kind::DeclTag || btf.component_idx(id) != -1 {
                continue;
            }
            let func = btf.target(id);
            if btf.kind(func) != Kind::Func {
                continue;
            }
            match btf.name(id) {
                b"bpf_kfunc" => kfuncs.push(func),
                b"bpf_fastcall" => fastcalls.push(func),
                _ => {}
            }
        }
        // Stable, as glibc's merge sort leaves the C tool's qsort_r().
        kfuncs.sort_by_key(|&func| btf.name(func));
        for func in kfuncs {
            self.put(b"extern ")?;
            if fastcalls.contains(&func) {
                self.put(b"__bpf_fastcall ")?;
            }
            self.emit_type_decl(btf.target(func), btf.name(func), 0)?;
            self.put(b" __weak __ksym;\n")?;
        }
        self.put(b"#endif\n\n")?;
        Ok(())
    }
}

fn roundup(x: i64, y: i64) -> i64 {
    (x + y - 1) / y * y
}

/// `orig` with the ___N suffix, cut as libbpf's 256-byte buffer cuts it.
fn suffixed(orig: &[u8], n: usize) -> Vec<u8> {
    let mut name = orig.to_vec();
    name.extend_from_slice(format!("___{n}").as_bytes());
    name.truncate(255);
    name
}

fn warn_unexpected(btf: &Types, id: u32) {
    eprintln!(
        "unexpected type in decl chain, kind:{}, id:[{id}]",
        btf.btf.kind(id)
    );
}

fn dump_c(btf: &Types, out: impl Write) -> Result {
    let order = btf.sorted_ids();
    let mut d = Dumper::new(btf, out);
    d.put(HEADER.as_bytes())?;
    for id in order.into_iter().filter(|&id| id != 0) {
        d.dump_type(id)?;
    }
    d.dump_kfuncs()?;
    d.put(FOOTER.as_bytes())?;
    Ok(())
}

fn invalid_data(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// The types and strings of a BTF blob behind a plain little-endian
/// header, the one layout the crate reader takes. libbpf also takes a
/// longer header, a layout section, gaps, bytes after the strings and
/// big-endian BTF, none of which changes what the types say.
fn canonical(raw: &[u8]) -> io::Result<Vec<u8>> {
    const HDR_LEN: usize = 24;
    let bad = || io::Error::from_raw_os_error(errno::EINVAL);
    let swapped = raw.starts_with(&[0xeb, 0x9f]);
    let word = |b: &[u8]| {
        let w = [b[0], b[1], b[2], b[3]];
        if swapped {
            u32::from_be_bytes(w)
        } else {
            u32::from_le_bytes(w)
        }
    };
    if raw.len() < HDR_LEN {
        return Err(bad());
    }
    let hdr_len = word(&raw[4..]) as usize;
    if hdr_len < HDR_LEN || raw.len() < hdr_len {
        return Err(bad());
    }
    // type_off, type_len, str_off, str_len and, past 24 bytes of header,
    // the layout section's offset and length, 0 where the header ends.
    let field = |i: usize| {
        let at = 8 + 4 * i;
        u64::from(if at + 4 <= hdr_len.min(32) {
            word(&raw[at..])
        } else {
            0
        })
    };
    let [type_off, type_len, str_off, str_len, layout_off, layout_len] =
        [0, 1, 2, 3, 4, 5].map(field);
    let meta_len = (raw.len() - hdr_len) as u64;
    if str_off + str_len > meta_len || type_off + type_len > str_off || type_off % 4 != 0 {
        return Err(bad());
    }
    if layout_len != 0
        && (layout_off % 4 != 0
            || layout_off < type_off + type_len
            || layout_off + layout_len > str_off
            || layout_len % 4 != 0)
    {
        return Err(bad());
    }
    let section = |off: u64, len: u64| &raw[hdr_len + off as usize..][..len as usize];
    let (types, strs) = (section(type_off, type_len), section(str_off, str_len));
    let mut out = Vec::with_capacity(HDR_LEN + types.len() + strs.len());
    out.extend_from_slice(&btf::MAGIC.to_le_bytes());
    out.extend_from_slice(&raw[2..4]);
    for w in [HDR_LEN as u64, 0, type_len, type_len, str_len] {
        out.extend_from_slice(&(w as u32).to_le_bytes());
    }
    if swapped {
        // Every field of a type record is a 32-bit word, so swapping the
        // words swaps the records; types of no whole words are malformed.
        if types.len() % 4 != 0 {
            return Err(bad());
        }
        for w in types.chunks_exact(4) {
            out.extend_from_slice(&word(w).to_le_bytes());
        }
    } else {
        out.extend_from_slice(types);
    }
    out.extend_from_slice(strs);
    Ok(out)
}

fn parse_btf(raw: &[u8]) -> io::Result<Btf> {
    Btf::parse(&canonical(raw)?).map_err(|err| io::Error::from_raw_os_error(-err))
}

/// The BTF at `path`, raw or the .BTF section of an ELF file, as
/// btf__parse() takes it.
fn load(path: &Path) -> io::Result<Types> {
    let file = File::open(path)?;
    let mut magic = [0; 2];
    file.read_exact_at(&mut magic, 0)?;
    if matches!(magic, [0x9f, 0xeb] | [0xeb, 0x9f]) {
        let mut raw = Vec::new();
        (&file).read_to_end(&mut raw)?;
        return Types::new(parse_btf(&raw)?);
    }
    let (sec, ptr_size) = elf_btf(&file)?;
    let btf = parse_btf(&sec)?;
    // libbpf takes the pointer size from the ELF class, the crate reader
    // from the size of long; they must agree.
    if btf.ptr_size() != ptr_size {
        return Err(invalid_data(
            "the ELF class and the BTF's long disagree on the pointer size",
        ));
    }
    Types::new(btf)
}

/// An ELF file of either class and byte order, read where needed: a
/// vmlinux is mostly sections the lookup skips.
struct Elf<'a> {
    file: &'a File,
    len: u64,
    wide: bool,
    le: bool,
}

/// The fields of a section header the lookup needs.
struct Section {
    name: u32,
    kind: u32,
    offset: u64,
    size: u64,
    link: u32,
}

impl Elf<'_> {
    fn read(&self, off: u64, len: u64) -> io::Result<Vec<u8>> {
        if off.checked_add(len).is_none_or(|end| end > self.len) {
            return Err(not_elf());
        }
        let mut buf = vec![0; len as usize];
        self.file.read_exact_at(&mut buf, off)?;
        Ok(buf)
    }

    fn uint(&self, bytes: &[u8]) -> u64 {
        let fold = |v: u64, &b: &u8| v << 8 | u64::from(b);
        if self.le {
            bytes.iter().rev().fold(0, fold)
        } else {
            bytes.iter().fold(0, fold)
        }
    }

    /// A section header of the class's size.
    fn section(&self, h: &[u8]) -> Section {
        let (offset, width, link) = if self.wide { (24, 8, 40) } else { (16, 4, 24) };
        Section {
            name: self.uint(&h[..4]) as u32,
            kind: self.uint(&h[4..8]) as u32,
            offset: self.uint(&h[offset..offset + width]),
            size: self.uint(&h[offset + width..offset + 2 * width]),
            link: self.uint(&h[link..link + 4]) as u32,
        }
    }

    fn contents(&self, sec: &Section) -> io::Result<Vec<u8>> {
        self.read(sec.offset, sec.size)
    }
}

fn not_elf() -> io::Error {
    invalid_data("not raw BTF nor a well-formed ELF file")
}

/// The .BTF section of an ELF file, the last if there are more, and the
/// pointer size of its class.
fn elf_btf(file: &File) -> io::Result<(Vec<u8>, u32)> {
    const SHT_PROGBITS: u32 = 1;
    const SHN_XINDEX: u64 = 0xffff;
    let mut ident = [0; 6];
    file.read_exact_at(&mut ident, 0).map_err(|_| not_elf())?;
    let (wide, le) = match ident {
        [0x7f, b'E', b'L', b'F', class @ (1 | 2), data @ (1 | 2)] => (class == 2, data == 1),
        _ => return Err(not_elf()),
    };
    let elf = Elf {
        file,
        len: file.metadata()?.len(),
        wide,
        le,
    };
    let (ehdr_len, shent_len, at) = if wide { (64, 64, 0x28) } else { (52, 40, 0x20) };
    let ehdr = elf.read(0, ehdr_len)?;
    let word = if wide { 8 } else { 4 };
    let shoff = elf.uint(&ehdr[at..at + word]);
    let at = at + word + 10;
    let [shentsize, mut shnum, mut shstrndx] =
        [0, 2, 4].map(|i| elf.uint(&ehdr[at + i..at + i + 2]));
    if shoff == 0 || shentsize != shent_len {
        return Err(not_elf());
    }
    // Past 0xff00 sections, section 0 holds their count and the index of
    // the section names.
    let first = elf.section(&elf.read(shoff, shent_len)?);
    if shnum == 0 {
        shnum = first.size;
    }
    if shstrndx == SHN_XINDEX {
        shstrndx = u64::from(first.link);
    }
    let table = elf.read(shoff, shnum.checked_mul(shent_len).ok_or_else(not_elf)?)?;
    let sections: Vec<Section> = table
        .chunks_exact(shent_len as usize)
        .map(|h| elf.section(h))
        .collect();
    let names = elf.contents(sections.get(shstrndx as usize).ok_or_else(not_elf)?)?;
    let mut btf = None;
    for sec in sections.iter().skip(1) {
        let name = names
            .get(sec.name as usize..)
            .and_then(|s| s.split(|&c| c == 0).next())
            .ok_or_else(not_elf)?;
        if !matches!(name, b".BTF" | b".BTF.ext" | b".BTF.base") {
            continue;
        }
        if sec.kind != SHT_PROGBITS
            || sec
                .offset
                .checked_add(sec.size)
                .is_none_or(|end| end > elf.len)
        {
            return Err(not_elf());
        }
        match name {
            b".BTF" => btf = Some(sec),
            b".BTF.base" => {
                return Err(invalid_data("split BTF over a .BTF.base is not supported"));
            }
            _ => {}
        }
    }
    let btf = btf.ok_or_else(|| io::Error::from_raw_os_error(errno::ENODATA))?;
    Ok((elf.contents(btf)?, if wide { 8 } else { 4 }))
}

fn main() -> ExitCode {
    let args: Vec<OsString> = env::args_os().collect();
    let prog = args
        .first()
        .map_or(Cow::Borrowed("gen-vmlinux-h"), |a| a.to_string_lossy());
    if args.len() > 2 || args.get(1).is_some_and(|a| a == "--help") {
        eprintln!("usage: {prog} [vmlinux.btf | ELF with .BTF] > vmlinux.h");
        return ExitCode::from(2);
    }
    let path = args
        .get(1)
        .map_or_else(|| PathBuf::from(DEFAULT_PATH), PathBuf::from);
    let btf = match load(&path) {
        Ok(btf) => btf,
        Err(e) => {
            eprintln!("{prog}: cannot parse BTF from {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let mut out = BufWriter::with_capacity(1 << 16, io::stdout().lock());
    let dumped = dump_c(&btf, &mut out);
    // What was dumped before a failure goes out too, as the C tool's does.
    let flushed = out.flush();
    if let Err(e) = dumped {
        eprintln!("{prog}: BTF dump failed: {e}");
        return ExitCode::FAILURE;
    }
    if flushed.is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
