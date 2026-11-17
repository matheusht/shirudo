// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! BTF as an object carries it: the raw section, its types found by id
//! and changed in place, as libbpf changes them before the loader takes
//! the section, and its strings.

use core::ffi::c_int;

use crate::errno::{E2BIG, EINVAL};

pub(crate) const MAGIC: u16 = 0xeb9f;

pub(crate) const KIND_INT: u32 = 1;
pub(crate) const KIND_PTR: u32 = 2;
pub(crate) const KIND_ARRAY: u32 = 3;
pub(crate) const KIND_STRUCT: u32 = 4;
pub(crate) const KIND_UNION: u32 = 5;
pub(crate) const KIND_ENUM: u32 = 6;
pub(crate) const KIND_FWD: u32 = 7;
pub(crate) const KIND_TYPEDEF: u32 = 8;
pub(crate) const KIND_VOLATILE: u32 = 9;
pub(crate) const KIND_CONST: u32 = 10;
pub(crate) const KIND_RESTRICT: u32 = 11;
pub(crate) const KIND_FUNC: u32 = 12;
pub(crate) const KIND_FUNC_PROTO: u32 = 13;
pub(crate) const KIND_VAR: u32 = 14;
pub(crate) const KIND_DATASEC: u32 = 15;
pub(crate) const KIND_FLOAT: u32 = 16;
pub(crate) const KIND_DECL_TAG: u32 = 17;
pub(crate) const KIND_TYPE_TAG: u32 = 18;
pub(crate) const KIND_ENUM64: u32 = 19;
pub(crate) const KIND_LOC_PARAM: u32 = 20;
pub(crate) const KIND_LOC_PROTO: u32 = 21;
pub(crate) const KIND_LOCSEC: u32 = 22;

pub(crate) const VAR_STATIC: u32 = 0;
pub(crate) const VAR_GLOBAL_ALLOCATED: u32 = 1;
pub(crate) const VAR_GLOBAL_EXTERN: u32 = 2;
pub(crate) const FUNC_STATIC: u32 = 0;
pub(crate) const FUNC_GLOBAL: u32 = 1;

const TYPE_SIZE: usize = 12;
/// How deep libbpf follows a chain of types before it gives up.
const MAX_RESOLVE_DEPTH: usize = 32;
/// The size of a pointer of the BPF target.
const PTR_SZ: u32 = 8;
/// The kind and the count of elements in a type's info, as this
/// bpf-next's BTF widens them.
const KIND_MASK: u32 = 0x7f;
const VLEN_MASK: u32 = 0xff_ffff;

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn le32_of(b: &[u8]) -> u32 {
    le32(b, 0)
}

/// The section as its header, types and strings, and each type's offset
/// within the types: type ids start at 1, type 0 being void. Unchanged,
/// the three make up the section's bytes again; a type added grows the
/// types and strings as libbpf grows them, and the header records it.
pub(crate) struct Btf {
    hdr: Vec<u8>,
    types: Vec<u8>,
    strs: Vec<u8>,
    offs: Vec<usize>,
}

impl Btf {
    /// The BTF in `raw`, checked as btf__new() checks it: -EINVAL for a
    /// bad header, string section or type, and for what clang does not
    /// write: a longer header, a layout section, or types and strings
    /// apart.
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, c_int> {
        let bad = Err(-EINVAL);
        if raw.len() < 24 || u16::from_le_bytes([raw[0], raw[1]]) != MAGIC {
            return bad;
        }
        let hdr_len = le32(raw, 4) as usize;
        if !(24..=32).contains(&hdr_len) || raw.len() < hdr_len {
            return bad;
        }
        let (type_off, type_len) = (le32(raw, 8) as usize, le32(raw, 12) as usize);
        let (str_off, str_len) = (le32(raw, 16) as usize, le32(raw, 20) as usize);
        if hdr_len == 32 && le32(raw, 28) != 0
            || type_off != 0
            || str_off != type_len
            || raw.len() != hdr_len + type_len + str_len
        {
            return bad;
        }
        let types = &raw[hdr_len..hdr_len + type_len];
        let strs = &raw[hdr_len + str_off..];
        if str_len == 0 || str_len - 1 > 0x7fff_ffff || strs[0] != 0 || strs[str_len - 1] != 0 {
            return bad;
        }
        let mut offs = vec![0];
        let mut off = 0;
        while off < type_len {
            if off + TYPE_SIZE > type_len {
                return bad;
            }
            let info = le32(types, off + 4);
            let vlen = (info & VLEN_MASK) as usize;
            let size = TYPE_SIZE
                + match (info >> 24) & KIND_MASK {
                    KIND_FWD | KIND_CONST | KIND_VOLATILE | KIND_RESTRICT | KIND_PTR
                    | KIND_TYPEDEF | KIND_FUNC | KIND_FLOAT | KIND_TYPE_TAG => 0,
                    KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
                    KIND_ENUM | KIND_FUNC_PROTO => 8 * vlen,
                    KIND_ENUM64 | KIND_STRUCT | KIND_UNION | KIND_DATASEC | KIND_LOCSEC => {
                        12 * vlen
                    }
                    KIND_ARRAY => 12,
                    KIND_LOC_PARAM => 4 + 4 * vlen,
                    KIND_LOC_PROTO => 4 * vlen,
                    _ => return bad,
                };
            offs.push(off);
            off += size;
        }
        if off != type_len {
            return bad;
        }
        let btf = Btf {
            hdr: raw[..hdr_len].to_vec(),
            types: types.to_vec(),
            strs: strs.to_vec(),
            offs,
        };
        if !(1..btf.type_cnt()).all(|id| btf.valid(id)) {
            return bad;
        }
        Ok(btf)
    }

    /// btf_validate_type(): the type's names are strings of the section
    /// and the types it refers to are types of it, a FUNC's a FUNC_PROTO.
    fn valid(&self, id: u32) -> bool {
        let str_ok = |off: u32| (off as usize) < self.strs.len();
        let id_ok = |t: u32| t < self.type_cnt();
        let n = self.vlen(id) as usize;
        // The words of each of the type's `n` elements of `w` words.
        let all = |w: usize, ok: &dyn Fn(&[u32]) -> bool| {
            (0..n).all(|i| ok(&(0..w).map(|j| self.word(id, w * i + j)).collect::<Vec<_>>()))
        };
        str_ok(self.name_off(id))
            && match self.kind(id) {
                KIND_PTR | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_VAR
                | KIND_DECL_TAG | KIND_TYPE_TAG => id_ok(self.size_or_type(id)),
                KIND_ARRAY => id_ok(self.word(id, 0)) && id_ok(self.word(id, 1)),
                KIND_STRUCT | KIND_UNION => all(3, &|m| str_ok(m[0]) && id_ok(m[1])),
                KIND_ENUM => all(2, &|m| str_ok(m[0])),
                KIND_ENUM64 => all(3, &|m| str_ok(m[0])),
                KIND_FUNC => {
                    id_ok(self.size_or_type(id))
                        && self.kind(self.size_or_type(id)) == KIND_FUNC_PROTO
                }
                KIND_FUNC_PROTO => all(2, &|m| str_ok(m[0]) && id_ok(m[1])),
                KIND_DATASEC => all(3, &|m| id_ok(m[0])),
                KIND_LOC_PROTO => all(1, &|m| id_ok(m[0])),
                KIND_LOCSEC => all(3, &|m| id_ok(m[0]) && id_ok(m[1])),
                _ => true,
            }
    }

    /// btf__raw_data(): the header, the types and the strings, the
    /// header's lengths and string offset as they now are.
    pub(crate) fn raw(&self) -> Vec<u8> {
        let mut out = self.hdr.clone();
        let (types, strs) = (self.types.len() as u32, self.strs.len() as u32);
        out[12..16].copy_from_slice(&types.to_le_bytes());
        out[16..20].copy_from_slice(&types.to_le_bytes());
        out[20..24].copy_from_slice(&strs.to_le_bytes());
        out.extend_from_slice(&self.types);
        out.extend_from_slice(&self.strs);
        out
    }

    /// btf__add_str(): the offset of `s` among the strings, the first
    /// that starts there, or of `s` added at their end.
    fn add_str(&mut self, s: &[u8]) -> u32 {
        let mut off = 0;
        for part in self.strs.split(|&c| c == 0) {
            if part == s && off < self.strs.len() {
                return off as u32;
            }
            off += part.len() + 1;
        }
        let off = self.strs.len() as u32;
        self.strs.extend_from_slice(s);
        self.strs.push(0);
        off
    }

    /// btf__add_var(): a VAR named `name` of `ty`, its id.
    pub(crate) fn add_var(&mut self, name: &[u8], linkage: u32, ty: u32) -> u32 {
        let name_off = self.add_str(name);
        self.offs.push(self.types.len());
        for w in [name_off, KIND_VAR << 24, ty, linkage] {
            self.types.extend_from_slice(&w.to_le_bytes());
        }
        self.type_cnt() - 1
    }

    /// btf__type_cnt(): the number of types, void included.
    pub(crate) fn type_cnt(&self) -> u32 {
        self.offs.len() as u32
    }

    fn off(&self, id: u32) -> Option<usize> {
        (id != 0)
            .then(|| self.offs.get(id as usize).copied())
            .flatten()
    }

    pub(crate) fn name_off(&self, id: u32) -> u32 {
        self.off(id).map_or(0, |t| le32(&self.types, t))
    }

    pub(crate) fn info(&self, id: u32) -> u32 {
        self.off(id).map_or(0, |t| le32(&self.types, t + 4))
    }

    pub(crate) fn kind(&self, id: u32) -> u32 {
        (self.info(id) >> 24) & KIND_MASK
    }

    /// The count of elements, or a FUNC's linkage.
    pub(crate) fn vlen(&self, id: u32) -> u32 {
        self.info(id) & VLEN_MASK
    }

    pub(crate) fn kflag(&self, id: u32) -> bool {
        self.info(id) >> 31 != 0
    }

    /// The size or the referenced type, the record's third word.
    pub(crate) fn size_or_type(&self, id: u32) -> u32 {
        self.off(id).map_or(0, |t| le32(&self.types, t + 8))
    }

    /// The `i`th 4-byte word after the record's base: an INT's encoding,
    /// a VAR's linkage, the words of the members, parameters or array.
    /// A record read past its end, as a malformed kind may lead to, is 0;
    /// one written there is dropped.
    pub(crate) fn word(&self, id: u32, i: usize) -> u32 {
        let at = self.off(id).map(|t| t + TYPE_SIZE + 4 * i);
        at.and_then(|at| self.types.get(at..at + 4))
            .map_or(0, le32_of)
    }

    pub(crate) fn set_word(&mut self, id: u32, i: usize, v: u32) {
        let at = self.off(id).map(|t| t + TYPE_SIZE + 4 * i);
        if let Some(w) = at.and_then(|at| self.types.get_mut(at..at + 4)) {
            w.copy_from_slice(&v.to_le_bytes());
        }
    }

    pub(crate) fn set_size(&mut self, id: u32, size: u32) {
        if let Some(t) = self.off(id) {
            self.types[t + 8..t + 12].copy_from_slice(&size.to_le_bytes());
        }
    }

    pub(crate) fn set_info(&mut self, id: u32, info: u32) {
        if let Some(t) = self.off(id) {
            self.types[t + 4..t + 8].copy_from_slice(&info.to_le_bytes());
        }
    }

    /// btf__name_by_offset(): the string at `off`.
    pub(crate) fn str_at(&self, off: u32) -> Option<&[u8]> {
        let s = self.strs.get(off as usize..)?;
        Some(&s[..s.iter().position(|&c| c == 0)?])
    }

    pub(crate) fn name(&self, id: u32) -> &[u8] {
        if id == 0 {
            return b"";
        }
        self.str_at(self.name_off(id)).unwrap_or_default()
    }

    /// A VAR's linkage.
    pub(crate) fn var_linkage(&self, id: u32) -> u32 {
        self.word(id, 0)
    }

    pub(crate) fn set_var_linkage(&mut self, id: u32, linkage: u32) {
        self.set_word(id, 0, linkage);
    }

    /// A DATASEC's `i`th variable: its type, offset and size.
    pub(crate) fn secinfo(&self, id: u32, i: u32) -> (u32, u32, u32) {
        let i = 3 * i as usize;
        (self.word(id, i), self.word(id, i + 1), self.word(id, i + 2))
    }

    pub(crate) fn set_secinfo_offset(&mut self, id: u32, i: u32, offset: u32) {
        self.set_word(id, 3 * i as usize + 1, offset);
    }

    /// Sorts a DATASEC's variables by offset, stably, as glibc's qsort()
    /// with compare_vsi_off() leaves them.
    pub(crate) fn sort_secinfos(&mut self, id: u32) {
        let Some(t) = self.off(id) else {
            return;
        };
        let n = self.vlen(id) as usize;
        let start = t + TYPE_SIZE;
        if self.kind(id) != KIND_DATASEC {
            return;
        }
        let mut v: Vec<[u8; 12]> = self.types[start..start + 12 * n]
            .chunks_exact(12)
            .map(|c| c.try_into().unwrap_or([0; 12]))
            .collect();
        v.sort_by_key(|c| le32(c, 4) as i32);
        for (i, c) in v.iter().enumerate() {
            self.types[start + 12 * i..start + 12 * (i + 1)].copy_from_slice(c);
        }
    }

    /// The first type of `kind` named `name`.
    pub(crate) fn find_by_name_kind(&self, name: &[u8], kind: u32) -> Option<u32> {
        (1..self.type_cnt()).find(|&id| self.kind(id) == kind && self.name(id) == name)
    }

    /// Skips typedefs and modifiers: the type `id` resolves to.
    pub(crate) fn skip_mods_and_typedefs(&self, mut id: u32) -> u32 {
        while matches!(
            self.kind(id),
            KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG
        ) {
            id = self.size_or_type(id);
        }
        id
    }

    /// btf__resolve_size(): the bytes a value of type `id` takes.
    pub(crate) fn resolve_size(&self, mut id: u32) -> Result<u32, c_int> {
        let mut nelems: u32 = 1;
        for _ in 0..MAX_RESOLVE_DEPTH {
            if id == 0 || id >= self.type_cnt() {
                break;
            }
            let size = match self.kind(id) {
                KIND_INT | KIND_STRUCT | KIND_UNION | KIND_ENUM | KIND_ENUM64 | KIND_DATASEC
                | KIND_FLOAT => self.size_or_type(id),
                KIND_PTR => PTR_SZ,
                KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_VAR
                | KIND_DECL_TAG | KIND_TYPE_TAG => {
                    id = self.size_or_type(id);
                    continue;
                }
                KIND_ARRAY => {
                    let n = self.word(id, 2);
                    if nelems != 0 && n > u32::MAX / nelems {
                        return Err(-E2BIG);
                    }
                    nelems *= n;
                    id = self.word(id, 0);
                    continue;
                }
                _ => return Err(-EINVAL),
            };
            if nelems != 0 && size > u32::MAX / nelems {
                return Err(-E2BIG);
            }
            return Ok(nelems * size);
        }
        Err(-EINVAL)
    }

    /// btf__align_of(): the alignment of type `id`, 1 for a packed struct
    /// or union.
    pub(crate) fn align_of(&self, id: u32) -> Result<u32, c_int> {
        self.align_at(id, 0)
    }

    fn align_at(&self, id: u32, depth: usize) -> Result<u32, c_int> {
        if depth > MAX_RESOLVE_DEPTH {
            return Err(-EINVAL);
        }
        match self.kind(id) {
            KIND_INT | KIND_ENUM | KIND_ENUM64 | KIND_FLOAT if id != 0 => {
                Ok(self.size_or_type(id).min(PTR_SZ))
            }
            KIND_PTR => Ok(PTR_SZ),
            KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => {
                self.align_at(self.size_or_type(id), depth + 1)
            }
            KIND_ARRAY => self.align_at(self.word(id, 0), depth + 1),
            KIND_STRUCT | KIND_UNION => {
                let mut max_align = 1;
                for i in 0..self.vlen(id) as usize {
                    let (ty, off) = (self.word(id, 3 * i + 1), self.word(id, 3 * i + 2));
                    let align = self.align_at(ty, depth + 1)?;
                    if align == 0 {
                        return Err(-EINVAL);
                    }
                    max_align = max_align.max(align);
                    let bitfield = self.kflag(id) && off >> 24 != 0;
                    if !bitfield && off % (8 * align) != 0 {
                        return Ok(1);
                    }
                }
                if self.size_or_type(id) % max_align != 0 {
                    return Ok(1);
                }
                Ok(max_align)
            }
            _ => Err(-EINVAL),
        }
    }
}
