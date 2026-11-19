// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! A BPF object as clang writes it: a 64-bit little-endian relocatable
//! ELF file for EM_BPF, its sections, symbols and relocations, read in
//! place as libbpf reads them through libelf.

use core::ffi::c_int;

use crate::errno::EINVAL;

pub(crate) const SHT_PROGBITS: u32 = 1;
pub(crate) const SHT_SYMTAB: u32 = 2;
pub(crate) const SHT_STRTAB: u32 = 3;
pub(crate) const SHT_NOBITS: u32 = 8;
pub(crate) const SHT_REL: u32 = 9;
pub(crate) const SHT_LLVM_ADDRSIG: u32 = 0x6fff_4c03;
pub(crate) const SHF_EXECINSTR: u64 = 4;

/// The size of the records libelf reads a section of type `ty` as, of
/// which its size must be a multiple: elfutils' type sizes for the
/// types it converts, a byte for any other.
fn record_size(ty: u32) -> u64 {
    match ty {
        // SYMTAB, RELA, DYNSYM
        2 | 4 | 11 => 24,
        // DYNAMIC, REL, GNU_verneed
        6 | SHT_REL | 0x6fff_fffe => 16,
        // INIT_ARRAY, FINI_ARRAY, PREINIT_ARRAY
        14..=16 => 8,
        // HASH, GROUP, SYMTAB_SHNDX, SUNW_syminfo
        5 | 17 | 18 | 0x6fff_fffc => 4,
        // GNU_LIBLIST
        0x6fff_fff7 => 20,
        // SUNW_move
        0x6fff_fffa => 28,
        // GNU_versym
        0x6fff_ffff => 2,
        _ => 1,
    }
}

pub(crate) const STT_OBJECT: u8 = 1;
pub(crate) const STT_FUNC: u8 = 2;
pub(crate) const STT_SECTION: u8 = 3;
pub(crate) const STB_LOCAL: u8 = 0;
pub(crate) const STB_GLOBAL: u8 = 1;
pub(crate) const STB_WEAK: u8 = 2;
pub(crate) const STV_HIDDEN: u8 = 2;
pub(crate) const STV_INTERNAL: u8 = 1;
pub(crate) const SHN_UNDEF: u16 = 0;

const ET_REL: u16 = 1;
const EM_BPF: u16 = 247;
const EHDR_SIZE: usize = 64;
const SHDR_SIZE: usize = 64;
pub(crate) const SYM_SIZE: usize = 24;
pub(crate) const REL_SIZE: usize = 16;

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// A section header and where its contents sit in the file.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Section {
    pub(crate) name: u32,
    pub(crate) ty: u32,
    pub(crate) flags: u64,
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) link: u32,
    pub(crate) info: u32,
    pub(crate) entsize: u64,
}

/// A symbol of the symbol table.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Symbol {
    pub(crate) name: u32,
    pub(crate) info: u8,
    pub(crate) other: u8,
    pub(crate) shndx: u16,
    pub(crate) value: u64,
    pub(crate) size: u64,
}

impl Symbol {
    pub(crate) fn ty(&self) -> u8 {
        self.info & 0xf
    }

    pub(crate) fn bind(&self) -> u8 {
        self.info >> 4
    }

    pub(crate) fn visibility(&self) -> u8 {
        self.other & 3
    }
}

/// A relocation of a REL section: where, and against which symbol.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Rel {
    pub(crate) offset: u64,
    pub(crate) sym: u32,
}

/// The object: its bytes and section headers, section 0 included.
pub(crate) struct Elf<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) sections: Vec<Section>,
    shstrndx: usize,
}

impl<'a> Elf<'a> {
    /// The object in `data`, or -EINVAL for anything but a 64-bit
    /// little-endian relocatable BPF object of the current ELF version,
    /// as libelf requires it, with sane headers.
    pub(crate) fn parse(data: &'a [u8]) -> Result<Self, c_int> {
        let bad = || -EINVAL;
        if data.len() < EHDR_SIZE
            || data[..4] != *b"\x7fELF"
            || data[4] != 2
            || data[5] != 1
            || data[6] != 1
        {
            return Err(bad());
        }
        let ty = u16_at(data, 16).ok_or_else(bad)?;
        let machine = u16_at(data, 18).ok_or_else(bad)?;
        if ty != ET_REL || (machine != 0 && machine != EM_BPF) {
            return Err(bad());
        }
        let shoff = u64_at(data, 40).ok_or_else(bad)? as usize;
        let shentsize = u16_at(data, 58).ok_or_else(bad)? as usize;
        let mut shnum = u16_at(data, 60).ok_or_else(bad)? as usize;
        let mut shstrndx = u16_at(data, 62).ok_or_else(bad)? as usize;
        if shentsize != SHDR_SIZE || shoff == 0 {
            return Err(bad());
        }
        let header = |i: usize| -> Option<Section> {
            let h = data.get(shoff + i * SHDR_SIZE..shoff + (i + 1) * SHDR_SIZE)?;
            Some(Section {
                name: u32_at(h, 0)?,
                ty: u32_at(h, 4)?,
                flags: u64_at(h, 8)?,
                offset: u64_at(h, 24)?,
                size: u64_at(h, 32)?,
                link: u32_at(h, 40)?,
                info: u32_at(h, 44)?,
                entsize: u64_at(h, 56)?,
            })
        };
        // Extended numbering keeps the counts in section 0.
        let first = header(0).ok_or_else(bad)?;
        if shnum == 0 {
            shnum = first.size as usize;
        }
        if shstrndx == 0xffff {
            shstrndx = first.link as usize;
        }
        let sections = (0..shnum)
            .map(header)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(bad)?;
        let elf = Elf {
            data,
            sections,
            shstrndx,
        };
        if shstrndx >= shnum || elf.section_data(shstrndx).is_none() {
            return Err(bad());
        }
        Ok(elf)
    }

    /// The contents of section `idx`, empty for NOBITS; none for a
    /// section past the file's end or not whole records, as
    /// elf_getdata() fails them.
    pub(crate) fn section_data(&self, idx: usize) -> Option<&'a [u8]> {
        let s = self.sections.get(idx)?;
        if s.ty == SHT_NOBITS {
            return Some(&[]);
        }
        if s.size % record_size(s.ty) != 0 {
            return None;
        }
        let start = usize::try_from(s.offset).ok()?;
        let end = start.checked_add(usize::try_from(s.size).ok()?)?;
        self.data.get(start..end)
    }

    /// The NUL-terminated string at `off` of the string section `idx`,
    /// which must be one, as elf_strptr() requires.
    pub(crate) fn str_at(&self, idx: usize, off: u32) -> Option<&'a [u8]> {
        if self.sections.get(idx)?.ty != SHT_STRTAB {
            return None;
        }
        let strs = self.section_data(idx)?;
        let s = strs.get(off as usize..)?;
        Some(&s[..s.iter().position(|&c| c == 0)?])
    }

    pub(crate) fn section_name(&self, idx: usize) -> Option<&'a [u8]> {
        self.str_at(self.shstrndx, self.sections.get(idx)?.name)
    }

    /// The index of the section named `name`.
    pub(crate) fn section_by_name(&self, name: &[u8]) -> Option<usize> {
        (1..self.sections.len()).find(|&i| self.section_name(i) == Some(name))
    }

    /// The symbols of the symbol table `idx`.
    pub(crate) fn symbols(&self, idx: usize) -> Option<Vec<Symbol>> {
        let d = self.section_data(idx)?;
        d.as_chunks::<SYM_SIZE>()
            .0
            .iter()
            .map(|s| {
                Some(Symbol {
                    name: u32_at(s, 0)?,
                    info: s[4],
                    other: s[5],
                    shndx: u16_at(s, 6)?,
                    value: u64_at(s, 8)?,
                    size: u64_at(s, 16)?,
                })
            })
            .collect()
    }

    /// The relocations of the REL section `idx`.
    pub(crate) fn rels(&self, idx: usize) -> Option<Vec<Rel>> {
        let d = self.section_data(idx)?;
        d.as_chunks::<REL_SIZE>()
            .0
            .iter()
            .map(|r| {
                Some(Rel {
                    offset: u64_at(r, 0)?,
                    sym: (u64_at(r, 8)? >> 32) as u32,
                })
            })
            .collect()
    }
}
