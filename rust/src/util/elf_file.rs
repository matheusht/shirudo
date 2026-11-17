// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! ELF files as elfutils' libelf reads them, for what elf_target.rs
//! takes of them: the section headers, a section's data, a string
//! table's strings, the program headers and a run of the file's bytes.
//! Either class and either byte order, as libelf, and its checks, so
//! that a file it refuses or reads in part is refused or read alike.
//! The file is read as it is asked for, never whole; a read that fails
//! fails as libelf's descriptor would, with nothing more said.
//!
//! One difference: libelf inflates a compressed string table, which no
//! linker writes, where this refuses it.

use std::fs::File;
use std::os::unix::fs::FileExt;

pub(crate) const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
pub(crate) const SHT_NOTE: u32 = 7;
const SHT_NOBITS: u32 = 8;
pub(crate) const SHT_DYNSYM: u32 = 11;
pub(crate) const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
pub(crate) const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;
const SHF_COMPRESSED: u64 = 1 << 11;
const PN_XNUM: u64 = 0xffff;
const EI_NIDENT: usize = 16;

/// What libelf takes a section's data as, which gelf_getsym(),
/// gelf_getversym() and gelf_getnote() check.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Sym,
    Half,
    Nhdr,
    Nhdr8,
    /// A compressed section's: its header, then what it compresses.
    Chdr,
    Other,
}

/// A section header, of either class.
#[derive(Clone, Copy, Default)]
pub(crate) struct Shdr {
    pub(crate) ty: u32,
    pub(crate) flags: u64,
    pub(crate) addr: u64,
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) link: u32,
    pub(crate) info: u32,
    pub(crate) addralign: u64,
    pub(crate) entsize: u64,
}

/// A symbol, of the fields read of it.
pub(crate) struct Sym {
    pub(crate) name: u32,
    pub(crate) info: u8,
    pub(crate) shndx: u16,
    pub(crate) value: u64,
}

/// A program header, of the fields read of it.
pub(crate) struct Phdr {
    pub(crate) ty: u32,
    pub(crate) offset: u64,
    pub(crate) filesz: u64,
}

/// A note's header, and where its name and descriptor lie in its data.
pub(crate) struct Note {
    pub(crate) namesz: u32,
    pub(crate) descsz: u32,
    pub(crate) ty: u32,
    pub(crate) name_off: usize,
    pub(crate) desc_off: usize,
}

/// A section's data, or a run of the file's, as libelf hands it out.
pub(crate) struct Data {
    pub(crate) bytes: Vec<u8>,
    pub(crate) kind: Kind,
}

/// The strings of a string table.
pub(crate) struct Strings(Vec<u8>);

impl Strings {
    /// elf_strptr(): the string at `off`, NUL-terminated within the
    /// table, without its NUL.
    pub(crate) fn at(&self, off: u32) -> Option<&[u8]> {
        let rest = self.0.get(off as usize..)?;
        rest.iter().position(|&c| c == 0).map(|n| &rest[..n])
    }
}

/// An ELF file open for reading.
pub(crate) struct ElfFile<'f> {
    file: &'f File,
    size: u64,
    is64: bool,
    big: bool,
    phoff: u64,
    phnum: u64,
    /// Every section's header, the zeroth among them; none when the
    /// table does not fit in the file, which libelf takes for none.
    shdrs: Vec<Shdr>,
}

impl<'f> ElfFile<'f> {
    /// elf_begin() of an ELF file: None for anything else, or a file
    /// that does not read.
    pub(crate) fn open(file: &'f File) -> Option<Self> {
        let size = file.metadata().ok()?.len();
        let mut ehdr = [0u8; 64];
        if size < EI_NIDENT as u64 {
            return None;
        }
        file.read_exact_at(&mut ehdr[..EI_NIDENT], 0).ok()?;
        if ehdr[..4] != *b"\x7fELF" || !(1..=2).contains(&ehdr[4]) || !(1..=2).contains(&ehdr[5]) {
            return None;
        }
        if ehdr[6] != 1 {
            return None;
        }
        // The whole of the ELF header, which libelf refuses a file short of.
        let ehsize = if ehdr[4] == 2 { 64 } else { 52 };
        if size < ehsize as u64 {
            return None;
        }
        file.read_exact_at(&mut ehdr[EI_NIDENT..ehsize], EI_NIDENT as u64)
            .ok()?;
        let mut elf = ElfFile {
            file,
            size,
            is64: ehdr[4] == 2,
            big: ehdr[5] == 2,
            phoff: 0,
            phnum: 0,
            shdrs: Vec::new(),
        };
        let (shoff, shnum, phoff, phnum) = if elf.is64 {
            (
                elf.u(&ehdr, 40, 8),
                elf.u(&ehdr, 60, 2),
                elf.u(&ehdr, 32, 8),
                elf.u(&ehdr, 56, 2),
            )
        } else {
            (
                elf.u(&ehdr, 32, 4),
                elf.u(&ehdr, 48, 2),
                elf.u(&ehdr, 28, 4),
                elf.u(&ehdr, 44, 2),
            )
        };
        elf.phoff = phoff;
        elf.phnum = phnum;
        let count = elf.shnum(shoff, shnum)?;
        if count != 0 {
            let len = count.checked_mul(elf.shdr_size())?;
            let mut table = vec![0u8; usize::try_from(len).ok()?];
            file.read_exact_at(&mut table, shoff).ok()?;
            elf.shdrs = table
                .chunks_exact(elf.shdr_size() as usize)
                .map(|b| elf.shdr(b))
                .collect();
        }
        Some(elf)
    }

    /// An unsigned field of `width` bytes at `off` of `b`, in the file's
    /// byte order.
    fn u(&self, b: &[u8], off: usize, width: usize) -> u64 {
        let f = &b[off..off + width];
        let fold = |v: u64, &c: &u8| (v << 8) | u64::from(c);
        if self.big {
            f.iter().fold(0, fold)
        } else {
            f.iter().rev().fold(0, fold)
        }
    }

    fn shdr_size(&self) -> u64 {
        if self.is64 { 64 } else { 40 }
    }

    fn phdr_size(&self) -> u64 {
        if self.is64 { 56 } else { 32 }
    }

    fn sym_size(&self) -> usize {
        if self.is64 { 24 } else { 16 }
    }

    fn shdr(&self, b: &[u8]) -> Shdr {
        let (w, o) = if self.is64 { (8, 24) } else { (4, 16) };
        Shdr {
            ty: self.u(b, 4, 4) as u32,
            flags: self.u(b, 8, w),
            addr: self.u(b, 8 + w, w),
            offset: self.u(b, o, w),
            size: self.u(b, o + w, w),
            link: self.u(b, o + 2 * w, 4) as u32,
            info: self.u(b, o + 2 * w + 4, 4) as u32,
            addralign: self.u(b, o + 2 * w + 8, w),
            entsize: self.u(b, o + 3 * w + 8, w),
        }
    }

    /// libelf's count of the sections: e_shnum, or the zeroth section's
    /// size when that is 0, and none when the table runs past the file;
    /// None, refusing the file, for a size of more than 32 bits there.
    fn shnum(&self, shoff: u64, shnum: u64) -> Option<u64> {
        let entry = self.shdr_size();
        let mut count = shnum;
        if count == 0 && shoff != 0 {
            if shoff >= self.size || self.size - shoff < entry {
                return Some(0);
            }
            let mut zeroth = vec![0u8; entry as usize];
            self.file.read_exact_at(&mut zeroth, shoff).ok()?;
            count = self.shdr(&zeroth).size;
            if count > u64::from(u32::MAX) {
                return None;
            }
        }
        let fits = shoff <= self.size
            && count
                .checked_mul(entry)
                .is_some_and(|len| self.size - shoff >= len);
        Some(if fits { count } else { 0 })
    }

    /// elf_nextscn() from the start: the sections but the zeroth.
    pub(crate) fn sections(&self) -> impl Iterator<Item = (usize, &Shdr)> {
        self.shdrs.iter().enumerate().skip(1)
    }

    /// elf_getscn() and gelf_getshdr(): the header of section `idx`.
    pub(crate) fn section(&self, idx: usize) -> Option<&Shdr> {
        self.shdrs.get(idx)
    }

    /// The first section of type `ty`, as elf_nextscn() finds it.
    pub(crate) fn section_of_type(&self, ty: u32) -> Option<(usize, &Shdr)> {
        self.sections().find(|(_, sh)| sh.ty == ty)
    }

    /// The size of the records libelf reads a section of type `ty` as,
    /// of the types read here, of which its size must be a multiple.
    fn record_size(&self, ty: u32) -> u64 {
        match ty {
            SHT_SYMTAB | SHT_DYNSYM => self.sym_size() as u64,
            SHT_GNU_VERSYM => 2,
            _ => 1,
        }
    }

    /// elf_getdata() of section `idx`, read whole: None when libelf
    /// would refuse it.
    pub(crate) fn data(&self, idx: usize) -> Option<Data> {
        let sh = *self.section(idx)?;
        let compressed = sh.flags & SHF_COMPRESSED != 0;
        let mut bytes = Vec::new();
        if sh.size != 0 && sh.ty != SHT_NOBITS {
            let unit = if compressed {
                1
            } else {
                self.record_size(sh.ty)
            };
            if sh.size % unit != 0 || sh.offset > self.size || self.size - sh.offset < sh.size {
                return None;
            }
            bytes = vec![0u8; usize::try_from(sh.size).ok()?];
            self.file.read_exact_at(&mut bytes, sh.offset).ok()?;
        }
        let kind = match sh.ty {
            _ if compressed => Kind::Chdr,
            SHT_SYMTAB | SHT_DYNSYM => Kind::Sym,
            SHT_GNU_VERSYM => Kind::Half,
            SHT_NOTE if sh.addralign == 8 => Kind::Nhdr8,
            SHT_NOTE => Kind::Nhdr,
            _ => Kind::Other,
        };
        Some(Data { bytes, kind })
    }

    /// The string table at section `idx`, which elf_strptr() reads: None
    /// when every string of it would be refused.
    pub(crate) fn strings(&self, idx: usize) -> Option<Strings> {
        let sh = self.section(idx)?;
        if sh.ty != SHT_STRTAB || sh.flags & SHF_COMPRESSED != 0 {
            return None;
        }
        self.data(idx).map(|d| Strings(d.bytes))
    }

    /// gelf_getsym(): symbol `i` of `data`.
    pub(crate) fn symbol(&self, data: &Data, i: usize) -> Option<Sym> {
        let size = self.sym_size();
        if data.kind != Kind::Sym || i >= data.bytes.len() / size {
            return None;
        }
        let b = &data.bytes[i * size..][..size];
        Some(if self.is64 {
            Sym {
                name: self.u(b, 0, 4) as u32,
                info: b[4],
                shndx: self.u(b, 6, 2) as u16,
                value: self.u(b, 8, 8),
            }
        } else {
            Sym {
                name: self.u(b, 0, 4) as u32,
                info: b[12],
                shndx: self.u(b, 14, 2) as u16,
                value: self.u(b, 4, 4),
            }
        })
    }

    /// gelf_getversym(): version `i` of `data`.
    pub(crate) fn versym(&self, data: &Data, i: usize) -> Option<u16> {
        if data.kind != Kind::Half || i >= data.bytes.len() / 2 {
            return None;
        }
        Some(self.u(&data.bytes, i * 2, 2) as u16)
    }

    /// gelf_getnote(): the note at `off` of `data`, and the offset of
    /// the next; None where libelf returns 0.
    pub(crate) fn note(&self, data: &Data, off: usize) -> Option<(Note, usize)> {
        let wide = match data.kind {
            Kind::Nhdr => false,
            Kind::Nhdr8 => true,
            _ => return None,
        };
        let size = data.bytes.len();
        if off > size || size - off < 12 {
            return None;
        }
        let h = &data.bytes[off..off + 12];
        let (namesz, descsz, ty) = (
            self.u(h, 0, 4) as u32,
            self.u(h, 4, 4) as u32,
            self.u(h, 8, 4) as u32,
        );
        let name_off = off + 12;
        if namesz as usize > size || name_off > size - namesz as usize {
            return None;
        }
        let (padded, at) = if wide {
            (
                descsz.wrapping_add(7) & !7,
                (name_off + namesz as usize + 7) & !7,
            )
        } else {
            (
                descsz.wrapping_add(3) & !3,
                (name_off + namesz as usize + 3) & !3,
            )
        };
        if at > size || size - at < padded as usize || (padded == 0 && descsz != 0) {
            return None;
        }
        let note = Note {
            namesz,
            descsz,
            ty,
            name_off,
            desc_off: at,
        };
        Some((note, at + padded as usize))
    }

    /// The program header count e_phnum gives, or the zeroth section's
    /// sh_info for PN_XNUM.
    fn raw_phnum(&self) -> u64 {
        match (self.phnum, self.shdrs.first()) {
            (PN_XNUM, Some(zeroth)) => u64::from(zeroth.info),
            (n, _) => n,
        }
    }

    /// elf_getphdrnum(): the program header count, cut to those the file
    /// holds whole.
    pub(crate) fn phdr_count(&self) -> Option<u64> {
        if self.phoff == 0 {
            return Some(0);
        }
        if self.phoff >= self.size {
            return None;
        }
        let (n, entry) = (self.raw_phnum(), self.phdr_size());
        Some(if (self.size - self.phoff) / entry < n {
            (self.size - self.phoff) / entry
        } else {
            n
        })
    }

    /// gelf_getphdr(): program header `i`, None unless the whole table
    /// e_phnum gives fits in the file.
    pub(crate) fn phdr(&self, i: u64) -> Option<Phdr> {
        let (n, entry) = (self.raw_phnum(), self.phdr_size());
        let len = n.checked_mul(entry)?;
        if n == 0 || self.phoff == 0 || self.phoff > self.size || self.size - self.phoff < len {
            return None;
        }
        if i >= self.phdr_count()? {
            return None;
        }
        let mut b = vec![0u8; entry as usize];
        self.file
            .read_exact_at(&mut b, self.phoff + i * entry)
            .ok()?;
        Some(if self.is64 {
            Phdr {
                ty: self.u(&b, 0, 4) as u32,
                offset: self.u(&b, 8, 8),
                filesz: self.u(&b, 32, 8),
            }
        } else {
            Phdr {
                ty: self.u(&b, 0, 4) as u32,
                offset: self.u(&b, 4, 4),
                filesz: self.u(&b, 16, 4),
            }
        })
    }

    /// elf_getdata_rawchunk() of notes: the `size` bytes at `off`.
    pub(crate) fn note_chunk(&self, off: u64, size: u64) -> Option<Data> {
        if i64::try_from(off).is_err() || off > self.size || self.size - off < size {
            return None;
        }
        let mut bytes = vec![0u8; usize::try_from(size).ok()?];
        self.file.read_exact_at(&mut bytes, off).ok()?;
        Some(Data {
            bytes,
            kind: Kind::Nhdr,
        })
    }
}
