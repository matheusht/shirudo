// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The ELF side of uprobe.multi upatches: the GNU build ID of a binary,
//! and the file offsets of the functions a symbol pattern names in it,
//! resolved as libbpf's elf_resolve_pattern_offsets() resolves them,
//! sorted and each once. The file is read as libelf reads it
//! (elf_file.rs).

use core::ffi::c_int;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;

use crate::errno::{E2BIG, EINVAL, EIO, ENOENT};
use crate::util::elf_file::{
    Data, ElfFile, SHT_DYNSYM, SHT_GNU_VERDEF, SHT_GNU_VERSYM, SHT_NOTE, SHT_SYMTAB,
};

/// `UPATCH_BUILD_ID_MAX`: the longest build ID a upatch names.
pub(crate) const BUILD_ID_MAX: usize = 64;
/// `UPATCH_UPROBE_OFFSETS_MAX`: the most offsets one target attaches to.
const OFFSETS_MAX: usize = 1 << 20;
const STT_FUNC: u8 = 2;
const PT_NOTE: u32 = 4;
const NT_GNU_BUILD_ID: u32 = 3;

/// A uprobe target resolved: its build ID, and the offsets of the
/// functions its pattern names, sorted and each once.
#[derive(Default)]
pub(crate) struct Target {
    pub(crate) build_id: Vec<u8>,
    pub(crate) offsets: Vec<u64>,
}

/// glob_match() of libbpf, after perf's: `?` any one byte, `*` any run.
fn glob_match(s: &[u8], p: &[u8]) -> bool {
    let (mut s, mut p) = (s, p);
    while let (Some(&c), Some(&q)) = (s.first(), p.first()) {
        if q == b'*' {
            break;
        }
        if q != b'?' && c != q {
            return false;
        }
        s = &s[1..];
        p = &p[1..];
    }
    if p.first() == Some(&b'*') {
        while p.first() == Some(&b'*') {
            p = &p[1..];
        }
        if p.is_empty() {
            return true;
        }
        while !s.is_empty() {
            if glob_match(s, p) {
                return true;
            }
            s = &s[1..];
        }
    }
    s.is_empty() && p.is_empty()
}

/// The file offsets of the functions in the symbol table of `sh_type`
/// whose names match `pattern`, onto `offsets`, as libbpf's symbol
/// iterator finds them: -ENOENT for no such table, -EINVAL for one, or
/// its versions, that does not read.
fn table_offsets(elf: &ElfFile<'_>, sh_type: u32, pattern: &[u8], offsets: &mut Vec<u64>) -> c_int {
    let Some((idx, sh)) = elf.section_of_type(sh_type) else {
        return -ENOENT;
    };
    if sh.entsize == 0 {
        return -EINVAL;
    }
    let (link, entsize) = (sh.link as usize, sh.entsize);
    let Some(syms) = elf.data(idx) else {
        return -EINVAL;
    };
    let nr = syms.bytes.len() as u64 / entsize;
    // Versions are a dynamic symbol table's alone.
    let mut versyms: Option<Data> = None;
    if sh_type == SHT_DYNSYM {
        if let Some((v, _)) = elf.section_of_type(SHT_GNU_VERSYM) {
            versyms = elf.data(v);
            if let Some((d, _)) = elf.section_of_type(SHT_GNU_VERDEF) {
                if elf.data(d).is_none() {
                    return -EINVAL;
                }
            }
        }
    }
    let strings = elf.strings(link);
    for i in 0..nr.min(c_int::MAX as u64 + 1) as usize {
        let Some(sym) = elf.symbol(&syms, i).filter(|s| s.info & 0xf == STT_FUNC) else {
            continue;
        };
        let Some(name) = strings.as_ref().and_then(|s| s.at(sym.name)) else {
            continue;
        };
        let Some(ssh) = elf.section(usize::from(sym.shndx)) else {
            continue;
        };
        if versyms.as_ref().is_some_and(|v| elf.versym(v, i).is_none()) {
            continue;
        }
        if glob_match(name, pattern) {
            offsets.push(sym.value.wrapping_sub(ssh.addr).wrapping_add(ssh.offset));
        }
    }
    0
}

/// elf_resolve_pattern_offsets(): the file offsets of the functions of
/// `elf` whose names match `pattern`, from .symtab, else .dynsym, or
/// -ENOENT for none.
fn pattern_offsets(elf: &ElfFile<'_>, pattern: &[u8]) -> Result<Vec<u64>, c_int> {
    let mut offsets = Vec::new();
    for sh_type in [SHT_SYMTAB, SHT_DYNSYM] {
        match table_offsets(elf, sh_type, pattern, &mut offsets) {
            0 => {}
            err if err == -ENOENT => {}
            err => return Err(err),
        }
        if !offsets.is_empty() {
            return Ok(offsets);
        }
    }
    Err(-ENOENT)
}

/// The GNU build ID among the notes of `data`: Ok(None) for none, or
/// -E2BIG for one empty or longer than a upatch holds.
fn note_build_id(elf: &ElfFile<'_>, data: &Data) -> Result<Option<Vec<u8>>, c_int> {
    let size = data.bytes.len();
    let mut off = 0usize;

    while off < size {
        let Some((n, next)) = elf.note(data, off) else {
            break;
        };
        let (name_len, desc_len) = (n.namesz as usize, n.descsz as usize);
        if n.ty == NT_GNU_BUILD_ID
            && n.namesz == 4
            && n.name_off <= size
            && name_len <= size - n.name_off
            && n.desc_off <= size
            && desc_len <= size - n.desc_off
            && data.bytes[n.name_off..n.name_off + 4] == *b"GNU\0"
        {
            if desc_len == 0 || desc_len > BUILD_ID_MAX {
                return Err(-E2BIG);
            }
            return Ok(Some(data.bytes[n.desc_off..n.desc_off + desc_len].to_vec()));
        }
        if next <= off {
            break;
        }
        off = next;
    }
    Ok(None)
}

/// The GNU build ID of `elf` from its note sections, or from its note
/// segments when the section headers are stripped: -ENOENT for none.
fn elf_build_id(elf: &ElfFile<'_>) -> Result<Vec<u8>, c_int> {
    for (idx, sh) in elf.sections() {
        if sh.ty != SHT_NOTE {
            continue;
        }
        if let Some(data) = elf.data(idx) {
            if let Some(id) = note_build_id(elf, &data)? {
                return Ok(id);
            }
        }
    }
    // Section headers can be stripped; fall back to PT_NOTE segments.
    let phnum = elf.phdr_count().ok_or(-EINVAL)?;
    for i in 0..phnum {
        let phdr = elf.phdr(i).ok_or(-EINVAL)?;
        if phdr.ty != PT_NOTE || phdr.filesz == 0 {
            continue;
        }
        let data = elf.note_chunk(phdr.offset, phdr.filesz).ok_or(-EINVAL)?;
        if let Some(id) = note_build_id(elf, &data)? {
            return Ok(id);
        }
    }
    Err(-ENOENT)
}

/// The GNU build ID of the ELF file `file`: -EINVAL for one that does
/// not read as ELF.
pub(crate) fn build_id(file: &File) -> Result<Vec<u8>, c_int> {
    let elf = ElfFile::open(file).ok_or(-EINVAL)?;
    elf_build_id(&elf)
}

/// The build ID of the ELF file at the absolute `path`, and the offsets
/// libbpf resolves for `pattern` in it, sorted and each once.
pub(crate) fn resolve(path: &[u8], pattern: &[u8]) -> Result<Target, c_int> {
    if path.first() != Some(&b'/') || pattern.is_empty() {
        return Err(-EINVAL);
    }
    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(path));
    let file = File::open(path).map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
    let elf = ElfFile::open(&file).ok_or(-EINVAL)?;
    let build_id = elf_build_id(&elf)?;
    let mut offsets = pattern_offsets(&elf, pattern)?;
    if offsets.len() > OFFSETS_MAX || offsets.len() > u32::MAX as usize {
        return Err(-E2BIG);
    }
    offsets.sort_unstable();
    offsets.dedup();
    Ok(Target { build_id, offsets })
}

mod capi {
    use core::ffi::c_int;
    use std::fs::File;
    use std::mem::ManuallyDrop;
    use std::os::fd::FromRawFd;

    /// The GNU build ID of the ELF file open at `fd` into `build_id`,
    /// room for BUILD_ID_MAX bytes, and its length: 0, or -errno with
    /// the length 0.
    ///
    /// # Safety
    ///
    /// `build_id` is NULL or room for an ID, and `build_id_len` NULL or
    /// room for its length.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn elf_build_id_fd(
        fd: c_int,
        build_id: *mut u8,
        build_id_len: *mut u32,
    ) -> c_int {
        if fd < 0 || build_id.is_null() || build_id_len.is_null() {
            return -crate::errno::EINVAL;
        }
        // SAFETY: the caller's room for the length.
        unsafe { *build_id_len = 0 };
        // SAFETY: the caller's fd, borrowed, never closed here.
        let file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
        match super::build_id(&file) {
            Ok(id) => {
                // SAFETY: the caller's room for an ID, which holds
                // BUILD_ID_MAX bytes, and for its length.
                unsafe {
                    core::ptr::copy_nonoverlapping(id.as_ptr(), build_id, id.len());
                    *build_id_len = id.len() as u32;
                }
                0
            }
            Err(err) => err,
        }
    }
}
