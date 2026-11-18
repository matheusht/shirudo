// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The ELF side of uprobe upatches: the GNU build ID of a binary, the
//! file offsets of the functions a symbol pattern names in it, resolved
//! as libbpf's elf_resolve_pattern_offsets() resolves them, sorted and
//! each once, and the file offset of one function, as libbpf's
//! elf_find_func_offset() finds it. The file is read as libelf reads
//! it (elf_file.rs), never mapped: a mapping of a binary that a loaded
//! upatch probes would take the probe's breakpoints into shirudo's
//! memory, and the seal takes the authority of a task whose memory a
//! uprobe reached.

use core::ffi::c_int;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;

use crate::errno::{E2BIG, EINVAL, EIO, ENOENT, ERANGE};
use crate::util::elf_file::{
    Data, ElfFile, SHT_DYNSYM, SHT_GNU_VERDEF, SHT_GNU_VERSYM, SHT_NOTE, SHT_SYMTAB,
};

/// `UPATCH_BUILD_ID_MAX`: the longest build ID a upatch names.
pub(crate) const BUILD_ID_MAX: usize = 64;
/// `UPATCH_UPROBE_OFFSETS_MAX`: the most offsets one target attaches to.
const OFFSETS_MAX: usize = 1 << 20;
const STT_FUNC: u8 = 2;
const STB_WEAK: u8 = 2;
/// The version of a versym, without its hidden bit.
const VERSYM_VERSION: u16 = 0x7fff;
/// libbpf's LIBBPF_ERRNO__FORMAT: an ELF it cannot make sense of, two
/// definitions of a function among them.
const LIBBPF_ERRNO_FORMAT: c_int = 4001;
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

/// elf_get_vername(): the name the version definitions of `verdefs`,
/// whose strings are section `strtab`'s, give version `ver`.
fn version_name(elf: &ElfFile<'_>, verdefs: &Data, strtab: usize, ver: u16) -> Option<Vec<u8>> {
    let mut off = 0usize;

    while let Some(d) = elf.verdef(verdefs, off) {
        if d.ndx != ver {
            if d.next == 0 {
                break;
            }
            off = off.checked_add(d.next as usize)?;
            continue;
        }
        let name = elf.verdaux_name(verdefs, off.checked_add(d.aux as usize)?)?;
        return elf.strings(strtab)?.at(name).map(<[u8]>::to_vec);
    }
    None
}

/// The function `name` names in the symbol table of `sh_type`, as
/// libbpf's symbol iterator and symbol_match() find it, folded into
/// `found`, the offset libbpf carries from table to table: Err(-ENOENT)
/// for no such table, another error for one that does not read or two
/// functions of the name, neither weak, at two places.
fn table_func_offset(
    elf: &ElfFile<'_>,
    sh_type: u32,
    name: &[u8],
    version: Option<&[u8]>,
    found: &mut i64,
) -> Result<(), c_int> {
    let (idx, sh) = elf.section_of_type(sh_type).ok_or(-ENOENT)?;
    if sh.entsize == 0 {
        return Err(-EINVAL);
    }
    let (link, entsize) = (sh.link as usize, sh.entsize);
    let syms = elf.data(idx).ok_or(-EINVAL)?;
    let nr = syms.bytes.len() as u64 / entsize;
    let (mut versyms, mut verdefs) = (None, None);
    if sh_type == SHT_DYNSYM {
        if let Some((v, _)) = elf.section_of_type(SHT_GNU_VERSYM) {
            versyms = elf.data(v);
            if let Some((d, dsh)) = elf.section_of_type(SHT_GNU_VERDEF) {
                verdefs = Some((elf.data(d).ok_or(-EINVAL)?, dsh.link as usize));
            }
        }
    }
    let strings = elf.strings(link);
    let mut last_bind = None;

    for i in 0..nr.min(c_int::MAX as u64 + 1) as usize {
        let Some(sym) = elf.symbol(&syms, i).filter(|s| s.info & 0xf == STT_FUNC) else {
            continue;
        };
        let Some(sym_name) = strings.as_ref().and_then(|s| s.at(sym.name)) else {
            continue;
        };
        let Some(ssh) = elf.section(usize::from(sym.shndx)) else {
            continue;
        };
        let ver = match &versyms {
            Some(v) => match elf.versym(v, i) {
                Some(ver) => ver & VERSYM_VERSION,
                None => continue,
            },
            None => 0,
        };
        // func, func@LIB_VER or func@@LIB_VER, but not func2.
        if !sym_name.starts_with(name) || !matches!(sym_name.get(name.len()), None | Some(b'@')) {
            continue;
        }
        if let Some(version) = version {
            let matched = if sh_type == SHT_DYNSYM {
                verdefs
                    .as_ref()
                    .and_then(|(d, strtab)| version_name(elf, d, *strtab, ver))
                    .is_some_and(|v| v == version)
            } else {
                sym_name.len() == name.len() + 1 + version.len()
                    && sym_name[name.len() + 1..] == *version
            };
            if !matched {
                continue;
            }
        }
        let offset = sym.value.wrapping_sub(ssh.addr).wrapping_add(ssh.offset) as i64;
        let bind = sym.info >> 4;
        if *found > 0 {
            if offset == *found {
                continue;
            }
            if last_bind != Some(STB_WEAK) && bind != STB_WEAK {
                return Err(-LIBBPF_ERRNO_FORMAT);
            }
            if bind == STB_WEAK {
                continue;
            }
        }
        *found = offset;
        last_bind = Some(bind);
    }
    Ok(())
}

/// elf_find_func_offset(): the file offset of the function `func` of
/// `elf`, `func@LIB_VER` or `func@@LIB_VER` for one version of it, from
/// .dynsym, else .symtab; -ENOENT for none, or one at offset 0.
fn func_offset(elf: &ElfFile<'_>, func: &[u8]) -> Result<u64, c_int> {
    let (name, version) = match func.iter().position(|&c| c == b'@') {
        Some(at) => {
            let rest = &func[at + 1..];
            (&func[..at], Some(rest.strip_prefix(b"@").unwrap_or(rest)))
        }
        None => (func, None),
    };
    // libbpf's ret: each table starts it again, at -ENOENT for a table
    // the file lacks.
    let mut ret = -i64::from(ENOENT);

    for sh_type in [SHT_DYNSYM, SHT_SYMTAB] {
        // The full name a symbol table holds for func@LIB_VER.
        let version = if sh_type == SHT_SYMTAB && version.is_some() {
            Some(&func[name.len() + 1..])
        } else {
            version
        };
        let mut found = 0i64;
        match table_func_offset(elf, sh_type, name, version, &mut found) {
            Ok(()) => ret = found,
            Err(err) if err == -ENOENT => {
                ret = -i64::from(ENOENT);
                continue;
            }
            Err(err) => return Err(err),
        }
        if ret > 0 {
            break;
        }
    }
    match ret {
        r if r > 0 => Ok(r as u64),
        0 => Err(-ENOENT),
        // As elf_target_resolve_func() narrows libbpf's long.
        r => Err(r as c_int),
    }
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

/// elf_target_resolve_func(): the build ID of the ELF file at the
/// absolute `path` and one file offset, of the function `func` plus
/// `offset`, or `offset` itself without one; -ERANGE for an offset past
/// the file.
pub(crate) fn resolve_func(path: &[u8], func: Option<&[u8]>, offset: u64) -> Result<Target, c_int> {
    if path.first() != Some(&b'/') || func.is_some_and(<[u8]>::is_empty) {
        return Err(-EINVAL);
    }
    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(path));
    let file = File::open(path).map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
    let size = file
        .metadata()
        .map_err(|e| -e.raw_os_error().unwrap_or(EIO))?
        .len();
    let build_id = build_id(&file)?;
    let base = match func {
        Some(func) => func_offset(&ElfFile::open(&file).ok_or(-LIBBPF_ERRNO_FORMAT)?, func)?,
        None => 0,
    };
    match base.checked_add(offset) {
        Some(at) if at < size => Ok(Target {
            build_id,
            offsets: vec![at],
        }),
        _ => Err(-ERANGE),
    }
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
