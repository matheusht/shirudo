// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The ELF side of uprobe.multi upatches behind `util/elf_target.h`: the
//! GNU build ID of a binary, and the file offsets of the functions a
//! symbol pattern names in it, resolved as libbpf's
//! elf_resolve_pattern_offsets() resolves them, sorted and each once.

use core::ffi::{c_char, c_int};
use core::ptr;

use crate::errno::{E2BIG, EINVAL, ENOENT, ENOMEM};
use crate::heap::{xcalloc, xfree};
use crate::sys::elf::{
    ELF_C_READ_MMAP, ELF_K_ELF, ELF_T_NHDR, EV_CURRENT, EV_NONE, Elf, ElfData, ElfScn, GElfEhdr,
    GElfNhdr, GElfPhdr, GElfShdr, GElfSym, NT_GNU_BUILD_ID, PT_NOTE, SHT_DYNSYM, SHT_GNU_VERDEF,
    SHT_GNU_VERSYM, SHT_NOTE, SHT_SYMTAB, STT_FUNC, elf_begin, elf_end, elf_getdata,
    elf_getdata_rawchunk, elf_getphdrnum, elf_getscn, elf_kind, elf_nextscn, elf_strptr,
    elf_version, gelf_getehdr, gelf_getnote, gelf_getphdr, gelf_getshdr, gelf_getsym,
    gelf_getversym,
};
use crate::sys::libc::{O_CLOEXEC, O_RDONLY, close, errno, open};

/// `UPATCH_BUILD_ID_MAX`: the longest build ID a upatch names.
const BUILD_ID_MAX: usize = 64;
/// `UPATCH_UPROBE_OFFSETS_MAX`: the most offsets one target attaches to.
const OFFSETS_MAX: usize = 1 << 20;

/// `struct elf_target`.
#[repr(C)]
pub struct ElfTarget {
    pub(crate) build_id: [u8; BUILD_ID_MAX],
    pub(crate) build_id_len: u32,
    pub(crate) offsets: *mut u64,
    pub(crate) nr_offsets: u32,
    pub(crate) offsets_cap: u32,
}

const _: () = assert!(size_of::<ElfTarget>() == 88);

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

/// The section of `sh_type` after `scn`, the first for NULL.
///
/// # Safety
///
/// `elf` is a descriptor and `scn` NULL or a section of it.
unsafe fn next_scn_by_type(elf: *mut Elf, sh_type: u32, mut scn: *mut ElfScn) -> *mut ElfScn {
    loop {
        // SAFETY: the caller's descriptor and section.
        scn = unsafe { elf_nextscn(elf, scn) };
        if scn.is_null() {
            return scn;
        }
        let mut sh = GElfShdr::default();
        // SAFETY: a section of the descriptor, and room for its header.
        if !unsafe { gelf_getshdr(scn, &mut sh) }.is_null() && sh.sh_type == sh_type {
            return scn;
        }
    }
}

/// The file offsets of the functions in the symbol table of `sh_type`
/// whose names match `pattern`, onto `offsets`, as libbpf's symbol
/// iterator finds them: -ENOENT for no such table, -EINVAL for one, or
/// its versions, that does not read.
///
/// # Safety
///
/// `elf` is a descriptor.
unsafe fn table_offsets(
    elf: *mut Elf,
    sh_type: u32,
    pattern: &[u8],
    offsets: &mut Vec<u64>,
) -> c_int {
    let mut ehdr = GElfEhdr::default();
    let mut sh = GElfShdr::default();

    // SAFETY: the caller's descriptor and room for its header.
    if unsafe { gelf_getehdr(elf, &mut ehdr) }.is_null() {
        return -EINVAL;
    }
    // SAFETY: as above.
    let scn = unsafe { next_scn_by_type(elf, sh_type, ptr::null_mut()) };
    if scn.is_null() {
        return -ENOENT;
    }
    // SAFETY: a section of the descriptor and room for its header.
    if unsafe { gelf_getshdr(scn, &mut sh) }.is_null() || sh.sh_entsize == 0 {
        return -EINVAL;
    }
    let strtab = sh.sh_link as usize;
    // SAFETY: the section.
    let syms = unsafe { elf_getdata(scn, ptr::null_mut()) };
    if syms.is_null() {
        return -EINVAL;
    }
    // SAFETY: the data libelf gave.
    let nr = unsafe { (*syms).d_size } / sh.sh_entsize as usize;
    // Versions are a dynamic symbol table's alone.
    let mut versyms = ptr::null_mut();
    if sh_type == SHT_DYNSYM {
        // SAFETY: the descriptor.
        let scn = unsafe { next_scn_by_type(elf, SHT_GNU_VERSYM, ptr::null_mut()) };
        if !scn.is_null() {
            // SAFETY: a section of the descriptor.
            versyms = unsafe { elf_getdata(scn, ptr::null_mut()) };
            // SAFETY: the descriptor.
            let scn = unsafe { next_scn_by_type(elf, SHT_GNU_VERDEF, ptr::null_mut()) };
            if !scn.is_null() {
                // SAFETY: a section of the descriptor.
                let verdefs = unsafe { elf_getdata(scn, ptr::null_mut()) };
                // SAFETY: as above, and room for its header.
                if verdefs.is_null() || unsafe { gelf_getshdr(scn, &mut sh) }.is_null() {
                    return -EINVAL;
                }
            }
        }
    }
    for idx in 0..nr {
        let mut sym = GElfSym::default();
        let mut ssh = GElfShdr::default();
        let mut versym = 0u16;
        let Ok(i) = c_int::try_from(idx) else {
            break;
        };
        // SAFETY: the symbols libelf gave, and room for one.
        if unsafe { gelf_getsym(syms, i, &mut sym) }.is_null() || sym.st_info & 0xf != STT_FUNC {
            continue;
        }
        // SAFETY: the descriptor, the table's strings and an offset.
        let name = unsafe { elf_strptr(elf, strtab, sym.st_name as usize) };
        if name.is_null() {
            continue;
        }
        // SAFETY: the descriptor and an index.
        let sym_scn = unsafe { elf_getscn(elf, usize::from(sym.st_shndx)) };
        // SAFETY: NULL or a section, and room for its header.
        if sym_scn.is_null() || unsafe { gelf_getshdr(sym_scn, &mut ssh) }.is_null() {
            continue;
        }
        // SAFETY: the versions libelf gave, and room for one.
        if !versyms.is_null() && unsafe { gelf_getversym(versyms, i, &mut versym) }.is_null() {
            continue;
        }
        // SAFETY: a name libelf found in the table's strings.
        if glob_match(unsafe { crate::ffi::c_str(name) }, pattern) {
            offsets.push(
                sym.st_value
                    .wrapping_sub(ssh.sh_addr)
                    .wrapping_add(ssh.sh_offset),
            );
        }
    }
    0
}

/// elf_resolve_pattern_offsets(): the file offsets of the functions of
/// `elf` whose names match `pattern`, from .symtab, else .dynsym, or
/// -ENOENT for none.
///
/// # Safety
///
/// `elf` is a descriptor.
unsafe fn pattern_offsets(elf: *mut Elf, pattern: &[u8]) -> Result<Vec<u64>, c_int> {
    let mut offsets = Vec::new();
    for sh_type in [SHT_SYMTAB, SHT_DYNSYM] {
        // SAFETY: the caller's descriptor.
        match unsafe { table_offsets(elf, sh_type, pattern, &mut offsets) } {
            0 | ENOENT_NEG => {}
            err => return Err(err),
        }
        if !offsets.is_empty() {
            return Ok(offsets);
        }
    }
    Err(-ENOENT)
}

const ENOENT_NEG: c_int = -ENOENT;

/// The GNU build ID among the notes of `data` into `build_id`: 0, -E2BIG
/// for one empty or longer than a upatch holds, or -ENOENT for none.
///
/// # Safety
///
/// `data` is libelf's, and `build_id` and `build_id_len` room for an ID
/// and its length.
unsafe fn note_build_id(data: *mut ElfData, build_id: *mut u8, build_id_len: *mut u32) -> c_int {
    // SAFETY: libelf's data, which outlives this call.
    let (buf, size) = unsafe { ((*data).d_buf.cast::<u8>().cast_const(), (*data).d_size) };
    let mut off = 0usize;

    while off < size {
        let mut nhdr = GElfNhdr::default();
        let mut name_off = 0usize;
        let mut desc_off = 0usize;
        // SAFETY: the data, an offset in it, and room for the header and
        // the offsets of the note's name and descriptor.
        let next = unsafe { gelf_getnote(data, off, &mut nhdr, &mut name_off, &mut desc_off) };

        if next == 0 {
            break;
        }
        let name_len = nhdr.n_namesz as usize;
        let desc_len = nhdr.n_descsz as usize;

        if nhdr.n_type == NT_GNU_BUILD_ID
            && nhdr.n_namesz == 4
            && name_off <= size
            && name_len <= size - name_off
            && desc_off <= size
            && desc_len <= size - desc_off
            // SAFETY: the four bytes of the name, within the data as
            // checked above.
            && unsafe { core::slice::from_raw_parts(buf.add(name_off), 4) } == b"GNU\0"
        {
            if desc_len == 0 || desc_len > BUILD_ID_MAX {
                return -E2BIG;
            }
            // SAFETY: the descriptor, within the data as checked above,
            // into the caller's room for an ID and its length.
            unsafe {
                ptr::copy_nonoverlapping(buf.add(desc_off), build_id, desc_len);
                *build_id_len = nhdr.n_descsz;
            }
            return 0;
        }
        if next <= off {
            break;
        }
        off = next;
    }
    -ENOENT
}

/// The GNU build ID of `elf` from its note sections, or from its note
/// segments when the section headers are stripped: 0 or -errno.
///
/// # Safety
///
/// `elf` is a descriptor of libelf's, and `build_id` and `build_id_len`
/// room for an ID and its length.
unsafe fn elf_build_id(elf: *mut Elf, build_id: *mut u8, build_id_len: *mut u32) -> c_int {
    let mut scn: *mut ElfScn = ptr::null_mut();

    loop {
        // SAFETY: the descriptor, and the section before, or NULL.
        scn = unsafe { elf_nextscn(elf, scn) };
        if scn.is_null() {
            break;
        }
        let mut shdr = GElfShdr::default();

        // SAFETY: the section, and room for its header.
        if unsafe { gelf_getshdr(scn, &mut shdr) }.is_null() {
            return -EINVAL;
        }
        if shdr.sh_type != SHT_NOTE {
            continue;
        }
        let mut data: *mut ElfData = ptr::null_mut();

        loop {
            // SAFETY: the section, and its data before, or NULL.
            data = unsafe { elf_getdata(scn, data) };
            if data.is_null() {
                break;
            }
            // SAFETY: the data, and the caller's room.
            let err = unsafe { note_build_id(data, build_id, build_id_len) };

            if err != -ENOENT {
                return err;
            }
        }
    }

    // Section headers can be stripped; fall back to PT_NOTE segments.
    let mut ehdr = GElfEhdr::default();
    let mut phnum = 0usize;
    // SAFETY: the descriptor, and room for its header and the number of
    // its program headers.
    if unsafe { gelf_getehdr(elf, &mut ehdr).is_null() || elf_getphdrnum(elf, &mut phnum) != 0 } {
        return -EINVAL;
    }
    for i in 0..phnum {
        let mut phdr = GElfPhdr::default();

        // SAFETY: the descriptor, an index the C passed as an int, and
        // room for the header.
        if unsafe { gelf_getphdr(elf, i as c_int, &mut phdr) }.is_null() {
            return -EINVAL;
        }
        if phdr.p_type != PT_NOTE || phdr.p_filesz == 0 {
            continue;
        }
        // SAFETY: the descriptor, and the segment's bytes in the file,
        // which libelf checks against it.
        let data = unsafe {
            elf_getdata_rawchunk(
                elf,
                phdr.p_offset as i64,
                phdr.p_filesz as usize,
                ELF_T_NHDR,
            )
        };
        if data.is_null() {
            return -EINVAL;
        }
        // SAFETY: the data, and the caller's room.
        let err = unsafe { note_build_id(data, build_id, build_id_len) };

        if err != -ENOENT {
            return err;
        }
    }
    -ENOENT
}

/// The GNU build ID of the ELF file open at `fd`: 0, or -errno with the
/// length 0.
///
/// # Safety
///
/// `build_id` is NULL or room for an ID, and `build_id_len` NULL or room
/// for its length.
pub(crate) unsafe fn build_id_fd(fd: c_int, build_id: *mut u8, build_id_len: *mut u32) -> c_int {
    if fd < 0 || build_id.is_null() || build_id_len.is_null() {
        return -EINVAL;
    }
    // SAFETY: the caller's room for the length.
    unsafe { *build_id_len = 0 };
    // SAFETY: a version libelf may support.
    if unsafe { elf_version(EV_CURRENT) } == EV_NONE {
        return -EINVAL;
    }
    // SAFETY: the caller's fd, read through a mapping.
    let elf = unsafe { elf_begin(fd, ELF_C_READ_MMAP, ptr::null_mut()) };

    if elf.is_null() {
        return -EINVAL;
    }
    // SAFETY: the descriptor, and the caller's room, and then the
    // descriptor ended once.
    unsafe {
        let err = if elf_kind(elf) != ELF_K_ELF {
            -EINVAL
        } else {
            elf_build_id(elf, build_id, build_id_len)
        };

        elf_end(elf);
        err
    }
}

/// Forgets `target`, its offsets scrubbed and freed.
///
/// # Safety
///
/// `target` is NULL or a target its resolve filled or zeroed.
unsafe fn target_free(target: *mut ElfTarget) {
    if target.is_null() {
        return;
    }
    // SAFETY: the target's offsets, of the room the resolve allocated,
    // and then all of it zeroed.
    unsafe {
        xfree(
            (*target).offsets.cast(),
            (*target).offsets_cap as usize * size_of::<u64>(),
        );
        target.write_bytes(0, 1);
    }
}

/// The build ID of the ELF file at the absolute `path`, and the offsets
/// libbpf resolves for `pattern` in it, sorted and each once, into
/// `out`: 0, or -errno with `out` zeroed.
///
/// # Safety
///
/// `path` and `pattern` are NULL or C strings, and `out` NULL or room for
/// a target.
unsafe fn target_resolve(
    path: *const c_char,
    pattern: *const c_char,
    out: *mut ElfTarget,
) -> c_int {
    // SAFETY: the first byte of each of the caller's C strings, read in
    // the C's order.
    let named = unsafe {
        !path.is_null() && *path.cast::<u8>() == b'/' && !pattern.is_null() && *pattern != 0
    };
    if !named || out.is_null() {
        return -EINVAL;
    }
    // SAFETY: the caller's room for a target, all of whose bits zeroed
    // are a valid one.
    let out = unsafe {
        out.write_bytes(0, 1);
        &mut *out
    };
    // SAFETY: a version libelf may support.
    if unsafe { elf_version(EV_CURRENT) } == EV_NONE {
        return -EINVAL;
    }
    // SAFETY: the caller's C string, and flags.
    let fd = unsafe { open(path, O_RDONLY | O_CLOEXEC) };

    if fd < 0 {
        return -errno();
    }
    // SAFETY: the fd opened above, read through a mapping.
    let elf = unsafe { elf_begin(fd, ELF_C_READ_MMAP, ptr::null_mut()) };
    let err = 'out: {
        // SAFETY: the descriptor, checked first.
        if elf.is_null() || unsafe { elf_kind(elf) } != ELF_K_ELF {
            break 'out -EINVAL;
        }
        // SAFETY: the descriptor, and the target's room for the ID.
        let err = unsafe { elf_build_id(elf, out.build_id.as_mut_ptr(), &mut out.build_id_len) };

        if err != 0 {
            break 'out err;
        }
        // SAFETY: the descriptor, and the caller's C string.
        let resolved = match unsafe { pattern_offsets(elf, crate::ffi::c_str(pattern)) } {
            Ok(r) => r,
            Err(err) => break 'out err,
        };
        let nr_resolved = resolved.len();
        if nr_resolved > OFFSETS_MAX || nr_resolved > u32::MAX as usize {
            break 'out -E2BIG;
        }
        // SAFETY: a count and a size.
        out.offsets = unsafe { xcalloc(nr_resolved, size_of::<u64>()) }.cast();
        out.offsets_cap = nr_resolved as u32;
        if out.offsets.is_null() {
            break 'out -ENOMEM;
        }
        // SAFETY: the room just allocated, of nr_resolved entries.
        let offsets = unsafe { core::slice::from_raw_parts_mut(out.offsets, nr_resolved) };
        offsets.copy_from_slice(&resolved);
        out.nr_offsets = nr_resolved as u32;

        offsets.sort_unstable();
        let mut unique = 1usize;

        for i in 1..offsets.len() {
            if offsets[i] != offsets[unique - 1] {
                offsets[unique] = offsets[i];
                unique += 1;
            }
        }
        out.nr_offsets = unique as u32;
        0
    };
    // SAFETY: the descriptor and the fd, each released once.
    unsafe {
        if !elf.is_null() {
            elf_end(elf);
        }
        close(fd);
    }
    if err != 0 {
        // SAFETY: the target this resolve filled.
        unsafe { target_free(out) };
    }
    err
}

pub(crate) use capi::{elf_target_free, elf_target_resolve};

mod capi {
    use core::ffi::{c_char, c_int};

    use super::ElfTarget;

    /// # Safety
    ///
    /// `path` and `pattern` are NULL or C strings, and `out` NULL or room
    /// for a target.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn elf_target_resolve(
        path: *const c_char,
        pattern: *const c_char,
        out: *mut ElfTarget,
    ) -> c_int {
        // SAFETY: the caller passes C strings and room for a target.
        unsafe { super::target_resolve(path, pattern, out) }
    }

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
        // SAFETY: the caller passes room for an ID and its length.
        unsafe { super::build_id_fd(fd, build_id, build_id_len) }
    }

    /// # Safety
    ///
    /// `target` is NULL or a target a resolve filled or zeroed.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn elf_target_free(target: *mut ElfTarget) {
        // SAFETY: the caller passes a target.
        unsafe { super::target_free(target) }
    }
}
