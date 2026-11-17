// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The part of elfutils' libelf and gelf the Rust code reads build IDs
//! with, the values of elf.h and libelf.h, and the resolver libbpf keeps
//! for its uprobe.multi attach path.

use core::ffi::{c_char, c_int, c_uint, c_void};

/// An `Elf` descriptor.
pub enum Elf {}
/// An `Elf_Scn` section.
pub enum ElfScn {}

/// `Elf_Data`: a piece of a section or segment, as libelf hands it out.
#[repr(C)]
pub struct ElfData {
    pub d_buf: *mut c_void,
    pub d_type: c_int,
    pub d_version: c_uint,
    pub d_size: usize,
    pub d_off: i64,
    pub d_align: usize,
}

const _: () = assert!(size_of::<ElfData>() == 40);

/// `GElf_Nhdr`.
#[repr(C)]
#[derive(Default)]
pub struct GElfNhdr {
    pub n_namesz: u32,
    pub n_descsz: u32,
    pub n_type: u32,
}

/// `GElf_Shdr`.
#[repr(C)]
#[derive(Default)]
pub struct GElfShdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

/// `GElf_Sym`.
#[repr(C)]
#[derive(Default)]
pub struct GElfSym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

const _: () = assert!(size_of::<GElfSym>() == 24);

/// `GElf_Ehdr`.
#[repr(C)]
#[derive(Default)]
pub struct GElfEhdr {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// `GElf_Phdr`.
#[repr(C)]
#[derive(Default)]
pub struct GElfPhdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

const _: () = assert!(size_of::<GElfNhdr>() == 12);
const _: () = assert!(size_of::<GElfShdr>() == 64);
const _: () = assert!(size_of::<GElfEhdr>() == 64);
const _: () = assert!(size_of::<GElfPhdr>() == 56);

/// `ELF_C_READ_MMAP` of `Elf_Cmd`.
pub const ELF_C_READ_MMAP: c_int = 8;
/// `ELF_K_ELF` of `Elf_Kind`.
pub const ELF_K_ELF: c_int = 3;
/// `ELF_T_NHDR` of `Elf_Type`.
pub const ELF_T_NHDR: c_int = 19;
pub const EV_NONE: c_uint = 0;
pub const EV_CURRENT: c_uint = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_NOTE: u32 = 7;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
pub const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;
pub const STT_FUNC: u8 = 2;
pub const PT_NOTE: u32 = 4;
pub const NT_GNU_BUILD_ID: u32 = 3;

unsafe extern "C" {
    pub fn elf_version(version: c_uint) -> c_uint;
    pub fn elf_begin(fd: c_int, cmd: c_int, reference: *mut Elf) -> *mut Elf;
    pub fn elf_kind(elf: *mut Elf) -> c_int;
    pub fn elf_end(elf: *mut Elf) -> c_int;
    pub fn elf_nextscn(elf: *mut Elf, scn: *mut ElfScn) -> *mut ElfScn;
    pub fn elf_getdata(scn: *mut ElfScn, data: *mut ElfData) -> *mut ElfData;
    pub fn elf_getdata_rawchunk(
        elf: *mut Elf,
        offset: i64,
        size: usize,
        kind: c_int,
    ) -> *mut ElfData;
    pub fn elf_getphdrnum(elf: *mut Elf, dst: *mut usize) -> c_int;
    pub fn gelf_getshdr(scn: *mut ElfScn, dst: *mut GElfShdr) -> *mut GElfShdr;
    pub fn gelf_getehdr(elf: *mut Elf, dst: *mut GElfEhdr) -> *mut GElfEhdr;
    pub fn gelf_getphdr(elf: *mut Elf, ndx: c_int, dst: *mut GElfPhdr) -> *mut GElfPhdr;
    pub fn gelf_getnote(
        data: *mut ElfData,
        offset: usize,
        result: *mut GElfNhdr,
        name_offset: *mut usize,
        desc_offset: *mut usize,
    ) -> usize;
    pub fn elf_getscn(elf: *mut Elf, index: usize) -> *mut ElfScn;
    /// The string at `offset` of string section `section`, or NULL.
    pub fn elf_strptr(elf: *mut Elf, section: usize, offset: usize) -> *mut c_char;
    pub fn gelf_getsym(data: *mut ElfData, ndx: c_int, dst: *mut GElfSym) -> *mut GElfSym;
    pub fn gelf_getversym(data: *mut ElfData, ndx: c_int, dst: *mut u16) -> *mut u16;
}
