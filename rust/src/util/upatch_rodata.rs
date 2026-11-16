// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The `.rodata` of a upatch behind `util/upatch_rodata.h`: found through
//! the loader's own sys_bpf() calls, the BTF it loads and the map update
//! that fills the section, then printed as text through libbpf's dumper
//! or as JSON from the BTF.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::errno::{E2BIG, EEXIST, EINVAL, ENODATA, ENOENT, ENOMEM, ENOSPC, EOPNOTSUPP};
use crate::ffi;
use crate::sys::btf::{
    self, Btf, BtfDumpTypeDataOpts, BtfType, KIND_ARRAY, KIND_CONST, KIND_DATASEC, KIND_ENUM,
    KIND_ENUM64, KIND_FLOAT, KIND_FWD, KIND_INT, KIND_PTR, KIND_RESTRICT, KIND_STRUCT,
    KIND_TYPE_TAG, KIND_TYPEDEF, KIND_UNION, KIND_VAR, KIND_VOLATILE, btf__find_by_name_kind,
    btf__free, btf__name_by_offset, btf__new, btf__resolve_size, btf__type_by_id, btf__type_cnt,
    btf_dump__dump_type_data, btf_dump__free, btf_dump__new, libbpf_get_error,
};
use crate::sys::libc::{STDOUT_FILENO, VaList, printf, putchar, stdout, vfprintf};
use crate::sys::log::pr_err;
use crate::sys::malloc::{xcalloc, xfree, xmalloc};
use crate::sys::string::{strsprintf, text_sanitize};
use crate::util::io::write_complete;
use crate::util::json::{JsonEmit, MAX_BYTES};
use crate::util::upatch::{NAME_MAX, Upatch, header_name, is_unload};

const MAPS_MAX: usize = 64;
const JSON_MAX_DEPTH: u32 = 8;
const TEXT_MAX_VALUES: u32 = 1 << 20;
const DECL_MAX: u32 = 32;

/// The instructions and calls of a loader libbpf's gen_loader wrote.
const INSN: usize = 8;
const LD_DW_IMM: u8 = 0x18;
const JMP_CALL: u8 = 0x85;
const ALU64_MOV_K: u8 = 0xb7;
const STX_W_MEM: u8 = 0x63;
const LDX_W_MEM: u8 = 0x61;
const STX_DW_MEM: u8 = 0x7b;
const PSEUDO_MAP_IDX_VALUE: u8 = 6;
const FUNC_SYS_BPF: i32 = 166;
const REG_0: u8 = 0;
const REG_1: u8 = 1;
const REG_2: u8 = 2;
const REG_3: u8 = 3;
const REG_7: u8 = 7;
const MAP_CREATE: u32 = 0;
const MAP_UPDATE_ELEM: u32 = 2;
const BTF_LOAD: u32 = 18;
const OBJ_NAME_LEN: usize = 16;

/// `union bpf_attr` of the vendored UAPI: its size, and the fields the
/// loader's calls set, as offsets.
const ATTR_SIZE: u32 = 168;
const ATTR_MAP_NAME: usize = 28;
const ATTR_MAP_NAME_END: u32 = 44;
const ATTR_VALUE_SIZE: usize = 8;
const ATTR_MAP_FD: u32 = 0;
const ATTR_VALUE: u32 = 16;
const ATTR_BTF: u32 = 0;
const ATTR_BTF_SIZE: usize = 16;
const ATTR_BTF_SIZE_END: u32 = 20;

/// `struct rodata_range` of `util/upatch_rodata.h`.
#[repr(C)]
pub struct RodataRange {
    offset: u32,
    size: u32,
}

/// The `.rodata` the loader fills: its BTF, its bytes in the loader
/// data, and its DATASEC.
struct View {
    btf: *mut Btf,
    bytes: *const u8,
    data_offset: u32,
    size: u32,
    type_id: u32,
}

impl View {
    const fn new() -> Self {
        View {
            btf: ptr::null_mut(),
            bytes: ptr::null(),
            data_offset: 0,
            size: 0,
            type_id: 0,
        }
    }
}

impl Drop for View {
    fn drop(&mut self) {
        // SAFETY: NULL or the BTF btf__new() gave, freed once.
        unsafe { btf__free(self.btf) };
    }
}

/// An instruction of the loader, as `struct bpf_insn` lays it out.
#[derive(Clone, Copy)]
struct Insn {
    code: u8,
    dst: u8,
    src: u8,
    off: i16,
    imm: i32,
}

/// The loader's instructions and its data, as bytes.
struct Loader<'a> {
    insns: &'a [u8],
    data: &'a [u8],
}

impl<'a> Loader<'a> {
    /// The loader and data of `u`, none of a closed container.
    fn of(u: &'a Upatch) -> Self {
        if u.map.is_null() {
            return Loader {
                insns: &[],
                data: &[],
            };
        }
        // SAFETY: the sections the reader kept inside the container.
        unsafe {
            Loader {
                insns: ffi::slice(
                    u.map.add(u.hdr.loader_insns_off as usize),
                    u.hdr.loader_insns_len as usize,
                ),
                data: ffi::slice(u.map.add(u.hdr.data_off as usize), u.hdr.data_len as usize),
            }
        }
    }

    fn count(&self) -> usize {
        self.insns.len() / INSN
    }

    fn insn(&self, i: usize) -> Insn {
        let b = &self.insns[i * INSN..][..INSN];

        Insn {
            code: b[0],
            dst: b[1] & 0xf,
            src: b[1] >> 4,
            off: i16::from_le_bytes([b[2], b[3]]),
            imm: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }

    /// The map value index of the ld_imm64 at `i` into `reg`.
    fn lddw(&self, i: usize, reg: u8) -> Option<u32> {
        if i + 1 >= self.count() {
            return None;
        }
        let (a, b) = (self.insn(i), self.insn(i + 1));
        if a.code != LD_DW_IMM
            || a.dst != reg
            || a.src != PSEUDO_MAP_IDX_VALUE
            || a.off != 0
            || a.imm != 0
            || b.code != 0
            || b.off != 0
        {
            return None;
        }
        Some(b.imm as u32)
    }

    /// The command, attr offset and attr size of the sys_bpf() call at
    /// `i`, as gen_loader sets them up in the four instructions before.
    fn sys_bpf_call(&self, i: usize) -> Option<(u32, u32, u32)> {
        if i < 4 || i >= self.count() {
            return None;
        }
        let call = self.insn(i);
        let cmd = self.insn(i - 4);
        let size = self.insn(i - 1);
        if call.code != JMP_CALL
            || call.imm != FUNC_SYS_BPF
            || cmd.code != ALU64_MOV_K
            || cmd.dst != REG_1
            || self.insn(i - 3).code != LD_DW_IMM
        {
            return None;
        }
        let attr = self.lddw(i - 3, REG_2)?;
        if size.code != ALU64_MOV_K || size.dst != REG_3 {
            return None;
        }
        Some((cmd.imm as u32, attr, size.imm as u32))
    }

    /// The fd slot a map create between `call` and `next_call` stores its
    /// fd into.
    fn map_create_slot(&self, call: usize, next_call: usize) -> Option<u32> {
        let mut i = call + 1;

        while i + 2 < next_call {
            if let Some(off) = self.lddw(i, REG_1) {
                let st = self.insn(i + 2);

                if st.code == STX_W_MEM
                    && st.dst == REG_1
                    && st.src == REG_7
                    && st.off == 0
                    && off % 4 == 0
                    && (off / 4) < MAPS_MAX as u32
                {
                    return Some(off / 4);
                }
            }
            i += 1;
        }
        None
    }

    /// The fd slot of the map a map update at `call`, of attr at `attr`,
    /// updates.
    fn map_update_slot(&self, call: usize, attr: u32) -> Option<u32> {
        let map_fd_off = attr.wrapping_add(ATTR_MAP_FD);
        let mut i = call.saturating_sub(48);

        while i + 5 < call {
            let fd_array_off = self.lddw(i, REG_2);
            let ld = self.insn(i + 2);
            let dest_off = self.lddw(i + 3, REG_1);
            let st = self.insn(i + 5);

            if let (Some(fd_array_off), Some(dest_off)) = (fd_array_off, dest_off)
                && ld.code == LDX_W_MEM
                && ld.dst == REG_0
                && ld.src == REG_2
                && ld.off == 0
                && dest_off == map_fd_off
                && st.code == STX_W_MEM
                && st.dst == REG_1
                && st.src == REG_0
                && st.off == 0
                && fd_array_off % 4 == 0
                && (fd_array_off / 4) < MAPS_MAX as u32
            {
                return Some(fd_array_off / 4);
            }
            i += 1;
        }
        None
    }

    /// The data offset the loader stores into the attr field at `field`
    /// before the sys_bpf() call at `call`, as libbpf's gen_loader writes
    /// a pointer into its data.
    fn store_source(&self, call: usize, field: u32) -> Option<u32> {
        let mut i = call.saturating_sub(24);

        while i + 4 < call {
            let source_off = self.lddw(i, REG_0);
            let dest_off = self.lddw(i + 2, REG_1);
            let st = self.insn(i + 4);

            if let (Some(source_off), Some(dest_off)) = (source_off, dest_off)
                && dest_off == field
                && st.code == STX_DW_MEM
                && st.dst == REG_1
                && st.src == REG_0
                && st.off == 0
            {
                return Some(source_off);
            }
            i += 1;
        }
        None
    }

    /// `attr_size` bytes of the attr at `attr_off` over a zeroed union,
    /// when they lie in the data and fit it, with at least `min` of them.
    fn attr(&self, attr_off: u32, attr_size: u32, min: u32) -> Option<[u8; ATTR_SIZE as usize]> {
        let data_len = self.data.len() as u32;
        let mut attr = [0u8; ATTR_SIZE as usize];

        if attr_size > ATTR_SIZE
            || attr_size < min
            || attr_off > data_len
            || attr_size > data_len - attr_off
        {
            return None;
        }
        attr[..attr_size as usize]
            .copy_from_slice(&self.data[attr_off as usize..][..attr_size as usize]);
        Some(attr)
    }
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn map_name_rodata(name: &[u8]) -> bool {
    name.ends_with(b".rodata")
}

/// The `.rodata` the loader fills with the BTF's DATASEC `datasec_id`:
/// the bytes of the map update of a `.rodata` map it creates.
///
/// # Safety
///
/// `btf` is a BTF.
unsafe fn find_rodata_data(u: &Upatch, btf: *const Btf, datasec_id: u32, view: &mut View) -> c_int {
    let mut maps = [(0u32, false); MAPS_MAX];
    let l = Loader::of(u);
    let count = l.count();

    // SAFETY: the caller's BTF.
    let sec = unsafe { btf__type_by_id(btf, datasec_id) };
    // SAFETY: NULL, or a type of the BTF.
    if sec.is_null() || unsafe { (*sec).kind() } != KIND_DATASEC || u.hdr.loader_insns_len % 8 != 0
    {
        return -EINVAL;
    }
    // SAFETY: as above.
    let sec_size = unsafe { (*sec).size_type };
    for i in 4..count {
        let Some((cmd, attr_off, attr_size)) = l.sys_bpf_call(i) else {
            continue;
        };
        if cmd == MAP_CREATE {
            let Some(attr) = l.attr(attr_off, attr_size, ATTR_MAP_NAME_END) else {
                return -EINVAL;
            };
            let name = &attr[ATTR_MAP_NAME..][..OBJ_NAME_LEN];
            let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(OBJ_NAME_LEN)];
            let end = (i + 1..count)
                .find(|&next| l.sys_bpf_call(next).is_some())
                .unwrap_or(count);
            if map_name_rodata(name) {
                let Some(slot) = l.map_create_slot(i, end) else {
                    return -EOPNOTSUPP;
                };
                maps[slot as usize] = (le32(&attr, ATTR_VALUE_SIZE), true);
            }
        } else if cmd == MAP_UPDATE_ELEM {
            let Some(value_field) = attr_off.checked_add(ATTR_VALUE) else {
                continue;
            };
            let Some(slot) = l.map_update_slot(i, attr_off) else {
                continue;
            };
            let Some(value_off) = l.store_source(i, value_field) else {
                continue;
            };
            let (value_size, found) = maps[slot as usize];
            if !found {
                continue;
            }
            let data_len = l.data.len() as u32;
            if value_size != sec_size || value_off > data_len || value_size > data_len - value_off {
                return -EINVAL;
            }
            view.bytes = l.data[value_off as usize..].as_ptr();
            view.data_offset = value_off;
            view.size = sec_size;
            view.type_id = datasec_id;
            return 0;
        }
    }
    -ENODATA
}

/// The BTF the loader's one BPF_BTF_LOAD loads: the offset in data it
/// stores into attr.btf, and the attr.btf_size beside it.
fn loader_btf(u: &Upatch) -> Result<(u32, u32), c_int> {
    let l = Loader::of(u);
    let mut found = None;

    if u.map.is_null() || u.hdr.data_len == 0 {
        return Err(-ENOENT);
    }
    if u.hdr.loader_insns_len % 8 != 0 {
        return Err(-EINVAL);
    }
    for i in 4..l.count() {
        let Some((cmd, attr_off, attr_size)) = l.sys_bpf_call(i) else {
            continue;
        };
        if cmd != BTF_LOAD {
            continue;
        }
        if found.is_some() {
            return Err(-E2BIG);
        }
        let Some(attr) = l.attr(attr_off, attr_size, ATTR_BTF_SIZE_END) else {
            return Err(-EINVAL);
        };
        let btf_size = le32(&attr, ATTR_BTF_SIZE);
        let data_len = l.data.len() as u32;
        let Some(btf_off) = attr_off
            .checked_add(ATTR_BTF)
            .and_then(|field| l.store_source(i, field))
        else {
            return Err(-EINVAL);
        };
        if btf_off > data_len || btf_size > data_len - btf_off {
            return Err(-EINVAL);
        }
        found = Some((btf_off, btf_size));
    }
    found.ok_or(-ENOENT)
}

fn btf_rodata_btf(u: &Upatch, view: &mut View) -> c_int {
    let (btf_off, btf_size) = match loader_btf(u) {
        Ok(found) => found,
        Err(ret) => return ret,
    };
    let data = Loader::of(u).data;
    // SAFETY: btf_size bytes of the loader data at btf_off, which
    // loader_btf() kept inside it.
    let btf = unsafe { btf__new(data[btf_off as usize..].as_ptr().cast(), btf_size) };
    // SAFETY: what btf__new() returned.
    if unsafe { libbpf_get_error(btf.cast_const().cast()) } != 0 {
        return -ENOENT;
    }
    // SAFETY: the BTF, a C string and a kind.
    let id = unsafe { btf__find_by_name_kind(btf, c".rodata".as_ptr(), u32::from(KIND_DATASEC)) };
    if id <= 0 {
        // SAFETY: the BTF btf__new() gave, freed once.
        unsafe { btf__free(btf) };
        return -ENOENT;
    }
    view.btf = btf;
    // The header is not signed: .rodata is where the signed loader
    // takes it from, and a header that names another offset would aim a
    // rewrite the operator then signs at other bytes.
    // SAFETY: the BTF.
    let ret = unsafe { find_rodata_data(u, btf, id as u32, view) };
    if ret == 0 && u.rodata_offset_in_header && view.data_offset != u.hdr.rodata_data_off {
        return -EINVAL;
    }
    ret
}

fn data_offset(u: &Upatch, offset: &mut u32) -> c_int {
    let mut view = View::new();
    let ret = btf_rodata_btf(u, &mut view);

    if ret == 0 {
        *offset = view.data_offset;
    }
    ret
}

/// The variables of the DATASEC `sec`: (type, offset, size) each.
///
/// # Safety
///
/// `sec` is a DATASEC of a BTF that stays alive for `'a`.
unsafe fn secinfo<'a>(sec: *const BtfType) -> &'a [[u32; 3]] {
    // SAFETY: the vlen btf_var_secinfo records behind the DATASEC.
    unsafe { ffi::slice(sec.add(1).cast::<[u32; 3]>(), (*sec).vlen() as usize) }
}

fn symbol_range(u: &Upatch, symbol: &[u8], range: &mut RodataRange) -> c_int {
    let mut view = View::new();
    let mut found = false;

    let ret = btf_rodata_btf(u, &mut view);
    if ret != 0 {
        return ret;
    }
    // SAFETY: the BTF, and its DATASEC.
    let sec = unsafe { btf__type_by_id(view.btf, view.type_id) };
    // SAFETY: NULL, or a type of the BTF.
    if sec.is_null() || unsafe { (*sec).kind() } != KIND_DATASEC {
        return -EINVAL;
    }
    // SAFETY: the DATASEC of the BTF, which view keeps.
    for &[ty, offset, size] in unsafe { secinfo(sec) } {
        // SAFETY: the BTF, and a type ID of it.
        let var = unsafe { btf__type_by_id(view.btf, ty) };
        // SAFETY: NULL, or a type of the BTF.
        if var.is_null() || unsafe { (*var).kind() } != KIND_VAR {
            continue;
        }
        // SAFETY: the BTF, and a name offset of it.
        let name = unsafe { btf__name_by_offset(view.btf, (*var).name_off) };
        // SAFETY: NULL, or a name of the BTF.
        if name.is_null() || unsafe { ffi::c_str(name) } != symbol {
            continue;
        }
        if found {
            return -EEXIST;
        }
        let inside = offset
            .checked_add(size)
            .filter(|&end| end <= view.size)
            .and_then(|end| view.data_offset.checked_add(end))
            .is_some_and(|end| end <= u.hdr.data_len);
        if !inside {
            return -EINVAL;
        }
        range.offset = view.data_offset + offset;
        range.size = size;
        found = true;
    }
    if found { 0 } else { -ENOENT }
}

/// The name at `off` of `btf`, when it is printable ASCII alone: the BTF
/// may come from an unsigned package, and its names go to the terminal.
///
/// # Safety
///
/// `btf` is a BTF.
unsafe fn name_printable(btf: *const Btf, off: u32) -> bool {
    // SAFETY: the caller's BTF, and an offset.
    let name = unsafe { btf__name_by_offset(btf, off) };

    // SAFETY: NULL, or a name of the BTF.
    !name.is_null()
        && unsafe { ffi::c_str(name) }
            .iter()
            .all(|&c| (0x20..=0x7e).contains(&c))
}

/// The type `id` resolves to through typedefs and modifiers, or 0.
///
/// # Safety
///
/// `btf` is a BTF.
unsafe fn unwrap(btf: *const Btf, mut id: u32) -> u32 {
    for _ in 0..JSON_MAX_DEPTH {
        // SAFETY: the caller's BTF.
        let t = unsafe { btf__type_by_id(btf, id) };
        if t.is_null() {
            return 0;
        }
        // SAFETY: a type of the BTF.
        let t = unsafe { &*t };
        match t.kind() {
            KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => {
                id = t.size_type;
            }
            _ => return id,
        }
    }
    0
}

/// `fmt` with one argument appended at `*off` of `buf`, as strsprintf()
/// writes it: -ENOSPC when it does not fit.
///
/// # Safety
///
/// `fmt` and its argument are as strsprintf() takes them.
unsafe fn append(
    buf: &mut [u8],
    off: &mut usize,
    fmt: &core::ffi::CStr,
    arg: *const c_void,
) -> c_int {
    // SAFETY: the room left in buf, and the caller's format and argument.
    let n = unsafe {
        strsprintf(
            buf[*off..].as_mut_ptr().cast(),
            buf.len() - *off,
            fmt.as_ptr(),
            arg,
        )
    };
    if n < 0 {
        return -ENOSPC;
    }
    *off += n as usize;
    0
}

/// The name of type `id`, its modifiers dropped, after `*off` in `buf`.
///
/// # Safety
///
/// `btf` is a BTF.
unsafe fn append_type_name(
    btf: *const Btf,
    id: u32,
    buf: &mut [u8],
    off: &mut usize,
    depth: u32,
) -> c_int {
    if depth >= JSON_MAX_DEPTH || *off >= buf.len() {
        return -E2BIG;
    }
    // SAFETY: the caller's BTF.
    let t = unsafe { btf__type_by_id(btf, id) };
    if t.is_null() {
        return -EINVAL;
    }
    // SAFETY: a type of the BTF.
    let (t, tp) = (unsafe { &*t }, t);
    let kind = t.kind();
    // SAFETY: the caller's BTF.
    if !unsafe { name_printable(btf, t.name_off) } {
        return -EINVAL;
    }
    // SAFETY: as above.
    let name = unsafe { btf__name_by_offset(btf, t.name_off) };
    // SAFETY: NULL, or a name of the BTF.
    let named = !name.is_null() && unsafe { *name } != 0;
    // SAFETY: the BTF, the caller's room, and the formats with their
    // arguments: C strings and integers.
    unsafe {
        if kind == KIND_TYPEDEF && named {
            return append(buf, off, c"%s", name.cast());
        }
        if matches!(
            kind,
            KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG
        ) {
            return append_type_name(btf, t.size_type, buf, off, depth + 1);
        }
        if kind == KIND_ARRAY {
            let a = &*btf::array(tp);

            if append_type_name(btf, a.ty, buf, off, depth + 1) != 0 {
                return -EINVAL;
            }
            let n = strsprintf(
                buf[*off..].as_mut_ptr().cast(),
                buf.len() - *off,
                c"[%u]".as_ptr(),
                a.nelems,
            );
            if n < 0 {
                return -ENOSPC;
            }
            *off += n as usize;
            return 0;
        }
        if kind == KIND_PTR {
            if append_type_name(btf, t.size_type, buf, off, depth + 1) != 0 {
                return -EINVAL;
            }
            let n = strsprintf(
                buf[*off..].as_mut_ptr().cast(),
                buf.len() - *off,
                c" *".as_ptr(),
            );
            if n < 0 {
                return -ENOSPC;
            }
            *off += n as usize;
            return 0;
        }
        let n = if named {
            let prefix = match kind {
                KIND_STRUCT => c"struct ",
                KIND_UNION => c"union ",
                KIND_ENUM => c"enum ",
                _ => c"",
            };
            strsprintf(
                buf[*off..].as_mut_ptr().cast(),
                buf.len() - *off,
                c"%s%s".as_ptr(),
                prefix.as_ptr(),
                name,
            )
        } else {
            let fallback = match kind {
                KIND_INT => c"integer",
                KIND_STRUCT => c"struct",
                KIND_UNION => c"union",
                KIND_ENUM | KIND_ENUM64 => c"enum",
                KIND_FLOAT => c"float",
                KIND_FWD => c"forward declaration",
                _ => c"?",
            };
            strsprintf(
                buf[*off..].as_mut_ptr().cast(),
                buf.len() - *off,
                c"%s".as_ptr(),
                fallback.as_ptr(),
            )
        };
        if n < 0 {
            return -ENOSPC;
        }
        *off += n as usize;
    }
    0
}

fn json_number(e: &mut JsonEmit, value: u64, signed: bool) -> c_int {
    let mut number = [0u8; 32];

    // SAFETY: the room of number, and the C's formats with an integer.
    let n = unsafe {
        if signed {
            strsprintf(
                number.as_mut_ptr().cast(),
                number.len(),
                c"%lld".as_ptr(),
                value as i64,
            )
        } else {
            strsprintf(
                number.as_mut_ptr().cast(),
                number.len(),
                c"%llu".as_ptr(),
                value,
            )
        }
    };
    if n < 0 {
        return n;
    }
    e.raw_value(&number[..n as usize]);
    e.err()
}

/// The integer of the INT `t` in `bytes`: its value, sign-extended when
/// signed, and whether it is signed and a bool.
///
/// # Safety
///
/// `t` is an INT of a BTF.
unsafe fn btf_integer(t: *const BtfType, bytes: &[u8]) -> Result<(u64, bool, bool), c_int> {
    // SAFETY: the caller's INT.
    let (size, enc_signed, enc_bool, bits, bit_off) = unsafe {
        let enc = btf::int_encoding(t);

        (
            (*t).size_type,
            enc & btf::INT_SIGNED != 0,
            enc & btf::INT_BOOL != 0,
            u32::from(btf::int_bits(t)),
            u32::from(btf::int_offset(t)),
        )
    };
    let mut result = 0u64;

    if size as usize > bytes.len() || size == 0 || size > 8 {
        return Err(-EINVAL);
    }
    if bits == 0 || bits > 64 || bit_off + bits > size * 8 {
        return Err(-EINVAL);
    }
    for i in 0..bits {
        let b = bit_off + i;

        if bytes[b as usize / 8] & (1u8 << (b % 8)) != 0 {
            result |= 1u64 << i;
        }
    }
    if enc_signed && bits < 64 && result & (1u64 << (bits - 1)) != 0 {
        result |= !((1u64 << bits) - 1);
    }
    Ok((result, enc_signed, enc_bool))
}

fn json_hex(e: &mut JsonEmit, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let cap = bytes.len().saturating_mul(2).saturating_add(3);

    if cap > MAX_BYTES {
        e.set_err(-E2BIG);
        return;
    }
    // SAFETY: a size.
    let text = unsafe { xmalloc(cap) }.cast::<u8>();
    if text.is_null() {
        e.set_err(-ENOMEM);
        return;
    }
    // SAFETY: the cap bytes xmalloc() gave, written whole, then freed
    // once.
    unsafe {
        let out = ffi::bytes_mut(text, cap);

        out[0] = b'0';
        out[1] = b'x';
        for (i, &b) in bytes.iter().enumerate() {
            out[2 + i * 2] = HEX[usize::from(b >> 4)];
            out[3 + i * 2] = HEX[usize::from(b & 0xf)];
        }
        out[2 + bytes.len() * 2] = 0;
        e.str_value(&out[..2 + bytes.len() * 2]);
        xfree(text.cast(), cap);
    }
}

/// The value of type `type_id` in `bytes` as JSON.
///
/// # Safety
///
/// `btf` is a BTF.
unsafe fn json_btf_value(
    e: &mut JsonEmit,
    btf: *const Btf,
    type_id: u32,
    bytes: &[u8],
    depth: u32,
) -> c_int {
    if depth >= JSON_MAX_DEPTH || type_id == 0 {
        return -EINVAL;
    }
    // SAFETY: the caller's BTF.
    let type_id = unsafe { unwrap(btf, type_id) };
    // SAFETY: as above.
    let tp = unsafe { btf__type_by_id(btf, type_id) };
    if tp.is_null() {
        return -EINVAL;
    }
    // SAFETY: a type of the BTF, with the records its kind and vlen give
    // behind it.
    let t = unsafe { &*tp };
    let size = bytes.len();
    match t.kind() {
        KIND_INT => {
            // SAFETY: an INT of the BTF.
            let (value, signed, boolean) = match unsafe { btf_integer(tp, bytes) } {
                Ok(v) => v,
                Err(ret) => return ret,
            };
            if boolean {
                e.raw_value(if value != 0 { b"true" } else { b"false" });
            } else {
                return json_number(e, value, signed);
            }
            e.err()
        }
        KIND_ENUM | KIND_ENUM64 => {
            let signed = t.kflag();
            let tsize = t.size_type as usize;
            let mut value = 0u64;
            let mut enum_name: *const c_char = ptr::null();

            if tsize == 0 || tsize > 8 || tsize > size {
                return -EINVAL;
            }
            for (i, &b) in bytes[..tsize].iter().enumerate() {
                value |= u64::from(b) << (i * 8);
            }
            if signed && tsize < 8 && value & (1u64 << (tsize * 8 - 1)) != 0 {
                value |= !((1u64 << (tsize * 8)) - 1);
            }
            // SAFETY: the enumerators behind the type, vlen of them, of
            // the BTF.
            unsafe {
                if t.kind() == KIND_ENUM {
                    let vals = ffi::slice(tp.add(1).cast::<[u32; 2]>(), t.vlen() as usize);

                    if let Some(v) = vals.iter().find(|v| v[1] == value as u32) {
                        enum_name = btf__name_by_offset(btf, v[0]);
                    }
                } else {
                    let vals = ffi::slice(tp.add(1).cast::<[u32; 3]>(), t.vlen() as usize);

                    if let Some(v) = vals
                        .iter()
                        .find(|v| (u64::from(v[1]) | u64::from(v[2]) << 32) == value)
                    {
                        enum_name = btf__name_by_offset(btf, v[0]);
                    }
                }
            }
            e.obj_value_open();
            // SAFETY: NULL, or a name of the BTF.
            if !enum_name.is_null() && unsafe { *enum_name } != 0 {
                // SAFETY: as above.
                e.kv_string(b"name", unsafe { ffi::c_str(enum_name) });
            }
            e.key(b"value");
            json_number(e, value, signed);
            e.obj_close();
            e.err()
        }
        KIND_STRUCT => {
            let kflag = t.kflag();
            // SAFETY: the members behind the struct, vlen of them.
            let members = unsafe { ffi::slice(btf::members(tp), t.vlen() as usize) };

            e.obj_value_open();
            for (i, m) in members.iter().enumerate() {
                if e.err() != 0 {
                    break;
                }
                let bit_off = if kflag {
                    m.offset & 0xff_ffff
                } else {
                    m.offset
                };
                let bit_size = if kflag { m.offset >> 24 } else { 0 };
                let byte_off = (bit_off / 8) as usize;
                // SAFETY: the BTF, and a name offset and a type of it.
                let (name, member_size) = unsafe {
                    (
                        btf__name_by_offset(btf, m.name_off),
                        btf__resolve_size(btf, m.ty),
                    )
                };
                let mut fallback = [0u8; 24];

                // SAFETY: NULL, or a name of the BTF.
                if !name.is_null() && unsafe { *name } != 0 {
                    // SAFETY: as above.
                    e.key(unsafe { ffi::c_str(name) });
                } else {
                    // SAFETY: the room of fallback, the C's format and
                    // an integer.
                    let n = unsafe {
                        strsprintf(
                            fallback.as_mut_ptr().cast(),
                            fallback.len(),
                            c"member_%u".as_ptr(),
                            i as u32,
                        )
                    };
                    if n < 0 {
                        return -EINVAL;
                    }
                    e.key(&fallback[..n as usize]);
                }
                if bit_size != 0 {
                    let n = (bit_off % 8 + bit_size).div_ceil(8) as usize;
                    // SAFETY: the BTF, and a type of it.
                    let mt = unsafe { btf__type_by_id(btf, unwrap(btf, m.ty)) };
                    // SAFETY: NULL, or a type of the BTF.
                    let int = !mt.is_null() && unsafe { (*mt).kind() } == KIND_INT;
                    if bit_size > 64 || byte_off + n > size || !int {
                        return -EINVAL;
                    }
                    // SAFETY: an INT of the BTF.
                    let signed = unsafe { btf::int_encoding(mt) } & btf::INT_SIGNED != 0;
                    let mut val = 0u64;
                    for j in 0..bit_size {
                        let pos = bit_off + j;

                        if bytes[pos as usize / 8] & (1u8 << (pos % 8)) != 0 {
                            val |= 1u64 << j;
                        }
                    }
                    if signed && bit_size < 64 && val & (1u64 << (bit_size - 1)) != 0 {
                        val |= !((1u64 << bit_size) - 1);
                    }
                    json_number(e, val, signed);
                } else {
                    if member_size < 0 || byte_off > size || member_size as usize > size - byte_off
                    {
                        return -EINVAL;
                    }
                    let member = &bytes[byte_off..][..member_size as usize];
                    // SAFETY: the BTF.
                    let ret = unsafe { json_btf_value(e, btf, m.ty, member, depth + 1) };
                    if ret != 0 {
                        return ret;
                    }
                }
            }
            e.obj_close();
            e.err()
        }
        KIND_ARRAY => {
            // SAFETY: the array record behind the type.
            let a = unsafe { &*btf::array(tp) };
            // SAFETY: the BTF, and a type of it.
            let elem_size = unsafe { btf__resolve_size(btf, a.ty) };
            let total = (elem_size as u64).checked_mul(u64::from(a.nelems));

            if elem_size < 0 || total.is_none_or(|total| total > size as u64) {
                return -EINVAL;
            }
            e.arr_open_value();
            for i in 0..a.nelems as usize {
                if e.err() != 0 {
                    break;
                }
                if elem_size == 0 {
                    return -EINVAL;
                }
                let elem = &bytes[i * elem_size as usize..][..elem_size as usize];
                // SAFETY: the BTF.
                let ret = unsafe { json_btf_value(e, btf, a.ty, elem, depth + 1) };
                if ret != 0 {
                    return ret;
                }
            }
            e.arr_close();
            e.err()
        }
        KIND_PTR => {
            let mut value = [0u8; 8];
            let mut text = [0u8; 32];

            if size > value.len() {
                return -EINVAL;
            }
            value[..size].copy_from_slice(bytes);
            // SAFETY: the room of text, the C's format and an integer.
            let n = unsafe {
                strsprintf(
                    text.as_mut_ptr().cast(),
                    text.len(),
                    c"0x%llx".as_ptr(),
                    u64::from_ne_bytes(value),
                )
            };
            if n < 0 {
                return n;
            }
            e.str_value(&text[..n as usize]);
            e.err()
        }
        _ => {
            json_hex(e, bytes);
            e.err()
        }
    }
}

/// The name of the variable of `var`, when it is a VAR with a printable
/// name.
///
/// # Safety
///
/// `btf` is a BTF.
unsafe fn var_name(btf: *const Btf, var: &[u32; 3]) -> *const c_char {
    // SAFETY: the caller's BTF.
    unsafe {
        let t = btf__type_by_id(btf, var[0]);

        if !t.is_null() && (*t).kind() == KIND_VAR && name_printable(btf, (*t).name_off) {
            btf__name_by_offset(btf, (*t).name_off)
        } else {
            ptr::null()
        }
    }
}

/// The type of the variable of `var`.
///
/// # Safety
///
/// `btf` is a BTF.
unsafe fn var_type(btf: *const Btf, var: &[u32; 3]) -> Option<u32> {
    // SAFETY: the caller's BTF.
    let t = unsafe { btf__type_by_id(btf, var[0]) };

    // SAFETY: NULL, or a type of the BTF.
    if t.is_null() || unsafe { (*t).kind() } != KIND_VAR {
        return None;
    }
    // SAFETY: as above.
    Some(unsafe { (*t).size_type })
}

/// libbpf's dumper prints through this: the C library's vfprintf() onto
/// the stream in `ctx`, with the format and the va_list it was handed.
unsafe extern "C" fn print_text(ctx: *mut c_void, fmt: *const c_char, args: VaList) {
    // SAFETY: the stream print_rodata_text() handed the dumper, and its
    // format and arguments.
    unsafe { vfprintf(ctx.cast(), fmt, args) };
}

/// The cast libbpf's dumper writes before a value spells its type
/// through modifiers, pointers and arrays, and stops at no loop: a
/// pointer to itself grows its stack until memory runs out, and a
/// function prototype whose parameter leads back to it recurses until
/// the stack does.
///
/// # Safety
///
/// `btf` is a BTF.
unsafe fn decl_printable(btf: *const Btf, mut id: u32) -> bool {
    for _ in 0..DECL_MAX {
        if id == 0 {
            return true;
        }
        // SAFETY: the caller's BTF.
        let t = unsafe { btf__type_by_id(btf, id) };
        if t.is_null() {
            return false;
        }
        // SAFETY: a type of the BTF.
        let t_ref = unsafe { &*t };
        match t_ref.kind() {
            KIND_PTR | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => {
                id = t_ref.size_type;
            }
            // SAFETY: the array record behind the type.
            KIND_ARRAY => id = unsafe { (*btf::array(t)).ty },
            KIND_INT | KIND_ENUM | KIND_ENUM64 | KIND_FWD | KIND_STRUCT | KIND_UNION
            | KIND_TYPEDEF | KIND_FLOAT => {
                // SAFETY: the caller's BTF.
                return unsafe { name_printable(btf, t_ref.name_off) };
            }
            _ => return false,
        }
    }
    false
}

/// What the dumper visits of a value of a type: values printed, types
/// deep.
#[derive(Clone, Copy)]
#[repr(C)]
struct DumpCost {
    values: u32,
    height: u32,
}

/// libbpf's dumper follows member, element and modifier types with no
/// bound, and the BTF may come from an unsigned package: a VAR whose
/// type is the DATASEC holding it sends it round until the stack is
/// gone, and billions of elements, of zero size or not, or members laid
/// over the same bytes keep it busy. Walk what it would follow first,
/// through value types alone, with the cast and the member and
/// enumerator names it would print, and count what it would visit:
/// -EINVAL for more than JSON_MAX_DEPTH types deep, -E2BIG for more than
/// TEXT_MAX_VALUES values. `cost` keeps the counts of the types found
/// fine, so a type reached again brings its depth and values along.
///
/// # Safety
///
/// `btf` is a BTF, and `cost` has a slot for each of its types.
unsafe fn dump_cost(btf: *const Btf, id: u32, depth: u32, cost: &mut [DumpCost]) -> c_int {
    // SAFETY: the caller's BTF.
    let tp = unsafe { btf__type_by_id(btf, id) };
    let mut c = DumpCost {
        values: 1,
        height: 1,
    };

    if tp.is_null() || depth >= JSON_MAX_DEPTH {
        return -EINVAL;
    }
    if cost[id as usize].values != 0 {
        return 0;
    }
    // SAFETY: the caller's BTF.
    if !unsafe { decl_printable(btf, id) } {
        return -EINVAL;
    }
    // SAFETY: a type of the BTF, with the records its kind and vlen give
    // behind it; the caller's BTF and costs.
    unsafe {
        let t = &*tp;
        match t.kind() {
            KIND_INT | KIND_PTR | KIND_FLOAT => {}
            KIND_ENUM => {
                for v in ffi::slice(tp.add(1).cast::<[u32; 2]>(), t.vlen() as usize) {
                    if !name_printable(btf, v[0]) {
                        return -EINVAL;
                    }
                }
            }
            KIND_ENUM64 => {
                for v in ffi::slice(tp.add(1).cast::<[u32; 3]>(), t.vlen() as usize) {
                    if !name_printable(btf, v[0]) {
                        return -EINVAL;
                    }
                }
            }
            KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => {
                let ret = dump_cost(btf, t.size_type, depth + 1, cost);
                if ret != 0 {
                    return ret;
                }
                c.values = cost[t.size_type as usize].values;
                c.height = cost[t.size_type as usize].height + 1;
            }
            KIND_ARRAY => {
                let a = &*btf::array(tp);

                if a.nelems != 0 && btf__resolve_size(btf, a.ty) <= 0 {
                    return -EINVAL;
                }
                let ret = dump_cost(btf, a.ty, depth + 1, cost);
                if ret != 0 {
                    return ret;
                }
                let Some(values) = cost[a.ty as usize]
                    .values
                    .checked_mul(a.nelems)
                    .and_then(|child| c.values.checked_add(child))
                else {
                    return -E2BIG;
                };
                c.values = values;
                c.height = cost[a.ty as usize].height + 1;
            }
            KIND_STRUCT | KIND_UNION => {
                for m in ffi::slice(btf::members(tp), t.vlen() as usize) {
                    if !name_printable(btf, m.name_off) {
                        return -EINVAL;
                    }
                    let ret = dump_cost(btf, m.ty, depth + 1, cost);
                    if ret != 0 {
                        return ret;
                    }
                    let Some(values) = c.values.checked_add(cost[m.ty as usize].values) else {
                        return -E2BIG;
                    };
                    c.values = values;
                    c.height = c.height.max(cost[m.ty as usize].height + 1);
                }
            }
            _ => return -EINVAL,
        }
    }
    if c.height > JSON_MAX_DEPTH {
        return -EINVAL;
    }
    if c.values > TEXT_MAX_VALUES {
        return -E2BIG;
    }
    cost[id as usize] = c;
    0
}

/// The DATASEC's variables of `view`, each checked to lie inside it: its
/// name, its type, and the name of its type.
///
/// # Safety
///
/// `view` holds a BTF with its DATASEC.
unsafe fn variable(
    view: &View,
    var: &[u32; 3],
    type_name: &mut [u8; 256],
) -> Result<(*const c_char, u32, usize), c_int> {
    let mut type_off = 0;

    // SAFETY: the view's BTF.
    let name = unsafe { var_name(view.btf, var) };
    // SAFETY: NULL, or a name of the BTF.
    if name.is_null() || unsafe { *name } == 0 {
        return Err(-EINVAL);
    }
    // SAFETY: the view's BTF.
    let Some(type_id) = (unsafe { var_type(view.btf, var) }) else {
        return Err(-EINVAL);
    };
    // SAFETY: the view's BTF.
    let ret = unsafe { append_type_name(view.btf, type_id, type_name, &mut type_off, 0) };
    if ret != 0 {
        return Err(ret);
    }
    if var[1] > view.size || var[2] > view.size - var[1] {
        return Err(-EINVAL);
    }
    Ok((name, type_id, type_off))
}

/// The view's DATASEC and its variables.
///
/// # Safety
///
/// `view` holds a BTF with its DATASEC.
unsafe fn datasec(view: &View) -> &[[u32; 3]] {
    // SAFETY: the view's BTF and the DATASEC btf_rodata_btf() found.
    unsafe { secinfo(btf__type_by_id(view.btf, view.type_id)) }
}

/// The bytes of a variable at `offset` of `size` in the view.
fn var_bytes(view: &View, offset: u32, size: u32) -> &[u8] {
    // SAFETY: bytes of the section, which variable() checked.
    unsafe { ffi::slice(view.bytes.add(offset as usize), size as usize) }
}

/// # Safety
///
/// `path` is a C string, and `view` holds a BTF with its DATASEC.
unsafe fn print_rodata_text(u: &Upatch, path: *const c_char, view: &View) -> c_int {
    let opts = BtfDumpTypeDataOpts {
        sz: size_of::<BtfDumpTypeDataOpts>(),
        indent_str: c"  ".as_ptr(),
        indent_level: 0,
        compact: false,
        skip_names: false,
        emit_zeroes: true,
        emit_strings: true,
    };
    let mut name = [0u8; NAME_MAX + 1];
    let mut values = 0u32;
    let mut ret = 0;

    // SAFETY: the view's BTF.
    let (vars, types) = unsafe { (datasec(view), btf__type_cnt(view.btf)) };
    header_name(u, &mut name);
    let len = name.iter().position(|&c| c == 0).unwrap_or(NAME_MAX);
    // SAFETY: the name, a C string of len bytes, sanitised in place; the
    // C's format with C strings and integers.
    unsafe {
        text_sanitize(name.as_mut_ptr().cast(), len, false);
        printf(
            c"upatch %s (%s) .rodata: %u bytes at data+%u, file+%u\n".as_ptr(),
            name.as_ptr(),
            path,
            view.size,
            view.data_offset,
            u.hdr.data_off.wrapping_add(view.data_offset),
        );
    }
    // SAFETY: a count of costs.
    let cost = unsafe { xcalloc(types as usize, size_of::<DumpCost>()) }.cast::<DumpCost>();
    if cost.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the view's BTF, the printer and its stream, no options.
    let dump = unsafe { btf_dump__new(view.btf, Some(print_text), stdout.cast(), ptr::null()) };
    // SAFETY: what btf_dump__new() returned.
    if unsafe { libbpf_get_error(dump.cast_const().cast()) } != 0 {
        // SAFETY: the costs xcalloc() gave, freed once.
        unsafe { xfree(cost.cast(), types as usize * size_of::<DumpCost>()) };
        return -EINVAL;
    }
    // SAFETY: the types costs, zeroed, one per type of the BTF.
    let costs = unsafe { core::slice::from_raw_parts_mut(cost, types as usize) };
    for var in vars {
        let mut type_name = [0u8; 256];

        // SAFETY: the view.
        let (var_name, type_id, _) = match unsafe { variable(view, var, &mut type_name) } {
            Ok(v) => v,
            Err(err) => {
                ret = err;
                break;
            }
        };
        // SAFETY: the view's BTF, and its costs.
        ret = unsafe { dump_cost(view.btf, type_id, 0, costs) };
        if ret == 0 {
            match values.checked_add(costs[type_id as usize].values) {
                Some(v) if v <= TEXT_MAX_VALUES => values = v,
                _ => ret = -E2BIG,
            }
        }
        if ret == -E2BIG {
            // SAFETY: the C's format and an integer.
            unsafe {
                pr_err(
                    c"BTF text output exceeds %u values".as_ptr(),
                    TEXT_MAX_VALUES,
                )
            };
        }
        if ret != 0 {
            break;
        }
        // SAFETY: the C's format with C strings and integers; the dumper,
        // a type of its BTF, the variable's bytes and the options.
        unsafe {
            printf(
                c"\n%s: %s, size=%u, rodata+%u, data+%u, file+%u = ".as_ptr(),
                var_name,
                type_name.as_ptr(),
                var[2],
                var[1],
                view.data_offset + var[1],
                u.hdr
                    .data_off
                    .wrapping_add(view.data_offset)
                    .wrapping_add(var[1]),
            );
            let bytes = var_bytes(view, var[1], var[2]);
            ret =
                btf_dump__dump_type_data(dump, type_id, bytes.as_ptr().cast(), bytes.len(), &opts);
            if ret < 0 {
                break;
            }
            putchar(c_int::from(b'\n'));
        }
    }
    // SAFETY: the dumper btf_dump__new() gave and the costs xcalloc()
    // gave, each freed once.
    unsafe {
        if ret >= 0 {
            putchar(c_int::from(b'\n'));
        }
        btf_dump__free(dump);
        xfree(cost.cast(), types as usize * size_of::<DumpCost>());
    }
    ret.min(0)
}

/// # Safety
///
/// `path` is a C string, and `view` holds a BTF with its DATASEC.
unsafe fn print_rodata_json(u: &Upatch, path: *const c_char, view: &View) -> c_int {
    let mut e = JsonEmit::growing(MAX_BYTES);
    let mut name = [0u8; NAME_MAX + 1];
    let mut ret = 0;

    // SAFETY: the view.
    let vars = unsafe { datasec(view) };
    header_name(u, &mut name);
    let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(NAME_MAX)];
    e.obj_open();
    e.kv_int(b"schema", 1);
    e.key(b"upatch");
    e.str_lossy(name);
    e.key(b"path");
    // SAFETY: the caller's C string.
    e.str_lossy(unsafe { ffi::c_str(path) });
    e.kv_string(b"section", b".rodata");
    e.kv_int(b"size", i64::from(view.size));
    e.kv_int(b"data_offset", i64::from(view.data_offset));
    e.kv_int(
        b"file_offset",
        i64::from(u.hdr.data_off.wrapping_add(view.data_offset)),
    );
    e.arr_open(b"variables");
    for var in vars {
        let mut type_name = [0u8; 256];

        if e.err() != 0 {
            break;
        }
        // SAFETY: the view.
        let (var_name, type_id, type_len) = match unsafe { variable(view, var, &mut type_name) } {
            Ok(v) => v,
            Err(err) => {
                ret = err;
                break;
            }
        };
        e.obj_open();
        // SAFETY: a name of the view's BTF.
        e.kv_string(b"name", unsafe { ffi::c_str(var_name) });
        e.kv_string(b"type", &type_name[..type_len]);
        e.kv_int(b"size", i64::from(var[2]));
        e.kv_int(b"rodata_offset", i64::from(var[1]));
        e.kv_int(b"data_offset", i64::from(view.data_offset + var[1]));
        e.kv_int(
            b"file_offset",
            i64::from(
                u.hdr
                    .data_off
                    .wrapping_add(view.data_offset)
                    .wrapping_add(var[1]),
            ),
        );
        e.key(b"value");
        // SAFETY: the view's BTF.
        ret = unsafe {
            json_btf_value(
                &mut e,
                view.btf,
                type_id,
                var_bytes(view, var[1], var[2]),
                0,
            )
        };
        e.obj_close();
        if ret != 0 {
            break;
        }
    }
    e.arr_close();
    e.obj_close();
    if ret == 0 && e.err() != 0 {
        ret = e.err();
    }
    let (buf, cap, len) = e.parts();
    // SAFETY: the len bytes the emitter wrote into its buffer, and a
    // newline, onto stdout; then the buffer freed once.
    unsafe {
        if ret == 0 {
            ret = write_complete(STDOUT_FILENO, buf.cast(), len);
        }
        if ret == 0 {
            ret = write_complete(STDOUT_FILENO, c"\n".as_ptr().cast(), 1);
        }
        if e.err() == -E2BIG {
            pr_err(
                c"BTF JSON output exceeds %u bytes".as_ptr(),
                MAX_BYTES as u32,
            );
        }
        xfree(buf.cast(), cap);
    }
    ret
}

/// # Safety
///
/// `path` is a C string.
unsafe fn print(u: &Upatch, path: *const c_char, json: bool) -> c_int {
    let mut view = View::new();

    if is_unload(u) {
        return -EINVAL;
    }
    let ret = btf_rodata_btf(u, &mut view);
    if ret != 0 {
        return ret;
    }
    // SAFETY: the caller's C string, and the view btf_rodata_btf() filled.
    unsafe {
        if json {
            print_rodata_json(u, path, &view)
        } else {
            print_rodata_text(u, path, &view)
        }
    }
}

mod capi {
    use core::ffi::{c_char, c_int};

    use super::{DumpCost, RodataRange};
    use crate::errno::EINVAL;
    use crate::ffi;
    use crate::sys::btf::{Btf, btf__type_cnt};
    use crate::util::upatch::Upatch;

    /// # Safety
    ///
    /// `btf` is a BTF, `buf` holds `cap` bytes, and `off` points to an
    /// offset into them.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_rodata_type_name(
        btf: *const Btf,
        id: u32,
        buf: *mut c_char,
        cap: usize,
        off: *mut usize,
        depth: u32,
    ) -> c_int {
        // SAFETY: the caller passes the BTF, the room and the offset.
        unsafe {
            super::append_type_name(btf, id, ffi::bytes_mut(buf.cast(), cap), &mut *off, depth)
        }
    }

    /// # Safety
    ///
    /// `btf` is a BTF, and `cost` holds a cost for each of its types.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_rodata_dump_cost(
        btf: *const Btf,
        id: u32,
        depth: u32,
        cost: *mut DumpCost,
    ) -> c_int {
        // SAFETY: the caller passes the BTF and a cost for each of its
        // types.
        unsafe {
            let costs = core::slice::from_raw_parts_mut(cost, btf__type_cnt(btf) as usize);

            super::dump_cost(btf, id, depth, costs)
        }
    }

    /// # Safety
    ///
    /// `u` is an open container, and `path` a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_rodata_print(
        u: *const Upatch,
        path: *const c_char,
        json: bool,
    ) -> c_int {
        // SAFETY: the caller passes a container and a path.
        unsafe { super::print(&*u, path, json) }
    }

    /// # Safety
    ///
    /// `u` is NULL or an open container, `symbol` NULL or a C string and
    /// `range` NULL or room for a range.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_rodata_symbol_range(
        u: *const Upatch,
        symbol: *const c_char,
        range: *mut RodataRange,
    ) -> c_int {
        // SAFETY: NULL or the caller's C string.
        if u.is_null() || symbol.is_null() || unsafe { *symbol } == 0 || range.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller's container, symbol and room.
        unsafe { super::symbol_range(&*u, ffi::c_str(symbol), &mut *range) }
    }

    /// # Safety
    ///
    /// `u` is NULL or an open container, and `offset` NULL or room for
    /// one.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_rodata_data_offset(
        u: *const Upatch,
        offset: *mut u32,
    ) -> c_int {
        if u.is_null() || offset.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller's container and room.
        unsafe { super::data_offset(&*u, &mut *offset) }
    }
}
