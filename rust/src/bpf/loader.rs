// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The loader program and its blob. The program runs as BPF_PROG_TYPE_
//! SYSCALL with its blob as the value of map 0 and does with sys_bpf()
//! what the object needs: loads its BTF, creates and fills its maps,
//! resolves its kfuncs and attach targets in the kernel's BTF and loads
//! its programs; it hands the descriptors back in its context. The
//! instructions and the blob are those the vendored libbpf's gen_loader
//! emits at log level 0.
//!
//! The registers: R6 holds the context, R7 the result of the last
//! command, R8 the instruction being resolved and R9 a descriptor being
//! closed. The stack holds the BTF's descriptor, an inner map's and
//! those of the programs.

use core::ffi::c_int;

use super::{
    ADD, ALU, ALU64, AND, B, CALL, DW, EXIT, H, IMM, Insn, JA, JEQ, JMP, JNE, JSET, JSGE, JSGT,
    JSLE, JSLT, K, LD, LDX, MAP_ARRAY_OF_MAPS, MAP_HASH_OF_MAPS, MEM, MOV, PSEUDO_MAP_IDX_VALUE,
    RSH, ST, STX, W, X,
};
use crate::errno::{E2BIG, EBADF, EFAULT, EINVAL, ENOSPC, ERANGE};

const MAX_USED_MAPS: u32 = 64;
const MAX_USED_PROGS: u32 = 64;
const MAX_KFUNC_DESCS: u32 = 256;
const MAX_FD_ARRAY_SZ: u32 = MAX_USED_MAPS + MAX_KFUNC_DESCS;

// The stack: the BTF's descriptor, an inner map's, and one per program.
const STACK_SZ: i32 = 8 + 4 * MAX_USED_PROGS as i32;
const STACK_BTF_FD: i16 = -STACK_SZ as i16;
const STACK_INNER_MAP_FD: i16 = (-STACK_SZ + 4) as i16;

fn stack_prog_fd(i: u32) -> i16 {
    (-STACK_SZ + 8 + 4 * i as i32) as i16
}

// struct bpf_loader_ctx, the map descriptors after it, then the programs'.
const CTX_FLAGS: i16 = 4;
const CTX_LOG_LEVEL: i16 = 8;
const CTX_LOG_SIZE: i16 = 12;
const CTX_LOG_BUF: i16 = 16;
const CTX_SZ: i32 = 24;
const MAP_DESC_SZ: i32 = 16;
const MAP_DESC_MAX_ENTRIES: i32 = 4;
const MAP_DESC_INITIAL_VALUE: i32 = 8;
const PROG_DESC_SZ: i32 = 4;
const SKEL_KERNEL: i32 = 1;

fn ctx_map(map_idx: u32, field: i32) -> i16 {
    (CTX_SZ + MAP_DESC_SZ * map_idx as i32 + field) as i16
}

// Registers.
const R0: u8 = 0;
const R1: u8 = 1;
const R2: u8 = 2;
const R3: u8 = 3;
const R4: u8 = 4;
const R6: u8 = 6;
const R7: u8 = 7;
const R8: u8 = 8;
const R9: u8 = 9;
const R10: u8 = 10;

// Helpers.
const FUNC_PROBE_READ_KERNEL: i32 = 113;
const FUNC_COPY_FROM_USER: i32 = 148;
const FUNC_SYS_BPF: i32 = 166;
const FUNC_BTF_FIND_BY_NAME_KIND: i32 = 167;
const FUNC_SYS_CLOSE: i32 = 168;

// Commands and the union bpf_attr fields the loader fills.
const CMD_MAP_CREATE: i32 = 0;
const CMD_MAP_UPDATE_ELEM: i32 = 2;
const CMD_PROG_LOAD: i32 = 5;
const CMD_BTF_LOAD: i32 = 18;
const CMD_MAP_FREEZE: i32 = 22;
const BTF_LOAD_SZ: usize = 28;
const MAP_CREATE_SZ: usize = 72;
const MAP_UPDATE_SZ: usize = 32;
const MAP_FREEZE_SZ: usize = 4;
const PROG_LOAD_SZ: usize = 140;
const BPF_OBJ_NAME_LEN: usize = 16;

// Offsets in struct bpf_insn.
const INSN_OFF: i16 = 2;
const INSN_IMM: i16 = 4;
const INSN_REGS: i16 = 1;
const INSN_NEXT_IMM: i32 = 8 + 4;

const KIND_TYPEDEF: i32 = 8;
const KIND_FUNC: i32 = 12;

fn mov64_reg(dst: u8, src: u8) -> Insn {
    Insn::new(ALU64 | MOV | X, dst, src, 0, 0)
}

fn mov64_imm(dst: u8, imm: i32) -> Insn {
    Insn::new(ALU64 | MOV | K, dst, 0, 0, imm)
}

fn alu64_imm(op: u8, dst: u8, imm: i32) -> Insn {
    Insn::new(ALU64 | op | K, dst, 0, 0, imm)
}

fn alu32_imm(op: u8, dst: u8, imm: i32) -> Insn {
    Insn::new(ALU | op | K, dst, 0, 0, imm)
}

fn call(func: i32) -> Insn {
    Insn::new(JMP | CALL, 0, 0, 0, func)
}

fn jmp_imm(op: u8, dst: u8, imm: i32, off: i16) -> Insn {
    Insn::new(JMP | op | K, dst, 0, off, imm)
}

fn ja(off: i16) -> Insn {
    jmp_imm(JA, 0, 0, off)
}

fn ldx(size: u8, dst: u8, src: u8, off: i16) -> Insn {
    Insn::new(LDX | size | MEM, dst, src, off, 0)
}

fn stx(size: u8, dst: u8, src: u8, off: i16) -> Insn {
    Insn::new(STX | size | MEM, dst, src, off, 0)
}

fn st(size: u8, dst: u8, off: i16, imm: i32) -> Insn {
    Insn::new(ST | size | MEM, dst, 0, off, imm)
}

fn exit() -> Insn {
    Insn::new(JMP | EXIT, 0, 0, 0, 0)
}

/// The size field of a load or store of `sz` bytes.
fn size_of(sz: u32) -> u8 {
    match sz {
        8 => DW,
        4 => W,
        2 => H,
        _ => B,
    }
}

/// libbpf_strlcpy() into a field of `cap` bytes: at most `cap - 1` bytes
/// of `s`, up to a NUL, and a NUL.
fn strlcpy(dst: &mut [u8], s: &[u8]) {
    let n = s
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(s.len())
        .min(dst.len() - 1);
    dst[..n].copy_from_slice(&s[..n]);
    dst[n] = 0;
}

fn put32(attr: &mut [u8], off: usize, v: u32) {
    attr[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// An extern an instruction of the program being loaded refers to.
pub(crate) struct ExternRelo {
    pub(crate) name: Vec<u8>,
    pub(crate) is_weak: bool,
    pub(crate) is_ld64: bool,
    pub(crate) kind: i32,
    pub(crate) insn_idx: u32,
}

/// An extern resolved once per program, the later references copying it.
struct Ksym {
    name: Vec<u8>,
    kind: i32,
    is_ld64: bool,
    refs: u32,
    off: u32,
    insn: i32,
}

/// A program to load, as bpf_gen__prog_load() takes it.
pub(crate) struct ProgLoad<'a> {
    pub(crate) prog_type: u32,
    pub(crate) name: &'a [u8],
    pub(crate) license: &'a [u8],
    pub(crate) insns: &'a [u8],
    pub(crate) expected_attach_type: u32,
    pub(crate) attach_btf_id: u32,
    pub(crate) prog_flags: u32,
    pub(crate) func_info: &'a [u8],
    pub(crate) func_info_rec_size: u32,
    pub(crate) line_info: &'a [u8],
    pub(crate) line_info_rec_size: u32,
}

/// A map to create, as bpf_gen__map_create() takes it.
pub(crate) struct MapCreate<'a> {
    pub(crate) map_type: u32,
    pub(crate) name: &'a [u8],
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) max_entries: u32,
    pub(crate) map_flags: u32,
    pub(crate) numa_node: u32,
    pub(crate) map_extra: u64,
    pub(crate) btf_key_type_id: u32,
    pub(crate) btf_value_type_id: u32,
}

/// The generator: the instructions and blob so far and what they record.
pub(crate) struct Gen {
    insns: Vec<u8>,
    data: Vec<u8>,
    gen_hash: bool,
    reuse_map_mask: u64,
    fd_array: i32,
    cleanup_label: usize,
    nr_maps: u32,
    nr_progs: u32,
    nr_fd_array: u32,
    attach_kind: i32,
    attach_target: Vec<u8>,
    relos: Vec<ExternRelo>,
    ksyms: Vec<Ksym>,
    core_relos: Vec<u8>,
}

type Res = Result<(), c_int>;

impl Gen {
    /// bpf_gen__init(): the blob's fd_array, the stack zeroed, and the
    /// cleanup code every failure jumps to, which closes the descriptors
    /// so far and returns the error.
    pub(crate) fn new(
        gen_hash: bool,
        reuse_map_mask: u64,
        nr_progs: u32,
        nr_maps: u32,
    ) -> Result<Self, c_int> {
        let mut g = Gen {
            insns: Vec::new(),
            data: Vec::new(),
            gen_hash,
            reuse_map_mask,
            fd_array: 0,
            cleanup_label: 0,
            nr_maps: 0,
            nr_progs: 0,
            nr_fd_array: 0,
            attach_kind: 0,
            attach_target: Vec::new(),
            relos: Vec::new(),
            ksyms: Vec::new(),
            core_relos: Vec::new(),
        };
        g.fd_array = g.add_data(None, (MAX_FD_ARRAY_SZ * 4) as usize)?;
        if nr_maps > MAX_USED_MAPS {
            crate::log::warn(format!("Total maps exceeds {MAX_USED_MAPS}").as_bytes());
            return Err(-E2BIG);
        }
        let reused = |i: u32| reuse_map_mask & (1u64 << i) != 0;
        let nr_cleanup_maps = (0..nr_maps).filter(|&i| !reused(i)).count() as u32;
        g.emit(mov64_reg(R6, 1))?;
        g.emit(mov64_reg(R1, R10))?;
        g.emit(alu64_imm(ADD, R1, -STACK_SZ))?;
        g.emit(mov64_imm(R2, STACK_SZ))?;
        g.emit(mov64_imm(R3, 0))?;
        g.emit(call(FUNC_PROBE_READ_KERNEL))?;
        let nr_progs = nr_progs.min(MAX_USED_PROGS);
        let nr_progs_sz = 8 + 4 * nr_progs;
        g.emit(ja(((nr_progs_sz / 4) * 3 + 2 + nr_cleanup_maps * 6) as i16))?;
        g.cleanup_label = g.insns.len();
        for i in (0..nr_progs_sz).step_by(4) {
            g.emit(ldx(W, R1, R10, (-STACK_SZ + i as i32) as i16))?;
            g.emit(jmp_imm(JSLE, R1, 0, 1))?;
            g.emit(call(FUNC_SYS_CLOSE))?;
        }
        for i in (0..nr_maps).filter(|&i| !reused(i)) {
            g.emit_sys_close_blob(g.fd_slot(i))?;
        }
        g.emit(mov64_reg(R0, R7))?;
        g.emit(exit())?;
        Ok(g)
    }

    fn fd_slot(&self, index: u32) -> i32 {
        self.fd_array + 4 * index as i32
    }

    fn emit(&mut self, insn: Insn) -> Res {
        if self.insns.len() + 8 > i32::MAX as usize {
            return Err(-ERANGE);
        }
        self.insns.extend_from_slice(&insn.bytes());
        Ok(())
    }

    /// An ldimm64 of the address of `off` in the blob, map 0's value.
    fn emit_ld_blob(&mut self, reg: u8, off: i32) -> Res {
        self.emit(Insn::new(LD | DW | IMM, reg, PSEUDO_MAP_IDX_VALUE, 0, 0))?;
        self.emit(Insn::new(0, 0, 0, 0, off))
    }

    /// add_data(): `data`, or `size` zero bytes, at the end of the blob,
    /// padded to 8 bytes; its offset.
    fn add_data(&mut self, data: Option<&[u8]>, size: usize) -> Result<i32, c_int> {
        let size8 = size.div_ceil(8) * 8;
        if size > i32::MAX as usize || self.data.len() + size8 > i32::MAX as usize {
            return Err(-ERANGE);
        }
        let off = self.data.len();
        match data {
            Some(d) => self.data.extend_from_slice(&d[..size]),
            None => self.data.resize(off + size, 0),
        }
        self.data.resize(off + size8, 0);
        Ok(off as i32)
    }

    fn add_bytes(&mut self, data: &[u8]) -> Result<i32, c_int> {
        self.add_data(Some(data), data.len())
    }

    /// `s` and a NUL.
    fn add_str(&mut self, s: &[u8]) -> Result<(i32, i32), c_int> {
        let mut z = s.to_vec();
        z.push(0);
        Ok((self.add_bytes(&z)?, z.len() as i32))
    }

    fn add_map_fd(&mut self) -> Result<u32, c_int> {
        if self.nr_maps == MAX_USED_MAPS {
            crate::log::warn(format!("Total maps exceeds {MAX_USED_MAPS}").as_bytes());
            return Err(-E2BIG);
        }
        self.nr_maps += 1;
        Ok(self.nr_maps - 1)
    }

    fn add_kfunc_btf_fd(&mut self) -> Result<u32, c_int> {
        if self.nr_fd_array == MAX_KFUNC_DESCS {
            let cur = self.add_data(None, 4)?;
            return Ok(((cur - self.fd_array) / 4) as u32);
        }
        self.nr_fd_array += 1;
        Ok(MAX_USED_MAPS + self.nr_fd_array - 1)
    }

    /// *(u64 *)(blob + off) = blob + data
    fn emit_rel_store(&mut self, off: i32, data: i32) -> Res {
        self.emit_ld_blob(R0, data)?;
        self.emit_ld_blob(R1, off)?;
        self.emit(stx(DW, R1, R0, 0))
    }

    fn move_blob2blob(&mut self, off: i32, size: u32, blob_off: i32) -> Res {
        self.emit_ld_blob(R2, blob_off)?;
        self.emit(ldx(size_of(size), R0, R2, 0))?;
        self.emit_ld_blob(R1, off)?;
        self.emit(stx(size_of(size), R1, R0, 0))
    }

    fn move_blob2ctx(&mut self, ctx_off: i16, size: u32, blob_off: i32) -> Res {
        self.emit_ld_blob(R1, blob_off)?;
        self.emit(ldx(size_of(size), R0, R1, 0))?;
        self.emit(stx(size_of(size), R6, R0, ctx_off))
    }

    /// A field of the context into the blob, unless `check_non_zero` and
    /// it is 0.
    fn move_ctx2blob(&mut self, off: i32, size: u32, ctx_off: i16, check_non_zero: bool) -> Res {
        self.emit(ldx(size_of(size), R0, R6, ctx_off))?;
        if check_non_zero {
            self.emit(jmp_imm(JEQ, R0, 0, 3))?;
        }
        self.emit_ld_blob(R1, off)?;
        self.emit(stx(size_of(size), R1, R0, 0))
    }

    fn move_stack2blob(&mut self, off: i32, size: u32, stack_off: i16) -> Res {
        self.emit(ldx(size_of(size), R0, R10, stack_off))?;
        self.emit_ld_blob(R1, off)?;
        self.emit(stx(size_of(size), R1, R0, 0))
    }

    fn move_stack2ctx(&mut self, ctx_off: i16, size: u32, stack_off: i16) -> Res {
        self.emit(ldx(size_of(size), R0, R10, stack_off))?;
        self.emit(stx(size_of(size), R6, R0, ctx_off))
    }

    /// sys_bpf(cmd, blob + attr, attr_size), its result in R7.
    fn emit_sys_bpf(&mut self, cmd: i32, attr: i32, attr_size: usize) -> Res {
        self.emit(mov64_imm(R1, cmd))?;
        self.emit_ld_blob(R2, attr)?;
        self.emit(mov64_imm(R3, attr_size as i32))?;
        self.emit(call(FUNC_SYS_BPF))?;
        self.emit(mov64_reg(R7, R0))
    }

    /// if (R7 < 0) goto cleanup
    fn emit_check_err(&mut self) -> Res {
        let off = -(((self.insns.len() - self.cleanup_label) / 8) as i64) - 1;
        let off = i16::try_from(off).map_err(|_| -ERANGE)?;
        self.emit(jmp_imm(JSLT, R7, 0, off))
    }

    /// Closes the descriptor in R1 if it is one.
    fn emit_sys_close(&mut self) -> Res {
        self.emit(jmp_imm(JSLE, R1, 0, 2))?;
        self.emit(mov64_reg(R9, R1))?;
        self.emit(call(FUNC_SYS_CLOSE))
    }

    fn emit_sys_close_stack(&mut self, stack_off: i16) -> Res {
        self.emit(ldx(W, R1, R10, stack_off))?;
        self.emit_sys_close()
    }

    fn emit_sys_close_blob(&mut self, blob_off: i32) -> Res {
        self.emit_ld_blob(R0, blob_off)?;
        self.emit(ldx(W, R1, R0, 0))?;
        self.emit_sys_close()
    }

    /// bpf_gen__finish(): the BTF closed, the descriptors handed to the
    /// context; the instructions and the blob.
    pub(crate) fn finish(
        mut self,
        nr_progs: u32,
        nr_maps: u32,
    ) -> Result<(Vec<u8>, Vec<u8>), c_int> {
        if nr_progs < self.nr_progs || nr_maps != self.nr_maps {
            crate::log::warn(
                format!(
                    "nr_progs {nr_progs}/{} nr_maps {nr_maps}/{} mismatch",
                    self.nr_progs, self.nr_maps
                )
                .as_bytes(),
            );
            return Err(-EFAULT);
        }
        self.emit_sys_close_stack(STACK_BTF_FD)?;
        for i in 0..self.nr_progs {
            let ctx_off = CTX_SZ + MAP_DESC_SZ * self.nr_maps as i32 + PROG_DESC_SZ * i as i32;
            self.move_stack2ctx(ctx_off as i16, 4, stack_prog_fd(i))?;
        }
        for i in 0..self.nr_maps {
            self.move_blob2ctx(ctx_map(i, 0), 4, self.fd_slot(i))?;
        }
        self.emit(mov64_imm(R0, 0))?;
        self.emit(exit())?;
        Ok((self.insns, self.data))
    }

    /// bpf_gen__load_btf(): BPF_BTF_LOAD of `raw`, its descriptor kept on
    /// the stack.
    pub(crate) fn load_btf(&mut self, raw: &[u8]) -> Res {
        let btf_data = self.add_bytes(raw)?;
        let mut attr = [0u8; BTF_LOAD_SZ];
        put32(&mut attr, 16, raw.len() as u32);
        let a = self.add_bytes(&attr)?;
        self.move_ctx2blob(a + 24, 4, CTX_LOG_LEVEL, false)?;
        self.move_ctx2blob(a + 20, 4, CTX_LOG_SIZE, false)?;
        self.move_ctx2blob(a + 8, 8, CTX_LOG_BUF, false)?;
        self.emit_rel_store(a, btf_data)?;
        self.emit_sys_bpf(CMD_BTF_LOAD, a, BTF_LOAD_SZ)?;
        self.emit_check_err()?;
        self.emit(stx(W, R10, R7, STACK_BTF_FD))
    }

    /// bpf_gen__map_create() of the object's map `map_idx`, or the
    /// descriptor the context passes for a map the mask says to reuse.
    pub(crate) fn map_create(&mut self, m: &MapCreate<'_>, map_idx: u32) -> Res {
        if map_idx < MAX_USED_MAPS && self.reuse_map_mask & (1u64 << map_idx) != 0 {
            let fd_idx = self.add_map_fd()?;
            self.emit(ldx(W, R7, R6, ctx_map(map_idx, 0)))?;
            self.emit(jmp_imm(JSGT, R7, 0, 2))?;
            self.emit(mov64_imm(R7, -EBADF))?;
            self.emit_check_err()?;
            self.emit_ld_blob(R1, self.fd_slot(fd_idx))?;
            return self.emit(stx(W, R1, R7, 0));
        }
        let mut attr = [0u8; MAP_CREATE_SZ];
        put32(&mut attr, 0, m.map_type);
        put32(&mut attr, 4, m.key_size);
        put32(&mut attr, 8, m.value_size);
        put32(&mut attr, 12, m.max_entries);
        put32(&mut attr, 16, m.map_flags);
        put32(&mut attr, 24, m.numa_node);
        strlcpy(&mut attr[28..28 + BPF_OBJ_NAME_LEN], m.name);
        put32(&mut attr, 52, m.btf_key_type_id);
        put32(&mut attr, 56, m.btf_value_type_id);
        attr[64..72].copy_from_slice(&m.map_extra.to_le_bytes());
        let a = self.add_bytes(&attr)?;
        if m.btf_value_type_id != 0 {
            self.move_stack2blob(a + 48, 4, STACK_BTF_FD)?;
        }
        let inner = matches!(m.map_type, MAP_ARRAY_OF_MAPS | MAP_HASH_OF_MAPS);
        if inner {
            self.move_stack2blob(a + 20, 4, STACK_INNER_MAP_FD)?;
        }
        if !self.gen_hash {
            self.move_ctx2blob(a + 12, 4, ctx_map(map_idx, MAP_DESC_MAX_ENTRIES), true)?;
        }
        self.emit_sys_bpf(CMD_MAP_CREATE, a, MAP_CREATE_SZ)?;
        self.emit_check_err()?;
        if map_idx != self.nr_maps {
            return Err(-EINVAL);
        }
        let idx = self.add_map_fd()?;
        self.emit_ld_blob(R1, self.fd_slot(idx))?;
        self.emit(stx(W, R1, R7, 0))?;
        if inner {
            self.emit_sys_close_stack(STACK_INNER_MAP_FD)?;
        }
        Ok(())
    }

    /// bpf_gen__record_attach_target(): the kernel BTF type the next
    /// program attaches to, its name prefixed as its attach type wants.
    pub(crate) fn record_attach_target(&mut self, name: &[u8], attach_type: u32) -> Res {
        let (prefix, kind): (&[u8], i32) = match attach_type {
            super::TRACE_RAW_TP => (b"btf_trace_", KIND_TYPEDEF),
            super::LSM_MAC => (b"bpf_lsm_", KIND_FUNC),
            _ => (b"", KIND_FUNC),
        };
        self.attach_kind = kind;
        self.attach_target = [prefix, name].concat();
        if self.attach_target.len() >= 128 {
            return Err(-ENOSPC);
        }
        Ok(())
    }

    fn emit_find_attach_target(&mut self) -> Res {
        let target = self.attach_target.clone();
        let (name, len) = self.add_str(&target)?;
        self.emit_ld_blob(R1, name)?;
        self.emit(mov64_imm(R2, len))?;
        self.emit(mov64_imm(R3, self.attach_kind))?;
        self.emit(mov64_imm(R4, 0))?;
        self.emit(call(FUNC_BTF_FIND_BY_NAME_KIND))?;
        self.emit(mov64_reg(R7, R0))?;
        self.emit_check_err()
    }

    /// bpf_gen__record_extern(): an extern of the next program.
    pub(crate) fn record_extern(&mut self, relo: ExternRelo) {
        self.relos.push(relo);
    }

    /// bpf_gen__record_relo_core(): a CO-RE relocation of the next
    /// program, for the kernel to apply.
    pub(crate) fn record_relo_core(&mut self, insn_off: u32, rec: &[u8]) {
        self.core_relos.extend_from_slice(&insn_off.to_le_bytes());
        self.core_relos.extend_from_slice(&rec[4..16]);
    }

    /// The extern's resolution, a new one or the one before with its
    /// count raised: its index.
    fn ksym(&mut self, relo: usize) -> usize {
        let r = &self.relos[relo];
        if let Some(i) = self
            .ksyms
            .iter()
            .position(|k| k.kind == r.kind && k.is_ld64 == r.is_ld64 && k.name == r.name)
        {
            self.ksyms[i].refs += 1;
            return i;
        }
        self.ksyms.push(Ksym {
            name: r.name.clone(),
            kind: r.kind,
            is_ld64: r.is_ld64,
            refs: 1,
            off: 0,
            insn: 0,
        });
        self.ksyms.len() - 1
    }

    /// R7 = btf_find_by_name_kind(name, kind)
    fn emit_find_by_name_kind(&mut self, relo: usize) -> Res {
        let (name, kind) = (self.relos[relo].name.clone(), self.relos[relo].kind);
        let (name_off, len) = self.add_str(&name)?;
        self.emit_ld_blob(R1, name_off)?;
        self.emit(mov64_imm(R2, len))?;
        self.emit(mov64_imm(R3, kind))?;
        self.emit(mov64_imm(R4, 0))?;
        self.emit(call(FUNC_BTF_FIND_BY_NAME_KIND))?;
        self.emit(mov64_reg(R7, R0))
    }

    /// A kfunc call at `insn`: its BTF id into imm and, for a module's,
    /// the module BTF's fd_array slot into off.
    fn emit_relo_kfunc_btf(&mut self, relo: usize, insn: i32) -> Res {
        let k = self.ksym(relo);
        if self.ksyms[k].refs > 1 {
            let first = self.ksyms[k].insn;
            self.move_blob2blob(insn + i32::from(INSN_IMM), 4, first + i32::from(INSN_IMM))?;
            return self.move_blob2blob(insn + i32::from(INSN_OFF), 2, first + i32::from(INSN_OFF));
        }
        self.ksyms[k].insn = insn;
        self.emit_find_by_name_kind(relo)?;
        if !self.relos[relo].is_weak {
            self.emit_check_err()?;
        }
        let btf_fd_idx = self.add_kfunc_btf_fd()?;
        if btf_fd_idx > i16::MAX as u32 {
            return Err(-E2BIG);
        }
        self.ksyms[k].off = btf_fd_idx;
        self.emit(jmp_imm(JSGE, R7, 0, 3))?;
        self.emit(st(W, R8, INSN_IMM, 0))?;
        self.emit(st(H, R8, INSN_OFF, 0))?;
        self.emit(ja(10))?;
        self.emit(stx(W, R8, R7, INSN_IMM))?;
        self.emit(mov64_reg(R9, R7))?;
        self.emit(alu64_imm(RSH, R9, 32))?;
        self.emit_ld_blob(R0, self.fd_slot(btf_fd_idx))?;
        self.emit(stx(W, R0, R9, 0))?;
        self.emit(jmp_imm(JNE, R9, 0, 2))?;
        self.emit(st(H, R8, INSN_OFF, 0))?;
        self.emit(ja(1))?;
        self.emit(st(H, R8, INSN_OFF, btf_fd_idx as i32))
    }

    /// A typed ksym's ldimm64 at `insn`: its BTF id and BTF object fd
    /// into the two imms, or a plain 0 when a weak one is missing.
    fn emit_relo_ksym_btf(&mut self, relo: usize, insn: i32) -> Res {
        let k = self.ksym(relo);
        if self.ksyms[k].refs > 1 {
            let first = self.ksyms[k].insn;
            self.move_blob2blob(insn + INSN_NEXT_IMM, 4, first + INSN_NEXT_IMM)?;
            self.move_blob2blob(insn + i32::from(INSN_IMM), 4, first + i32::from(INSN_IMM))?;
            self.emit(jmp_imm(JNE, R0, 0, 3))?;
        } else {
            self.ksyms[k].insn = insn;
            self.emit_find_by_name_kind(relo)?;
            if !self.relos[relo].is_weak {
                self.emit_check_err()?;
            }
            self.emit(jmp_imm(JSGE, R7, 0, 3))?;
            self.emit(st(W, R8, INSN_IMM, 0))?;
            self.emit(st(W, R8, INSN_NEXT_IMM as i16, 0))?;
            self.emit(ja(4))?;
            self.emit(stx(W, R8, R7, INSN_IMM))?;
            self.emit(alu64_imm(RSH, R7, 32))?;
            self.emit(stx(W, R8, R7, INSN_NEXT_IMM as i16))?;
            self.emit(ja(3))?;
        }
        // Clears the BPF_PSEUDO_BTF_ID the instruction's source register
        // has, for a weak ksym not found.
        self.emit(ldx(B, R9, R8, INSN_REGS))?;
        self.emit(alu32_imm(AND, R9, 0x0f))?;
        self.emit(stx(B, R8, R9, INSN_REGS))
    }

    fn emit_relos(&mut self, insns: i32) -> Res {
        for i in 0..self.relos.len() {
            let insn = insns + 8 * self.relos[i].insn_idx as i32;
            self.emit_ld_blob(R8, insn)?;
            if self.relos[i].is_ld64 {
                self.emit_relo_ksym_btf(i, insn)?;
            } else {
                self.emit_relo_kfunc_btf(i, insn)?;
            }
        }
        Ok(())
    }

    /// Closes the module BTFs the externs of the program held.
    fn cleanup_relos(&mut self) -> Res {
        for k in std::mem::take(&mut self.ksyms) {
            if k.is_ld64 {
                self.emit_sys_close_blob(k.insn + INSN_NEXT_IMM)?;
            } else {
                self.emit_sys_close_blob(self.fd_slot(k.off))?;
                if k.off < MAX_FD_ARRAY_SZ {
                    self.nr_fd_array -= 1;
                }
            }
        }
        self.relos.clear();
        self.core_relos.clear();
        Ok(())
    }

    /// bpf_gen__prog_load(): BPF_PROG_LOAD of `p` with the externs and
    /// CO-RE relocations recorded for it, its descriptor kept on the
    /// stack.
    pub(crate) fn prog_load(&mut self, p: &ProgLoad<'_>) -> Res {
        let (license, _) = self.add_str(p.license)?;
        let insns = self.add_bytes(p.insns)?;
        let mut attr = [0u8; PROG_LOAD_SZ];
        put32(&mut attr, 0, p.prog_type);
        put32(&mut attr, 4, (p.insns.len() / 8) as u32);
        put32(&mut attr, 44, p.prog_flags);
        put32(&mut attr, 68, p.expected_attach_type);
        put32(&mut attr, 108, p.attach_btf_id);
        let cnt = |b: &[u8], rec: u32| (b.len() as u32).checked_div(rec).unwrap_or(0);
        put32(&mut attr, 76, p.func_info_rec_size);
        put32(&mut attr, 88, cnt(p.func_info, p.func_info_rec_size));
        let func_info = self.add_bytes(p.func_info)?;
        put32(&mut attr, 92, p.line_info_rec_size);
        put32(&mut attr, 104, cnt(p.line_info, p.line_info_rec_size));
        let line_info = self.add_bytes(p.line_info)?;
        put32(&mut attr, 136, 16);
        put32(&mut attr, 116, (self.core_relos.len() / 16) as u32);
        let core = self.core_relos.clone();
        let core_relos = self.add_bytes(&core)?;
        strlcpy(&mut attr[48..48 + BPF_OBJ_NAME_LEN], p.name);
        let a = self.add_bytes(&attr)?;
        self.emit_rel_store(a + 16, license)?;
        self.emit_rel_store(a + 8, insns)?;
        self.emit_rel_store(a + 80, func_info)?;
        self.emit_rel_store(a + 96, line_info)?;
        self.emit_rel_store(a + 128, core_relos)?;
        self.emit_rel_store(a + 120, self.fd_array)?;
        self.move_ctx2blob(a + 24, 4, CTX_LOG_LEVEL, false)?;
        self.move_ctx2blob(a + 28, 4, CTX_LOG_SIZE, false)?;
        self.move_ctx2blob(a + 32, 8, CTX_LOG_BUF, false)?;
        self.move_stack2blob(a + 72, 4, STACK_BTF_FD)?;
        if self.attach_kind != 0 {
            self.emit_find_attach_target()?;
            self.emit_ld_blob(R0, a)?;
            self.emit(stx(W, R0, R7, 108))?;
            self.emit(alu64_imm(RSH, R7, 32))?;
            self.emit(stx(W, R0, R7, 112))?;
        }
        self.emit_relos(insns)?;
        self.emit_sys_bpf(CMD_PROG_LOAD, a, PROG_LOAD_SZ)?;
        self.cleanup_relos()?;
        if self.attach_kind != 0 {
            self.emit_sys_close_blob(a + 112)?;
            self.attach_kind = 0;
        }
        self.emit_check_err()?;
        if self.nr_progs == MAX_USED_PROGS {
            crate::log::warn(format!("Total programs exceeds {MAX_USED_PROGS}").as_bytes());
            return Err(-E2BIG);
        }
        self.emit(stx(W, R10, R7, stack_prog_fd(self.nr_progs)))?;
        self.nr_progs += 1;
        Ok(())
    }

    /// bpf_gen__map_update_elem(): element 0 of map `map_idx` set to
    /// `value`, or, for an unsigned loader, to the initial value the
    /// context passes for it.
    pub(crate) fn map_update_elem(&mut self, map_idx: u32, value: &[u8], flags: u64) -> Res {
        let mut attr = [0u8; MAP_UPDATE_SZ];
        attr[24..32].copy_from_slice(&flags.to_le_bytes());
        let v = self.add_bytes(value)?;
        let key = self.add_bytes(&0u32.to_le_bytes())?;
        if !self.gen_hash {
            self.emit(ldx(DW, R3, R6, ctx_map(map_idx, MAP_DESC_INITIAL_VALUE)))?;
            self.emit(jmp_imm(JEQ, R3, 0, 8))?;
            self.emit_ld_blob(R1, v)?;
            self.emit(mov64_imm(R2, value.len() as i32))?;
            self.emit(ldx(W, R0, R6, CTX_FLAGS))?;
            self.emit(jmp_imm(JSET, R0, SKEL_KERNEL, 2))?;
            self.emit(call(FUNC_COPY_FROM_USER))?;
            self.emit(ja(1))?;
            self.emit(call(FUNC_PROBE_READ_KERNEL))?;
        }
        let a = self.add_bytes(&attr)?;
        self.move_blob2blob(a, 4, self.fd_slot(map_idx))?;
        self.emit_rel_store(a + 8, key)?;
        self.emit_rel_store(a + 16, v)?;
        self.emit_sys_bpf(CMD_MAP_UPDATE_ELEM, a, MAP_UPDATE_SZ)?;
        self.emit_check_err()
    }

    /// bpf_gen__map_freeze()
    pub(crate) fn map_freeze(&mut self, map_idx: u32) -> Res {
        let a = self.add_bytes(&[0u8; MAP_FREEZE_SZ])?;
        self.move_blob2blob(a, 4, self.fd_slot(map_idx))?;
        self.emit_sys_bpf(CMD_MAP_FREEZE, a, MAP_FREEZE_SZ)?;
        self.emit_check_err()
    }
}
