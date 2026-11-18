// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! BPF objects turned into light skeleton loaders: an object as clang
//! writes it read, its programs, maps and relocations collected, and the
//! loader program and its blob generated, byte for byte what the vendored
//! libbpf's gen_loader makes of it.

pub(crate) mod btf;
pub(crate) mod btf_dump;
pub(crate) mod btf_ext;
pub(crate) mod elf;
pub(crate) mod loader;
pub(crate) mod lskel;
pub(crate) mod object;
pub(crate) mod skel;

/// An instruction: its opcode, its registers, the destination in the low
/// nibble, and its offset and immediate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Insn {
    pub(crate) code: u8,
    pub(crate) regs: u8,
    pub(crate) off: i16,
    pub(crate) imm: i32,
}

pub(crate) const INSN_SZ: usize = 8;

impl Insn {
    pub(crate) const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Insn {
            code,
            regs: (src << 4) | (dst & 0xf),
            off,
            imm,
        }
    }

    pub(crate) fn parse(b: &[u8]) -> Self {
        Insn {
            code: b[0],
            regs: b[1],
            off: i16::from_le_bytes([b[2], b[3]]),
            imm: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }

    pub(crate) fn bytes(&self) -> [u8; INSN_SZ] {
        let mut b = [0; INSN_SZ];
        b[0] = self.code;
        b[1] = self.regs;
        b[2..4].copy_from_slice(&self.off.to_le_bytes());
        b[4..8].copy_from_slice(&self.imm.to_le_bytes());
        b
    }

    pub(crate) fn dst(&self) -> u8 {
        self.regs & 0xf
    }

    pub(crate) fn src(&self) -> u8 {
        self.regs >> 4
    }

    pub(crate) fn set_src(&mut self, src: u8) {
        self.regs = (self.regs & 0xf) | (src << 4);
    }

    pub(crate) fn is_ldimm64(&self) -> bool {
        self.code == LD | DW | IMM
    }

    pub(crate) fn is_call(&self) -> bool {
        self.code == JMP | CALL
    }

    /// A call of a subprogram, which is not a call of a helper or kfunc.
    pub(crate) fn is_subprog_call(&self) -> bool {
        self.is_call() && self.src() == PSEUDO_CALL && self.dst() == 0 && self.off == 0
    }

    /// The address of a subprogram loaded.
    pub(crate) fn is_pseudo_func(&self) -> bool {
        self.is_ldimm64() && self.src() == PSEUDO_FUNC
    }
}

// Instruction classes, sizes, modes, sources and operations.
pub(crate) const LD: u8 = 0x00;
pub(crate) const LDX: u8 = 0x01;
pub(crate) const ST: u8 = 0x02;
pub(crate) const STX: u8 = 0x03;
pub(crate) const ALU: u8 = 0x04;
pub(crate) const JMP: u8 = 0x05;
pub(crate) const ALU64: u8 = 0x07;
pub(crate) const W: u8 = 0x00;
pub(crate) const H: u8 = 0x08;
pub(crate) const B: u8 = 0x10;
pub(crate) const DW: u8 = 0x18;
pub(crate) const IMM: u8 = 0x00;
pub(crate) const MEM: u8 = 0x60;
pub(crate) const K: u8 = 0x00;
pub(crate) const X: u8 = 0x08;
pub(crate) const ADD: u8 = 0x00;
pub(crate) const AND: u8 = 0x50;
pub(crate) const RSH: u8 = 0x70;
pub(crate) const MOV: u8 = 0xb0;
pub(crate) const JA: u8 = 0x00;
pub(crate) const JEQ: u8 = 0x10;
pub(crate) const JSET: u8 = 0x40;
pub(crate) const JNE: u8 = 0x50;
pub(crate) const JSGT: u8 = 0x60;
pub(crate) const JSGE: u8 = 0x70;
pub(crate) const CALL: u8 = 0x80;
pub(crate) const EXIT: u8 = 0x90;
pub(crate) const JSLT: u8 = 0xc0;
pub(crate) const JSLE: u8 = 0xd0;

// What an ldimm64's or a call's source register says it is.
pub(crate) const PSEUDO_CALL: u8 = 1;
pub(crate) const PSEUDO_KFUNC_CALL: u8 = 2;
pub(crate) const PSEUDO_BTF_ID: u8 = 3;
pub(crate) const PSEUDO_FUNC: u8 = 4;
pub(crate) const PSEUDO_MAP_IDX: u8 = 5;
pub(crate) const PSEUDO_MAP_IDX_VALUE: u8 = 6;

// Program types and the attach types they are loaded for.
pub(crate) const PROG_KPROBE: u32 = 2;
pub(crate) const PROG_TRACEPOINT: u32 = 5;
pub(crate) const PROG_XDP: u32 = 6;
pub(crate) const PROG_CGROUP_SKB: u32 = 8;
pub(crate) const PROG_RAW_TRACEPOINT: u32 = 17;
pub(crate) const PROG_TRACING: u32 = 26;
pub(crate) const PROG_LSM: u32 = 29;
pub(crate) const PROG_SYSCALL: u32 = 31;
pub(crate) const PROG_NETFILTER: u32 = 32;
pub(crate) const CGROUP_INET_INGRESS: u32 = 0;
pub(crate) const CGROUP_INET_EGRESS: u32 = 1;
pub(crate) const TRACE_RAW_TP: u32 = 23;
pub(crate) const TRACE_FENTRY: u32 = 24;
pub(crate) const TRACE_FEXIT: u32 = 25;
pub(crate) const MODIFY_RETURN: u32 = 26;
pub(crate) const LSM_MAC: u32 = 27;
pub(crate) const XDP: u32 = 37;
pub(crate) const TRACE_KPROBE_MULTI: u32 = 42;
pub(crate) const NETFILTER: u32 = 45;
pub(crate) const TRACE_UPROBE_MULTI: u32 = 48;
pub(crate) const TRACE_KPROBE_SESSION: u32 = 56;
pub(crate) const TRACE_UPROBE_SESSION: u32 = 57;
pub(crate) const F_SLEEPABLE: u32 = 1 << 4;
pub(crate) const F_XDP_HAS_FRAGS: u32 = 1 << 5;

// Map types and flags.
pub(crate) const MAP_ARRAY: u32 = 2;
pub(crate) const MAP_PERF_EVENT_ARRAY: u32 = 4;
pub(crate) const MAP_STACK_TRACE: u32 = 7;
pub(crate) const MAP_CGROUP_ARRAY: u32 = 8;
pub(crate) const MAP_ARRAY_OF_MAPS: u32 = 12;
pub(crate) const MAP_HASH_OF_MAPS: u32 = 13;
pub(crate) const MAP_DEVMAP: u32 = 14;
pub(crate) const MAP_SOCKMAP: u32 = 15;
pub(crate) const MAP_CPUMAP: u32 = 16;
pub(crate) const MAP_XSKMAP: u32 = 17;
pub(crate) const MAP_SOCKHASH: u32 = 18;
pub(crate) const MAP_QUEUE: u32 = 22;
pub(crate) const MAP_STACK: u32 = 23;
pub(crate) const MAP_DEVMAP_HASH: u32 = 25;
pub(crate) const MAP_STRUCT_OPS: u32 = 26;
pub(crate) const MAP_RINGBUF: u32 = 27;
pub(crate) const MAP_USER_RINGBUF: u32 = 31;
pub(crate) const MAP_ARENA: u32 = 33;
pub(crate) const F_RDONLY_PROG: u32 = 1 << 7;
pub(crate) const F_MMAPABLE: u32 = 1 << 10;

/// The host's page size, which sizes ring buffers and arenas.
pub(crate) fn page_size() -> u64 {
    const SC_PAGESIZE: core::ffi::c_int = 30;
    // SAFETY: a query without side effects.
    let sz = unsafe { crate::sys::libc::sysconf(SC_PAGESIZE) };
    u64::try_from(sz).unwrap_or(4096)
}
