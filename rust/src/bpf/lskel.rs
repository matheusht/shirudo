// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! A light skeleton as shirudo embeds one: an object's loader program and
//! data, which a run of the loader turns into the object's maps and
//! programs, with what its caller finds them by.
//!
//! Little endian: the magic `SHLSKEL1`; the number of maps, of programs
//! and of externs; the maps the loader takes from its caller instead of
//! creating, as a mask of their indices; the size of the names, of the
//! instructions and of the data; then the maps' names, in the order of
//! the loader's map descriptors; each program's type, attach type and
//! name, in the order of its program descriptors; the names of the
//! kernel symbols it resolves; then, at an offset a multiple of 8, the
//! instructions, then the data. Each name ends in a NUL.

const MAGIC: &[u8; 8] = b"SHLSKEL1";
const HEADER: usize = 40;
/// The maps and programs a loader's descriptors can hold.
const MAX_ENTRIES: usize = 64;
const INSN: usize = 8;

/// A program the loader loads: its type and expected attach type, by
/// which its caller attaches it, and its name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Program<'a> {
    pub(crate) prog_type: u32,
    pub(crate) attach_type: u32,
    pub(crate) name: &'a [u8],
}

/// The skeleton.
#[derive(PartialEq, Eq, Debug)]
pub(crate) struct Lskel<'a> {
    pub(crate) maps: Vec<&'a [u8]>,
    pub(crate) progs: Vec<Program<'a>>,
    pub(crate) externs: Vec<&'a [u8]>,
    pub(crate) reuse_map_mask: u64,
    pub(crate) insns: &'a [u8],
    pub(crate) data: &'a [u8],
}

fn le32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

/// The NUL-terminated name at the front of `b` and what follows it.
fn name(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = b.iter().position(|&c| c == 0)?;
    Some((&b[..end], &b[end + 1..]))
}

impl<'a> Lskel<'a> {
    /// The index and the program named `name`.
    pub(crate) fn prog(&self, name: &[u8]) -> Option<(usize, &Program<'a>)> {
        self.progs.iter().enumerate().find(|(_, p)| p.name == name)
    }

    /// Whether the loader takes map `i` from its caller.
    pub(crate) fn reuses(&self, i: usize) -> bool {
        i < MAX_ENTRIES && self.reuse_map_mask & (1 << i) != 0
    }

    /// The skeleton's bytes, which tools/bpf-lskel writes: the binaries
    /// only read skeletons.
    #[allow(dead_code)]
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut names = Vec::new();
        for m in &self.maps {
            names.extend_from_slice(m);
            names.push(0);
        }
        for p in &self.progs {
            names.extend_from_slice(&p.prog_type.to_le_bytes());
            names.extend_from_slice(&p.attach_type.to_le_bytes());
            names.extend_from_slice(p.name);
            names.push(0);
        }
        for e in &self.externs {
            names.extend_from_slice(e);
            names.push(0);
        }
        names.resize((HEADER + names.len()).next_multiple_of(INSN) - HEADER, 0);
        let mut out = Vec::with_capacity(HEADER + names.len() + self.insns.len() + self.data.len());
        out.extend_from_slice(MAGIC);
        for n in [self.maps.len(), self.progs.len(), self.externs.len()] {
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        out.extend_from_slice(&self.reuse_map_mask.to_le_bytes());
        for n in [names.len(), self.insns.len(), self.data.len()] {
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        out.extend_from_slice(&names);
        out.extend_from_slice(self.insns);
        out.extend_from_slice(self.data);
        out
    }

    /// The skeleton in `b`, whole and consistent, or none.
    pub(crate) fn parse(b: &'a [u8]) -> Option<Self> {
        if b.get(..8)? != MAGIC {
            return None;
        }
        let [nr_maps, nr_progs, nr_externs] =
            [8, 12, 16].map(|off| le32(b, off).map(|n| n as usize));
        let (nr_maps, nr_progs, nr_externs) = (nr_maps?, nr_progs?, nr_externs?);
        let reuse_map_mask = u64::from_le_bytes(b.get(20..28)?.try_into().ok()?);
        let [names_len, insns_len, data_len] =
            [28, 32, 36].map(|off| le32(b, off).map(|n| n as usize));
        let (names_len, insns_len, data_len) = (names_len?, insns_len?, data_len?);
        if nr_maps > MAX_ENTRIES
            || nr_progs > MAX_ENTRIES
            || reuse_map_mask.checked_shr(nr_maps as u32).unwrap_or(0) != 0
            || !(HEADER + names_len).is_multiple_of(INSN)
            || insns_len == 0
            || insns_len % INSN != 0
            || HEADER + names_len + insns_len + data_len != b.len()
        {
            return None;
        }
        let mut rest = &b[HEADER..HEADER + names_len];
        let mut maps = Vec::with_capacity(nr_maps);
        for _ in 0..nr_maps {
            let (m, r) = name(rest)?;
            maps.push(m);
            rest = r;
        }
        let mut progs = Vec::with_capacity(nr_progs);
        for _ in 0..nr_progs {
            let (prog_type, attach_type) = (le32(rest, 0)?, le32(rest, 4)?);
            let (n, r) = name(&rest[8..])?;
            progs.push(Program {
                prog_type,
                attach_type,
                name: n,
            });
            rest = r;
        }
        let mut externs = Vec::with_capacity(nr_externs.min(rest.len()));
        for _ in 0..nr_externs {
            let (e, r) = name(rest)?;
            externs.push(e);
            rest = r;
        }
        if rest.iter().any(|&c| c != 0) {
            return None;
        }
        let insns = &b[HEADER + names_len..][..insns_len];
        let data = &b[HEADER + names_len + insns_len..];
        Some(Lskel {
            maps,
            progs,
            externs,
            reuse_map_mask,
            insns,
            data,
        })
    }
}
