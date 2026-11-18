// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! A BTF built type by type, ids from 1 in the order added, as libbpf's
//! btf__add_*() build one: for the unit tests and the test helpers that
//! hand shirudo's BTF readers types of their choosing.

use crate::bpf::btf::{
    Btf, KIND_ARRAY, KIND_FUNC_PROTO, KIND_INT, KIND_PTR, KIND_STRUCT, KIND_TYPEDEF, MAGIC,
};

pub(crate) struct BtfBuilder {
    types: Vec<u8>,
    strings: Vec<u8>,
    n: u32,
}

impl BtfBuilder {
    pub(crate) fn new() -> Self {
        BtfBuilder {
            types: Vec::new(),
            strings: vec![0],
            n: 0,
        }
    }

    /// The offset of `s` in the strings, 0 for none.
    fn name(&mut self, s: &[u8]) -> u32 {
        if s.is_empty() {
            return 0;
        }
        let off = self.strings.len() as u32;
        self.strings.extend_from_slice(s);
        self.strings.push(0);
        off
    }

    fn add(&mut self, name: &[u8], kind: u32, vlen: u32, size_or_type: u32, extra: &[u32]) -> u32 {
        let name = self.name(name);
        for v in [name, (kind << 24) | vlen, size_or_type]
            .iter()
            .chain(extra)
        {
            self.types.extend_from_slice(&v.to_ne_bytes());
        }
        self.n += 1;
        self.n
    }

    /// The id the next type added gets.
    #[cfg(feature = "test-helpers")]
    pub(crate) fn next_id(&self) -> u32 {
        self.n + 1
    }

    pub(crate) fn int(&mut self, name: &str, size: u32, encoding: u32) -> u32 {
        self.add(
            name.as_bytes(),
            KIND_INT,
            0,
            size,
            &[(encoding << 24) | (size * 8)],
        )
    }

    pub(crate) fn typedef(&mut self, name: &str, ty: u32) -> u32 {
        self.add(name.as_bytes(), KIND_TYPEDEF, 0, ty, &[])
    }

    pub(crate) fn array(&mut self, index: u32, elem: u32, n: u32) -> u32 {
        self.add(b"", KIND_ARRAY, 0, 0, &[elem, index, n])
    }

    pub(crate) fn ptr(&mut self, ty: u32) -> u32 {
        self.add(b"", KIND_PTR, 0, ty, &[])
    }

    /// A struct of `members`, each its name, type and bit offset.
    pub(crate) fn structure(&mut self, name: &str, size: u32, members: &[(&str, u32, u32)]) -> u32 {
        let extra: Vec<u32> = members
            .iter()
            .flat_map(|&(name, ty, off)| [self.name(name.as_bytes()), ty, off])
            .collect();
        self.add(
            name.as_bytes(),
            KIND_STRUCT,
            members.len() as u32,
            size,
            &extra,
        )
    }

    /// An enum of `size` bytes and its `values`, by name.
    #[cfg(feature = "test-helpers")]
    pub(crate) fn enumeration(&mut self, name: &str, size: u32, values: &[(&str, u32)]) -> u32 {
        let extra: Vec<u32> = values
            .iter()
            .flat_map(|&(name, v)| [self.name(name.as_bytes()), v])
            .collect();
        self.add(
            name.as_bytes(),
            crate::bpf::btf::KIND_ENUM,
            values.len() as u32,
            size,
            &extra,
        )
    }

    /// A function prototype returning `ret` of `params`, by name and type.
    pub(crate) fn func_proto(&mut self, ret: u32, params: &[(&str, u32)]) -> u32 {
        let extra: Vec<u32> = params
            .iter()
            .flat_map(|&(name, ty)| [self.name(name.as_bytes()), ty])
            .collect();
        self.add(b"", KIND_FUNC_PROTO, params.len() as u32, ret, &extra)
    }

    #[cfg(test)]
    pub(crate) fn func(&mut self, name: &str, proto: u32) -> u32 {
        use crate::bpf::btf::{FUNC_GLOBAL, KIND_FUNC};
        self.add(name.as_bytes(), KIND_FUNC, FUNC_GLOBAL, proto, &[])
    }

    /// The BTF's bytes: its header, types and strings.
    pub(crate) fn raw(&self) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(&MAGIC.to_ne_bytes());
        raw.extend_from_slice(&[1, 0]);
        for v in [
            24,
            0,
            self.types.len() as u32,
            self.types.len() as u32,
            self.strings.len() as u32,
        ] {
            raw.extend_from_slice(&v.to_ne_bytes());
        }
        raw.extend_from_slice(&self.types);
        raw.extend_from_slice(&self.strings);
        raw
    }

    /// The BTF as shirudo parses it.
    pub(crate) fn parse(&self) -> Result<Btf, core::ffi::c_int> {
        Btf::parse(&self.raw())
    }
}
