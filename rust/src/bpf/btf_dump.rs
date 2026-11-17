// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! C declarations of BTF types, as libbpf's btf_dump__emit_type_decl()
//! writes them: a variable of a type with its name, pointers, arrays and
//! function prototypes unscrambled into C's syntax, and a name two types
//! share told apart with a ___N suffix, in the order names are first
//! asked for. An anonymous struct, union or enum, which libbpf writes out
//! in full in place, is refused.

use core::ffi::c_int;
use std::collections::HashMap;

use super::btf::{self, Btf};
use crate::errno::EOPNOTSUPP;

/// One dump: the names given out so far, which later declarations of the
/// same dump keep apart from.
pub(crate) struct Dump<'b> {
    btf: &'b Btf,
    strip_mods: bool,
    type_names: HashMap<Vec<u8>, usize>,
    ident_names: HashMap<Vec<u8>, usize>,
    resolved: HashMap<u32, Vec<u8>>,
}

fn is_mod(kind: u32) -> bool {
    matches!(
        kind,
        btf::KIND_VOLATILE | btf::KIND_CONST | btf::KIND_RESTRICT | btf::KIND_TYPE_TAG
    )
}

impl<'b> Dump<'b> {
    pub(crate) fn new(btf: &'b Btf) -> Self {
        Dump {
            btf,
            strip_mods: false,
            type_names: HashMap::new(),
            ident_names: HashMap::new(),
            resolved: HashMap::new(),
        }
    }

    /// btf_dump_resolve_name(): the name of type `id` in `idents` or the
    /// struct, union and enum names, made unique in that namespace.
    fn resolve_name(&mut self, id: u32, idents: bool) -> Vec<u8> {
        let btf = self.btf;
        if btf.name_off(id) == 0 {
            return Vec::new();
        }
        let orig = btf.name(id).to_vec();
        if let Some(n) = self.resolved.get(&id) {
            return n.clone();
        }
        let kind = btf.kind(id);
        if kind == btf::KIND_FWD || (kind == btf::KIND_ENUM && btf.vlen(id) == 0) {
            self.resolved.insert(id, orig.clone());
            return orig;
        }
        let map = if idents {
            &mut self.ident_names
        } else {
            &mut self.type_names
        };
        let dups = map.entry(orig.clone()).or_insert(0);
        *dups += 1;
        let name = if *dups > 1 {
            let mut n = orig;
            n.extend_from_slice(format!("___{dups}").as_bytes());
            n.truncate(255);
            n
        } else {
            orig
        };
        self.resolved.insert(id, name.clone());
        name
    }

    /// btf_dump__emit_type_decl(): `id` declared as `fname`, its modifiers
    /// dropped with `strip_mods`.
    pub(crate) fn emit_type_decl(
        &mut self,
        out: &mut Vec<u8>,
        id: u32,
        fname: &[u8],
        strip_mods: bool,
    ) -> Result<(), c_int> {
        self.strip_mods = strip_mods;
        let res = self.type_decl(out, id, fname);
        self.strip_mods = false;
        res
    }

    /// btf_dump_emit_type_decl(): the chain from `id` to the type it ends
    /// in, then that chain written out.
    fn type_decl(&mut self, out: &mut Vec<u8>, mut id: u32, fname: &[u8]) -> Result<(), c_int> {
        let btf = self.btf;
        let mut stack = Vec::new();
        loop {
            let kind = btf.kind(id);
            if !(self.strip_mods && is_mod(kind)) {
                stack.push(id);
            }
            if id == 0 {
                break;
            }
            match kind {
                btf::KIND_PTR
                | btf::KIND_VOLATILE
                | btf::KIND_CONST
                | btf::KIND_RESTRICT
                | btf::KIND_FUNC_PROTO
                | btf::KIND_TYPE_TAG => id = btf.size_or_type(id),
                btf::KIND_ARRAY => id = btf.word(id, 0),
                btf::KIND_INT
                | btf::KIND_ENUM
                | btf::KIND_ENUM64
                | btf::KIND_FWD
                | btf::KIND_STRUCT
                | btf::KIND_UNION
                | btf::KIND_TYPEDEF
                | btf::KIND_FLOAT => break,
                _ => {
                    crate::log::warn(
                        format!("unexpected type in decl chain, kind:{kind}, id:[{id}]").as_bytes(),
                    );
                    break;
                }
            }
        }
        self.type_chain(out, &mut stack, fname)
    }

    /// btf_dump_emit_mods(): the const, volatile and restrict on top of the
    /// stack, written before the type they modify.
    fn emit_mods(&self, out: &mut Vec<u8>, stack: &mut Vec<u32>) {
        while let Some(&id) = stack.last() {
            out.extend_from_slice(match self.btf.kind(id) {
                btf::KIND_VOLATILE => b"volatile ",
                btf::KIND_CONST => b"const ",
                btf::KIND_RESTRICT => b"restrict ",
                _ => return,
            });
            stack.pop();
        }
    }

    fn drop_mods(&self, stack: &mut Vec<u32>) {
        while stack.last().is_some_and(|&id| is_mod(self.btf.kind(id))) {
            stack.pop();
        }
    }

    fn emit_name(out: &mut Vec<u8>, name: &[u8], last_was_ptr: bool) {
        if !name.is_empty() && !last_was_ptr {
            out.push(b' ');
        }
        out.extend_from_slice(name);
    }

    /// btf_dump_emit_type_chain(): the stack popped from the type the
    /// declaration ends in outwards.
    fn type_chain(
        &mut self,
        out: &mut Vec<u8>,
        stack: &mut Vec<u32>,
        fname: &[u8],
    ) -> Result<(), c_int> {
        let btf = self.btf;
        let mut last_was_ptr = true;
        while let Some(id) = stack.pop() {
            if id == 0 {
                self.emit_mods(out, stack);
                out.extend_from_slice(b"void");
                last_was_ptr = false;
                continue;
            }
            let kind = btf.kind(id);
            match kind {
                btf::KIND_INT | btf::KIND_FLOAT => {
                    self.emit_mods(out, stack);
                    out.extend_from_slice(btf.name(id));
                }
                btf::KIND_STRUCT | btf::KIND_UNION | btf::KIND_ENUM | btf::KIND_ENUM64 => {
                    self.emit_mods(out, stack);
                    if btf.name_off(id) == 0 {
                        crate::log::warn(
                            b"btf_dump: an anonymous struct, union or enum is not supported",
                        );
                        return Err(-EOPNOTSUPP);
                    }
                    out.extend_from_slice(match kind {
                        btf::KIND_STRUCT => b"struct ",
                        btf::KIND_UNION => b"union ",
                        _ => b"enum ",
                    });
                    let name = self.resolve_name(id, false);
                    out.extend_from_slice(&name);
                }
                btf::KIND_FWD => {
                    self.emit_mods(out, stack);
                    out.extend_from_slice(if btf.kflag(id) { b"union " } else { b"struct " });
                    let name = self.resolve_name(id, false);
                    out.extend_from_slice(&name);
                }
                btf::KIND_TYPEDEF => {
                    self.emit_mods(out, stack);
                    let name = self.resolve_name(id, true);
                    out.extend_from_slice(&name);
                }
                btf::KIND_PTR => out.extend_from_slice(if last_was_ptr { b"*" } else { b" *" }),
                btf::KIND_VOLATILE => out.extend_from_slice(b" volatile"),
                btf::KIND_CONST => out.extend_from_slice(b" const"),
                btf::KIND_RESTRICT => out.extend_from_slice(b" restrict"),
                btf::KIND_TYPE_TAG => {
                    self.emit_mods(out, stack);
                    let name = btf.name(id);
                    let tag = if btf.kflag(id) {
                        if name.starts_with(b"__attribute__(") {
                            [b" ", name].concat()
                        } else {
                            [b" __attribute__((", name, b"))"].concat()
                        }
                    } else if name == b"arena" {
                        b" __attribute__((address_space(1))) __attribute__((btf_type_tag(\"arena\")))".to_vec()
                    } else {
                        [b" __attribute__((btf_type_tag(\"", name, b"\")))"].concat()
                    };
                    out.extend_from_slice(&tag);
                }
                btf::KIND_ARRAY => {
                    let nelems = btf.word(id, 2);
                    self.drop_mods(stack);
                    let Some(&next) = stack.last() else {
                        Self::emit_name(out, fname, last_was_ptr);
                        out.extend_from_slice(format!("[{nelems}]").as_bytes());
                        return Ok(());
                    };
                    let multidim = btf.kind(next) == btf::KIND_ARRAY;
                    if !fname.is_empty() && !last_was_ptr {
                        out.push(b' ');
                    }
                    if !multidim {
                        out.push(b'(');
                    }
                    self.type_chain(out, stack, fname)?;
                    if !multidim {
                        out.push(b')');
                    }
                    out.extend_from_slice(format!("[{nelems}]").as_bytes());
                    return Ok(());
                }
                btf::KIND_FUNC_PROTO => {
                    self.drop_mods(stack);
                    if stack.is_empty() {
                        Self::emit_name(out, fname, last_was_ptr);
                    } else {
                        out.extend_from_slice(b" (");
                        self.type_chain(out, stack, fname)?;
                        out.push(b')');
                    }
                    out.push(b'(');
                    let vlen = btf.vlen(id) as usize;
                    if vlen == 0 || (vlen == 1 && btf.word(id, 1) == 0) {
                        out.extend_from_slice(b"void)");
                        return Ok(());
                    }
                    for i in 0..vlen {
                        if i > 0 {
                            out.extend_from_slice(b", ");
                        }
                        let (name_off, ty) = (btf.word(id, 2 * i), btf.word(id, 2 * i + 1));
                        if i == vlen - 1 && ty == 0 {
                            out.extend_from_slice(b"...");
                            break;
                        }
                        let name = btf.str_at(name_off).unwrap_or_default().to_vec();
                        self.type_decl(out, ty, &name)?;
                    }
                    out.push(b')');
                    return Ok(());
                }
                _ => {
                    crate::log::warn(
                        format!("unexpected type in decl chain, kind:{kind}, id:[{id}]").as_bytes(),
                    );
                    return Ok(());
                }
            }
            last_was_ptr = kind == btf::KIND_PTR;
        }
        Self::emit_name(out, fname, last_was_ptr);
        Ok(())
    }
}
