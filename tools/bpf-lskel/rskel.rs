// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The Rust side of a light skeleton, which rust/src/skel.rs includes:
//! the types of its maps' keys and values, read from the object's BTF,
//! the maps as the object defines them, and typed handles to the maps
//! its loader makes.
//!
//! A type is written as C lays it out, and the crate checks it compiles
//! so, by size and by each field's offset: integers, typedefs of them,
//! arrays and named structs of byte-aligned members. A map holding
//! anything else fails the build.

use std::collections::BTreeMap;
use std::fmt::Write;

use crate::bpf::btf::{self, Btf};
use crate::bpf::object::Object;

/// The structs a skeleton writes, by C name: their Rust source.
pub(crate) type Structs = BTreeMap<String, String>;

const LSKEL: &str = "crate::util::lskel";

/// Rust's keywords a C member or map may be named.
const KEYWORDS: [&str; 12] = [
    "type", "match", "ref", "move", "impl", "trait", "loop", "mod", "use", "where", "fn", "box",
];

fn ident(name: &[u8]) -> Result<String, String> {
    let s = std::str::from_utf8(name).map_err(|_| "a name that is not UTF-8".to_string())?;
    let first = s.bytes().next();
    if first.is_none_or(|c| c.is_ascii_digit())
        || !s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
    {
        return Err(format!("name {s:?} is no Rust identifier"));
    }
    Ok(if KEYWORDS.contains(&s) {
        format!("r#{s}")
    } else {
        s.to_string()
    })
}

/// `struct task_authority` as `TaskAuthority`.
fn camel(name: &str) -> String {
    name.split('_')
        .filter(|p| !p.is_empty())
        .map(|p| p[..1].to_ascii_uppercase() + &p[1..])
        .collect()
}

struct Gen<'b> {
    btf: &'b Btf,
    structs: Structs,
}

impl Gen<'_> {
    /// The Rust type of BTF type `id`, the structs it takes written.
    fn ty(&mut self, id: u32, depth: usize) -> Result<String, String> {
        let btf = self.btf;
        if depth > 32 {
            return Err(format!("type [{id}] nests too deep"));
        }
        let id = btf.skip_mods_and_typedefs(id);
        match btf.kind(id) {
            btf::KIND_INT => {
                let (size, bits) = (btf.size_or_type(id), u32::from(btf.int_bits(id)));
                if btf.int_offset(id) != 0 || bits != size * 8 {
                    return Err(format!("integer [{id}] is not all its bits"));
                }
                let signed = btf.int_encoding(id) & btf::INT_SIGNED != 0;
                let t = match (size, signed) {
                    (1, true) => "i8",
                    (1, false) => "u8",
                    (2, true) => "i16",
                    (2, false) => "u16",
                    (4, true) => "i32",
                    (4, false) => "u32",
                    (8, true) => "i64",
                    (8, false) => "u64",
                    _ => return Err(format!("integer [{id}] of {size} bytes")),
                };
                Ok(t.into())
            }
            btf::KIND_ARRAY => {
                let a = btf.array(id);
                Ok(format!("[{}; {}]", self.ty(a.ty, depth + 1)?, a.nelems))
            }
            btf::KIND_STRUCT if btf.name_off(id) != 0 => self.strukt(id, depth),
            k => Err(format!(
                "type [{id}] {:?} of kind {k} has no Rust form here",
                String::from_utf8_lossy(btf.name(id))
            )),
        }
    }

    /// A named struct, written once: its Rust name.
    fn strukt(&mut self, id: u32, depth: usize) -> Result<String, String> {
        let btf = self.btf;
        let c_name = std::str::from_utf8(btf.name(id))
            .map_err(|_| format!("struct [{id}]: a name that is not UTF-8"))?
            .to_string();
        ident(c_name.as_bytes())?;
        let name = camel(&c_name);
        if self.structs.contains_key(&c_name) {
            return Ok(name);
        }
        let mut fields = Vec::new();
        for m in btf.members(id) {
            let fname = ident(btf.str_at(m.name_off).unwrap_or_default())
                .map_err(|e| format!("struct {c_name}: {e}"))?;
            if m.bitfield_size() != 0 || m.bit_offset() % 8 != 0 {
                return Err(format!("struct {c_name}: {fname} is a bitfield"));
            }
            fields.push((fname, self.ty(m.ty, depth + 1)?, m.bit_offset() / 8));
        }
        let mut s = String::new();
        let _ = writeln!(s, "/// `struct {c_name}`, as the object's BTF lays it out.");
        let _ = writeln!(
            s,
            "#[repr(C)]\n#[derive(Clone, Copy)]\npub(crate) struct {name} {{"
        );
        for (f, t, _) in &fields {
            let _ = writeln!(s, "    pub(crate) {f}: {t},");
        }
        let _ = writeln!(s, "}}\n");
        let size = btf.size_or_type(id);
        let _ = writeln!(s, "const _: () = assert!(size_of::<{name}>() == {size});");
        for (f, _, off) in &fields {
            let _ = writeln!(
                s,
                "const _: () = assert!(core::mem::offset_of!({name}, {f}) == {off});"
            );
        }
        let _ = writeln!(
            s,
            "\nimpl {name} {{\n\
             \x20   /// All bits zero.\n\
             \x20   pub(crate) const fn zeroed() -> Self {{\n\
             \x20       // SAFETY: integers and arrays of them, which all bits\n\
             \x20       // zero is a value of.\n\
             \x20       unsafe {{ core::mem::zeroed() }}\n\
             \x20   }}\n\
             }}\n\n\
             // SAFETY: integers and arrays of them, which any bits are a value of.\n\
             unsafe impl {LSKEL}::Pod for {name} {{}}"
        );
        self.structs.insert(c_name, s);
        Ok(name)
    }
}

/// What a skeleton shares with another: its module and its structs, and
/// the maps it takes from it, by index.
pub(crate) struct Share<'s> {
    pub(crate) module: &'s str,
    pub(crate) structs: &'s Structs,
    pub(crate) maps: Vec<usize>,
}

/// The Rust of the skeleton `name` of `obj`, built from `source`, whose
/// map types it writes or, laid out alike, takes from `share`'s module:
/// the source, and every struct its maps hold.
pub(crate) fn write(
    obj: &Object,
    name: &str,
    source: &str,
    share: Option<&Share<'_>>,
) -> Result<(String, Structs), String> {
    let mut g = Gen {
        btf: obj.btf(),
        structs: Structs::new(),
    };
    let mut maps = Vec::new();
    for (i, m) in obj.maps.iter().enumerate() {
        if m.is_internal() {
            continue;
        }
        let field = ident(&m.name)?;
        let key = g
            .ty(m.key_type_id(), 0)
            .map_err(|e| format!("map {field}: key: {e}"))?;
        let value = g
            .ty(m.value_type_id(), 0)
            .map_err(|e| format!("map {field}: value: {e}"))?;
        maps.push((i, m, field, key, value));
    }

    let mut out = format!(
        "// Generated by tools/bpf-lskel from {source}: the types of its maps,\n\
         // the maps as it defines them, and handles to those its loader\n\
         // makes. Do not edit.\n\n"
    );
    for (c_name, s) in &g.structs {
        match share.and_then(|sh| sh.structs.get(c_name).map(|t| (sh, t))) {
            Some((sh, theirs)) if theirs == s => {
                let _ = writeln!(
                    out,
                    "pub(crate) use super::{}::{};\n",
                    sh.module,
                    camel(c_name)
                );
            }
            _ => {
                let _ = writeln!(out, "{s}");
            }
        }
    }

    let list = |names: &mut dyn Iterator<Item = &[u8]>| {
        names.fold(String::new(), |mut l, n| {
            let _ = writeln!(l, "    b{:?},", String::from_utf8_lossy(n));
            l
        })
    };
    let progs: Vec<&[u8]> = obj.loaded_programs().map(|p| p.name.as_slice()).collect();
    let _ = writeln!(
        out,
        "/// The names of the maps and programs, in the order of the loader's\n\
         /// descriptors: those of the embedded skeleton, which loading checks.\n\
         const MAP_NAMES: [&[u8]; {}] = [\n{}];\n\
         const PROG_NAMES: [&[u8]; {}] = [\n{}];\n",
        obj.maps.len(),
        list(&mut obj.maps.iter().map(|m| m.name.as_slice())),
        progs.len(),
        list(&mut progs.iter().copied()),
    );

    let _ = writeln!(
        out,
        "/// The maps of `.maps`, as the object defines them.\npub(crate) mod def {{"
    );
    for (i, m, f, _, _) in &maps {
        let _ = writeln!(
            out,
            "    pub(crate) const {upper}: {LSKEL}::MapDef = {LSKEL}::MapDef {{\n\
             \x20       name: c{name:?},\n\
             \x20       index: {i},\n\
             \x20       map_type: {},\n\
             \x20       key_size: {},\n\
             \x20       value_size: {},\n\
             \x20       max_entries: {},\n\
             \x20       flags: {},\n\
             \x20   }};",
            m.map_type(),
            m.key_size(),
            m.value_size(),
            m.max_entries(),
            m.map_flags(),
            upper = f.trim_start_matches("r#").to_ascii_uppercase(),
            name = String::from_utf8_lossy(&m.name),
        );
    }
    let _ = writeln!(
        out,
        "}}\n\n/// The maps of `.maps` the loader made, typed.\npub(crate) struct Maps<'s> {{"
    );
    for (_, _, f, k, v) in &maps {
        let _ = writeln!(out, "    pub(crate) {f}: {LSKEL}::Map<'s, {k}, {v}>,");
    }
    let _ = writeln!(
        out,
        "}}\n\n\
         pub(crate) fn maps(s: &{LSKEL}::Skeleton) -> Maps<'_> {{\n\
         \x20   // SAFETY: each map of the types tools/bpf-lskel read from its\n\
         \x20   // BTF, which the skeleton was built from.\n\
         \x20   unsafe {{\n\
         \x20       Maps {{"
    );
    for (i, _, f, _, _) in &maps {
        let _ = writeln!(out, "            {f}: s.map({i}),");
    }
    let _ = writeln!(out, "        }}\n    }}\n}}\n");

    let load = format!(
        "{LSKEL}::Skeleton::load(\n\
         \x20       b\"{name}\",\n\
         \x20       // SAFETY: the embedded skeleton, static.\n\
         \x20       unsafe {{ crate::sys::loader::{name}_blob() }},\n\
         \x20       &MAP_NAMES,\n\
         \x20       &PROG_NAMES,\n"
    );
    match share {
        None => {
            let _ = writeln!(
                out,
                "/// Runs the embedded loader: the maps and programs it made.\n\
                 pub(crate) fn load() -> Result<{LSKEL}::Skeleton, {LSKEL}::Failed> {{\n\
                 \x20   {load}\
                 \x20       |_| None,\n\
                 \x20   )\n\
                 }}"
            );
        }
        Some(sh) => {
            let (mut fields, mut arms) = (String::new(), String::new());
            for &i in &sh.maps {
                let Some((_, _, f, k, v)) = maps.iter().find(|(j, ..)| *j == i) else {
                    return Err(format!("shared map {i} is not one of .maps"));
                };
                let _ = writeln!(
                    fields,
                    "    pub(crate) {f}: &'a {LSKEL}::Map<'a, {k}, {v}>,"
                );
                let _ = writeln!(arms, "            {i} => Some(shared.{f}.fd()),");
            }
            let _ = writeln!(
                out,
                "/// The maps the loader takes from {m}'s instead of making them.\n\
                 pub(crate) struct Shared<'a> {{\n{fields}}}\n\n\
                 /// Runs the embedded loader, the shared maps passed in: the maps\n\
                 /// and programs it made.\n\
                 pub(crate) fn load(shared: &Shared<'_>) -> Result<{LSKEL}::Skeleton, {LSKEL}::Failed> {{\n\
                 \x20   {load}\
                 \x20       |i| match i {{\n{arms}\
                 \x20           _ => None,\n\
                 \x20       }},\n\
                 \x20   )\n\
                 }}",
                m = sh.module,
            );
        }
    }
    Ok((out, g.structs))
}
