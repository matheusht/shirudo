// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! A pinned map's keys, values and types as text: through the map's BTF
//! where the build embedded it, as plain numbers or hex where not, and a
//! per-CPU value as the sum over the CPUs. Map reading, printing, JSON and
//! OTLP all render cells through here.

use crate::bpf::btf::{
    Btf, INT_SIGNED, KIND_ARRAY, KIND_CONST, KIND_ENUM, KIND_ENUM64, KIND_INT, KIND_PTR,
    KIND_RESTRICT, KIND_STRUCT, KIND_TYPE_TAG, KIND_TYPEDEF, KIND_UNION, KIND_VOLATILE,
};
use crate::sys::upatch_maps::MapView;

/// How deep the value and type renderers follow nested types: real map
/// values are flat, and chains beyond a few hops are crafted BTF or a
/// layout too deep to show.
const BTF_MAX_DEPTH: i32 = 6;

/// BPF_MAP_TYPE_PERCPU_HASH, _PERCPU_ARRAY and _LRU_PERCPU_HASH.
const PERCPU_TYPES: [u32; 3] = [5, 6, 10];

/// Whether a map of BPF_MAP_TYPE_* `ty` keeps a value per CPU.
pub(crate) fn is_percpu(ty: u32) -> bool {
    PERCPU_TYPES.contains(&ty)
}

/// The bytes between two CPUs' values of the view's entries.
pub(crate) fn value_stride(v: &MapView) -> u32 {
    if v.value_stride != 0 {
        v.value_stride
    } else {
        v.value_size
    }
}

/// Each CPU's value of a per-CPU entry's `values`: value_size bytes a
/// stride apart, and none for a CPU past their end.
pub(crate) fn cpu_values<'a>(v: &MapView, values: &'a [u8]) -> impl Iterator<Item = &'a [u8]> {
    let (stride, size) = (value_stride(v) as usize, v.value_size as usize);
    (0..v.n_cpus as usize).map(move |cpu| {
        cpu.checked_mul(stride)
            .and_then(|at| values.get(at..)?.get(..size))
            .unwrap_or_default()
    })
}

/// Type `id` of `btf`, void included, or none past its types.
fn type_of(btf: &Btf, id: u32) -> Option<u32> {
    btf.has(id).then_some(id)
}

/// The string at `off` of `btf`'s string section, "" for none.
fn name(btf: &Btf, off: u32) -> &[u8] {
    btf.str_at(off).unwrap_or_default()
}

/// The type `id` names past its typedefs, qualifiers and type tags.
fn unwrap(btf: &Btf, mut id: u32) -> u32 {
    for _ in 0..BTF_MAX_DEPTH {
        match type_of(btf, id) {
            Some(t)
                if matches!(
                    btf.kind(t),
                    KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG
                ) =>
            {
                id = btf.size_or_type(t);
            }
            _ => return id,
        }
    }
    id
}

/// The name of type `id` of `btf`, or of what an anonymous one refers
/// to within a few hops (an unnamed pointer to a named struct, say),
/// into `out` as strscpy() leaves it; empty for none.
pub(crate) fn type_name(btf: Option<&Btf>, id: u32, out: &mut [u8]) {
    if let Some(first) = out.first_mut() {
        *first = 0;
    }
    let Some(btf) = btf else {
        return;
    };
    if id == 0 || type_of(btf, id).is_none() {
        return;
    }
    let mut id = id;
    for _ in 0..4 {
        let Some(t) = type_of(btf, id) else {
            return;
        };
        let n = name(btf, btf.name_off(t));
        if !n.is_empty() {
            let _ = crate::text::strscpy(out, n);
            return;
        }
        id = btf.size_or_type(t);
        if id == 0 {
            return;
        }
    }
}

fn kind_prefix(k: u32) -> &'static [u8] {
    match k {
        KIND_STRUCT => b"struct ",
        KIND_UNION => b"union ",
        KIND_ENUM | KIND_ENUM64 => b"enum ",
        _ => b"",
    }
}

/// A type definition built into a buffer of `cap` bytes, its NUL
/// included, cut short as the C's appenders cut it.
struct Def {
    buf: Vec<u8>,
    cap: usize,
}

impl Def {
    fn push(&mut self, s: &[u8]) {
        let off = self.buf.len();
        if off >= self.cap {
            return;
        }
        let n = s.len().min(self.cap - 1 - off);
        self.buf.extend_from_slice(&s[..n]);
    }

    fn indent(&mut self, depth: i32) {
        for _ in 0..depth {
            if self.buf.len() + 2 >= self.cap {
                break;
            }
            self.buf.extend_from_slice(b"  ");
        }
    }

    fn room(&self) -> usize {
        self.cap - self.buf.len()
    }
}

fn or<'a>(s: &'a [u8], default: &'a [u8]) -> &'a [u8] {
    if s.is_empty() { default } else { s }
}

/// Type `id` of `btf` as a definition: a struct or union with its
/// members by short type name, an array with its length, an enum or a
/// name.
fn signature(btf: &Btf, id: u32, d: &mut Def, depth: i32) {
    if depth >= BTF_MAX_DEPTH || id == 0 || d.buf.len() >= d.cap {
        return;
    }
    let id = unwrap(btf, id);
    let Some(t) = type_of(btf, id) else {
        d.push(b"?");
        return;
    };
    let k = btf.kind(t);
    let tname = name(btf, btf.name_off(t));
    match k {
        KIND_STRUCT | KIND_UNION => {
            d.push(kind_prefix(k));
            d.push(or(tname, b"<anon>"));
            d.push(b" {\n");
            for m in btf.members(t) {
                if d.room() < 8 {
                    d.push(b"  ...\n");
                    break;
                }
                d.indent(depth + 1);
                let mt = type_of(btf, unwrap(btf, m.ty));
                d.push(kind_prefix(mt.map_or(0, |mt| btf.kind(mt))));
                d.push(or(
                    mt.map_or(&b""[..], |mt| name(btf, btf.name_off(mt))),
                    b"?",
                ));
                d.push(b" ");
                d.push(or(name(btf, m.name_off), b"<anon>"));
                d.push(b";\n");
            }
            d.indent(depth);
            d.push(b"}");
        }
        KIND_ARRAY => {
            let a = btf.array(t);
            let en =
                type_of(btf, unwrap(btf, a.ty)).map_or(&b"?"[..], |et| name(btf, btf.name_off(et)));
            d.push(or(en, b"?"));
            d.push(format!("[{}]", a.nelems).as_bytes());
        }
        KIND_ENUM | KIND_ENUM64 => {
            d.push(b"enum ");
            d.push(or(tname, b"<anon>"));
        }
        _ => d.push(or(tname, b"?")),
    }
}

/// Type `id` of `btf` as a definition into `out`, a C string of its
/// room.
pub(crate) fn type_def(btf: Option<&Btf>, id: u32, out: &mut [u8]) {
    let mut d = Def {
        buf: Vec::new(),
        cap: out.len(),
    };
    if let Some(btf) = btf {
        signature(btf, id, &mut d, 0);
    }
    if let Some(slot) = out.get_mut(..=d.buf.len()) {
        slot[..d.buf.len()].copy_from_slice(&d.buf);
        slot[d.buf.len()] = 0;
    }
}

fn le(bytes: &[u8]) -> u64 {
    bytes.iter().rev().fold(0, |v, &b| (v << 8) | u64::from(b))
}

/// Widens the low `bits` of `v` with its sign bit, below 64.
fn sign_extend(v: u64, bits: u32) -> u64 {
    if bits < 64 && v & (1 << (bits - 1)) != 0 {
        v | !((1u64 << bits) - 1)
    } else {
        v
    }
}

fn number(v: u64, signed: bool) -> Vec<u8> {
    if signed {
        (v as i64).to_string().into_bytes()
    } else {
        v.to_string().into_bytes()
    }
}

/// An integer of type `t` in the low bytes of `bytes`.
fn format_int(btf: &Btf, t: u32, bytes: &[u8]) -> Vec<u8> {
    let enc = btf.word(t, 0);
    let bits = enc & 0xff;
    let signed = (enc >> 24) & 0x0f & 1 != 0;
    let used = bits.div_ceil(8) as u8 as usize;
    if used == 0 || used > bytes.len() || used > 8 {
        return b"?".to_vec();
    }
    let v = le(&bytes[..used]);
    number(if signed { sign_extend(v, bits) } else { v }, signed)
}

/// A struct member declared with a bit width, `bit_size` bits at
/// `bit_off` of the struct's `bytes`.
fn format_bitfield(btf: &Btf, ty: u32, bytes: &[u8], bit_off: u32, bit_size: u32) -> Vec<u8> {
    let shift = bit_off % 8;
    let n = (shift + bit_size).div_ceil(8);
    let start = (bit_off / 8) as usize;
    if bit_size == 0 || shift + bit_size > 64 || start + n as usize > bytes.len() {
        return b"?".to_vec();
    }
    let mut v = le(&bytes[start..start + n as usize]) >> shift;
    if bit_size < 64 {
        v &= (1u64 << bit_size) - 1;
    }
    let signed = match type_of(btf, unwrap(btf, ty)) {
        Some(t) if btf.kind(t) == KIND_INT => btf.int_encoding(t) & INT_SIGNED != 0,
        Some(t) if matches!(btf.kind(t), KIND_ENUM | KIND_ENUM64) => btf.kflag(t),
        _ => false,
    };
    number(if signed { sign_extend(v, bit_size) } else { v }, signed)
}

/// The value in `bytes` as type `id` of `btf` shows it: numbers, enum
/// names, pointers in hex, structs and unions as `{ field=value, ... }`,
/// arrays as `[ ... ]` of up to 16. None for a type it cannot show.
fn format_btf(btf: &Btf, id: u32, bytes: &[u8], depth: i32) -> Option<Vec<u8>> {
    if depth >= BTF_MAX_DEPTH || id == 0 || bytes.is_empty() {
        return None;
    }
    let id = unwrap(btf, id);
    let t = type_of(btf, id)?;
    let size = bytes.len();
    match btf.kind(t) {
        KIND_INT => Some(format_int(btf, t, bytes)),
        KIND_PTR => {
            let v = if size >= 8 {
                le(&bytes[..8])
            } else if size >= 4 {
                le(&bytes[..4])
            } else {
                0
            };
            Some(format!("0x{v:x}").into_bytes())
        }
        KIND_ENUM => {
            let width = btf.size_or_type(t) as usize;
            if width == 0 || width > 4 || width > size {
                return Some(b"?".to_vec());
            }
            let mut v = le(&bytes[..width]) as u32;
            if btf.kflag(t) && width < 4 && v & (1 << (8 * width - 1)) != 0 {
                v |= !((1u32 << (8 * width)) - 1);
            }
            if let Some(i) = (0..btf.vlen(t)).find(|&i| btf.word(t, 2 * i as usize + 1) == v) {
                return Some(or(name(btf, btf.word(t, 2 * i as usize)), b"?").to_vec());
            }
            Some(
                if btf.kflag(t) {
                    (v as i32).to_string()
                } else {
                    v.to_string()
                }
                .into_bytes(),
            )
        }
        KIND_ENUM64 => {
            let v = if size >= 8 { le(&bytes[..8]) } else { 0 };
            let found = (0..btf.vlen(t))
                .map(|i| btf.enum_value(t, i))
                .find(|&(_, val)| val == v);
            Some(match found {
                Some((name_off, _)) => or(name(btf, name_off), b"?").to_vec(),
                None => format!("0x{v:x}").into_bytes(),
            })
        }
        KIND_STRUCT | KIND_UNION => {
            let mut out = b"{ ".to_vec();
            for (i, m) in btf.members(t).enumerate() {
                let bit_off = m.bit_offset();
                let byte_off = (bit_off / 8) as usize;
                if byte_off >= size {
                    continue;
                }
                let bit_size = m.bitfield_size();
                let mut fsize = 0usize;
                if type_of(btf, unwrap(btf, m.ty)).is_some() {
                    fsize = btf.resolve_size(m.ty).unwrap_or(0) as usize;
                }
                if fsize == 0 || byte_off.checked_add(fsize).is_none_or(|end| end > size) {
                    fsize = size - byte_off;
                }
                let fval = if bit_size != 0 {
                    Some(format_bitfield(btf, m.ty, bytes, bit_off, bit_size))
                } else {
                    format_btf(btf, m.ty, &bytes[byte_off..byte_off + fsize], depth + 1)
                };
                if i != 0 {
                    out.extend_from_slice(b", ");
                }
                out.extend_from_slice(or(name(btf, m.name_off), b"?"));
                out.push(b'=');
                out.extend_from_slice(fval.as_deref().unwrap_or(b"?"));
            }
            out.extend_from_slice(b" }");
            Some(out)
        }
        KIND_ARRAY => {
            let a = btf.array(t);
            let esz = btf.resolve_size(a.ty).unwrap_or(0);
            let n = a.nelems;
            if esz == 0 || u128::from(esz) * u128::from(n) > size as u128 {
                return None;
            }
            let esz = esz as usize;
            let mut out = b"[ ".to_vec();
            for i in 0..n.min(16) as usize {
                if i != 0 {
                    out.extend_from_slice(b", ");
                }
                let ev = format_btf(btf, a.ty, &bytes[i * esz..i * esz + esz], depth + 1);
                out.extend_from_slice(ev.as_deref().unwrap_or(b"?"));
            }
            if n > 16 {
                out.extend_from_slice(format!(", ... ({} more)", n - 16).as_bytes());
            }
            out.extend_from_slice(b" ]");
            Some(out)
        }
        _ => None,
    }
}

/// A value without BTF: as the number its BTF type name says, as an
/// unsigned number of 4 or 8 bytes, or as hex of up to 32 bytes.
fn format_plain(value: &[u8], btf_type: &[u8]) -> Vec<u8> {
    let size = value.len();
    let one_of = |names: &[&[u8]]| names.contains(&btf_type);
    if !btf_type.is_empty() {
        if size == 8 && one_of(&[b"__u64", b"u64", b"long long unsigned int"]) {
            return le(value).to_string().into_bytes();
        }
        if size == 8 && one_of(&[b"__s64", b"s64", b"long long int"]) {
            return (le(value) as i64).to_string().into_bytes();
        }
        if size == 4 && one_of(&[b"__u32", b"u32", b"unsigned int"]) {
            return (le(value) as u32).to_string().into_bytes();
        }
        if size == 4 && one_of(&[b"__s32", b"s32", b"int"]) {
            return (le(value) as u32 as i32).to_string().into_bytes();
        }
    }
    if size == 8 || size == 4 {
        return le(value).to_string().into_bytes();
    }
    let shown = &value[..size.min(32)];
    let mut out = b"0x".to_vec();
    out.extend(shown.iter().flat_map(|b| {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        [HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xf)]]
    }));
    if size > 32 {
        out.extend_from_slice(b"...");
    }
    out
}

/// A key or value of the view: through its BTF type `type_id` where the
/// view has BTF, else as `btf_name` names it, else plain.
pub(crate) fn format_cell(v: &MapView, type_id: u32, bytes: &[u8], btf_name: &[u8]) -> Vec<u8> {
    let formatted = match &v.btf {
        Some(btf) if type_id != 0 => format_btf(btf, type_id, bytes, 0),
        _ => None,
    };
    formatted.unwrap_or_else(|| format_plain(bytes, btf_name))
}

/// The sum of an entry's per-CPU values, each widened by its sign when
/// the value type is a signed integer; the sum wraps as the C's did.
pub(crate) fn percpu_sum(v: &MapView, values: &[u8]) -> Vec<u8> {
    let width = v.value_size as usize;
    if ![1, 2, 4, 8].contains(&width) {
        return b"(unsupported width)".to_vec();
    }
    let bits = 8 * v.value_size;
    let signed = v.btf.as_ref().is_some_and(|btf| {
        v.value_type_id != 0
            && type_of(btf, unwrap(btf, v.value_type_id))
                .is_some_and(|t| btf.kind(t) == KIND_INT && btf.int_encoding(t) & INT_SIGNED != 0)
    });
    let sum = cpu_values(v, values).fold(0u64, |sum, one| {
        let one = le(one);
        sum.wrapping_add(if signed { sign_extend(one, bits) } else { one })
    });
    number(sum, signed)
}
