// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! C declarations of BTF types, as libbpf's btf_dump__emit_type_decl()
//! writes them: a variable of a type with its name, pointers, arrays and
//! function prototypes unscrambled into C's syntax, and a name two types
//! share told apart with a ___N suffix, in the order names are first
//! asked for. An anonymous struct, union or enum, which libbpf writes out
//! in full in place, is refused, but in a cast, which names it bare; and
//! values of BTF types as btf_dump__dump_type_data() writes them.

use core::ffi::c_int;
use std::collections::HashMap;

use super::btf::{self, Btf};
use crate::errno::{E2BIG, EINVAL, ENOENT, EOPNOTSUPP};

/// One dump: the names given out so far, which later declarations of the
/// same dump keep apart from.
pub(crate) struct Dump<'b> {
    btf: &'b Btf,
    strip_mods: bool,
    skip_anon_defs: bool,
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
            skip_anon_defs: false,
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
                    let anon = btf.name_off(id) == 0;
                    if anon && !self.skip_anon_defs {
                        crate::log::warn(
                            b"btf_dump: an anonymous struct, union or enum is not supported",
                        );
                        return Err(-EOPNOTSUPP);
                    }
                    // btf_dump_emit_struct_fwd() and btf_dump_emit_enum_fwd()
                    out.extend_from_slice(match kind {
                        btf::KIND_STRUCT if anon => b"struct",
                        btf::KIND_UNION if anon => b"union",
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

/// One btf_dump__dump_type_data() of a value, as upatch_rodata asks for
/// it: indented by two spaces, names and type casts shown, zeroes shown,
/// a char array that holds a string as one.
///
/// The value is `len` bytes from `start` of `mem`, which libbpf reads past
/// for a bitfield: such a read sees the bytes of `mem` there, and zeroes
/// beyond it, where libbpf would read what memory follows. `base` is the
/// address of `mem`, which libbpf's choices between aligned and unaligned
/// reads, and so some of what it prints, depend on.
struct Typed<'m> {
    mem: &'m [u8],
    base: usize,
    end: usize,
    depth: i32,
    is_array_member: bool,
    is_array_terminated: bool,
    is_array_char: bool,
}

const INDENT: &[u8] = b"  ";
/// ENOTSUP, EOPNOTSUPP on Linux.
const ENOTSUP: c_int = EOPNOTSUPP;

/// isprint() in the C locale.
fn isprint(c: u8) -> bool {
    (0x20..0x7f).contains(&c)
}

impl Typed<'_> {
    fn byte(&self, pos: usize) -> u8 {
        self.mem.get(pos).copied().unwrap_or(0)
    }

    /// The `n` bytes at `pos`, little endian, as libbpf assembles them.
    fn le(&self, pos: usize, n: usize) -> u64 {
        (0..n).rev().fold(0u64, |v, i| {
            v.wrapping_mul(256)
                .wrapping_add(u64::from(self.byte(pos.wrapping_add(i))))
        })
    }

    fn newline(&self) -> &'static [u8] {
        if self.depth == 0 { b"" } else { b"\n" }
    }

    fn delim(&self) -> &'static [u8] {
        if self.depth == 0 { b"" } else { b"," }
    }

    /// btf_dump_data_pfx()
    fn pfx(&self, out: &mut Vec<u8>) {
        for _ in 0..self.depth.max(0) {
            out.extend_from_slice(INDENT);
        }
    }

    /// btf_dump_type_values(): `s`, then the delimiter and newline.
    fn values(&self, out: &mut Vec<u8>, s: &[u8]) {
        out.extend_from_slice(s);
        out.extend_from_slice(self.delim());
        out.extend_from_slice(self.newline());
    }
}

/// glibc's "%f" of a double: six decimals, "inf" and "nan" spelled as it
/// spells them.
fn format_f64(v: f64) -> String {
    let sign = if v.is_sign_negative() { "-" } else { "" };
    if v.is_nan() {
        format!("{sign}nan")
    } else if v.is_infinite() {
        format!("{sign}inf")
    } else {
        format!("{v:.6}")
    }
}

/// A non-negative integer in base 10^9 limbs, least significant first:
/// enough arithmetic to write an 80-bit long double out exactly.
#[derive(Clone)]
struct Big(Vec<u32>);

const LIMB: u64 = 1_000_000_000;

impl Big {
    fn from_u64(mut v: u64) -> Self {
        let mut l = Vec::new();
        while v != 0 {
            l.push((v % LIMB) as u32);
            v /= LIMB;
        }
        Big(l)
    }

    fn mul_small(&mut self, m: u32) {
        let mut carry = 0u64;
        for l in &mut self.0 {
            let v = u64::from(*l) * u64::from(m) + carry;
            *l = (v % LIMB) as u32;
            carry = v / LIMB;
        }
        while carry != 0 {
            self.0.push((carry % LIMB) as u32);
            carry /= LIMB;
        }
    }

    /// Divides by 2^`k`, returning whether the remainder was nonzero and
    /// how it compared with a half: Less, Equal or Greater.
    fn div_pow2(&mut self, mut k: u32) -> core::cmp::Ordering {
        use core::cmp::Ordering;
        let mut half = Ordering::Less;
        let mut sticky = false;
        while k != 0 {
            let s = k.min(29);
            let mut rem = 0u64;
            for l in self.0.iter_mut().rev() {
                let v = rem * LIMB + u64::from(*l);
                *l = (v >> s) as u32;
                rem = v & ((1 << s) - 1);
            }
            while self.0.last() == Some(&0) {
                self.0.pop();
            }
            // The bits shifted out, the first of them the half bit.
            let top = rem >> (s - 1);
            let below = rem & ((1 << (s - 1)) - 1);
            if k == s {
                half = match (top, below != 0 || sticky) {
                    (0, _) => Ordering::Less,
                    (_, false) => Ordering::Equal,
                    _ => Ordering::Greater,
                };
            } else {
                sticky |= rem != 0;
            }
            k -= s;
        }
        half
    }

    fn add_one(&mut self) {
        for l in &mut self.0 {
            if *l + 1 < LIMB as u32 {
                *l += 1;
                return;
            }
            *l = 0;
        }
        self.0.push(1);
    }

    fn is_odd(&self) -> bool {
        self.0.first().is_some_and(|l| l % 2 == 1)
    }

    fn to_decimal(&self) -> String {
        let Some((last, rest)) = self.0.split_last() else {
            return "0".into();
        };
        let mut s = last.to_string();
        for l in rest.iter().rev() {
            s.push_str(&format!("{l:09}"));
        }
        s
    }
}

/// glibc's "%Lf" of the x86 80-bit long double in the first 10 of
/// `b`: written out exactly, rounded to six decimals, ties to even.
fn format_long_double(b: &[u8; 16]) -> String {
    let mant = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let se = u16::from_le_bytes([b[8], b[9]]);
    let (neg, exp) = (se & 0x8000 != 0, i32::from(se & 0x7fff));
    let sign = if neg { "-" } else { "" };
    let int_bit = mant >> 63 != 0;
    if exp == 0x7fff {
        return if int_bit && mant << 1 == 0 {
            format!("{sign}inf")
        } else {
            format!("{sign}nan")
        };
    }
    if exp != 0 && !int_bit {
        // An unnormal, which glibc writes as a NaN.
        return format!("{sign}nan");
    }
    // value = mant * 2^(e - 16383 - 63), e 1 for a denormal.
    let e = exp.max(1) - 16383 - 63;
    let mut v = Big::from_u64(mant);
    v.mul_small(1_000_000);
    if e >= 0 {
        for _ in 0..e {
            v.mul_small(2);
        }
    } else {
        let half = v.div_pow2((-e) as u32);
        if half == core::cmp::Ordering::Greater
            || (half == core::cmp::Ordering::Equal && v.is_odd())
        {
            v.add_one();
        }
    }
    let digits = v.to_decimal();
    let digits = format!("{digits:0>7}");
    let (int, frac) = digits.split_at(digits.len() - 6);
    format!("{sign}{int}.{frac}")
}

impl Dump<'_> {
    /// btf_dump__dump_type_data() of type `id` over `len` bytes from
    /// `start` of `mem`, into `out`: the bytes the type takes, or the
    /// negative errno with what it wrote so far in `out`.
    pub(crate) fn dump_type_data(
        &mut self,
        out: &mut Vec<u8>,
        id: u32,
        mem: &[u8],
        start: usize,
        len: usize,
    ) -> Result<c_int, c_int> {
        if !self.btf.has(id) {
            return Err(-ENOENT);
        }
        let mut t = Typed {
            mem,
            base: mem.as_ptr() as usize,
            end: start.saturating_add(len),
            depth: 0,
            is_array_member: false,
            is_array_terminated: false,
            is_array_char: false,
        };
        self.data(&mut t, out, b"", id, start, 0, 0)
    }

    /// skip_mods_and_typedefs(), which libbpf follows without bound and
    /// this stops at a loop.
    fn skip_mods(&self, mut id: u32) -> Option<u32> {
        for _ in 0..=self.btf.type_cnt() {
            if !self.btf.has(id) {
                return None;
            }
            if !(is_mod(self.btf.kind(id)) || self.btf.kind(id) == btf::KIND_TYPEDEF) {
                return Some(id);
            }
            id = self.btf.size_or_type(id);
        }
        None
    }

    /// ptr_is_aligned(): whether the value of `id` at `pos` sits at a
    /// multiple of the type's alignment.
    fn aligned(&self, t: &Typed<'_>, id: u32, pos: usize) -> bool {
        match self.btf.align_of(id) {
            Ok(a) if a != 0 => t.base.wrapping_add(pos).is_multiple_of(a as usize),
            _ => false,
        }
    }

    /// btf_dump_emit_type_cast()
    fn type_cast(&mut self, t: &Typed<'_>, out: &mut Vec<u8>, id: u32, top_level: bool) {
        if t.is_array_member {
            return;
        }
        if matches!(self.btf.kind(id), btf::KIND_VAR | btf::KIND_DATASEC) {
            return;
        }
        if top_level {
            out.push(b'(');
        }
        self.skip_anon_defs = true;
        self.strip_mods = true;
        let _ = self.type_decl(out, id, b"");
        self.strip_mods = false;
        self.skip_anon_defs = false;
        if top_level {
            out.push(b')');
        }
    }

    /// btf_dump_get_bitfield_value()
    fn bitfield_value(
        &self,
        t: &Typed<'_>,
        ty: u32,
        pos: usize,
        bits_offset: u8,
        bit_sz: u8,
    ) -> Result<u64, c_int> {
        let start_bit = bits_offset % 8;
        let nr_bytes = (u32::from(start_bit) + u32::from(bit_sz)).div_ceil(8) as u8;
        if pos.saturating_add(usize::from(nr_bytes)) > t.end {
            return Err(-E2BIG);
        }
        let size = self.btf.size_or_type(ty);
        if size > 8 {
            crate::log::warn(format!("unexpected bitfield size {size}").as_bytes());
            return Err(-EINVAL);
        }
        let num = t.le(pos, size as usize);
        let nr_copy_bits = bit_sz.wrapping_add(bits_offset);
        let left = 64u16.wrapping_sub(u16::from(nr_copy_bits));
        let right = 64u16.wrapping_sub(u16::from(bit_sz));
        // x86 takes a shift count modulo 64, as libbpf's shifts by 64 do.
        Ok(num
            .wrapping_shl(u32::from(left))
            .wrapping_shr(u32::from(right)))
    }

    /// btf_dump_type_data_check_overflow(): the bytes the value takes.
    fn check_overflow(
        &self,
        t: &Typed<'_>,
        id: u32,
        pos: usize,
        bits_offset: u8,
        bit_sz: u8,
    ) -> Result<c_int, c_int> {
        if bit_sz != 0 {
            let nr_bytes = (u32::from(bits_offset) + u32::from(bit_sz)).div_ceil(8) as u8;
            return if pos.saturating_add(usize::from(nr_bytes)) > t.end {
                Err(-E2BIG)
            } else {
                Ok(c_int::from(nr_bytes))
            };
        }
        let size = match self.btf.resolve_size(id) {
            Ok(s) if s < c_int::MAX as u32 => s,
            other => {
                // As libbpf shows it: an error as the size_t it casts it to.
                let shown = other.map_or_else(|err| err as isize as usize, |s| s as usize);
                crate::log::warn(format!("unexpected size [{shown}] for id [{id}]").as_bytes());
                return Err(-EINVAL);
            }
        };
        let Some(base) = self.skip_mods(id) else {
            crate::log::warn(
                format!("unexpected error skipping mods/typedefs for id [{id}]").as_bytes(),
            );
            return Err(-EINVAL);
        };
        if matches!(
            self.btf.kind(base),
            btf::KIND_INT | btf::KIND_FLOAT | btf::KIND_PTR | btf::KIND_ENUM | btf::KIND_ENUM64
        ) && pos
            .saturating_add(usize::from(bits_offset / 8))
            .saturating_add(size as usize)
            > t.end
        {
            return Err(-E2BIG);
        }
        Ok(size as c_int)
    }

    /// btf_dump_dump_type_data(): the value of `id` at `pos`, named
    /// `fname` within its struct.
    #[allow(clippy::too_many_arguments)]
    fn data(
        &mut self,
        t: &mut Typed<'_>,
        out: &mut Vec<u8>,
        fname: &[u8],
        id: u32,
        pos: usize,
        bits_offset: u8,
        bit_sz: u8,
    ) -> Result<c_int, c_int> {
        let size = self.check_overflow(t, id, pos, bits_offset, bit_sz)?;
        t.pfx(out);
        if !fname.is_empty() {
            out.push(b'.');
            out.extend_from_slice(fname);
            out.extend_from_slice(b" = ");
        }
        self.type_cast(t, out, id, true);
        let base = self.skip_mods(id).unwrap_or(0);
        let btf = self.btf;
        let kind = btf.kind(base);
        match kind {
            btf::KIND_INT if bit_sz != 0 => {
                let v = self.bitfield_value(t, base, pos, bits_offset, bit_sz)?;
                t.values(out, format!("0x{v:x}").as_bytes());
            }
            btf::KIND_INT => self.int_data(t, out, base, pos)?,
            btf::KIND_FLOAT => self.float_data(t, out, base, pos)?,
            btf::KIND_PTR => {
                let ptr_sz = btf.ptr_size();
                if self.aligned(t, id, pos) && ptr_sz == 8 {
                    let p = t.le(pos, 8);
                    let s = if p == 0 {
                        "(nil)".into()
                    } else {
                        format!("0x{p:x}")
                    };
                    t.values(out, s.as_bytes());
                } else if ptr_sz == 4 {
                    t.values(out, format!("0x{:x}", t.le(pos, 4)).as_bytes());
                } else {
                    t.values(out, format!("0x{:x}", t.le(pos, 8)).as_bytes());
                }
            }
            btf::KIND_ARRAY => self.array_data(t, out, base, pos)?,
            btf::KIND_STRUCT | btf::KIND_UNION => self.struct_data(t, out, base, pos)?,
            btf::KIND_ENUM | btf::KIND_ENUM64 if bit_sz != 0 => {
                let v = self.bitfield_value(t, base, pos, bits_offset, bit_sz)?;
                // libbpf reads it back from a local, aligned unless the
                // type has no alignment, when it measures the local
                // against the end of the data, on the stack and past it.
                if !matches!(btf.align_of(id), Ok(a) if a != 0) {
                    return Err(-E2BIG);
                }
                let v = self.enum_value_of(base, v)?;
                self.enum_data(t, out, base, v);
            }
            btf::KIND_ENUM | btf::KIND_ENUM64 => {
                let v = self.get_enum_value(t, id, base, pos)?;
                self.enum_data(t, out, base, v);
            }
            btf::KIND_VAR => {
                let linkage = btf.var_linkage(base);
                out.extend_from_slice(match linkage {
                    btf::VAR_STATIC => b"static ",
                    btf::VAR_GLOBAL_EXTERN => b"extern ",
                    _ => b"",
                });
                let ty = btf.size_or_type(base);
                self.type_cast(t, out, ty, false);
                out.push(b' ');
                out.extend_from_slice(btf.name(base));
                out.extend_from_slice(b" = ");
                self.data(t, out, b"", ty, pos, 0, 0)?;
            }
            btf::KIND_DATASEC => {
                let name = [&b"SEC(\""[..], btf.name(base), b"\") "].concat();
                t.values(out, &name);
                for i in 0..btf.vlen(base) {
                    let (ty, off, _) = btf.secinfo(base, i);
                    self.data(t, out, b"", ty, pos.saturating_add(off as usize), 0, 0)?;
                    out.push(b';');
                }
            }
            btf::KIND_FWD
            | btf::KIND_FUNC
            | btf::KIND_FUNC_PROTO
            | btf::KIND_DECL_TAG
            | btf::KIND_LOC_PARAM
            | btf::KIND_LOC_PROTO
            | btf::KIND_LOCSEC
            | 0 => {
                out.extend_from_slice(format!("<unsupported kind:{kind}>").as_bytes());
                return Err(-ENOTSUP);
            }
            _ => {
                crate::log::warn(format!("unexpected kind [{kind}] for id [{id}]").as_bytes());
                return Err(-EINVAL);
            }
        }
        Ok(size)
    }

    /// btf_dump_int_data()
    fn int_data(
        &self,
        t: &mut Typed<'_>,
        out: &mut Vec<u8>,
        ty: u32,
        pos: usize,
    ) -> Result<(), c_int> {
        let btf = self.btf;
        let sign = btf.int_encoding(ty) & 1 != 0;
        let s = match btf.size_or_type(ty) {
            16 => {
                let (lsi, msi) = (t.le(pos, 8), t.le(pos + 8, 8));
                if msi == 0 {
                    format!("0x{lsi:x}")
                } else {
                    format!("0x{msi:x}{lsi:016x}")
                }
            }
            8 if sign => (t.le(pos, 8) as i64).to_string(),
            8 => t.le(pos, 8).to_string(),
            4 if sign => (t.le(pos, 4) as u32 as i32).to_string(),
            4 => (t.le(pos, 4) as u32).to_string(),
            2 if sign => (t.le(pos, 2) as u16 as i16).to_string(),
            2 => (t.le(pos, 2) as u16).to_string(),
            1 => {
                let c = t.byte(pos);
                if t.is_array_char {
                    if t.is_array_terminated {
                        return Ok(());
                    }
                    if c == 0 {
                        t.values(out, b"'\\0'");
                        t.is_array_terminated = true;
                        return Ok(());
                    }
                    if isprint(c) {
                        t.values(out, &[b'\'', c, b'\'']);
                        return Ok(());
                    }
                }
                if sign {
                    (c as i8).to_string()
                } else {
                    c.to_string()
                }
            }
            sz => {
                crate::log::warn(format!("unexpected size {sz} for id [{ty}]").as_bytes());
                return Err(-EINVAL);
            }
        };
        t.values(out, s.as_bytes());
        Ok(())
    }

    /// btf_dump_float_data()
    fn float_data(
        &self,
        t: &Typed<'_>,
        out: &mut Vec<u8>,
        ty: u32,
        pos: usize,
    ) -> Result<(), c_int> {
        let s = match self.btf.size_or_type(ty) {
            16 => {
                let mut b = [0u8; 16];
                for (i, x) in b.iter_mut().enumerate() {
                    *x = t.byte(pos + i);
                }
                format_long_double(&b)
            }
            8 => format_f64(f64::from_bits(t.le(pos, 8))),
            4 => format_f64(f64::from(f32::from_bits(t.le(pos, 4) as u32))),
            sz => {
                crate::log::warn(format!("unexpected size {sz} for id [{ty}]").as_bytes());
                return Err(-EINVAL);
            }
        };
        t.values(out, s.as_bytes());
        Ok(())
    }

    /// btf_dump_string_data(): -EINVAL for an array holding no NUL.
    fn string_data(
        &self,
        t: &Typed<'_>,
        out: &mut Vec<u8>,
        ty: u32,
        pos: usize,
    ) -> Result<(), c_int> {
        let nelems = self.btf.array(ty).nelems as usize;
        let mut len = 0;
        while len < nelems {
            if pos.saturating_add(len) >= t.end {
                return Err(-E2BIG);
            }
            if t.byte(pos + len) == 0 {
                break;
            }
            len += 1;
        }
        if len == nelems {
            return Err(-EINVAL);
        }
        t.pfx(out);
        out.push(b'"');
        for i in 0..len {
            let c = t.byte(pos + i);
            if isprint(c) {
                out.push(c);
            } else {
                out.extend_from_slice(format!("\\x{c:02x}").as_bytes());
            }
        }
        out.push(b'"');
        Ok(())
    }

    /// btf_dump_array_data(): an element that fails is passed over, as
    /// libbpf passes it.
    fn array_data(
        &mut self,
        t: &mut Typed<'_>,
        out: &mut Vec<u8>,
        ty: u32,
        pos: usize,
    ) -> Result<(), c_int> {
        let btf = self.btf;
        let a = btf.array(ty);
        let elem = self.skip_mods(a.ty);
        let elem_size = match btf.resolve_size(a.ty) {
            Ok(s) if s > 0 => s as usize,
            other => {
                let shown = other.map_or_else(i64::from, i64::from);
                crate::log::warn(
                    format!("unexpected elem size {shown} for array type [{ty}]").as_bytes(),
                );
                return Err(-EINVAL);
            }
        };
        if elem.is_some_and(|e| btf.kind(e) == btf::KIND_INT) && elem_size == 1 {
            if self.string_data(t, out, ty, pos).is_ok() {
                return Ok(());
            }
            t.is_array_char = true;
        }
        t.depth += 1;
        out.push(b'[');
        out.extend_from_slice(t.newline());
        let (member, terminated) = (t.is_array_member, t.is_array_terminated);
        t.is_array_member = true;
        t.is_array_terminated = false;
        for i in 0..a.nelems as usize {
            if t.is_array_terminated {
                break;
            }
            let at = pos.saturating_add(i.saturating_mul(elem_size));
            let _ = self.data(t, out, b"", a.ty, at, 0, 0);
        }
        t.is_array_member = member;
        t.is_array_terminated = terminated;
        t.depth -= 1;
        t.pfx(out);
        t.values(out, b"]");
        Ok(())
    }

    /// btf_dump_struct_data()
    fn struct_data(
        &mut self,
        t: &mut Typed<'_>,
        out: &mut Vec<u8>,
        ty: u32,
        pos: usize,
    ) -> Result<(), c_int> {
        let btf = self.btf;
        t.depth += 1;
        out.push(b'{');
        out.extend_from_slice(t.newline());
        for m in btf.members(ty) {
            let off = m.bit_offset();
            let name = btf.str_at(m.name_off).unwrap_or_default();
            let at = pos.saturating_add((off / 8) as usize);
            self.data(
                t,
                out,
                name,
                m.ty,
                at,
                (off % 8) as u8,
                m.bitfield_size() as u8,
            )?;
        }
        t.depth -= 1;
        t.pfx(out);
        t.values(out, b"}");
        Ok(())
    }

    /// btf_dump_get_enum_value() of the enum at `pos`. Unaligned, libbpf
    /// takes it as a bitfield of no bits, shifting it by 64 both ways,
    /// which the compiler folds to 0.
    fn get_enum_value(&self, t: &Typed<'_>, id: u32, ty: u32, pos: usize) -> Result<i64, c_int> {
        if !self.aligned(t, id, pos) {
            self.bitfield_value(t, ty, pos, 0, 0)?;
            return Ok(0);
        }
        let signed = self.btf.kflag(ty);
        Ok(match self.btf.size_or_type(ty) {
            8 => t.le(pos, 8) as i64,
            4 if signed => i64::from(t.le(pos, 4) as u32 as i32),
            4 => i64::from(t.le(pos, 4) as u32),
            2 if signed => i64::from(t.le(pos, 2) as u16 as i16),
            2 => i64::from(t.le(pos, 2) as u16),
            1 if signed => i64::from(t.le(pos, 1) as u8 as i8),
            1 => i64::from(t.le(pos, 1) as u8),
            sz => {
                crate::log::warn(format!("unexpected size {sz} for enum, id:[{ty}]").as_bytes());
                return Err(-EINVAL);
            }
        })
    }

    /// btf_dump_get_enum_value() of a bitfield's value, which libbpf
    /// stored in an aligned local of 8 bytes and reads back as the enum.
    fn enum_value_of(&self, ty: u32, v: u64) -> Result<i64, c_int> {
        let signed = self.btf.kflag(ty);
        Ok(match self.btf.size_or_type(ty) {
            8 => v as i64,
            4 if signed => i64::from(v as u32 as i32),
            4 => i64::from(v as u32),
            2 if signed => i64::from(v as u16 as i16),
            2 => i64::from(v as u16),
            1 if signed => i64::from(v as u8 as i8),
            1 => i64::from(v as u8),
            sz => {
                crate::log::warn(format!("unexpected size {sz} for enum, id:[{ty}]").as_bytes());
                return Err(-EINVAL);
            }
        })
    }

    /// btf_dump_enum_data(): the value's name, else the value, which an
    /// ENUM's printf() takes as an int.
    fn enum_data(&self, t: &Typed<'_>, out: &mut Vec<u8>, ty: u32, value: i64) {
        let btf = self.btf;
        let signed = btf.kflag(ty);
        let is_enum = btf.kind(ty) == btf::KIND_ENUM;
        for i in 0..btf.vlen(ty) {
            let (name_off, v) = btf.enum_value(ty, i);
            let hit = if is_enum {
                value == i64::from(v as u32 as i32)
            } else {
                value as u64 == v
            };
            if hit {
                t.values(out, btf.str_at(name_off).unwrap_or_default());
                return;
            }
        }
        // libbpf joins its delimiter and newline to the format as
        // `signed ? "%d" : "%u" "%s%s"`, which joins them to the unsigned
        // one alone: a signed value goes out bare.
        match (is_enum, signed) {
            (true, true) => out.extend_from_slice((value as i32).to_string().as_bytes()),
            (true, false) => t.values(out, (value as u32).to_string().as_bytes()),
            (false, true) => out.extend_from_slice(format!("{value}LL").as_bytes()),
            (false, false) => t.values(out, format!("{}ULL", value as u64).as_bytes()),
        }
    }
}
