// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::text::cstr;

/// A BTF built type by type, ids from 1 in the order added, as libbpf's
/// btf__add_*() build one.
struct BtfBuilder {
    types: Vec<u8>,
    strings: Vec<u8>,
    n: u32,
}

const KIND_INT: u32 = 1;
const KIND_PTR: u32 = 2;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_TYPEDEF: u32 = 8;
const KIND_FUNC: u32 = 12;
const KIND_FUNC_PROTO: u32 = 13;
const INT_SIGNED: u32 = 1;
const INT_CHAR: u32 = 2;
const FUNC_GLOBAL: u32 = 1;

impl BtfBuilder {
    fn new() -> Self {
        BtfBuilder {
            types: Vec::new(),
            strings: vec![0],
            n: 0,
        }
    }

    fn name(&mut self, s: &str) -> u32 {
        if s.is_empty() {
            return 0;
        }
        let off = self.strings.len() as u32;
        self.strings.extend_from_slice(s.as_bytes());
        self.strings.push(0);
        off
    }

    fn add(&mut self, name: &str, kind: u32, vlen: u32, size_or_type: u32, extra: &[u32]) -> u32 {
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

    fn int(&mut self, name: &str, size: u32, encoding: u32) -> u32 {
        self.add(name, KIND_INT, 0, size, &[(encoding << 24) | (size * 8)])
    }

    fn typedef(&mut self, name: &str, ty: u32) -> u32 {
        self.add(name, KIND_TYPEDEF, 0, ty, &[])
    }

    fn array(&mut self, index: u32, elem: u32, n: u32) -> u32 {
        self.add("", KIND_ARRAY, 0, 0, &[elem, index, n])
    }

    fn ptr(&mut self, ty: u32) -> u32 {
        self.add("", KIND_PTR, 0, ty, &[])
    }

    /// A struct of `size` bytes and its members: name, type and bit offset.
    fn structure(&mut self, name: &str, size: u32, members: &[(&str, u32, u32)]) -> u32 {
        let extra: Vec<u32> = members
            .iter()
            .flat_map(|&(name, ty, off)| [self.name(name), ty, off])
            .collect();
        self.add(name, KIND_STRUCT, members.len() as u32, size, &extra)
    }

    fn func_proto(&mut self, ret: u32) -> u32 {
        self.add("", KIND_FUNC_PROTO, 0, ret, &[])
    }

    fn func(&mut self, name: &str, proto: u32) -> u32 {
        self.add(name, KIND_FUNC, FUNC_GLOBAL, proto, &[])
    }

    /// The BTF as shirudo parses it.
    fn parse(&self) -> Btf {
        let mut raw = Vec::new();
        raw.extend_from_slice(&0xeb9fu16.to_ne_bytes());
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
        Btf::parse(&raw).unwrap()
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Fixture {
    Valid,
    NoMap,
    NoSha,
    ShaLength,
    ShaWidth,
    ShaSigned,
    NoExclProgSha,
    ExclProgShaType,
    ExclProgShaTarget,
    NoProgAux,
    NoSig,
    SigType,
    NoKeyringSerial,
    KeyringSerialWidth,
    NoKeyringType,
    KeyringTypeWidth,
    NoVerdict,
    VerdictSigned,
    TrailingDrift,
}

use Fixture::*;

/// The kernel's BPF structs as far as shirudo needs them, but for what
/// `f` leaves out or gets wrong.
fn fixture(f: Fixture) -> Btf {
    let mut b = BtfBuilder::new();
    let raw_u8 = b.int("unsigned char", 1, INT_CHAR);
    let u16 = b.int("u16", 2, 0);
    let raw_u32 = b.int("unsigned int", 4, 0);
    let s8 = b.int("s8", 1, INT_SIGNED);
    let s32 = b.int("s32", 4, INT_SIGNED);
    let index = b.int("index", 4, 0);
    let u8 = b.typedef("u8", raw_u8);
    let u32 = b.typedef("u32", raw_u32);
    let sha32 = b.array(index, u8, 32);
    let sha31 = b.array(index, u8, 31);
    let sha_u16 = b.array(index, u16, 32);
    let sha_s8 = b.array(index, s8, 32);
    let byte_ptr = b.ptr(raw_u8);
    let u32_ptr = b.ptr(u32);

    if f != NoMap {
        let mut members = Vec::new();
        if f != NoSha {
            let sha = match f {
                ShaLength => sha31,
                ShaWidth => sha_u16,
                ShaSigned => sha_s8,
                _ => sha32,
            };
            members.push(("sha", sha, 0));
        }
        if f != NoExclProgSha {
            let excl = match f {
                ExclProgShaType => u32,
                ExclProgShaTarget => u32_ptr,
                _ => byte_ptr,
            };
            members.push(("excl_prog_sha", excl, 256));
        }
        if f == TrailingDrift {
            members.push(("future_map_field", u32, 320));
        }
        b.structure("bpf_map", 64, &members);
    }
    if f == NoProgAux {
        return b.parse();
    }
    let mut sig = u32;
    if f != SigType {
        let mut members = Vec::new();
        if f != NoKeyringSerial {
            members.push((
                "keyring_serial",
                if f == KeyringSerialWidth { s8 } else { s32 },
                0,
            ));
        }
        if f != NoKeyringType {
            members.push((
                "keyring_type",
                if f == KeyringTypeWidth { u32 } else { u8 },
                32,
            ));
        }
        if f != NoVerdict {
            members.push(("verdict", if f == VerdictSigned { s8 } else { u8 }, 40));
        }
        sig = b.structure("", 8, &members);
    }
    let mut members = Vec::new();
    if f != NoSig {
        members.push(("sig", sig, 0));
    }
    if f == TrailingDrift {
        members.push(("future_aux_field", u32, 64));
    }
    b.structure("bpf_prog_aux", 32, &members);
    b.parse()
}

/// validate_btf() of the fixture: Ok, or the detail of its refusal.
fn validated(f: Fixture) -> Result<(), Vec<u8>> {
    let btf = fixture(f);
    let mut detail = [0u8; DETAIL_MAX];
    // SAFETY: room for the detail.
    match unsafe { validate_btf(Some(&btf), detail.as_mut_ptr().cast(), detail.len()) } {
        0 => Ok(()),
        _ => Err(cstr(&detail).to_vec()),
    }
}

fn refused_for(f: Fixture, want: &str) {
    let detail = validated(f).unwrap_err();
    assert!(
        crate::text::find(&detail, want.as_bytes()).is_some(),
        "{:?} lacks {want:?}",
        String::from_utf8_lossy(&detail)
    );
}

#[test]
fn accepts_the_required_prefix() {
    assert_eq!(validated(Valid), Ok(()));
}

#[test]
fn accepts_fields_past_the_prefix() {
    assert_eq!(validated(TrailingDrift), Ok(()));
}

#[test]
fn each_missing_or_mistyped_field_is_named() {
    for (f, want) in [
        (NoMap, "no struct bpf_map"),
        (NoSha, "bpf_map.sha is missing"),
        (ShaLength, "u8[32]"),
        (ShaWidth, "u8[32]"),
        (ShaSigned, "u8[32]"),
        (NoExclProgSha, "bpf_map.excl_prog_sha is missing"),
        (ExclProgShaType, "must have pointer type"),
        (ExclProgShaTarget, "must point to a byte"),
        (NoProgAux, "no struct bpf_prog_aux"),
        (NoSig, "bpf_prog_aux.sig is missing"),
        (SigType, "sig must have struct type"),
        (NoKeyringSerial, "keyring_serial must have type s32"),
        (KeyringSerialWidth, "keyring_serial must have type s32"),
        (NoKeyringType, "keyring_type must have type u8"),
        (KeyringTypeWidth, "keyring_type must have type u8"),
        (NoVerdict, "verdict must have type u8"),
        (VerdictSigned, "verdict must have type u8"),
    ] {
        refused_for(f, want);
    }
}

/// A BTF with a bpf_lsm_<hook> function for each hook but `skip`.
fn lsm_btf(hooks: &LsmHooks, skip: Option<&[u8]>) -> Btf {
    let mut b = BtfBuilder::new();
    let ret = b.int("int", 4, INT_SIGNED);
    let proto = b.func_proto(ret);

    for hook in hooks.names().filter(|h| Some(*h) != skip) {
        b.func(&format!("bpf_lsm_{}", String::from_utf8_lossy(hook)), proto);
    }
    b.parse()
}

fn hooks_of(names: &[&str]) -> Box<LsmHooks> {
    let mut hooks = LsmHooks::new();
    for name in names {
        hooks.add(name.as_bytes()).unwrap();
    }
    hooks
}

fn embedded_hooks() -> Box<LsmHooks> {
    let mut hooks = LsmHooks::new();
    for obj in crate::skel::embedded() {
        lsm_hooks(obj, &mut hooks).unwrap();
    }
    hooks
}

#[test]
fn lsm_hooks_come_from_the_embedded_objects() {
    let hooks = embedded_hooks();
    let names: Vec<&[u8]> = hooks.names().collect();

    for hook in [&b"bpf"[..], b"inode_unlink", b"mm_read_access"] {
        assert!(names.contains(&hook), "{hook:?}");
    }
    assert!(!names.contains(&&b"lsm/bpf"[..]));
    let mut unique = names.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), names.len());
}

#[test]
fn lsm_hooks_all_present() {
    let hooks = hooks_of(&["bpf", "file_open"]);

    assert_eq!(
        validate_lsm_hooks(Some(&lsm_btf(&hooks, None)), &hooks),
        Ok(())
    );
}

#[test]
fn lsm_hooks_missing_are_named() {
    let hooks = hooks_of(&["bpf", "file_open", "mm_read_access"]);
    let btf = lsm_btf(&hooks, Some(b"mm_read_access"));

    assert_eq!(
        validate_lsm_hooks(Some(&btf), &hooks),
        Err(b"kernel has no LSM hook mm_read_access; boot a shirudo-patched kernel".to_vec())
    );
    let btf = lsm_btf(&hooks_of(&["bpf"]), None);
    assert_eq!(
        validate_lsm_hooks(Some(&btf), &hooks_of(&["bpf", "x_one", "x_two"])),
        Err(b"kernel has no LSM hooks x_one, x_two; boot a shirudo-patched kernel".to_vec())
    );
}

#[test]
fn lsm_hooks_of_the_embedded_objects_checked() {
    let hooks = embedded_hooks();

    assert_eq!(
        validate_lsm_hooks(Some(&lsm_btf(&hooks, None)), &hooks),
        Ok(())
    );
    assert_eq!(
        validate_lsm_hooks(Some(&lsm_btf(&hooks, Some(b"mm_read_access"))), &hooks),
        Err(b"kernel has no LSM hook mm_read_access; boot a shirudo-patched kernel".to_vec())
    );
}

#[test]
fn lsm_hooks_need_btf() {
    let detail = validate_lsm_hooks(None, &LsmHooks::new()).unwrap_err();

    assert!(crate::text::find(&detail, b"kernel BTF is unavailable").is_some());
}
