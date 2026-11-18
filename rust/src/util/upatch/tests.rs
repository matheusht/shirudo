// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::text::cstr;
use core::ffi::CStr;

#[test]
fn bpffs_name_round_trips() {
    assert_eq!(pin_name(b"a.b..c"), b"a~db~d~dc");
    assert_eq!(name_from_pin(b"a~db~d~dc").as_deref(), Some(&b"a.b..c"[..]));
    assert_eq!(name_from_pin(b"a~x"), None);
    assert_eq!(name_from_pin(b"a~"), None);
}

/// An attach entry of `kind`, an XDP program's classes in its union.
fn entry(kind: u32, classes: u32) -> Vec<u8> {
    let mut e = vec![0u8; PROG_ENTRY];

    e[..4].copy_from_slice(&ROLE_ATTACH.to_le_bytes());
    e[4..8].copy_from_slice(&kind.to_le_bytes());
    e[8..12].copy_from_slice(&classes.to_le_bytes());
    e
}

/// Program metadata of `nr_maps` maps and the entries.
fn metadata(nr_maps: u32, entries: &[Vec<u8>]) -> Vec<u8> {
    let head = [PROG_MAGIC, PROG_VERSION, entries.len() as u32, nr_maps];
    head.iter()
        .flat_map(|v| v.to_le_bytes())
        .chain(entries.concat())
        .collect()
}

/// The specs of `md` parsed for the counts the header signed, freed
/// when they go.
struct Specs(*mut ProgSpec, u32);

impl Specs {
    fn parse(md: &[u8], nr_maps: u32, nr_progs: u32) -> Result<Self, c_int> {
        let mut out = ptr::null_mut();
        // SAFETY: the metadata's bytes and room for the specs' pointer.
        match unsafe {
            specs_parse(
                md.as_ptr().cast(),
                md.len() as u32,
                nr_maps,
                nr_progs,
                &mut out,
            )
        } {
            0 => Ok(Specs(out, nr_progs)),
            err => {
                assert!(out.is_null());
                Err(err)
            }
        }
    }

    fn get(&self) -> &[ProgSpec] {
        // SAFETY: the specs specs_parse() gave, as many as asked for.
        unsafe { core::slice::from_raw_parts(self.0, self.1 as usize) }
    }
}

impl Drop for Specs {
    fn drop(&mut self) {
        // SAFETY: what specs_parse() gave, freed once.
        unsafe { specs_free(self.0, self.1) };
    }
}

#[test]
fn prog_specs_take_the_signed_counts() {
    let md = metadata(3, &[entry(ATTACH_RAW_TRACEPOINT, 0)]);
    let specs = Specs::parse(&md, 3, 1).unwrap();
    let s = &specs.get()[0];

    assert_eq!(
        (s.role, s.kind, s.target_fd),
        (ROLE_ATTACH, ATTACH_RAW_TRACEPOINT, -1)
    );
}

#[test]
fn prog_specs_refuse_another_header_count() {
    let md = metadata(3, &[entry(ATTACH_RAW_TRACEPOINT, 0)]);

    for (maps, progs) in [(4, 1), (2, 1), (3, 2), (3, 0)] {
        assert_eq!(
            Specs::parse(&md, maps, progs).err(),
            Some(-EINVAL),
            "{maps} {progs}"
        );
    }
}

/// A container of no bytes whose header names `name`.
fn named(name: &[u8]) -> Upatch {
    // SAFETY: a container of no bytes, for which zeros are a value.
    let mut u: Upatch = unsafe { core::mem::zeroed() };
    u.hdr.name[..name.len()].copy_from_slice(name);
    u
}

#[test]
fn header_name_is_terminated() {
    let mut out = [0xffu8; NAME_MAX + 1];

    header_name(&named(b"kernel-obs"), &mut out);
    assert_eq!(cstr(&out), b"kernel-obs");
    header_name(&named(&[b'a'; NAME_MAX]), &mut out);
    assert_eq!(cstr(&out).len(), NAME_MAX);
}

#[test]
fn prog_name_is_what_the_kernel_takes() {
    let mut out = [0xffu8; 16];

    prog_name(&named(b"fix-cve.2026"), &mut out);
    assert_eq!(cstr(&out), b"fix_cve.2026");
    prog_name(&named(&[b'a'; NAME_MAX]), &mut out);
    assert_eq!(cstr(&out).len(), 15);
}

#[test]
fn name_signed_is_the_header_name() {
    let mut signed = [0u8; NAME_MAX];
    let mut u = named(b"fix");

    signed[..3].copy_from_slice(b"fix");
    u.map = signed.as_ptr();
    assert!(!name_signed(&u));
    u.signed_name = signed.as_ptr().cast();
    assert!(name_signed(&u));
    u.hdr.name[2] = b'y';
    assert!(!name_signed(&u));
}

#[test]
fn member_is_a_name_and_a_payload() {
    let payload = c"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let long = c"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0";
    let valid = |name: &CStr, payload: *const c_char| {
        // SAFETY: a C string, and NULL or another.
        unsafe { member_valid(name.as_ptr(), payload) }
    };

    assert!(valid(c"fix", payload.as_ptr()));
    for name in [c"a\nb", c"../fix", c""] {
        assert!(!valid(name, payload.as_ptr()), "{name:?}");
    }
    assert!(!valid(c"fix", long.as_ptr()));
    assert!(!valid(c"fix", c"00".as_ptr()));
    assert!(!valid(c"fix", ptr::null()));
}

/// A name's pin directory spells each dot in two bytes, within the
/// kernel's NAME_MAX.
#[test]
fn name_fits_its_pin_directory() {
    const LINUX_NAME_MAX: usize = 255;
    let mut name = vec![b'a'; LINUX_NAME_MAX];

    assert!(name_valid(Some(&name)));
    name[LINUX_NAME_MAX - 1] = b'.';
    assert!(!name_valid(Some(&name)));
    name.pop();
    name[LINUX_NAME_MAX - 2] = b'.';
    assert!(name_valid(Some(&name)));
    assert!(!name_valid(Some(&[b'a'; LINUX_NAME_MAX + 1])));
}

#[test]
fn xdp_classes_come_from_xdp_programs_alone() {
    let spec = |kind, device_classes| {
        // SAFETY: a spec of no binary, for which zeros are a value.
        let mut s: ProgSpec = unsafe { core::mem::zeroed() };
        s.kind = kind;
        s.device_classes = device_classes;
        s
    };
    let specs = [
        spec(ATTACH_XDP, 1),
        spec(ATTACH_RAW_TRACEPOINT, 16),
        spec(ATTACH_XDP, 8),
    ];

    assert_eq!(specs_xdp_classes(&specs), 9);
    assert_eq!(specs_xdp_classes(&specs[1..2]), 0);
    assert_eq!(specs_xdp_classes(&[]), 0);
}

#[test]
fn xdp_masks_are_signed_and_bounded() {
    for mask in 1..=31u32 {
        let md = metadata(0, &[entry(ATTACH_XDP, mask)]);
        match Specs::parse(&md, 0, 1) {
            Ok(specs) => {
                let s = &specs.get()[0];
                assert_eq!(mask & !XDP_ALL, 0);
                assert_eq!((s.kind, s.device_classes, s.offset), (ATTACH_XDP, mask, 0));
            }
            Err(_) => assert_ne!(mask & !XDP_ALL, 0),
        }
    }
    for spoil in [
        |e: &mut Vec<u8>| e[8..12].copy_from_slice(&0u32.to_le_bytes()),
        |e: &mut Vec<u8>| e[8..12].copy_from_slice(&32u32.to_le_bytes()),
        |e: &mut Vec<u8>| e[12] = 1,
        |e: &mut Vec<u8>| e[16] = b'x',
        |e: &mut Vec<u8>| e[16 + ATTACH_TARGET_MAX] = b'x',
        |e: &mut Vec<u8>| e[16 + ATTACH_TARGET_MAX - 1] = b'x',
        |e: &mut Vec<u8>| *e.last_mut().unwrap() = b'x',
    ] {
        let mut e = entry(ATTACH_XDP, XDP_ALL);
        spoil(&mut e);
        assert_eq!(Specs::parse(&metadata(0, &[e]), 0, 1).err(), Some(-EINVAL));
    }
}

#[test]
fn xdp_programs_select_disjoint_classes() {
    let two = |first, second| metadata(0, &[entry(ATTACH_XDP, first), entry(ATTACH_XDP, second)]);

    assert!(Specs::parse(&two(XDP_NETWORK, XDP_VIRTUAL), 0, 2).is_ok());
    assert_eq!(
        Specs::parse(&two(XDP_NETWORK | XDP_VIRTUAL, XDP_VIRTUAL), 0, 2).err(),
        Some(-EINVAL)
    );
}
