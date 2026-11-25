// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::text::cstr;

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

#[test]
fn prog_specs_take_the_signed_counts() {
    let md = metadata(3, &[entry(ATTACH_RAW_TRACEPOINT, 0)]);
    let specs = Specs::parse(&md, 3, 1).unwrap();
    let s = &specs.as_slice()[0];

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

/// A container named `name` of an 8-byte loader and signature, whose
/// data is the signed `sections`, each a tag and its bytes, then their
/// directory and its trailer.
fn container(name: &[u8], sections: &[(u32, &[u8])]) -> Vec<u8> {
    let words = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
    let (mut data, mut dir) = (Vec::new(), Vec::new());

    for &(tag, bytes) in sections {
        dir.extend(words(&[tag, 0, data.len() as u32, bytes.len() as u32]));
        data.extend_from_slice(bytes);
    }
    let dir_off = data.len() as u32;
    data.extend(dir);
    data.extend(words(&[
        SIGNED_TRAILER_MAGIC,
        SIGNED_VERSION,
        dir_off,
        sections.len() as u32,
    ]));
    let at = HEADER_SIZE as u32;
    let mut c = [&MAGIC.to_le_bytes()[..], &words(&[VERSION, 0]), name].concat();
    c.resize(304, 0);
    c.extend(words(&[
        at,
        8,
        at + 8,
        8,
        0,
        0,
        at + 16,
        data.len() as u32,
        0,
        0,
        0,
        0,
        TYPE_BPF,
        0,
    ]));
    c.resize(HEADER_SIZE + 16, 0);
    c.extend(data);
    c
}

#[test]
fn name_stops_at_its_nul() {
    let c = container(b"kernel-obs", &[]);

    assert_eq!(Upatch::from_bytes(&c).unwrap().name(), b"kernel-obs");
}

#[test]
fn a_name_without_its_nul_is_refused() {
    let c = container(&[b'a'; NAME_MAX], &[]);

    assert_eq!(Upatch::from_bytes(&c).err(), Some(-EINVAL));
}

#[test]
fn prog_name_is_what_the_kernel_takes() {
    let mut out = [0xffu8; 16];

    let c = container(b"fix-cve.2026", &[]);
    Upatch::from_bytes(&c).unwrap().prog_name(&mut out);
    assert_eq!(cstr(&out), b"fix_cve.2026");
    let c = container(&[b'a'; NAME_MAX - 1], &[]);
    Upatch::from_bytes(&c).unwrap().prog_name(&mut out);
    assert_eq!(cstr(&out).len(), 15);
}

#[test]
fn name_signed_is_the_header_name() {
    let mut signed = [0u8; NAME_MAX];
    let name_signed = |name: &[u8], sections: &[(u32, &[u8])]| {
        Upatch::from_bytes(&container(name, sections))
            .unwrap()
            .name_signed()
    };

    signed[..3].copy_from_slice(b"fix");
    assert!(!name_signed(b"fix", &[]));
    assert!(name_signed(b"fix", &[(SECTION_NAME, &signed)]));
    assert!(!name_signed(b"fiy", &[(SECTION_NAME, &signed)]));
}

/// Each signed section is found where the directory places it, and a
/// directory that names one twice is taken for none.
#[test]
fn signed_sections_are_once_each() {
    let payload = [7u8; PAYLOAD_HASH_LEN];
    let one = container(
        b"fix",
        &[(SECTION_ATTACH, b"meta"), (SECTION_UNLOAD, &payload)],
    );
    let twice = container(
        b"fix",
        &[
            (SECTION_UNLOAD, &payload),
            (SECTION_ATTACH, b"meta"),
            (SECTION_UNLOAD, &payload),
        ],
    );

    let u = Upatch::from_bytes(&one).unwrap();
    assert_eq!(u.signed_attach(), Some(&b"meta"[..]));
    assert_eq!(u.signed_unload_payload(), Some(&payload));
    assert!(u.signed_name().is_none() && !u.has_decoders());
    let u = Upatch::from_bytes(&twice).unwrap();
    assert_eq!((u.signed_attach(), u.signed_unload_payload()), (None, None));
}

/// One signed byte string holds a second directory where a header that
/// ends the loader 16 bytes earlier would otherwise find it.
fn split_container(shift: usize) -> Vec<u8> {
    let words = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
    let at = HEADER_SIZE as u32;
    let insns = [b'x'; 32];
    let mut name = [0u8; NAME_MAX];
    name[..3].copy_from_slice(b"fix");
    let directory = words(&[SECTION_NAME, 0, 0, NAME_MAX as u32]);
    let trailer = words(&[
        SIGNED_TRAILER_MAGIC,
        SIGNED_VERSION,
        (NAME_MAX + SIGNED_SECTION) as u32,
        1,
    ]);
    let data = [&name[..], &directory, &directory, &trailer].concat();
    let mut c = [&MAGIC.to_le_bytes()[..], &words(&[VERSION, 0]), b"fix"].concat();

    c.resize(304, 0);
    c.extend(words(&[
        at,
        8,
        at + 8,
        (insns.len() - shift) as u32,
        0,
        0,
        at + 8 + insns.len() as u32 - shift as u32,
        data.len() as u32 + shift as u32,
        0,
        0,
        0,
        0,
        TYPE_BPF,
        0,
    ]));
    c.resize(HEADER_SIZE + 8, 0);
    c.extend(insns);
    c.extend(data);
    c
}

#[test]
fn one_signature_keeps_its_sections_in_one_split() {
    assert!(
        Upatch::from_bytes(&split_container(0))
            .unwrap()
            .name_signed()
    );
    assert!(
        Upatch::from_bytes(&split_container(16))
            .unwrap()
            .signed_name()
            .is_none()
    );
}

/// What does not fit the container, or is not one, is refused.
#[test]
fn a_cut_container_is_refused() {
    let c = container(b"fix", &[(SECTION_ATTACH, b"meta")]);

    assert!(Upatch::from_bytes(&c).is_ok());
    for len in [0, 8, HEADER_SIZE, c.len() - 1] {
        assert_eq!(Upatch::from_bytes(&c[..len]).err(), Some(-EINVAL), "{len}");
    }
}

#[test]
fn member_is_a_name_and_a_payload() {
    let payload = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let long = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0";

    assert!(member_valid(b"fix", payload));
    for name in [&b"a\nb"[..], b"../fix", b""] {
        assert!(!member_valid(name, payload), "{name:?}");
    }
    assert!(!member_valid(b"fix", long));
    assert!(!member_valid(b"fix", b"00"));
    assert!(!member_valid(b"fix", b""));
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
                let s = &specs.as_slice()[0];
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
