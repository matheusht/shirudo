// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::errno::{ENAMETOOLONG, ENOENT};
use crate::util::upatch::NAME_MAX;

const ABSENT: &[u8] = b"shirudo-unit-no-such-upatch";

/// The pins of the entries `names`.
fn noted(names: &[&[u8]]) -> Pins {
    let mut pins = Pins::default();
    for name in names {
        pins.note(name);
    }
    pins
}

#[test]
fn names_are_parsed_strictly() {
    let pins = noted(&[
        b"link_",
        b"link_07",
        b"link_1x",
        b"link_-1",
        b"link_+1",
        b"link_4294967296",
        b"link_ 1",
        b"links",
        b"xdp_prog_",
        b"xdp_prog_01",
        b"xdp_prog_a",
        b"test",
        b"maps",
        b"serializers",
        b".",
        b"..",
    ]);

    assert!(!pins.has_link);
    assert_eq!((pins.nr_links, pins.nr_xdp_progs), (0, 0));
    assert!(!pins.loaded());
}

#[test]
fn lowest_index_is_kept_in_any_order() {
    let pins = noted(&[
        b"link_7",
        b"link_4294967295",
        b"link_2",
        b"xdp_prog_3",
        b"xdp_prog_1",
    ]);

    assert_eq!((pins.nr_links, pins.first_link), (3, 2));
    assert_eq!((pins.nr_xdp_progs, pins.first_xdp_prog), (2, 1));
}

#[test]
fn loaded_needs_the_first_link_or_a_program() {
    assert!(!noted(&[b"link_1"]).loaded());
    assert!(noted(&[b"link_1", b"link_0"]).loaded());
    assert!(noted(&[b"link"]).loaded());
    assert!(noted(&[b"xdp_prog_4"]).loaded());
}

#[test]
fn complete_means_every_link() {
    assert!(noted(&[]).complete(0));
    assert!(!noted(&[]).complete(1));
    assert!(noted(&[b"link"]).complete(1));
    assert!(!noted(&[b"link_0"]).complete(1));
    assert!(!noted(&[b"link_0"]).complete(2));
    assert!(noted(&[b"link_0", b"link_1"]).complete(2));
    assert!(!noted(&[b"link_0", b"link_1"]).complete(3));
    assert!(!noted(&[b"link_1", b"link_2"]).complete(2));
    assert!(!noted(&[b"link_0", b"link_2"]).complete(2));
}

#[test]
fn absent_upatch_has_no_pins() {
    assert_eq!(Pins::read(ABSENT).err(), Some(-ENOENT));
    assert!(!loaded_pins(ABSENT));
}

#[test]
fn xdp_program_pins_have_one_name() {
    let pin = xdp_prog_pin(b"fw", 3).unwrap();

    assert!(pin.to_bytes().ends_with(b"/fw/xdp_prog_3"));
    assert_eq!(
        xdp_prog_pin(&[b'a'; NAME_MAX + 1], 3).err(),
        Some(-ENAMETOOLONG)
    );
}

#[test]
fn an_unpinned_xdp_program_does_not_open() {
    assert!(xdp_prog_open(ABSENT, 0).is_err());
}

#[test]
fn link_pins_read_back_as_links() {
    let pins = noted(&[b"link_4294967295"]);

    assert_eq!((pins.nr_links, pins.last_link), (1, u32::MAX));
}

#[test]
fn payload_of_absent_upatch_is_enoent() {
    assert_eq!(pin_payload(ABSENT).err(), Some(-ENOENT));
    assert_eq!(pin_payload(&[b'a'; 4095]).err(), Some(-ENAMETOOLONG));
}

#[test]
fn no_pin_directory_is_no_upatch() {
    let dir = crate::util::upatch_resolve::BPFFS_UPATCHES_DIR;
    let mut seen = 0;

    if std::path::Path::new(dir).exists() {
        eprintln!("skipped: this host has a shirudo pin directory");
        return;
    }
    assert_eq!(
        each_pinned(&mut |_| {
            seen += 1;
            0
        }),
        0
    );
    assert_eq!(seen, 0);
}
