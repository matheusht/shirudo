// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::testutil::{TempDir, testing_path};
use crate::util::crypto_openssl::sha256;
use std::fs::File;

const ABSENT: &[u8] = b"shirudo-unit-no-such-upatch";

fn fixture() -> Vec<u8> {
    std::fs::read(testing_path("fuzz/corpus/upatch/xdp-virtual")).unwrap()
}

/// `bytes` in the file `name` of `dir`, open to read.
fn file_of(dir: &TempDir, name: &str, bytes: &[u8]) -> File {
    std::fs::write(dir.join(name), bytes).unwrap();
    File::open(dir.join(name)).unwrap()
}

/// The bytes the header of `u` places at `off` for `len`.
fn part(bytes: &[u8], off: u32, len: u32) -> &[u8] {
    &bytes[off as usize..(off + len) as usize]
}

#[test]
fn the_payload_digest_hashes_the_loader_then_the_data() {
    let (dir, bytes) = (TempDir::new(), fixture());
    let u = Upatch::read(&file_of(&dir, "u", &bytes)).unwrap();
    let h = &u.hdr;
    let want = sha256(
        &[
            part(&bytes, h.loader_insns_off, h.loader_insns_len),
            part(&bytes, h.data_off, h.data_len),
        ]
        .concat(),
    )
    .unwrap();

    assert!(h.data_len > 0);
    assert_eq!(payload_digest(&u), Ok(want));
    assert_eq!(h.payload_sha256, want);
}

#[test]
fn a_payload_without_data_hashes_the_loader_alone() {
    let (dir, bytes) = (TempDir::new(), fixture());
    let mut u = Upatch::read(&file_of(&dir, "u", &bytes)).unwrap();

    u.hdr.data_len = 0;
    let h = &u.hdr;
    let want = sha256(part(&bytes, h.loader_insns_off, h.loader_insns_len)).unwrap();
    assert_eq!(payload_digest(&u), Ok(want));
}

/// verify_file() of `bytes` against `payload`: 0 or -errno.
fn verify(dir: &TempDir, bytes: &[u8], payload: &[u8; PAYLOAD_HASH_LEN]) -> c_int {
    verify_file(&file_of(dir, "v", bytes), payload).map_or_else(|err| err, |_| 0)
}

/// The container in the file `name` of `dir` that holds `bytes`.
fn read(dir: &TempDir, name: &str, bytes: &[u8]) -> Upatch<'static> {
    Upatch::read(&file_of(dir, name, bytes)).unwrap()
}

/// The payload the fixture's header names.
fn payload_of(dir: &TempDir, bytes: &[u8]) -> [u8; PAYLOAD_HASH_LEN] {
    read(dir, "p", bytes).hdr.payload_sha256
}

#[test]
fn the_loaded_bytes_verify() {
    let (dir, bytes) = (TempDir::new(), fixture());
    let payload = payload_of(&dir, &bytes);

    assert_eq!(verify(&dir, &bytes, &payload), 0);
}

#[test]
fn another_payload_is_stale() {
    let (dir, bytes) = (TempDir::new(), fixture());
    let mut payload = payload_of(&dir, &bytes);

    payload[0] ^= 1;
    assert_eq!(verify(&dir, &bytes, &payload), -ESTALE);
}

#[test]
fn changed_data_under_an_intact_header_is_stale() {
    let (dir, mut bytes) = (TempDir::new(), fixture());
    let payload = payload_of(&dir, &bytes);
    let off = read(&dir, "o", &bytes).hdr.data_off as usize;

    bytes[off] ^= 1;
    assert_eq!(verify(&dir, &bytes, &payload), -ESTALE);
}

#[test]
fn a_truncated_file_is_stale() {
    let (dir, bytes) = (TempDir::new(), fixture());

    assert_eq!(verify(&dir, &bytes[..64], &[0; PAYLOAD_HASH_LEN]), -ESTALE);
}

#[test]
fn a_missing_archive_is_stale() {
    assert_eq!(
        archive_verify(ABSENT, &[0; PAYLOAD_HASH_LEN]).err(),
        Some(-ESTALE)
    );
}

#[test]
fn links_of_a_missing_archive_are_stale() {
    assert_eq!(
        links_complete(ABSENT, c"/nonexistent/shirudo-unit.upatch"),
        -ESTALE
    );
}

#[test]
fn specs_of_a_missing_archive_are_stale() {
    assert_eq!(
        archive_specs(ABSENT, &[0; PAYLOAD_HASH_LEN]).err(),
        Some(-ESTALE)
    );
}

#[test]
fn nothing_pinned_checks_clean() {
    if std::path::Path::new(crate::util::upatch_resolve::BPFFS_UPATCHES_DIR).exists() {
        eprintln!("skipped: upatches are pinned on this host");
        return;
    }
    let (mut changed, mut lost) = (|_: &[u8]| 1, |_: &[u8]| 1);
    let mut c = Checks {
        changed: Some(&mut changed),
        lost: Some(&mut lost),
        ..Checks::default()
    };

    checks_run(&MeasuredSet::default(), &mut c);
    assert_eq!(c.nr_changed + c.nr_lost + c.nr_uncovered, 0);
    assert_eq!((c.check_err, c.coverage_err), (0, 0));
}
