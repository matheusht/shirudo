// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::testutil::{TempDir, testing_path};
use crate::util::crypto_openssl::sha256;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd};

const ABSENT: &[u8] = b"shirudo-unit-no-such-upatch";

fn fixture() -> Vec<u8> {
    std::fs::read(testing_path("fuzz/corpus/upatch/xdp-virtual")).unwrap()
}

/// `bytes` in the file `name` of `dir`, open to read.
fn file_of(dir: &TempDir, name: &str, bytes: &[u8]) -> File {
    std::fs::write(dir.join(name), bytes).unwrap();
    File::open(dir.join(name)).unwrap()
}

/// The container in `f`, closed when it goes.
struct Open(Upatch);

impl Open {
    fn new(f: &File) -> Self {
        // SAFETY: an all-zero container is a closed one.
        let mut u: Upatch = unsafe { core::mem::zeroed() };
        // SAFETY: an open descriptor and the container to fill.
        assert_eq!(unsafe { upatch_open_fd(f.as_raw_fd(), &mut u) }, 0);
        Open(u)
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        // SAFETY: the container opened, closed once.
        unsafe { upatch_close(&mut self.0) };
    }
}

/// The bytes the header of `u` places at `off` for `len`.
fn part(bytes: &[u8], off: u32, len: u32) -> &[u8] {
    &bytes[off as usize..(off + len) as usize]
}

#[test]
fn the_payload_digest_hashes_the_loader_then_the_data() {
    let (dir, bytes) = (TempDir::new(), fixture());
    let u = Open::new(&file_of(&dir, "u", &bytes));
    let h = &u.0.hdr;
    let want = sha256(
        &[
            part(&bytes, h.loader_insns_off, h.loader_insns_len),
            part(&bytes, h.data_off, h.data_len),
        ]
        .concat(),
    )
    .unwrap();

    assert!(h.data_len > 0);
    assert_eq!(payload_digest(&u.0), Ok(want));
    assert_eq!(h.payload_sha256, want);
}

#[test]
fn a_payload_without_data_hashes_the_loader_alone() {
    let (dir, bytes) = (TempDir::new(), fixture());
    let mut u = Open::new(&file_of(&dir, "u", &bytes));

    u.0.hdr.data_len = 0;
    let h = &u.0.hdr;
    let want = sha256(part(&bytes, h.loader_insns_off, h.loader_insns_len)).unwrap();
    assert_eq!(payload_digest(&u.0), Ok(want));
}

/// verify_fd() of `bytes` against `payload`, the container closed again.
fn verify(dir: &TempDir, bytes: &[u8], payload: &[u8; PAYLOAD_HASH_LEN]) -> c_int {
    let f = file_of(dir, "v", bytes);
    // SAFETY: an all-zero container is a closed one.
    let mut u: Upatch = unsafe { core::mem::zeroed() };
    let ret = verify_fd(f.as_fd(), payload, &mut u);

    if ret == 0 {
        // SAFETY: the container verify_fd() opened, closed once.
        unsafe { upatch_close(&mut u) };
    }
    ret
}

/// The payload the fixture's header names.
fn payload_of(dir: &TempDir, bytes: &[u8]) -> [u8; PAYLOAD_HASH_LEN] {
    Open::new(&file_of(dir, "p", bytes)).0.hdr.payload_sha256
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
    let off = Open::new(&file_of(&dir, "o", &bytes)).0.hdr.data_off as usize;

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
    // SAFETY: an all-zero container is a closed one.
    let mut u: Upatch = unsafe { core::mem::zeroed() };

    assert_eq!(
        archive_verify(ABSENT, &[0; PAYLOAD_HASH_LEN], &mut u),
        -ESTALE
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
    // SAFETY: an all-zero container is a closed one.
    let mut u: Upatch = unsafe { core::mem::zeroed() };

    assert_eq!(
        archive_specs(ABSENT, &[0; PAYLOAD_HASH_LEN], &mut u).err(),
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

    checks_run(core::ptr::null(), &mut c);
    assert_eq!(c.nr_changed + c.nr_lost + c.nr_uncovered, 0);
    assert_eq!((c.check_err, c.coverage_err), (0, 0));
}
