// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::errno::ENOTDIR;
use crate::testutil::TempDir;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd};

/// A log of `text` in `dir`, open to append to.
fn log_with(dir: &TempDir, text: &[u8]) -> File {
    let mut f = OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(true)
        .open(dir.join("log"))
        .unwrap();

    f.write_all(text).unwrap();
    f
}

/// What the log holds.
fn log_of(dir: &TempDir) -> Vec<u8> {
    std::fs::read(dir.join("log")).unwrap()
}

/// append_line() of `line` to the log `f`.
fn append(f: &File, line: &[u8]) -> Result<(), c_int> {
    append_line(f.as_fd(), c"log", line)
}

#[test]
fn append_line_adds_one_record() {
    let dir = TempDir::new();
    let f = log_with(&dir, b"");

    assert_eq!(append(&f, b"x"), Ok(()));
    assert_eq!(append(&f, b"y\n"), Ok(()));
    assert_eq!(log_of(&dir), b"x\ny\n");
}

/// A record killed before its newline would run into the next one on
/// its line, and every reader after would refuse the log.
#[test]
fn append_line_drops_what_did_not_finish() {
    let long = [&b"x\n"[..], &[b'a'; 11998]].concat();

    for (text, want) in [
        (&b"x\n{\"half\":"[..], &b"x\nz\n"[..]),
        (b"{\"whole\":1}", b"z\n"),
        (&long, b"x\nz\n"),
    ] {
        let dir = TempDir::new();
        let f = log_with(&dir, text);

        assert_eq!(append(&f, b"z"), Ok(()));
        assert_eq!(log_of(&dir), want);
    }
}

#[test]
fn append_line_takes_one_line_alone() {
    let dir = TempDir::new();
    let f = log_with(&dir, b"x\n");

    assert_eq!(append(&f, b"a\nb"), Err(-EINVAL));
    assert_eq!(append(&f, b"a\0b"), Err(-EINVAL));
    assert_eq!(log_of(&dir), b"x\n");
}

#[test]
fn lock_exclusive_keeps_others_out() {
    let dir = TempDir::new();
    let f = log_with(&dir, b"");
    let other = File::open(dir.join("log")).unwrap();

    assert_eq!(lock_exclusive(f.as_fd()), Ok(()));
    // SAFETY: an open descriptor.
    let ret = unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(ret, -1);
    assert_eq!(errno(), libc::EWOULDBLOCK);
    drop(f);
    assert_eq!(lock_exclusive(other.as_fd()), Ok(()));
}

#[test]
fn kernel_dev_is_major_over_20_minor_bits() {
    assert_eq!(kernel_dev(libc::makedev(8, 1)), 0x800001);
    assert_eq!(kernel_dev(libc::makedev(253, 0x12345)), 253 << 20 | 0x12345);
    assert_eq!(kernel_dev(libc::makedev(0xfff, 0xfffff)), 0xffffffff);
}

#[test]
fn bpffs_mounted_at_wants_the_root_of_a_bpffs() {
    let dir = TempDir::new();
    let mounted = |path: &CStr| {
        // SAFETY: a C string.
        unsafe { bpffs_mounted_at(path.as_ptr()) }
    };

    assert_eq!(mounted(&dir.cpath("")), 0);
    assert_eq!(mounted(c"/"), 0);
    assert_eq!(mounted(c"/nonexistent/shirudo"), 0);
    assert_eq!(mounted(c"/dev/null"), -ENOTDIR);
}

#[test]
fn dir_names_at_reads_as_dir_names_does() {
    let dir = TempDir::new();
    for name in ["b.der", "a.der", ".der", "c.vouch", "Z.der"] {
        File::create(dir.join(name)).unwrap();
    }
    std::fs::create_dir(dir.join("d.der")).unwrap();
    let is_der = |n: &[u8]| crate::text::name_has_suffix(n, b".der");
    let open = File::open(dir.join("")).unwrap();
    let names = dir_names_at(open.as_fd(), is_der).unwrap();

    assert_eq!(names, [&b"Z.der"[..], b"a.der", b"b.der", b"d.der"]);
    assert_eq!(
        dir_names(dir.join("").as_os_str().as_encoded_bytes(), is_der),
        Ok(names)
    );
    assert_eq!(
        dir_names_at(File::open("/dev/null").unwrap().as_fd(), is_der),
        Err(-ENOTDIR)
    );
}
