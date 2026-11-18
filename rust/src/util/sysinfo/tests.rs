// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::testutil::TempDir;
use crate::text::cstr;

const ROOT_LOWER: &str = "a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c";
const ROOT_UPPER: &str = "A3C3F1B0E4C2D7F09E3B6B2A8B1D5E7C4F6A9D0B2C8E1F3A5B7D9C0E2F4A6B8C";
const USR_LOWER: &str = "1d8465c5b17838303fee92b3905420d294d2c22c576a0bdef0f69f190ed22807";

/// The image's id, version and root, each "" where absent.
type Image = (String, String, String);

/// The image of /etc/os-release `etc`, /usr/lib/os-release `usr` and a
/// kernel command line `cmdline`, a file left out where None.
fn image_of(etc: Option<&[u8]>, usr: Option<&[u8]>, cmdline: Option<&[u8]>) -> Image {
    let dir = TempDir::new();
    for (name, text) in [
        ("etc-os-release", etc),
        ("usr-lib-os-release", usr),
        ("cmdline", cmdline),
    ] {
        if let Some(text) = text {
            std::fs::write(dir.join(name), text).unwrap();
        }
    }
    let img = image_read_at(
        &dir.cpath("etc-os-release"),
        &dir.cpath("usr-lib-os-release"),
        &dir.cpath("cmdline"),
    );
    let text = |f: &[u8]| String::from_utf8(cstr(f).to_vec()).unwrap();
    (text(&img.id), text(&img.version), text(&img.root))
}

fn os_release(text: &str) -> Image {
    image_of(Some(text.as_bytes()), None, None)
}

fn cmdline(text: &str) -> String {
    image_of(None, None, Some(text.as_bytes())).2
}

fn id_version(img: Image) -> (String, String) {
    (img.0, img.1)
}

fn pair(id: &str, version: &str) -> (String, String) {
    (id.to_string(), version.to_string())
}

#[test]
fn unquoted_values_are_copied() {
    let img = os_release("NAME=Fleet\nIMAGE_ID=fleet-os\nIMAGE_VERSION=2026.11.1\n");

    assert_eq!(img, ("fleet-os".into(), "2026.11.1".into(), String::new()));
}

#[test]
fn one_pair_of_matching_quotes_is_stripped() {
    assert_eq!(
        id_version(os_release(
            "IMAGE_ID=\"fleet os\"\nIMAGE_VERSION='2026 \"11\"'\n"
        )),
        pair("fleet os", "2026 \"11\"")
    );
    assert_eq!(
        id_version(os_release(
            "IMAGE_ID=\"\"fleet\"\"\nIMAGE_VERSION=\"2026'\n"
        )),
        pair("\"fleet\"", "\"2026'")
    );
}

#[test]
fn double_quotes_drop_the_escaping_backslash() {
    assert_eq!(
        id_version(os_release(
            "IMAGE_ID=\"a\\\"b\\\\c\\$d\\`e\\nf\"\nIMAGE_VERSION='a\\\"b'\n"
        )),
        pair("a\"b\\c$d`e\\nf", "a\\\"b")
    );
    assert_eq!(os_release("IMAGE_ID=a\\\"b\n").0, "a\\\"b");
}

#[test]
fn missing_key_is_absent() {
    assert_eq!(
        id_version(os_release(
            "NAME=Fleet\nXIMAGE_ID=no\nIMAGE_ID_LIKE=no\n#IMAGE_ID=no\nIMAGE_VERSION=7\n"
        )),
        pair("", "7")
    );
    assert_eq!(id_version(image_of(None, None, None)), pair("", ""));
}

#[test]
fn empty_value_is_absent() {
    assert_eq!(
        id_version(os_release("IMAGE_ID=\nIMAGE_VERSION=\"\"\n")),
        pair("", "")
    );
}

#[test]
fn last_assignment_counts() {
    let img = image_of(
        Some(b"IMAGE_ID=first\nIMAGE_ID=second\nIMAGE_VERSION=1\nIMAGE_VERSION=caf\xc3\xa9"),
        None,
        None,
    );

    assert_eq!(id_version(img), pair("second", ""));
}

#[test]
fn usr_lib_is_read_when_etc_does_not_exist() {
    let usr = Some(&b"IMAGE_ID=from-usr\nIMAGE_VERSION=2\n"[..]);

    assert_eq!(id_version(image_of(None, usr, None)), pair("from-usr", "2"));
    assert_eq!(
        id_version(image_of(Some(b"IMAGE_ID=from-etc\n"), usr, None)),
        pair("from-etc", "")
    );
}

#[test]
fn value_longer_than_255_bytes_is_absent() {
    let (longest, too_long) = ("a".repeat(255), "b".repeat(256));

    assert_eq!(
        id_version(os_release(&format!(
            "IMAGE_ID=\"{longest}\"\nIMAGE_VERSION={too_long}\n"
        ))),
        pair(&longest, "")
    );
}

#[test]
fn value_outside_printable_ascii_is_absent() {
    let img = image_of(
        Some(b"IMAGE_ID=caf\xc3\xa9\nIMAGE_VERSION=1\t2\n"),
        None,
        None,
    );

    assert_eq!(id_version(img), pair("", ""));
    assert_eq!(
        id_version(os_release("IMAGE_ID=fleet\r\nIMAGE_VERSION=1\x7f\n")),
        pair("", "")
    );
}

#[test]
fn value_with_a_nul_is_absent() {
    assert_eq!(
        id_version(os_release("IMAGE_ID=fle\0et\nIMAGE_VERSION=3\n")),
        pair("", "3")
    );
}

#[test]
fn roothash_wins_over_usrhash() {
    assert_eq!(
        cmdline(&format!(
            "quiet usrhash={USR_LOWER} roothash={ROOT_LOWER} ro\n"
        )),
        ROOT_LOWER
    );
    assert_eq!(
        cmdline(&format!("roothash={ROOT_LOWER} usrhash={USR_LOWER}\n")),
        ROOT_LOWER
    );
}

#[test]
fn usrhash_is_used_without_roothash() {
    assert_eq!(
        cmdline(&format!(
            "BOOT_IMAGE=/vmlinuz xroothash={ROOT_LOWER}\tusrhash={USR_LOWER}"
        )),
        USR_LOWER
    );
}

#[test]
fn hash_is_normalised_to_lowercase() {
    assert_eq!(cmdline(&format!("roothash={ROOT_UPPER}\n")), ROOT_LOWER);
}

#[test]
fn malformed_hash_is_absent() {
    for bad in [
        "roothash=abc123\n".to_string(),
        format!("roothash={ROOT_LOWER}0\n"),
        format!("roothash=g{USR_LOWER}\n"),
        format!("roothash=\"{ROOT_LOWER}\"\n"),
        format!("roothash=sha256:{ROOT_LOWER}\n"),
    ] {
        assert_eq!(cmdline(&bad), "", "{bad}");
    }
}

#[test]
fn malformed_roothash_does_not_fall_back_to_usrhash() {
    assert_eq!(
        cmdline(&format!("roothash=abc123 usrhash={USR_LOWER}\n")),
        ""
    );
}

#[test]
fn no_hash_is_absent() {
    assert_eq!(cmdline("BOOT_IMAGE=/vmlinuz root=/dev/sda2 ro\n"), "");
    assert_eq!(cmdline(""), "");
    let img = os_release("IMAGE_ID=fleet-os\n");
    assert_eq!((img.0.as_str(), img.2.as_str()), ("fleet-os", ""));
}

#[test]
fn command_line_that_does_not_fit_is_absent() {
    const LEN: usize = 8192 + 128;
    let hash = format!(" roothash={ROOT_LOWER}");

    // The hash at the end of a line too long for the room, terminator
    // included, and at its start.
    let mut at_end = vec![b'x'; LEN - hash.len() - 1];
    at_end.extend_from_slice(hash.as_bytes());
    assert_eq!(image_of(None, None, Some(&at_end)).2, "");
    let mut at_start = vec![b'x'; LEN - 1];
    at_start[..hash.len()].copy_from_slice(format!("roothash={ROOT_LOWER} ").as_bytes());
    assert_eq!(image_of(None, None, Some(&at_start)).2, "");
}
