// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-bpm-source: the lines of a target's BPM source and upatch tree
//! configuration, parsed as bpm reads them.

use core::ffi::{CStr, c_int};

use super::{helper_main, out};
use crate::errno::{E2BIG, EINVAL};
use crate::text::cstr;
use crate::util::bpm_source_config::{parse_source_line, parse_tree_line};

helper_main!(shirudo_helper_test_bpm_source, run);

/// `text` as the NUL-terminated line a parse takes and changes.
fn line(text: &str) -> Vec<u8> {
    [text.as_bytes(), b"\0"].concat()
}

fn s(field: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(cstr(field))
}

fn run(_: &[&CStr]) -> c_int {
    let (mut endpoint, mut index_repository, mut key_file) = ([0u8; 512], [0u8; 512], [0u8; 256]);
    let mut reference = [0u8; 80];
    let source = |text: &str, endpoint: &mut [u8], index: &mut [u8], key: &mut [u8]| {
        parse_source_line(&mut line(text), endpoint, index, key)
    };

    for text in [
        "endpoint = oci://registry.test:5443\n",
        "index_repository = team/bpm-index\n",
        "key_file = /etc/shirudo/bpm/keys/jbrust.pem\n",
    ] {
        if source(text, &mut endpoint, &mut index_repository, &mut key_file) != 0 {
            return 1;
        }
    }
    if cstr(&endpoint) != b"oci://registry.test:5443"
        || cstr(&index_repository) != b"team/bpm-index"
        || cstr(&key_file) != b"/etc/shirudo/bpm/keys/jbrust.pem"
    {
        return 1;
    }
    out(&format!(
        "endpoint={}\nindex_repository={}\nkey_file={}\n",
        s(&endpoint),
        s(&index_repository),
        s(&key_file)
    ));
    let tree = |text: &str, endpoint: &mut [u8], reference: &mut [u8]| {
        parse_tree_line(&mut line(text), endpoint, reference)
    };
    if tree(
        " endpoint=\"oci://registry.test/tree\"\n",
        &mut endpoint,
        &mut reference,
    ) != 0
        || tree("reference = sha256:feed\r\n", &mut endpoint, &mut reference) != 0
        || tree("reference = \"sha256:feed\n", &mut endpoint, &mut reference) != -EINVAL
    {
        return 1;
    }
    out(&format!(
        "tree endpoint={}\ntree reference={}\n",
        s(&endpoint),
        s(&reference)
    ));
    // A value that does not fit is refused, not cut.
    let long_reference = format!("reference = sha256:{}\n", "0".repeat(reference.len()));
    if tree(&long_reference, &mut endpoint, &mut reference) != -E2BIG {
        return 1;
    }
    let long_key = format!("key_file = /{}\n", "0".repeat(key_file.len()));
    c_int::from(
        source(
            &long_key,
            &mut endpoint,
            &mut index_repository,
            &mut key_file,
        ) != -E2BIG,
    )
}
