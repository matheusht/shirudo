// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::errno::EINVAL;

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const MEDIA: &str = r#""mediaType":"application/vnd.shirudo.upatch.v1""#;

/// parse_manifest() of a manifest with `layers`: its result and the
/// count of layers.
fn manifest_of(layers: &str) -> (core::ffi::c_int, core::ffi::c_int) {
    let mut descs = [const { Descriptor::new() }; 4];
    let text = format!(r#"{{"schemaVersion":2,"layers":[{layers}]}}"#);
    let mut n = -1;
    let ret = manifest::parse_manifest(text.as_bytes(), descs.as_mut_ptr(), 4, &mut n, None);

    (ret, n)
}

/// The registry writes the manifest before anything is verified: a layer
/// without its digest or with a negative size would be fetched from an
/// empty URL or skip the size check.
#[test]
fn manifest_layer_is_a_whole_descriptor() {
    let layer = format!(r#"{{{MEDIA},"digest":"{DIGEST}","size":5}}"#);

    assert_eq!(manifest_of(&layer), (0, 1));
    for bad in [
        format!(r#"{{{MEDIA},"size":5}}"#),
        format!(r#"{{{MEDIA},"digest":"sha512:aa","size":5}}"#),
        format!(r#"{{{MEDIA},"digest":"{DIGEST}"}}"#),
        format!(r#"{{{MEDIA},"digest":"{DIGEST}","size":-5}}"#),
        format!(r#"{{"digest":"{DIGEST}","size":5}}"#),
        format!(r#"{layer},{{{MEDIA},"size":5}}"#),
    ] {
        assert_eq!(manifest_of(&bad).0, -EINVAL, "{bad}");
    }
}
