// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-oci-manifest: an image manifest parsed; fuzz-oci-http: a
//! registry's response headers, its auth challenge, upload location and
//! token; fuzz-oci-ref: references and endpoints parsed and made URLs;
//! fuzz-registry-auth: the registry auth file read for an endpoint.

use super::{Client, HttpResponse, auth, copy_string, http, manifest_layers, refs};
use crate::fuzzing::{fuzz_target, input_file};
use crate::sys::libc::PATH_MAX;
use crate::text::cstr;

/// Sets the environment variable, or unsets it for None.
fn env(name: &str, value: Option<&str>) {
    // SAFETY: the environment, which the fuzzer's one thread alone
    // touches.
    unsafe {
        match value {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        }
    }
}

fuzz_target!(
    shirudo_fuzz_oci_manifest,
    shirudo_fuzz_oci_manifest_init,
    |data| {
        let _ = manifest_layers(data, 16, true);
    }
);

fuzz_target!(shirudo_fuzz_oci_http, shirudo_fuzz_oci_http_init, |data| {
    // SAFETY: a response of nothing, for which zeros are the value.
    let mut r: Box<HttpResponse> = Box::new(unsafe { core::mem::zeroed() });
    // Each header line in a buffer of its own, end included, as curl
    // hands the callback one.
    for line in data.split_inclusive(|&b| b == b'\n') {
        let mut line = line.to_vec();
        // SAFETY: the line's bytes and the response, as curl passes them.
        unsafe {
            http::header(
                line.as_mut_ptr().cast(),
                1,
                line.len(),
                (&raw mut *r).cast(),
            )
        };
    }
    let (mut realm, mut service, mut scope) = ([0; PATH_MAX], [0; 256], [0; 512]);
    auth::parse_challenge(cstr(&r.www_auth), &mut realm, &mut service, &mut scope);
    let mut c = Client::new();
    copy_string(&mut c.as_mut().base_url, b"https://registry.example:5000");
    let mut upload = [0; PATH_MAX];
    refs::upload_location(c.as_mut(), cstr(&r.location), &mut upload);
    auth::token_from_body(cstr(data), &mut c.as_mut().token);
});

fn oci_ref_init() {
    // Credentials from here, not from the auth file of whoever runs it.
    env("BPM_OCI_USERNAME", Some("fuzz"));
    env("BPM_OCI_PASSWORD", Some("fuzz"));
    env("BPM_OCI_SCHEME", None);
    env("BPM_OCI_CA_FILE", None);
}

fuzz_target!(
    shirudo_fuzz_oci_ref,
    shirudo_fuzz_oci_ref_init,
    |data| {
        // The input as a C caller's string is, cut at its first NUL.
        let r = cstr(data);
        let mut c = Client::new();
        let _ = c.parse_endpoint(r);
        if let Ok((repo, tag)) = c.parse_pull_ref(r) {
            let _ = c.url(&repo, b"manifests", &tag);
        }
        let _ = c.parse_push_repo(r);
        if let Ok(repo) = c.parse_tree_repo(r) {
            let _ = c.url(&repo, b"blobs", r);
        }
    },
    oci_ref_init
);

fn registry_auth_init() {
    env("BPM_OCI_USERNAME", None);
    env("BPM_OCI_SCHEME", None);
    env("BPM_OCI_CA_FILE", None);
}

fuzz_target!(
    shirudo_fuzz_registry_auth,
    shirudo_fuzz_registry_auth_init,
    |data| {
        let Some(input) = input_file(data) else {
            return;
        };
        env("REGISTRY_AUTH_FILE", Some(&input.path.to_string_lossy()));
        let _ = Client::new().parse_endpoint(b"oci://registry.example:5000");
    },
    registry_auth_init
);
