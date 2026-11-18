// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-oci-manifest: an image manifest parsed; fuzz-oci-http: a
//! registry's response headers, its auth challenge, upload location and
//! token; fuzz-oci-ref: references and endpoints parsed and made URLs;
//! fuzz-registry-auth: the registry auth file read for an endpoint.

use core::ffi::{c_char, c_void};

use super::capi::{
    bpm_copy_string, bpm_oci_header, bpm_oci_parse_challenge, bpm_oci_parse_endpoint,
    bpm_oci_parse_manifest, bpm_oci_parse_pull_ref, bpm_oci_parse_push_repo,
    bpm_oci_parse_tree_repo, bpm_oci_token_from_body, bpm_oci_upload_location, bpm_oci_url,
};
use super::{Descriptor, HttpResponse, MAX_ENDPOINT, MAX_NAME, OciClient};
use crate::fuzzing::{fuzz_target, input_file};

const PATH_MAX: usize = 4096;

/// A client of nothing, as `= {}` makes one.
fn client() -> Box<OciClient> {
    // SAFETY: arrays and a TLS setting of nothing, for which zeros are
    // the value.
    Box::new(unsafe { core::mem::zeroed() })
}

/// The input as a C string, cut at its first NUL as a C caller's is.
fn c_string(data: &[u8]) -> Vec<u8> {
    [data, b"\0"].concat()
}

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
        // SAFETY: descriptors of nothing, for which zeros are the value.
        let mut layers: [Descriptor; 16] = unsafe { core::mem::zeroed() };
        let mut name = [0 as c_char; MAX_NAME];
        let mut n = 0;
        // SAFETY: the input, and rooms for the layers, their count and the
        // name.
        unsafe {
            bpm_oci_parse_manifest(
                data.as_ptr(),
                data.len(),
                layers.as_mut_ptr(),
                16,
                &mut n,
                name.as_mut_ptr(),
                name.len(),
            )
        };
    }
);

fuzz_target!(shirudo_fuzz_oci_http, shirudo_fuzz_oci_http_init, |data| {
    // SAFETY: a response of nothing, for which zeros are the value.
    let mut r: Box<HttpResponse> = Box::new(unsafe { core::mem::zeroed() });
    let (mut realm, mut service, mut scope) = (
        [0 as c_char; PATH_MAX],
        [0 as c_char; 256],
        [0 as c_char; 512],
    );
    let mut upload = [0 as c_char; PATH_MAX];
    let mut c = client();
    let body = c_string(data);
    // SAFETY: each header line in a buffer of its own, as curl hands the
    // callback one, end included; the response's C strings and rooms of
    // their sizes.
    unsafe {
        for line in data.split_inclusive(|&b| b == b'\n') {
            let mut line = line.to_vec();
            bpm_oci_header(
                line.as_mut_ptr().cast(),
                1,
                line.len(),
                (&raw mut *r).cast::<c_void>(),
            );
        }
        bpm_oci_parse_challenge(
            r.www_auth.as_ptr().cast(),
            realm.as_mut_ptr(),
            realm.len(),
            service.as_mut_ptr(),
            service.len(),
            scope.as_mut_ptr(),
            scope.len(),
        );
        bpm_copy_string(
            c.base_url.as_mut_ptr().cast(),
            c.base_url.len(),
            c"https://registry.example:5000".as_ptr(),
        );
        bpm_oci_upload_location(
            &*c,
            r.location.as_ptr().cast(),
            upload.as_mut_ptr(),
            upload.len(),
        );
        bpm_oci_token_from_body(
            body.as_ptr().cast(),
            c.token.as_mut_ptr().cast(),
            c.token.len(),
        );
    }
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
        let reference = c_string(data);
        let r = reference.as_ptr().cast::<c_char>();
        let (mut repo, mut tag, mut url) = (
            [0 as c_char; MAX_ENDPOINT],
            [0 as c_char; MAX_NAME],
            [0 as c_char; PATH_MAX],
        );
        let mut c = client();
        // SAFETY: the reference as a C string, the client, and rooms of
        // their sizes.
        unsafe {
            bpm_oci_parse_endpoint(r, &mut *c);
            if bpm_oci_parse_pull_ref(
                r,
                &mut *c,
                repo.as_mut_ptr(),
                repo.len(),
                tag.as_mut_ptr(),
                tag.len(),
            ) == 0
            {
                bpm_oci_url(
                    &*c,
                    repo.as_ptr(),
                    c"manifests".as_ptr(),
                    tag.as_ptr(),
                    url.as_mut_ptr(),
                    url.len(),
                );
            }
            bpm_oci_parse_push_repo(r, &mut *c, repo.as_mut_ptr(), repo.len());
            if bpm_oci_parse_tree_repo(r, &mut *c, repo.as_mut_ptr(), repo.len()) == 0 {
                bpm_oci_url(
                    &*c,
                    repo.as_ptr(),
                    c"blobs".as_ptr(),
                    r,
                    url.as_mut_ptr(),
                    url.len(),
                );
            }
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
        let mut c = client();
        // SAFETY: a C string and the client to fill.
        unsafe { bpm_oci_parse_endpoint(c"oci://registry.example:5000".as_ptr(), &mut *c) };
    },
    registry_auth_init
);
