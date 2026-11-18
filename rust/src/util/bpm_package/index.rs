// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The signed index of a repository: the packages it offers.

use core::ffi::{c_int, c_void};

use super::IndexEntry;
use crate::errno::{E2BIG, EINVAL};
use crate::text::cstr;
use crate::util::bpm_oci::{MAX_DIGEST, MAX_ENDPOINT, MAX_NAME, name_ok, version_ok};
use crate::util::json::{JsonArray, JsonField, parse_schema};

/// Where the entries go, and the scratch entry the schema fills for each
/// before `on_index_entry()` takes it.
struct IndexSink {
    items: *mut IndexEntry,
    n: usize,
    max: usize,
    scratch: IndexEntry,
}

unsafe extern "C" fn on_index_entry(ud: *mut c_void) -> c_int {
    let s = ud.cast::<IndexSink>();

    // SAFETY: the sink index_parse() made the array's context, read and
    // written through this pointer alone, as the parser writes the
    // scratch entry through its own and is not running now; items has
    // room for max entries.
    unsafe {
        if (*s).n >= (*s).max {
            return -E2BIG;
        }
        let e = (*s).scratch;

        if !name_ok(cstr(&e.name))
            || !version_ok(cstr(&e.version))
            || e.repository[0] == 0
            || e.manifest_digest[0] == 0
            || e.package_digest[0] == 0
            || e.package_size <= 0
        {
            return -EINVAL;
        }
        (*s).items.add((*s).n).write(e);
        (*s).n += 1;
        // A field the next entry leaves out is not this entry's.
        (*s).scratch = IndexEntry::new();
        (*s).scratch.package_size = -1;
    }
    0
}

/// The entries of an index of schema 1, as many as `entries` has room
/// for, into it, and how many there are.
pub(super) fn index_parse(body: &[u8], entries: &mut [IndexEntry], n_entries: &mut c_int) -> c_int {
    let mut sink = IndexSink {
        items: entries.as_mut_ptr(),
        n: 0,
        max: entries.len(),
        scratch: IndexEntry::new(),
    };
    let mut schema = 0i64;

    // Missing from the first entry as from any other, not 0.
    sink.scratch.package_size = -1;
    let mut arr = JsonArray::new(on_index_entry, (&raw mut sink).cast());
    let mut sub = [
        JsonField::string(c"name", (&raw mut sink.scratch.name).cast(), MAX_NAME),
        JsonField::string(c"version", (&raw mut sink.scratch.version).cast(), MAX_NAME),
        JsonField::string(
            c"repository",
            (&raw mut sink.scratch.repository).cast(),
            MAX_ENDPOINT,
        ),
        JsonField::string(
            c"manifest_digest",
            (&raw mut sink.scratch.manifest_digest).cast(),
            MAX_DIGEST,
        ),
        JsonField::string(
            c"package_digest",
            (&raw mut sink.scratch.package_digest).cast(),
            MAX_DIGEST,
        ),
        JsonField::string(
            c"signer_fingerprint",
            (&raw mut sink.scratch.signer).cast(),
            MAX_DIGEST,
        ),
        JsonField::int(c"package_size", &raw mut sink.scratch.package_size),
    ];
    let mut root = [
        JsonField::int(c"schema", &raw mut schema),
        JsonField::array(c"packages", &raw mut arr, sub.as_mut_ptr(), sub.len()),
    ];
    // SAFETY: every pointer of the schema names a local of this frame,
    // which outlives the parse and is touched meanwhile only through
    // those pointers and the sink's.
    let ret = unsafe { parse_schema(body, root.as_mut_ptr(), root.len()) };

    if ret != 0 || schema != 1 || !root[1].seen() {
        return -EINVAL;
    }
    *n_entries = sink.n as c_int;
    0
}
