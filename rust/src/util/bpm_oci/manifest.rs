// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Manifests: the layers of one as a registry wrote them, and a
//! descriptor as shirudo writes one.

use core::ffi::{c_int, c_void};

use super::{Descriptor, MAX_DIGEST, MAX_MEDIA, MAX_NAME, PATH_MAX, copy_string, cstr};
use crate::errno::{E2BIG, EINVAL};
use crate::util::hex::sha256_digest_decode;
use crate::util::json::{JsonArray, JsonEmit, JsonField, parse_schema};

/// Where the layers go, and the scratch descriptor the schema fills for
/// each before `on_descriptor()` takes it.
struct DescSink {
    items: *mut Descriptor,
    n: c_int,
    max: c_int,
    scratch: Descriptor,
    package_name: [u8; MAX_NAME],
}

unsafe extern "C" fn on_descriptor(ud: *mut c_void) -> c_int {
    let s = ud.cast::<DescSink>();
    let mut digest = [0u8; 32];

    // SAFETY: the sink parse_manifest() made the array's context, read
    // and written through this pointer alone, as the parser writes the
    // scratch descriptor through its own and is not running now.
    unsafe {
        if (*s).n >= (*s).max {
            return -E2BIG;
        }
        // The registry wrote this: a layer is all three or none.
        if (*s).scratch.media[0] == 0
            || (*s).scratch.size < 0
            || sha256_digest_decode((&raw const (*s).scratch.digest).cast(), digest.as_mut_ptr())
                != 0
        {
            return -EINVAL;
        }
        (*s).items.add((*s).n as usize).write((*s).scratch);
        (*s).n += 1;
        (*s).scratch = Descriptor::new();
        (*s).scratch.size = -1;
    }
    0
}

/// The layers of an image manifest of schema 2, as many as `layers`
/// has room for, into it, and the package name its annotations give.
pub(crate) fn parse_manifest(
    body: &[u8],
    layers: &mut [Descriptor],
    n_layers: &mut c_int,
    package_name: Option<&mut [u8]>,
) -> c_int {
    let mut sink = DescSink {
        items: layers.as_mut_ptr(),
        n: 0,
        max: c_int::try_from(layers.len()).unwrap_or(c_int::MAX),
        scratch: Descriptor::new(),
        package_name: [0; MAX_NAME],
    };
    let mut schema = 0i64;

    sink.scratch.size = -1;
    let mut arr = JsonArray::new(on_descriptor, (&raw mut sink).cast());
    let mut layer_annotations = [JsonField::string(
        c"org.opencontainers.image.title",
        (&raw mut sink.scratch.title).cast(),
        PATH_MAX,
    )];
    let mut sub = [
        JsonField::string(
            c"mediaType",
            (&raw mut sink.scratch.media).cast(),
            MAX_MEDIA,
        ),
        JsonField::string(c"digest", (&raw mut sink.scratch.digest).cast(), MAX_DIGEST),
        JsonField::int(c"size", &raw mut sink.scratch.size),
        JsonField::object(
            c"annotations",
            layer_annotations.as_mut_ptr(),
            layer_annotations.len(),
        ),
    ];
    let mut manifest_annotations = [JsonField::string(
        c"dev.shirudo.bpm.package.name",
        (&raw mut sink.package_name).cast(),
        MAX_NAME,
    )];
    let mut root = [
        JsonField::int(c"schemaVersion", &raw mut schema),
        JsonField::array(c"layers", &raw mut arr, sub.as_mut_ptr(), sub.len()),
        JsonField::object(
            c"annotations",
            manifest_annotations.as_mut_ptr(),
            manifest_annotations.len(),
        ),
    ];
    // SAFETY: every pointer of the schema names a local of this frame,
    // which outlives the parse and is touched meanwhile only through
    // those pointers and the sink's.
    let ret = unsafe { parse_schema(body, root.as_mut_ptr(), root.len()) };

    if ret != 0 || !root[0].seen() || schema != 2 || !root[1].seen() {
        return -EINVAL;
    }
    *n_layers = sink.n;
    if let Some(name) = package_name {
        copy_string(name, cstr(&sink.package_name));
    }
    0
}

pub(crate) fn emit_descriptor(
    e: &mut JsonEmit,
    key: Option<&[u8]>,
    d: &Descriptor,
    title: Option<&[u8]>,
) {
    match key {
        Some(key) => e.obj_open_key(key),
        None => e.obj_open(),
    }
    e.kv_string(b"mediaType", cstr(&d.media));
    e.kv_string(b"digest", cstr(&d.digest));
    e.kv_int(b"size", d.size);
    if let Some(title) = title {
        e.obj_open_key(b"annotations");
        e.kv_string(b"org.opencontainers.image.title", title);
        e.obj_close();
    }
    e.obj_close();
}
