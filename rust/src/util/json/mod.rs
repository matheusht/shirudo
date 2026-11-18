// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The JSON emitter and schema parser behind `util/json.h`; the parser
//! dispatches declared keys and parses and discards the rest.

mod emit;
mod parse;

pub(crate) use emit::JsonEmit;
pub(crate) use parse::{JsonArray, JsonField, JsonMap, parse_schema};

/// `JSON_MAX_BYTES`: the largest document either reader takes.
pub(crate) const MAX_BYTES: usize = 8 * 1024 * 1024;
/// `JSON_MAX_DEPTH`: the deepest nesting either reader takes.
const MAX_DEPTH: u32 = 32;
/// `JSON_MAX_FIELDS`: the most declared keys one object tells apart.
const MAX_FIELDS: usize = 64;
/// `JSON_MAX_STRING_BYTES`: the longest decoded string.
const MAX_STRING_BYTES: usize = 16 * 1024 * 1024;
/// `JSON_EMIT_MAX_DEPTH`: an OTLP AnyValue nests four levels for each
/// level of a decoder table.
const EMIT_MAX_DEPTH: u32 = 192;

/// The width of the well-formed UTF-8 character `s` starts with, or 0,
/// as `utf8_width()` gives it.
fn utf8_width(s: &[u8]) -> usize {
    let Some(&lead) = s.first() else {
        return 0;
    };
    let width = match lead {
        0x00..=0x7f => return 1,
        _ if lead & 0xe0 == 0xc0 => 2,
        _ if lead & 0xf0 == 0xe0 => 3,
        _ if lead & 0xf8 == 0xf0 => 4,
        _ => return 0,
    };

    match s.get(..width) {
        Some(char) if core::str::from_utf8(char).is_ok() => width,
        _ => 0,
    }
}
