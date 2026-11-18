// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The Beefile, the TOML subset a package is built from: the package,
//! its files, its upatches with their .rodata generators, policy labels
//! and tree entries. Anything the reader cannot read exactly is refused,
//! since a tree selector misread would widen a rollout.

use core::ffi::c_int;
use core::ptr;

use crate::errno::{E2BIG, EEXIST, EINVAL, ENAMETOOLONG};
use crate::text::parse_x64;
use crate::util::bpm_tree::{
    MAX_KCONFIG, MAX_LABELS, MAX_VALUES, STRING_MAX, Text, TreeSelector, TreeSelectorKv,
    tree_selector_free, tree_selector_kv_add,
};
use crate::util::upatch;

/// The most files, and the most upatches, a package holds.
pub(super) const MAX_ENTRIES: usize = 128;
const MAX_RODATA: usize = 16;
pub(super) const MAX_COMMAND_ARGS: usize = 16;
const MAX_POLICIES: usize = 64;
const MAX_POLICY_PATHS: usize = 16;
/// The longest quoted value an array element may be.
const MAX_VALUE: usize = 1024;
const SECTION_MAX: usize = 48;
pub(super) const PATH_MAX: usize = 4096;
const NAME_CAP: usize = 128;
const TYPE_CAP: usize = 16;
const POLICY_ID_CAP: usize = 64;
const SYMBOL_CAP: usize = 128;
const TREE_ID_CAP: usize = upatch::NAME_MAX;
/// `BPM_BUILD_MAX_FIXES`: the IDs one tree entry fixes at most.
pub(super) const MAX_FIXES: usize = 16;

/// An ID a tree entry fixes: one or more of [A-Za-z0-9._:-].
pub(super) fn fix_id_ok(id: &[u8]) -> bool {
    !id.is_empty()
        && id
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-'))
}

/// The `fixes` of an [upatches.tree]: 1 to MAX_FIXES IDs, each once,
/// sorted so that equal Beefiles publish equally.
fn parse_fixes(value: &[u8], fixes: &mut Vec<Vec<u8>>) -> Result<(), c_int> {
    let fail = |msg: String, err: c_int| {
        crate::log::err(msg.as_bytes());
        Err(err)
    };

    if !fixes.is_empty() {
        return fail(
            "Beefile: fixes is given twice in one [upatches.tree]".into(),
            -EINVAL,
        );
    }
    let mut ids = match parse_string_array(value, MAX_FIXES) {
        Ok(ids) => ids,
        Err(err) if err == -E2BIG => {
            return fail(
                format!("Beefile: fixes holds more than {MAX_FIXES} IDs"),
                err,
            );
        }
        Err(err) => {
            return fail(
                format!(
                    "Beefile: fixes is not an array of 1 to {MAX_FIXES} strings of at most {} bytes",
                    STRING_MAX - 1
                ),
                err,
            );
        }
    };
    for (i, id) in ids.iter().enumerate() {
        if id.is_empty() {
            return fail("Beefile: fixes holds an empty ID".into(), -EINVAL);
        }
        if !fix_id_ok(id) {
            return fail(
                format!(
                    "Beefile: ID {} of fixes has a character outside [A-Za-z0-9._:-]",
                    i + 1
                ),
                -EINVAL,
            );
        }
    }
    ids.sort();
    if let Some(w) = ids.windows(2).find(|w| w[0] == w[1]) {
        return fail(
            format!(
                "Beefile: fixes holds {} twice",
                String::from_utf8_lossy(&w[1])
            ),
            -EINVAL,
        );
    }
    *fixes = ids;
    Ok(())
}

pub(super) struct Policy {
    pub(super) id: Vec<u8>,
    pub(super) paths: Vec<Vec<u8>>,
    pub(super) bit: u64,
}

pub(super) struct Rodata {
    pub(super) symbol: Vec<u8>,
    pub(super) input: Vec<u8>,
    pub(super) generator: Vec<Vec<u8>>,
    pub(super) update: Vec<Vec<u8>>,
}

pub(super) struct FileEntry {
    pub(super) source: Vec<u8>,
    pub(super) target: Vec<u8>,
}

/// A tree selector the Beefile spells, freed when it goes.
pub(super) struct Selector(pub(super) Box<TreeSelector>);

impl Selector {
    fn new() -> Self {
        // SAFETY: an all-zero selector is an empty one.
        Selector(Box::new(unsafe { core::mem::zeroed() }))
    }
}

impl Drop for Selector {
    fn drop(&mut self) {
        // SAFETY: the selector, its pairs from tree_selector_kv_add().
        unsafe { tree_selector_free(&mut *self.0) };
    }
}

#[derive(Default)]
pub(super) struct Tree {
    pub(super) present: bool,
    pub(super) id: Vec<u8>,
    pub(super) load_artifact: Vec<u8>,
    pub(super) unload_artifact: Vec<u8>,
    /// What the operation fixes, sorted: IDs the publisher carries
    /// forward and no node reads.
    pub(super) fixes: Vec<Vec<u8>>,
    pub(super) selector: Option<Selector>,
}

#[derive(Default)]
pub(super) struct Upatch {
    pub(super) source: Vec<u8>,
    pub(super) ty: Vec<u8>,
    pub(super) load_target: Vec<u8>,
    pub(super) unload_target: Vec<u8>,
    /// Where the build signs the artifacts, in its stage.
    pub(super) load_path: Vec<u8>,
    pub(super) unload_path: Vec<u8>,
    /// What the signed load artifact says it is.
    pub(super) name: Vec<u8>,
    pub(super) payload_sha256: Vec<u8>,
    pub(super) tree: Tree,
    pub(super) rodata: Vec<Rodata>,
    pub(super) policies: Vec<Policy>,
}

#[derive(Default)]
pub(super) struct Spec {
    pub(super) name: Vec<u8>,
    /// The directory the Beefile is in, which its paths are relative to.
    pub(super) scope: Vec<u8>,
    /// The build's private directory.
    pub(super) stage: Vec<u8>,
    pub(super) build_file: Vec<u8>,
    pub(super) files: Vec<FileEntry>,
    pub(super) upatches: Vec<Upatch>,
}

impl Drop for Spec {
    fn drop(&mut self) {
        for u in self.upatches.iter().filter(|u| !u.load_path.is_empty()) {
            let _ = std::fs::remove_file(super::path(&[&u.load_path[..], b".bpf.o"].concat()));
            let _ = std::fs::remove_file(super::path(&u.load_path));
            let _ = std::fs::remove_file(super::path(&u.unload_path));
        }
        if !self.stage.is_empty() {
            let _ = std::fs::remove_dir_all(super::path(&self.stage));
        }
    }
}

/// isspace() of the C locale.
fn space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn trim(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&c| !space(c)).unwrap_or(s.len());
    let end = s.iter().rposition(|&c| !space(c)).map_or(start, |e| e + 1);
    &s[start..end.max(start)]
}

fn skip_space(s: &[u8]) -> &[u8] {
    &s[s.iter().position(|&c| !space(c)).unwrap_or(s.len())..]
}

/// The line up to a `#` outside a string.
fn strip_comment(s: &[u8]) -> &[u8] {
    let (mut basic, mut literal, mut escaped) = (false, false, false);

    for (i, &c) in s.iter().enumerate() {
        if escaped {
            escaped = false;
        } else if basic && c == b'\\' {
            escaped = true;
        } else if !literal && c == b'"' {
            basic = !basic;
        } else if !basic && c == b'\'' {
            literal = !literal;
        } else if !basic && !literal && c == b'#' {
            return &s[..i];
        }
    }
    s
}

/// One quoted string and nothing after it but blanks; "..." takes the
/// escapes \n \r \t \\ \" and no other, '...' none. At most `cap - 1`
/// bytes.
fn parse_string(value: &[u8], cap: usize) -> Result<Vec<u8>, c_int> {
    let p = skip_space(value);
    let (&quote, mut rest) = p.split_first().ok_or(-EINVAL)?;
    let mut out = Vec::new();

    if quote != b'"' && quote != b'\'' {
        return Err(-EINVAL);
    }
    loop {
        let (&c, tail) = rest.split_first().ok_or(-EINVAL)?;
        rest = tail;
        if c == quote {
            break;
        }
        let c = if c == b'\\' && quote == b'"' {
            let (&e, tail) = rest.split_first().ok_or(-EINVAL)?;
            rest = tail;
            match e {
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'\\' | b'"' => e,
                _ => return Err(-EINVAL),
            }
        } else {
            c
        };
        if out.len() + 1 >= cap {
            return Err(-ENAMETOOLONG);
        }
        out.push(c);
    }
    if !skip_space(rest).is_empty() {
        return Err(-EINVAL);
    }
    Ok(out)
}

/// A string, or with `array_ok` an array whose content is not read.
fn parse_value(value: &[u8], cap: usize, array_ok: bool) -> Result<Vec<u8>, c_int> {
    let p = skip_space(value);

    if array_ok && p.first() == Some(&b'[') {
        let end = p.iter().rposition(|&c| c == b']').ok_or(-EINVAL)?;
        return if skip_space(&p[end + 1..]).is_empty() {
            Ok(Vec::new())
        } else {
            Err(-EINVAL)
        };
    }
    parse_string(value, cap)
}

/// A TOML array of strings, ["a", 'b'], of at most `max`; an empty array
/// is refused, since every selector list is a non-empty set.
fn parse_string_array(value: &[u8], max: usize) -> Result<Vec<Vec<u8>>, c_int> {
    let p = skip_space(value);
    let mut items = Vec::new();

    let mut p = match p.split_first() {
        Some((b'[', rest)) => rest,
        _ => return Err(-EINVAL),
    };
    loop {
        p = skip_space(p);
        match p.first() {
            Some(b']') => break,
            Some(&q) if q == b'"' || q == b'\'' => {
                let mut i = 1;
                while i < p.len() && p[i] != q {
                    if q == b'"' && p[i] == b'\\' && i + 1 < p.len() {
                        i += 1;
                    }
                    i += 1;
                }
                if i >= p.len() {
                    return Err(-EINVAL);
                }
                let item = &p[..=i];
                if item.len() >= MAX_VALUE {
                    return Err(-ENAMETOOLONG);
                }
                if items.len() >= max {
                    return Err(-E2BIG);
                }
                items.push(parse_string(item, STRING_MAX).map_err(|_| -EINVAL)?);
                p = skip_space(&p[i + 1..]);
                match p.split_first() {
                    Some((b',', rest)) => p = rest,
                    Some((b']', _)) => {}
                    _ => return Err(-EINVAL),
                }
            }
            _ => return Err(-EINVAL),
        }
    }
    if !skip_space(&p[1..]).is_empty() || items.is_empty() {
        return Err(-EINVAL);
    }
    Ok(items)
}

fn text(s: &[u8]) -> Text {
    let mut t = [0u8; STRING_MAX];
    t[..s.len()].copy_from_slice(s);
    t
}

/// `key = [...]` of a kconfig or labels table: the key unquoted, unique,
/// and its values.
fn parse_selector_kv(
    key: &[u8],
    value: &[u8],
    selector: &mut Selector,
    kconfig: bool,
) -> Result<(), c_int> {
    let (kvs, n, max) = if kconfig {
        (
            &mut selector.0.kconfig,
            &mut selector.0.n_kconfig,
            MAX_KCONFIG,
        )
    } else {
        (&mut selector.0.labels, &mut selector.0.n_labels, MAX_LABELS)
    };
    let key = match key {
        [q @ (b'"' | b'\''), inner @ .., last] if q == last => inner,
        _ => key,
    };
    if key.is_empty() || key.len() >= STRING_MAX {
        return Err(-EINVAL);
    }
    // SAFETY: the pairs the selector holds.
    let held = unsafe { crate::util::bpm_tree::pairs(*kvs, *n, max) };
    if held.iter().any(|kv| crate::text::cstr(&kv.key) == key) {
        return Err(-EEXIST);
    }
    let mut kv: *mut TreeSelectorKv = ptr::null_mut();
    // SAFETY: the selector's pairs, their count and room for the new one.
    let ret =
        unsafe { tree_selector_kv_add(kvs, n, c_int::try_from(max).map_err(|_| -E2BIG)?, &mut kv) };
    if ret != 0 {
        return Err(ret);
    }
    // SAFETY: the pair just added.
    let kv = unsafe { &mut *kv };
    kv.key = text(key);
    match parse_string_array(value, MAX_VALUES) {
        Ok(values) => {
            for (dst, v) in kv.values.iter_mut().zip(&values) {
                *dst = text(v);
            }
            kv.n_values = c_int::try_from(values.len()).map_err(|_| -E2BIG)?;
            Ok(())
        }
        Err(_) => Err(-EINVAL),
    }
}

/// A TOML bare key, or with `dots` a dotted one of bare keys alone.
fn bare_key(key: &[u8], dots: bool) -> bool {
    let mut part = false;

    for &c in key {
        if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' {
            part = true;
        } else if dots && c == b'.' && part {
            part = false;
        } else {
            return false;
        }
    }
    part
}

/// A package or tree id: 1 to 127 of [A-Za-z0-9._-], starting with a
/// letter or digit.
pub(super) fn name_ok(s: &[u8]) -> bool {
    s.first().is_some_and(u8::is_ascii_alphanumeric)
        && s.len() < NAME_CAP
        && s.iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// A path inside the archive: relative, and every component neither
/// empty, '.' nor '..', as the target's archive reader takes one, or the
/// package would build and never install.
pub(super) fn target_ok(target: &[u8]) -> bool {
    if target.is_empty() || target[0] == b'/' || target.ends_with(b"/") {
        return false;
    }
    target
        .split(|&c| c == b'/')
        .all(|c| !c.is_empty() && c != b"." && c != b"..")
}

/// upatches/<base>.upatch and its .unload.upatch, unless given.
fn default_targets(u: &mut Upatch) -> Result<(), c_int> {
    let src = &u.source;
    let mut base = &src[src.iter().rposition(|&c| c == b'/').map_or(0, |s| s + 1)..];

    if base.len() > 6 && (base.ends_with(b".bpf.c") || base.ends_with(b".bpf.o")) {
        base = &base[..base.len() - 6];
    } else if let Some(dot) = base.iter().rposition(|&c| c == b'.') {
        base = &base[..dot];
    }
    if base.is_empty() {
        return Err(-EINVAL);
    }
    for (target, suffix) in [
        (&mut u.load_target, &b".upatch"[..]),
        (&mut u.unload_target, b".unload.upatch"),
    ] {
        if target.is_empty() {
            let t = [b"upatches/", base, suffix].concat();
            if t.len() >= PATH_MAX {
                return Err(-ENAMETOOLONG);
            }
            *target = t;
        }
    }
    Ok(())
}

/// Where the next key = value line goes.
#[derive(Clone, Copy, PartialEq)]
enum At {
    Nothing,
    File(usize),
    Upatch(usize),
    Rodata(usize, usize),
    Policy(usize, usize),
}

fn set(dst: &mut Vec<u8>, value: &[u8], cap: usize) -> Result<(), c_int> {
    match parse_string(value, cap) {
        Ok(v) => {
            *dst = v;
            Ok(())
        }
        Err(_) => Err(-EINVAL),
    }
}

/// One `[header]` or `[[header]]`.
fn header(
    spec: &mut Spec,
    s: &[u8],
    section: &mut Vec<u8>,
    at: &mut At,
    tree_owner: &mut Option<usize>,
    tree_section: &mut bool,
) -> Result<(), c_int> {
    let array = s.get(1) == Some(&b'[');
    let (start, close): (usize, &[u8]) = if array { (2, b"]]") } else { (1, b"]") };
    let body = &s[start..];
    let Some(end) = body.windows(close.len()).position(|w| w == close) else {
        return Err(-EINVAL);
    };
    if end + close.len() != body.len() {
        return Err(-EINVAL);
    }
    if end >= SECTION_MAX {
        return Err(-ENAMETOOLONG);
    }
    *section = trim(&body[..end]).to_vec();
    // TOML spells [upatches.tree] with blanks or quotes around its parts
    // too: such a header could name a tree table this reader would pass
    // over.
    if !bare_key(section, true) {
        return Err(-EINVAL);
    }
    *at = At::Nothing;
    *tree_section = !array
        && matches!(
            section.as_slice(),
            b"upatches.tree"
                | b"upatches.tree.selector"
                | b"upatches.tree.selector.kconfig"
                | b"upatches.tree.selector.labels"
        );
    match (array, section.as_slice()) {
        (true, b"files") => {
            if spec.files.len() >= MAX_ENTRIES {
                return Err(-E2BIG);
            }
            spec.files.push(FileEntry {
                source: Vec::new(),
                target: Vec::new(),
            });
            *at = At::File(spec.files.len() - 1);
            *tree_owner = None;
        }
        (true, b"upatches") => {
            if spec.upatches.len() >= MAX_ENTRIES {
                return Err(-E2BIG);
            }
            spec.upatches.push(Upatch::default());
            *at = At::Upatch(spec.upatches.len() - 1);
            *tree_owner = Some(spec.upatches.len() - 1);
        }
        (true, b"upatches.rodata") => {
            let Some(o) = tree_owner.filter(|&o| spec.upatches[o].rodata.len() < MAX_RODATA) else {
                return Err(-E2BIG);
            };
            let u = &mut spec.upatches[o];
            u.rodata.push(Rodata {
                symbol: Vec::new(),
                input: Vec::new(),
                generator: Vec::new(),
                update: Vec::new(),
            });
            *at = At::Rodata(o, u.rodata.len() - 1);
        }
        (true, b"upatches.policy") => {
            let Some(o) = tree_owner.filter(|&o| spec.upatches[o].policies.len() < MAX_POLICIES)
            else {
                return Err(-E2BIG);
            };
            let u = &mut spec.upatches[o];
            u.policies.push(Policy {
                id: Vec::new(),
                paths: Vec::new(),
                bit: 0,
            });
            *at = At::Policy(o, u.policies.len() - 1);
        }
        (true, _) => return Err(-EINVAL),
        _ if *tree_section => {
            // The tree tables qualify the preceding [[upatches]].
            let Some(o) = *tree_owner else {
                return Err(-EINVAL);
            };
            let t = &mut spec.upatches[o].tree;
            t.present = true;
            t.selector.get_or_insert_with(Selector::new);
        }
        // A selector the builder cannot read would widen the rollout.
        _ if section.starts_with(b"upatches.tree") => return Err(-EINVAL),
        _ => *tree_owner = None,
    }
    Ok(())
}

/// One `key = value` line.
fn assignment(
    spec: &mut Spec,
    s: &[u8],
    section: &[u8],
    at: At,
    tree_owner: Option<usize>,
    tree_section: bool,
) -> Result<(), c_int> {
    let Some(eq) = s.iter().position(|&c| c == b'=') else {
        return Err(-EINVAL);
    };
    let (key, value) = (trim(&s[..eq]), trim(&s[eq + 1..]));

    if section == b"package" {
        return match key {
            b"name" => set(&mut spec.name, value, NAME_CAP),
            b"description" | b"license" => parse_value(value, MAX_VALUE, false)
                .map(|_| ())
                .map_err(|_| -EINVAL),
            b"authors" => parse_value(value, MAX_VALUE, true)
                .map(|_| ())
                .map_err(|_| -EINVAL),
            _ => Err(-EINVAL),
        };
    }
    match at {
        At::File(i) => {
            let f = &mut spec.files[i];
            match key {
                b"source" => set(&mut f.source, value, PATH_MAX),
                b"target" => set(&mut f.target, value, PATH_MAX),
                _ => Err(-EINVAL),
            }
        }
        At::Upatch(i) => {
            let u = &mut spec.upatches[i];
            match key {
                b"source" => set(&mut u.source, value, PATH_MAX),
                b"type" => set(&mut u.ty, value, TYPE_CAP),
                b"load_target" => set(&mut u.load_target, value, PATH_MAX),
                b"unload_target" => set(&mut u.unload_target, value, PATH_MAX),
                _ => Err(-EINVAL),
            }
        }
        At::Policy(o, j) => {
            let p = &mut spec.upatches[o].policies[j];
            match key {
                b"id" => set(&mut p.id, value, POLICY_ID_CAP),
                b"bit" => {
                    let number = match value {
                        [b'0', b'x' | b'X', rest @ ..] if value.len() > 2 => rest,
                        _ => value,
                    };
                    let bit = parse_x64(number, u64::MAX).unwrap_or(0);
                    if bit == 0 || bit & (bit - 1) != 0 {
                        return Err(-EINVAL);
                    }
                    p.bit = bit;
                    Ok(())
                }
                b"paths" if p.paths.is_empty() => match parse_string_array(value, MAX_POLICY_PATHS)
                {
                    Ok(v) => {
                        p.paths = v;
                        Ok(())
                    }
                    Err(_) => Err(-EINVAL),
                },
                _ => Err(-EINVAL),
            }
        }
        At::Rodata(o, j) => {
            let r = &mut spec.upatches[o].rodata[j];
            let command = |dst: &mut Vec<Vec<u8>>| {
                if !dst.is_empty() {
                    return Err(-EINVAL);
                }
                match parse_string_array(value, MAX_COMMAND_ARGS) {
                    Ok(v) => {
                        *dst = v;
                        Ok(())
                    }
                    Err(_) => Err(-EINVAL),
                }
            };
            match key {
                b"symbol" => set(&mut r.symbol, value, SYMBOL_CAP),
                b"input" => set(&mut r.input, value, PATH_MAX),
                b"generator" => command(&mut r.generator),
                b"update" => command(&mut r.update),
                _ => Err(-EINVAL),
            }
        }
        At::Nothing if tree_section => {
            let Some(o) = tree_owner else {
                return Err(-EINVAL);
            };
            let t = &mut spec.upatches[o].tree;
            match section {
                b"upatches.tree" => {
                    // Unknown tree keys are metadata for newer publishers,
                    // but a dotted key or an inline table would be the
                    // selector spelled another way.
                    if !bare_key(key, false) || key == b"selector" {
                        return Err(-EINVAL);
                    }
                    match key {
                        b"id" => set(&mut t.id, value, TREE_ID_CAP),
                        b"load_artifact" => set(&mut t.load_artifact, value, PATH_MAX),
                        b"unload_artifact" => set(&mut t.unload_artifact, value, PATH_MAX),
                        b"fixes" => parse_fixes(value, &mut t.fixes),
                        _ => Ok(()),
                    }
                }
                b"upatches.tree.selector" => {
                    let Some(sel) = t.selector.as_mut() else {
                        return Err(-EINVAL);
                    };
                    let sel = &mut sel.0;
                    let (dst, n) = match key {
                        b"kernel_release_prefix" => (
                            &mut sel.kernel_release_prefix,
                            &mut sel.n_kernel_release_prefix,
                        ),
                        b"kernel_build_id" => {
                            (&mut sel.kernel_build_id, &mut sel.n_kernel_build_id)
                        }
                        b"architecture" => (&mut sel.architecture, &mut sel.n_architecture),
                        _ => return Err(-EINVAL),
                    };
                    if *n != 0 {
                        return Err(-EINVAL);
                    }
                    match parse_string_array(value, MAX_VALUES) {
                        Ok(v) => {
                            for (d, s) in dst.iter_mut().zip(&v) {
                                *d = text(s);
                            }
                            *n = c_int::try_from(v.len()).map_err(|_| -EINVAL)?;
                            Ok(())
                        }
                        Err(_) => Err(-EINVAL),
                    }
                }
                _ => {
                    let Some(sel) = t.selector.as_mut() else {
                        return Err(-EINVAL);
                    };
                    parse_selector_kv(
                        key,
                        value,
                        sel,
                        section == b"upatches.tree.selector.kconfig",
                    )
                    .map_err(|_| -EINVAL)
                }
            }
        }
        At::Nothing => Ok(()),
    }
}

/// The checks and defaults once every line is read.
fn finish(spec: &mut Spec) -> Result<(), c_int> {
    if !name_ok(&spec.name) {
        return Err(-EINVAL);
    }
    for f in &mut spec.files {
        if f.source.is_empty() {
            return Err(-EINVAL);
        }
        if f.target.is_empty() {
            f.target = f.source.clone();
        }
    }
    for u in &mut spec.upatches {
        if u.source.is_empty() {
            return Err(-EINVAL);
        }
        if u.ty.is_empty() {
            u.ty = b"bpf".to_vec();
        }
        u.ty.make_ascii_lowercase();
        if u.ty != b"bpf" || default_targets(u).is_err() {
            return Err(-EINVAL);
        }
        for r in &u.rodata {
            if r.symbol.is_empty()
                || r.input.is_empty()
                || r.generator.is_empty()
                || r.update.is_empty()
                || r.input[0] == b'/'
                || r.input.windows(3).any(|w| w == b"../")
                || r.input == b".."
            {
                return Err(-EINVAL);
            }
        }
        let t = &mut u.tree;
        if !t.present {
            continue;
        }
        if t.id.is_empty() || !upatch::name_valid(Some(&t.id)) {
            return Err(-EINVAL);
        }
        if t.load_artifact.is_empty() {
            t.load_artifact = u.load_target.clone();
        }
        if t.unload_artifact.is_empty() {
            t.unload_artifact = u.unload_target.clone();
        }
        if !target_ok(&t.load_artifact) || !target_ok(&t.unload_artifact) {
            return Err(-EINVAL);
        }
    }
    Ok(())
}

/// The parsed Beefile, including the bytes to put in the archive.
pub(super) fn parse(body: &[u8]) -> Result<Spec, c_int> {
    if body.contains(&0) {
        return Err(-EINVAL);
    }
    let mut spec = Spec::default();
    spec.build_file = body.to_vec();
    let mut section = Vec::new();
    let (mut at, mut tree_owner, mut tree_section) = (At::Nothing, None, false);

    for line in body.split(|&c| c == b'\n').filter(|l| !l.is_empty()) {
        let s = trim(strip_comment(line));
        if s.is_empty() {
            continue;
        }
        if s[0] == b'[' {
            header(
                &mut spec,
                s,
                &mut section,
                &mut at,
                &mut tree_owner,
                &mut tree_section,
            )?;
        } else {
            assignment(&mut spec, s, &section, at, tree_owner, tree_section)?;
        }
    }
    finish(&mut spec)?;
    Ok(spec)
}

#[cfg(shirudo_fuzz)]
mod fuzz;
