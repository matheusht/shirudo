// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The order of package versions: SemVer 2.0.0 precedence, and a total
//! order over the versions it does not describe.

use core::cmp::Ordering;
use core::ffi::c_int;

use crate::text::{at, digits, parse_u64};

struct Semver<'a> {
    core: [u64; 3],
    /// The pre-release, empty when there is none.
    pre: &'a [u8],
}

/// SemVer 2.0.0, 9 and 10: identifiers of [0-9A-Za-z-], dot-separated.
fn identifiers(s: &[u8], prerelease: bool) -> bool {
    let len = s.len();
    let mut i = 0;

    while i < len {
        let mut n = 0;

        while i + n < len && s[i + n] != b'.' {
            if !s[i + n].is_ascii_alphanumeric() && s[i + n] != b'-' {
                return false;
            }
            n += 1;
        }
        if n == 0 || (prerelease && n > 1 && s[i] == b'0' && digits(&s[i..i + n]) == n) {
            return false;
        }
        i += n;
        if i < len {
            i += 1;
            if i == len {
                return false;
            }
        }
    }
    len > 0
}

fn parse(s: &[u8]) -> Option<Semver<'_>> {
    let mut v = Semver {
        core: [0; 3],
        pre: &[],
    };
    let mut p = 0;

    for i in 0..3 {
        let rest = &s[p..];
        let n = digits(rest);

        if n == 0 || (n > 1 && rest[0] == b'0') {
            return None;
        }
        v.core[i] = parse_u64(&rest[..n], u64::MAX).ok()?;
        p += n;
        if i < 2 {
            if at(s, p) != b'.' {
                return None;
            }
            p += 1;
        }
    }
    if at(s, p) == b'-' {
        let rest = &s[p + 1..];
        let n = rest.iter().position(|&c| c == b'+').unwrap_or(rest.len());

        if !identifiers(&rest[..n], true) {
            return None;
        }
        v.pre = &rest[..n];
        p += 1 + n;
    }
    if at(s, p) == b'+' {
        let rest = &s[p + 1..];

        if !identifiers(rest, false) {
            return None;
        }
        p += 1 + rest.len();
    }
    (p == s.len()).then_some(v)
}

/// The length of the identifier `s` starts with.
fn ident_len(s: &[u8]) -> usize {
    s.iter().position(|&c| c == b'.').unwrap_or(s.len())
}

/// SemVer 2.0.0, 11.4: identifiers left to right, numeric ones by value
/// and below alphanumeric ones, a longer list after a shorter equal one.
fn prerelease_compare(mut a: &[u8], mut b: &[u8]) -> Ordering {
    while !a.is_empty() && !b.is_empty() {
        let (na, nb) = (ident_len(a), ident_len(b));
        let (ia, ib) = (&a[..na], &b[..nb]);
        let numa = digits(ia) == na;
        let numb = digits(ib) == nb;
        let c = match (numa, numb) {
            (true, true) => na.cmp(&nb).then_with(|| ia.cmp(ib)),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => ia.cmp(ib),
        };

        if c != Ordering::Equal {
            return c;
        }
        a = &a[na..];
        b = &b[nb..];
        if !a.is_empty() {
            a = &a[1..];
        }
        if !b.is_empty() {
            b = &b[1..];
        }
    }
    a.len().min(1).cmp(&b.len().min(1))
}

/// Whether `s` is a SemVer 2.0.0 version.
pub(super) fn valid(s: &[u8]) -> bool {
    parse(s).is_some()
}

/// SemVer 2.0.0 precedence, build metadata ignored. A version it does not
/// describe sorts below every one it does, and such versions sort among
/// themselves by their bytes, so that the order stays total over every
/// version `bpm_version_ok()` lets through.
pub(super) fn compare(a: &[u8], b: &[u8]) -> c_int {
    let (va, vb) = match (parse(a), parse(b)) {
        (Some(va), Some(vb)) => (va, vb),
        (Some(_), None) => return 1,
        (None, Some(_)) => return -1,
        (None, None) => return sign(a.cmp(b)),
    };

    for (ca, cb) in va.core.iter().zip(vb.core.iter()) {
        if ca != cb {
            return sign(ca.cmp(cb));
        }
    }
    if va.pre.is_empty() || vb.pre.is_empty() {
        // A pre-release sorts below its release.
        return sign(vb.pre.len().min(1).cmp(&va.pre.len().min(1)));
    }
    sign(prerelease_compare(va.pre, vb.pre))
}

fn sign(o: Ordering) -> c_int {
    match o {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}
