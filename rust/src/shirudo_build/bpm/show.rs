// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `bpm tree show`: a tree publication, or with --walk every segment of
//! it oldest first, verified as a node verifies it and printed with its
//! document's bytes verbatim. The publisher fetches the sealed segments
//! of a tree through it too.

use core::ffi::{CStr, c_int};
use std::io::Write;

use crate::errno::{EINVAL, EIO, EKEYREJECTED};
use crate::text::cstr;
use crate::util::bpm_oci::Client;
use crate::util::bpm_package::fetch_document;
use crate::util::bpm_tree::{
    MAX_JOIN_OPS, Publication, TreePublication, digest_bytes, publication_verify, segment_precedes,
    tree_parse, walk_within,
};
use crate::util::help::Help;
use crate::util::hex::sha256_digest_encode;
use crate::util::json::{JsonEmit, MAX_BYTES};
use crate::util::keys::{TrustedSet, load_image_at};
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};

const SHOW_CERT: c_int = 0;
const SHOW_REFERENCE: c_int = 1;
const SHOW_WALK: c_int = 2;

static SHOW_OPTS: [OptSpec; 3] = [
    OptSpec::new(
        c"--cert",
        0,
        0,
        Some(c"<cert.der>"),
        c"the certificate the tree is signed for",
    ),
    OptSpec::new(
        c"--reference",
        0,
        0,
        Some(c"<ref>"),
        c"the tag of the publication (default stable)",
    ),
    OptSpec::new(
        c"--walk",
        0,
        0,
        None,
        c"print every segment, oldest first, back from the one the reference names",
    ),
];

static SHOW_SECTIONS: [crate::util::help::HelpSection; 1] =
    [crate::util::help::HelpSection::options(
        c"options:",
        &SHOW_OPTS,
    )];

static SHOW_HELP: Help = Help::new(
    c"shirudo bpm tree show <repository> --cert <cert.der> [--reference <ref>] [--walk]",
    Some(
        c"Fetch the tree publication at <repository>:<ref>, verify it against the\n\
          certificate as tree sync does, and print\n\
          {\"manifest_digest\":\"sha256:<hex>\",\"document\":<document>} with the document's\n\
          bytes verbatim, then a newline.",
    ),
    &SHOW_SECTIONS,
    None,
);

fn error(msg: String) {
    crate::log::err(msg.as_bytes());
}

pub(super) fn strerr(err: c_int) -> String {
    // SAFETY: strerror() gives a C string.
    String::from_utf8_lossy(unsafe { crate::ffi::c_str(crate::sys::libc::strerror(err)) })
        .into_owned()
}

/// What the node's signer is: a certificate's path, or a set.
#[derive(Clone, Copy)]
pub(super) enum Signer<'a> {
    Cert(&'a CStr),
    Set(&'a TrustedSet),
}

/// The publication at `reference`, a tag or a manifest digest, checked
/// against the signer as tree sync checks it and parsed into `p`, with
/// its manifest's digest and, when asked, its checked bytes.
pub(super) fn fetch_checked(
    c: &mut Client,
    repository: &[u8],
    reference: &[u8],
    signer: Signer<'_>,
    p: &mut TreePublication,
    keep: bool,
) -> Result<(Vec<u8>, Option<Vec<u8>>), c_int> {
    let (cert, set) = match signer {
        Signer::Cert(c) => (Some(c), None),
        Signer::Set(s) => (None, Some(s)),
    };
    let (document, digest) = fetch_document(c, repository, reference, cert, set)?;
    // SAFETY: the document's bytes, and the caller's publication.
    match unsafe { tree_parse(document.as_ptr().cast(), document.len(), p) } {
        0 => {}
        err => return Err(err),
    }
    // SAFETY: the publication the parse filled.
    unsafe { publication_verify(p) }.map_err(|(err, _)| err)?;
    Ok((digest, keep.then_some(document)))
}

/// The sealed segment `succ` names, as a node walking back fetches it:
/// by digest, checked, and the one that ends where `succ` starts.
pub(super) fn fetch_sealed(
    c: &mut Client,
    repository: &[u8],
    signer: Signer<'_>,
    succ: &TreePublication,
    pred: &mut TreePublication,
) -> Result<Vec<u8>, c_int> {
    let (digest, _) = fetch_checked(
        c,
        repository,
        cstr(&succ.segment_manifest_digest),
        signer,
        pred,
        false,
    )?;
    match segment_precedes(pred, &digest, succ) {
        0 => Ok(digest),
        err => Err(err),
    }
}

fn print(manifest_digest: &[u8], document: &[u8]) -> c_int {
    let mut e = JsonEmit::growing(MAX_BYTES * 2);

    e.obj_open();
    e.kv_string(b"manifest_digest", manifest_digest);
    e.kv_raw(b"document", document);
    e.obj_close();
    match e.err() {
        0 => {
            let out = e.output();
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(out)
                .and_then(|()| stdout.write_all(b"\n"))
                .and_then(|()| stdout.flush())
                .map_or_else(|e| -e.raw_os_error().unwrap_or(EIO), |()| 0)
        }
        err => err,
    }
}

/// Back from `tag` to the segment at base seq 0, each sealed segment
/// fetched by the digest its successor names and checked as the one it
/// names: their manifest digests, newest first. Only these are kept; the
/// printing pass fetches each segment again by its digest, which names
/// the same bytes, so a long tree costs no more memory than one
/// document. A tree too long for a node to join is refused, as tree sync
/// and bpm tree append refuse it.
fn walk_back(
    c: &mut Client,
    repository: &[u8],
    set: &TrustedSet,
    tag: &TreePublication,
) -> Result<Vec<[u8; 32]>, c_int> {
    let within = walk_within(tag.base_seq, 0);
    if within != 0 {
        error(format!(
            "bpm tree show: the current segment starts after seq {}, more than the {MAX_JOIN_OPS} operations a joining node walks",
            tag.base_seq
        ));
        return Err(within);
    }
    let mut digests = Vec::new();
    let mut succ: Option<Publication> = None;
    loop {
        let s = succ.as_ref().map_or(tag, |p| p.get());
        if s.base_seq <= 0 {
            return Ok(digests);
        }
        let mut pred = Publication::new();
        let digest = fetch_sealed(c, repository, Signer::Set(set), s, pred.get_mut()).inspect_err(|_| {
            error(format!(
                "bpm tree show: the sealed segment {}, which ends at seq {}, cannot be fetched or does not verify",
                String::from_utf8_lossy(cstr(&s.segment_manifest_digest)),
                s.base_seq
            ));
        })?;
        digests.push(digest_bytes(&digest).ok_or(-EINVAL)?);
        succ = Some(pred);
    }
}

/// A sealed segment the walk back checked, fetched and printed again.
fn show_sealed(c: &mut Client, repository: &[u8], set: &TrustedSet, digest: &[u8; 32]) -> c_int {
    let reference = sha256_digest_encode(digest);
    let reference = cstr(&reference);
    let mut p = Publication::new();
    let fetched = fetch_checked(
        c,
        repository,
        reference,
        Signer::Set(set),
        p.get_mut(),
        true,
    )
    .and_then(|(d, doc)| {
        if d == reference {
            Ok(doc)
        } else {
            Err(-EKEYREJECTED)
        }
    });
    match fetched {
        Ok(doc) => print(reference, &doc.unwrap_or_default()),
        Err(err) => {
            error(format!(
                "bpm tree show: the sealed segment {} cannot be fetched again or changed",
                String::from_utf8_lossy(reference)
            ));
            err
        }
    }
}

fn show(args: &[&CStr]) -> c_int {
    let mut p = OptParser::new(c"bpm tree show", &SHOW_OPTS, Some(&SHOW_HELP), args, 1);
    let (mut raw_repository, mut cert, mut walk) = (None, None, false);
    let mut reference: &[u8] = b"stable";

    loop {
        let opt = p.next();
        let value = p.value();
        match opt {
            OPT_END => break,
            SHOW_CERT => cert = value,
            SHOW_REFERENCE => reference = value.map_or(&[], CStr::to_bytes),
            SHOW_WALK => walk = true,
            OPT_ARG => {
                if raw_repository.is_some() {
                    p.usage_arg(b"unexpected argument ");
                    return EXIT_USAGE;
                }
                raw_repository = value;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let (Some(raw_repository), Some(cert)) = (raw_repository, cert) else {
        p.usage(b"takes <repository> and --cert <cert.der>");
        return EXIT_USAGE;
    };
    let mut c = Client::new();
    let repository = match c.parse_tree_repo(raw_repository.to_bytes()) {
        Ok(r) => r,
        Err(err) => {
            error("bpm tree show: the repository must be oci://registry/repository".into());
            return err;
        }
    };
    // A node verifies against its config image's set; a set of this
    // certificate alone takes the same path, so a refusal names the errno
    // sync would.
    let set = match load_image_at(cert, None, false) {
        Ok(set) => set,
        Err(ret) => {
            error(format!(
                "bpm tree show: cannot read the certificate {}",
                String::from_utf8_lossy(cert.to_bytes())
            ));
            return ret;
        }
    };
    let mut publ = Publication::new();
    let run = (|| {
        let (digest, doc) = fetch_checked(
            &mut c,
            &repository,
            reference,
            Signer::Set(&set),
            publ.get_mut(),
            true,
        )?;
        if walk {
            for d in walk_back(&mut c, &repository, &set, publ.get())?
                .iter()
                .rev()
            {
                match show_sealed(&mut c, &repository, &set, d) {
                    0 => {}
                    err => return Err(err),
                }
            }
        }
        match print(&digest, &doc.unwrap_or_default()) {
            0 => Ok(()),
            err => Err(err),
        }
    })();
    run.err().unwrap_or(0)
}

/// `bpm tree show`, from `show` on.
pub(super) fn run(args: &[&CStr]) -> c_int {
    let Ok(curl) = super::Curl::init() else {
        error(format!("bpm tree show: {}", strerr(EIO)));
        return 1;
    };
    let ret = show(args);
    drop(curl);
    if ret == EXIT_USAGE {
        return EXIT_USAGE;
    }
    if ret < 0 {
        error(format!("bpm tree show: {}", strerr(-ret)));
    }
    c_int::from(ret != 0)
}
