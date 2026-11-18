// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::testutil::TempDir;

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

#[test]
fn anchor_digest_of_one_is_that_one() {
    assert_eq!(anchor_digest(&[digest(7)]), Ok(digest(7)));
}

#[test]
fn anchor_digest_hashes_the_sorted_digests() {
    let mut sorted = Vec::new();
    for d in [digest(1), digest(2), digest(3)] {
        sorted.extend_from_slice(&d);
    }
    let expected = crypto_openssl::sha256(&sorted).unwrap();

    assert_eq!(
        anchor_digest(&[digest(3), digest(1), digest(2)]),
        Ok(expected)
    );
    assert_eq!(
        anchor_digest(&[digest(2), digest(3), digest(1)]),
        Ok(expected)
    );
}

#[test]
fn anchor_digest_wants_one_to_keys_max() {
    assert_eq!(anchor_digest(&[]), Err(-EINVAL));
    assert!(anchor_digest(&[digest(0); KEYS_MAX]).is_ok());
    assert_eq!(anchor_digest(&[digest(0); KEYS_MAX + 1]), Err(-EINVAL));
}

#[test]
fn vouch_payload_is_the_prefix_its_nul_and_the_der() {
    assert_eq!(
        vouch_payload(b"\x30\x03der").unwrap(),
        b"shirudo-key-vouch\0\x30\x03der"
    );
    assert_eq!(vouch_payload(b"").unwrap(), b"shirudo-key-vouch\0");
}

#[test]
fn digest_der_refuses_what_is_not_a_certificate() {
    assert_eq!(digest_der(b"").err(), Some(-EINVAL));
    assert_eq!(digest_der(b"\x30\x03abc").err(), Some(-EINVAL));
}

/// A key and its self-signed certificate, which a vouch is signed with.
struct Signer {
    key: openssl::pkey::PKey<openssl::pkey::Private>,
    cert: X509,
    der: Vec<u8>,
}

/// A P-256 signer: the set takes any key libcrypto verifies a CMS
/// signature with, and P-256 keys are quick to make.
fn signer(name: &str) -> Signer {
    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::X509NameBuilder;

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut subject = X509NameBuilder::new().unwrap();
    subject.append_entry_by_text("CN", name).unwrap();
    let subject = subject.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_subject_name(&subject).unwrap();
    cert.set_issuer_name(&subject).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = cert.build();
    let der = cert.to_der().unwrap();

    Signer { key, cert, der }
}

/// `by`'s vouch for the certificate `der`.
fn vouch(by: &Signer, der: &[u8]) -> Vec<u8> {
    use openssl::cms::{CMSOptions, CmsContentInfo};

    let payload = vouch_payload(der).unwrap();
    CmsContentInfo::sign(
        Some(&by.cert),
        Some(&by.key),
        None,
        Some(&payload),
        CMSOptions::BINARY | CMSOptions::DETACHED,
    )
    .unwrap()
    .to_der()
    .unwrap()
}

fn fingerprint(s: &Signer) -> [u8; 32] {
    digest_der(&s.der).unwrap().fingerprint
}

fn sha256(s: &Signer) -> [u8; 32] {
    digest_der(&s.der).unwrap().sha256
}

/// A directory holding keys/: `primary` as its cert.der, and its
/// trusted/ and revoked/.
fn keys_dir(primary: &Signer) -> TempDir {
    let dir = TempDir::new();
    for sub in ["keys", "keys/trusted", "keys/revoked"] {
        std::fs::create_dir(dir.join(sub)).unwrap();
    }
    std::fs::write(dir.join("keys/cert.der"), &primary.der).unwrap();
    dir
}

/// `cert` under keys/trusted/ as `<stem>.der`, with `by`'s vouch for it.
fn trust(dir: &TempDir, stem: &str, cert: &Signer, by: Option<&Signer>) {
    std::fs::write(dir.join(&format!("keys/trusted/{stem}.der")), &cert.der).unwrap();
    if let Some(by) = by {
        std::fs::write(
            dir.join(&format!("keys/trusted/{stem}.vouch")),
            vouch(by, &cert.der),
        )
        .unwrap();
    }
}

fn revoke(dir: &TempDir, cert: &Signer) {
    let hex = String::from_utf8(encode(&fingerprint(cert))).unwrap();
    std::fs::write(dir.join(&format!("keys/revoked/{hex}.der")), &cert.der).unwrap();
}

/// The signers the set tests share: the store keeps every certificate a
/// set takes for the life of the process, up to KEPT_MAX.
fn signers() -> &'static [Signer; 4] {
    static SIGNERS: std::sync::OnceLock<[Signer; 4]> = std::sync::OnceLock::new();
    SIGNERS.get_or_init(|| [signer("a"), signer("b"), signer("c"), signer("d")])
}

#[test]
fn a_set_takes_vouched_members_in_rounds_sorted_by_sha256() {
    let [a, b, c, _] = signers();
    let dir = keys_dir(a);
    // c, vouched for by b, is read before b, vouched for by a: it joins
    // in the round after b's.
    trust(&dir, "0", c, Some(b));
    trust(&dir, "1", b, Some(a));
    let set = load(&dir.cpath("keys"), None, true).unwrap();

    assert_eq!((set.len(), set.n_revoked(), set.n_unvouched()), (3, 0, 0));
    let mut sha = [sha256(a), sha256(b), sha256(c)];
    sha.sort();
    assert_eq!(
        members(&set)
            .iter()
            .map(|m| *m.sha256())
            .collect::<Vec<_>>(),
        sha
    );
    let find = |s: &Signer| {
        members(&set)
            .iter()
            .find(|m| *m.fingerprint() == fingerprint(s))
            .unwrap()
    };
    assert!(find(a).primary() && find(a).voucher().is_none());
    assert_eq!(find(b).voucher(), Some(&fingerprint(a)));
    assert_eq!(find(c).voucher(), Some(&fingerprint(b)));
    assert_eq!(cert_path(find(a)), dir.cpath("keys/cert.der").as_bytes());
    assert_eq!(
        cert_path(find(c)),
        dir.cpath("keys/trusted/0.der").as_bytes()
    );
    assert_eq!(cert_der(find(c)).unwrap(), c.der);
    assert_eq!(set.digest(), anchor_digest(&sha));
    assert_eq!(
        verify_vouch(&set, &a.der, &vouch(b, &a.der)),
        Ok(fingerprint(b))
    );

    let primary = load(&dir.cpath("keys"), None, false).unwrap();
    assert_eq!((primary.len(), primary.n_unvouched()), (1, 0));
    assert_eq!(primary.digest(), Ok(sha256(a)));
}

#[test]
fn a_set_counts_the_unvouched_and_leaves_out_the_revoked() {
    let [a, b, c, d] = signers();
    let dir = keys_dir(a);
    trust(&dir, "b", b, Some(a));
    trust(&dir, "c", c, Some(b));
    trust(&dir, "d", d, None);
    revoke(&dir, b);
    std::fs::write(dir.join("keys/revoked/other.der"), b"").unwrap();
    let set = load(&dir.cpath("keys"), None, true).unwrap();

    assert_eq!((set.len(), set.n_revoked(), set.n_unvouched()), (1, 2, 2));
    assert!(members(&set)[0].primary());

    revoke(&dir, a);
    let set = load(&dir.cpath("keys"), None, false).unwrap();
    assert_eq!(set.len(), 0);
    assert_eq!(set.digest(), Err(-EINVAL));
}

#[test]
fn an_image_set_counts_vouches_of_the_revoked() {
    let [a, b, c, _] = signers();
    let dir = keys_dir(a);
    trust(&dir, "b", b, Some(a));
    trust(&dir, "c", c, Some(b));
    revoke(&dir, b);
    let keys = File::open(dir.join("keys")).unwrap();
    let set = load_image_at(&dir.cpath("keys/cert.der"), Some(keys.as_fd()), true).unwrap();

    assert_eq!((set.len(), set.n_revoked(), set.n_unvouched()), (2, 1, 0));
    let mut sha = [sha256(a), sha256(c)];
    sha.sort();
    assert_eq!(
        members(&set)
            .iter()
            .map(|m| *m.sha256())
            .collect::<Vec<_>>(),
        sha
    );
    let c_member = members(&set).iter().find(|m| !m.primary()).unwrap();
    assert_eq!(cert_path(c_member), b"keys/trusted/c.der");

    let alone = load_image_at(&dir.cpath("keys/cert.der"), None, true).unwrap();
    assert_eq!((alone.len(), alone.n_revoked()), (1, 0));
}

#[test]
fn a_set_holds_at_most_keys_max() {
    let [a, ..] = signers();
    let dir = keys_dir(a);
    for i in 0..KEYS_MAX {
        let s = signer(&format!("member {i}"));
        trust(&dir, &format!("m{i:02}"), &s, Some(a));
    }

    assert_eq!(load(&dir.cpath("keys"), None, true).err(), Some(-E2BIG));
}

#[test]
fn a_scan_looks_at_scan_max_certificates() {
    let [a, b, ..] = signers();
    let dir = keys_dir(a);
    for i in 0..SCAN_MAX {
        trust(&dir, &format!("copy{i:02}"), b, None);
    }
    let set = load(&dir.cpath("keys"), None, true).unwrap();
    assert_eq!((set.len(), set.n_unvouched()), (1, SCAN_MAX));

    trust(&dir, "one-more", b, None);
    assert_eq!(load(&dir.cpath("keys"), None, true).err(), Some(-E2BIG));
}

#[test]
fn read_der_wants_a_regular_file_of_one_to_der_max_bytes() {
    let dir = TempDir::new();
    std::fs::write(dir.join("empty"), b"").unwrap();
    std::fs::write(dir.join("big"), vec![0u8; DER_MAX + 1]).unwrap();
    std::fs::write(dir.join("max"), vec![7u8; DER_MAX]).unwrap();

    assert_eq!(read_der(&dir.cpath("empty")), Err(-EINVAL));
    assert_eq!(read_der(&dir.cpath("big")), Err(-EINVAL));
    assert_eq!(read_der(&dir.cpath("")), Err(-EINVAL));
    assert_eq!(read_der(&dir.cpath("missing")), Err(-ENOENT));
    assert_eq!(read_der(&dir.cpath("max")).map(|d| d.len()), Ok(DER_MAX));
    let empty = File::open(dir.join("empty")).unwrap();
    assert_eq!(read_der_fd(empty.as_raw_fd()), Err(-EINVAL));
}

#[test]
fn a_vouch_sits_beside_its_certificate() {
    assert_eq!(
        vouch_path_for(b"/k/trusted/x.der").unwrap().as_bytes(),
        b"/k/trusted/x.vouch"
    );
    assert_eq!(vouch_path_for(b"der").unwrap().as_bytes(), b"der.vouch");
    let long = vec![b'a'; PATH_MAX];
    assert!(vouch_path_for(&long[..PATH_MAX - 3]).is_ok());
    assert_eq!(
        vouch_path_for(&long[..PATH_MAX - 2]).err(),
        Some(-ENAMETOOLONG)
    );
    assert!(path_of(&[&long[..PATH_MAX - 2], b"a"]).is_ok());
    assert_eq!(
        path_of(&[&long[..PATH_MAX - 2], b"ab"]).err(),
        Some(-ENAMETOOLONG)
    );
}

#[test]
fn cert_der_wants_a_certificate_a_set_took() {
    let stranger = TrustedCert {
        path: Vec::new(),
        digests: CertDigests {
            sha256: digest(0xee),
            fingerprint: digest(0xee),
        },
        voucher: None,
    };

    assert_eq!(cert_der(&stranger).err(), Some(-ENOKEY));
}
