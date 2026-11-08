//! Certificate revocation (docs/design/revocation.md) through the public
//! API, beside the shared cases in `fixtures/cases.json`: the rules those
//! cases cannot state, because they need a list or a built-in list minted
//! on the spot (the bounds, the built-in list and its `newest`, the order
//! of refusals, when the clock is read), and the messages.
//!
//! Lists are minted here from the receipt test PKI (`common/pki.rs`),
//! DER written field by field and signed with the issuer's key, so a test
//! can state exactly the list it needs.

mod common;

use apple_purchase_receipt_verifier::__internal::base64_encode;
use apple_purchase_receipt_verifier::{Config, ConfigBuilder, Reason, Verifier};
use common::pki::{self, extension, payload_at, x509_time, Hash, Key, Pki, DAY_MS};
use common::{der, der_int, der_seq, tag};
use openssl::sha::sha256;

const REASON_CODE: &str = "2.5.29.21";
const CRL_NUMBER: &str = "2.5.29.20";
const AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
const SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
const INVALIDITY_DATE: &str = "2.5.29.24";
const KEY_COMPROMISE: u8 = 1;
const CERTIFICATE_HOLD: u8 = 6;

/// The issuer id of a certificate (§2): SHA-256 over its `subject` and
/// `subjectPublicKeyInfo` as encoded, through the test BER reader.
fn issuer_id(certificate: &[u8]) -> String {
    let fields = pki::cert_fields(certificate);
    hex::encode(sha256(&[fields.subject, fields.spki].concat()))
}

/// A certificate's serial as §2 writes it.
fn serial_hex(certificate: &[u8]) -> String {
    let fields = pki::cert_fields(certificate);
    let digits: Vec<u8> = fields
        .serial
        .iter()
        .copied()
        .skip_while(|b| *b == 0)
        .collect();
    if digits.is_empty() {
        "00".to_owned()
    } else {
        hex::encode_upper(digits)
    }
}

/// One list entry: a serial's INTEGER content octets and a reason code.
struct Entry {
    serial: Vec<u8>,
    reason: Option<u8>,
}

/// A v2 list signed by `key` under the `issuer` Name, from `this_update`
/// to `next_update` (epoch ms), with a CRL Number when given.
fn list(
    issuer: &[u8],
    key: &Key,
    this_update: i64,
    next_update: i64,
    number: Option<u64>,
    entries: &[Entry],
) -> Vec<u8> {
    let label = key.label(Hash::Sha256);
    let mut fields = vec![
        der_int(1),
        label.clone(),
        issuer.to_vec(),
        x509_time(this_update),
        x509_time(next_update),
    ];
    if !entries.is_empty() {
        let revoked: Vec<Vec<u8>> = entries
            .iter()
            .map(|entry| {
                let mut parts = vec![der(tag::INTEGER, &entry.serial), x509_time(this_update)];
                if let Some(reason) = entry.reason {
                    parts.push(der_seq(&[extension(
                        REASON_CODE,
                        false,
                        &der(0x0a, &[reason]),
                    )]));
                }
                der_seq(&parts)
            })
            .collect();
        fields.push(der_seq(&revoked));
    }
    if let Some(number) = number {
        fields.push(der(
            tag::CONTEXT_0,
            &der_seq(&[extension(CRL_NUMBER, false, &der_int(number))]),
        ));
    }
    let tbs = der_seq(&fields);
    let signature = key.sign(Hash::Sha256, &tbs);
    pki::assemble(tbs, &label, &signature)
}

/// The `issuer` Name of a certificate, as encoded: what a list it signs
/// names as its issuer.
fn subject(certificate: &[u8]) -> Vec<u8> {
    pki::cert_fields(certificate).subject
}

/// One entry whose extensions are given whole, each an encoded Extension:
/// what `Entry` cannot say (a critical flag, a value that does not read).
struct RawEntry {
    serial: Vec<u8>,
    extensions: Vec<Vec<u8>>,
}

/// A v2 list as `list` writes it, with the list's own `extensions` (each an
/// encoded Extension) and `entries` given whole.
fn raw_list(
    issuer: &[u8],
    key: &Key,
    this_update: i64,
    next_update: i64,
    extensions: &[Vec<u8>],
    entries: &[RawEntry],
) -> Vec<u8> {
    let label = key.label(Hash::Sha256);
    let mut fields = vec![
        der_int(1),
        label.clone(),
        issuer.to_vec(),
        x509_time(this_update),
        x509_time(next_update),
    ];
    if !entries.is_empty() {
        let revoked: Vec<Vec<u8>> = entries
            .iter()
            .map(|entry| {
                let mut parts = vec![der(tag::INTEGER, &entry.serial), x509_time(this_update)];
                if !entry.extensions.is_empty() {
                    parts.push(der_seq(&entry.extensions));
                }
                der_seq(&parts)
            })
            .collect();
        fields.push(der_seq(&revoked));
    }
    if !extensions.is_empty() {
        fields.push(der(tag::CONTEXT_0, &der_seq(extensions)));
    }
    let tbs = der_seq(&fields);
    let signature = key.sign(Hash::Sha256, &tbs);
    pki::assemble(tbs, &label, &signature)
}

/// A receipt PKI, valid around 2026-11-05, and its receipt.
struct Setup {
    pki: Pki,
    receipt: String,
}

/// 2026-11-05T00:00:00Z.
const NOW: i64 = 1_793_836_800_000;

fn setup() -> Setup {
    let pki = Pki::receipt_with(NOW - 365 * DAY_MS, NOW + 365 * DAY_MS, true, true);
    setup_from(pki)
}

/// The setup for `pki`: its receipt, signed at `NOW`.
fn setup_from(pki: Pki) -> Setup {
    let receipt = base64_encode(&pki.sign_receipt_at(&payload_at("2026-10-01T00:00:00Z"), NOW));
    Setup { pki, receipt }
}

/// `setup()`'s PKI with a SubjectKeyIdentifier `key_id` on the intermediate,
/// so that a list can name the intermediate by AuthorityKeyIdentifier (§4:
/// a candidate without a SubjectKeyIdentifier is not one then).
fn setup_with_key_identifier(key_id: &[u8]) -> Setup {
    let (not_before, not_after) = (NOW - 365 * DAY_MS, NOW + 365 * DAY_MS);
    let (root_key, intermediate_key, leaf_key) = (Key::rsa(), Key::rsa(), Key::rsa());
    let root = pki::test_pki_cert(
        "Fake Apple Inc Root",
        &root_key,
        "Fake Apple Inc Root",
        &root_key,
        true,
        None,
        not_before,
        not_after,
    );
    let mut spec = pki::CertSpec::new(
        pki::name("Fake WWDR CA"),
        pki::name("Fake Apple Inc Root"),
        intermediate_key.spki(),
    );
    spec.not_before = not_before;
    spec.not_after = not_after;
    spec.extensions.push(pki::basic_constraints(true, None));
    spec.extensions.push(pki::marker(pki::WWDR_OID, pki::NULL));
    spec.extensions.push(extension(
        SUBJECT_KEY_IDENTIFIER,
        false,
        &der(tag::OCTET_STRING, key_id),
    ));
    let intermediate = spec.sign(&root_key);
    let leaf = pki::test_pki_cert(
        "Fake Receipt Signing",
        &leaf_key,
        "Fake WWDR CA",
        &intermediate_key,
        false,
        Some(pki::SIGNING_LEAF_OID),
        not_before,
        not_after,
    );
    let chain = vec![leaf.clone(), intermediate.clone(), root.clone()];
    setup_from(Pki {
        root_key,
        intermediate_key,
        leaf_key,
        root,
        intermediate,
        leaf,
        chain,
        not_before,
        not_after,
    })
}

impl Setup {
    fn builder(&self) -> ConfigBuilder {
        Config::builder()
            .roots([common::anchor_from_der(&self.pki.root)])
            .clock(|| NOW)
    }

    fn verify(&self, builder: ConfigBuilder) -> Result<(), (Reason, String)> {
        let verifier = Verifier::new(builder.build().expect("the configuration builds"));
        verifier
            .verify_receipt(&self.receipt)
            .map(|_| ())
            .map_err(|failure| (failure.reason(), failure.message().to_owned()))
    }

    /// A list of the intermediate's revoking `serials` for keyCompromise.
    fn intermediate_list(&self, number: u64, serials: &[&[u8]], reason: u8) -> Vec<u8> {
        let entries: Vec<Entry> = serials
            .iter()
            .map(|serial| Entry {
                serial: serial.to_vec(),
                reason: Some(reason),
            })
            .collect();
        list(
            &subject(&self.pki.intermediate),
            &self.pki.intermediate_key,
            NOW - DAY_MS,
            NOW + 14 * DAY_MS,
            Some(number),
            &entries,
        )
    }

    fn leaf_serial(&self) -> Vec<u8> {
        pki::cert_fields(&self.pki.leaf).serial
    }

    /// The receipt's verdict, and what the verifier reports as
    /// `revocation_valid_until`, with `list` held for the added
    /// intermediate.
    fn held(&self, list: Vec<u8>) -> (Result<(), Reason>, Option<i64>) {
        let verifier = Verifier::new(
            self.builder()
                .revocation_lists([list])
                .revocation_issuers([common::anchor_from_der(&self.pki.intermediate)])
                .build()
                .expect("the configuration builds"),
        );
        let verdict = verifier
            .verify_receipt(&self.receipt)
            .map(|_| ())
            .map_err(|failure| failure.reason());
        (verdict, verifier.revocation_valid_until())
    }

    /// A built-in list in the format of `certs/revocations.json` with one
    /// issuer, the test root, and `revoked` entries under it.
    fn built_in(&self, newest: &str, revoked: &[(String, String)]) -> Vec<u8> {
        let entries: Vec<serde_json::Value> = revoked
            .iter()
            .map(|(issuer, serial)| serde_json::json!({"issuer": issuer, "serial": serial, "reason": "keyCompromise", "revocationDate": "2026-01-01T00:00:00Z", "crlNumber": null}))
            .collect();
        let newest: serde_json::Value = serde_json::from_str(newest).unwrap();
        serde_json::json!({
            "comment": "a test list",
            "issuers": [{
                "id": issuer_id(&self.pki.root),
                "name": "Fake Apple Inc Root",
                "certificate": null,
                "list": "http://crl.example.test/root.crl",
                "newest": newest,
            }],
            "revoked": entries,
        })
        .to_string()
        .into_bytes()
    }
}

#[test]
fn each_layer_revokes_and_names_itself_and_the_serial() {
    let setup = setup();
    let leaf = serial_hex(&setup.pki.leaf);
    let intermediate = issuer_id(&setup.pki.intermediate);
    assert_eq!(setup.verify(setup.builder()), Ok(()));

    // The built-in list, injected.
    let json = setup.built_in(
        r#"{"crlNumber":null,"thisUpdate":"2026-01-01T00:00:00Z"}"#,
        &[(intermediate.clone(), leaf.to_ascii_lowercase())],
    );
    assert_eq!(
        setup.verify(setup.builder().built_in_revocations(&json, &[])),
        Err((
            Reason::CertificateRevoked,
            format!("revoked: built-in list, serial {leaf}")
        ))
    );
    // distrust, the issuer id in upper case.
    assert_eq!(
        setup.verify(
            setup
                .builder()
                .distrust([(intermediate.to_ascii_uppercase(), leaf.clone())])
        ),
        Err((
            Reason::CertificateRevoked,
            format!("revoked: distrust, serial {leaf}")
        ))
    );
    // A list the intermediate signed, the intermediate added as an issuer.
    let list = setup.intermediate_list(1, &[&setup.leaf_serial()], KEY_COMPROMISE);
    assert_eq!(
        setup.verify(
            setup
                .builder()
                .revocation_lists([list])
                .revocation_issuers([common::anchor_from_der(&setup.pki.intermediate)])
        ),
        Err((
            Reason::CertificateRevoked,
            format!("revoked: Apple's list, serial {leaf}")
        ))
    );
}

#[test]
fn the_built_in_newest_refuses_an_older_list_and_takes_an_equal_or_newer_one() {
    let setup = setup();
    let root_name = subject(&setup.pki.root);
    let root_list = |this_update: i64, number: Option<u64>| {
        list(
            &root_name,
            &setup.pki.root_key,
            this_update,
            NOW + 30 * DAY_MS,
            number,
            &[],
        )
    };
    let build = |newest: &str, list: Vec<u8>| {
        setup
            .builder()
            .built_in_revocations(&setup.built_in(newest, &[]), &[])
            .revocation_lists([list])
            .build()
            .map(|_| ())
            .map_err(|error| error.detail().to_owned())
    };
    let numbered = r#"{"crlNumber":"05","thisUpdate":"2026-10-01T00:00:00Z"}"#;
    let older = build(numbered, root_list(NOW, Some(4))).unwrap_err();
    assert!(older.starts_with("revocation_lists[0]: "), "{older}");
    assert!(older.contains("older than the newest"), "{older}");
    // Equal is not older; by number, thisUpdate does not matter.
    assert_eq!(
        build(numbered, root_list(NOW - 60 * DAY_MS, Some(5))),
        Ok(())
    );
    assert_eq!(
        build(numbered, root_list(NOW - 60 * DAY_MS, Some(0x100))),
        Ok(())
    );
    // Without a number on either side, thisUpdate decides.
    let dated = r#"{"crlNumber":null,"thisUpdate":"2026-11-04T00:00:00Z"}"#;
    assert!(build(dated, root_list(NOW - 2 * DAY_MS, None)).is_err());
    assert_eq!(build(dated, root_list(NOW - DAY_MS, None)), Ok(()));
    assert!(build(numbered, root_list(NOW - 60 * DAY_MS, None)).is_err());
    assert_eq!(build(numbered, root_list(NOW, None)), Ok(()));
}

#[test]
fn a_list_over_one_mebibyte_is_refused_before_it_is_read() {
    let setup = setup();
    let mut oversized = setup.intermediate_list(1, &[], KEY_COMPROMISE);
    let error = setup
        .builder()
        .revocation_lists([oversized.clone(), vec![0u8; 1_048_577]])
        .build()
        .unwrap_err();
    assert_eq!(
        error.detail(),
        "revocation_lists[1]: the list is over 1 MiB"
    );
    // At exactly 1 MiB the size is no objection: the bytes are judged.
    oversized.resize(1_048_576, 0);
    let error = setup
        .builder()
        .revocation_lists([oversized])
        .build()
        .unwrap_err();
    assert_eq!(
        error.detail(),
        "revocation_lists[0]: not a DER certificate revocation list"
    );
}

#[test]
fn exactly_100000_entries_in_all_build_and_100001_are_refused() {
    let setup = setup();
    // Three lists under 1 MiB each, with CRL Numbers 1, 2 and 3 and a
    // nextUpdate of 10, 11 and 12 days: the list kept for the intermediate
    // has the highest number, so `revocation_valid_until` tells which one
    // was kept.
    let minted = |index: u64, count: u64, days: i64| {
        let entries: Vec<Entry> = (0..count)
            .map(|n| Entry {
                serial: pki::unsigned_integer(&(index * 1_000_000 + n + 1).to_be_bytes()),
                reason: None,
            })
            .collect();
        list(
            &subject(&setup.pki.intermediate),
            &setup.pki.intermediate_key,
            NOW - DAY_MS,
            NOW + days * DAY_MS,
            Some(index + 1),
            &entries,
        )
    };
    let first = minted(0, 33_334, 10);
    let second = minted(1, 33_333, 11);
    let third = minted(2, 33_333, 12);
    let third_with_one_more = minted(2, 33_334, 12);
    for list in [&first, &second, &third, &third_with_one_more] {
        assert!(list.len() < 1_048_576, "a test list is over 1 MiB");
    }
    let build = |lists: Vec<Vec<u8>>| {
        setup
            .builder()
            .revocation_lists(lists)
            .revocation_issuers([common::anchor_from_der(&setup.pki.intermediate)])
            .build()
    };
    // 33,334 + 33,333 + 33,333 = 100,000: the bound is "more than".
    let config = build(vec![first.clone(), second.clone(), third])
        .unwrap_or_else(|error| panic!("100,000 entries: {}", error.detail()));
    assert_eq!(
        Verifier::new(config).revocation_valid_until(),
        Some(NOW + 12 * DAY_MS),
        "the list with the highest CRL Number is the one kept"
    );
    // One more entry in the last list makes 100,001.
    assert_eq!(
        build(vec![first, second, third_with_one_more])
            .unwrap_err()
            .detail(),
        "revocation_lists[2]: the lists hold more than 100,000 entries in all"
    );
}

#[test]
fn exactly_16_lists_build_and_17_are_refused() {
    let setup = setup();
    let own = setup.intermediate_list(1, &[], KEY_COMPROMISE);
    let build = |count: usize| {
        setup
            .builder()
            .revocation_lists(vec![own.clone(); count])
            .revocation_issuers([common::anchor_from_der(&setup.pki.intermediate)])
            .build()
    };
    let config = build(16).unwrap_or_else(|error| panic!("16 lists: {}", error.detail()));
    assert_eq!(
        Verifier::new(config).revocation_valid_until(),
        Some(NOW + 14 * DAY_MS)
    );
    assert_eq!(
        build(17).unwrap_err().detail(),
        "revocation_lists: more than 16 lists"
    );
}

#[test]
fn distrust_takes_at_most_1000_well_formed_entries() {
    let setup = setup();
    let intermediate = issuer_id(&setup.pki.intermediate);
    let entries = |count: usize| {
        (0..count)
            .map(|n| (intermediate.clone(), format!("{:x}", n + 0x1_0000)))
            .collect::<Vec<_>>()
    };
    assert!(setup.builder().distrust(entries(1_000)).build().is_ok());
    assert_eq!(
        setup
            .builder()
            .distrust(entries(1_001))
            .build()
            .unwrap_err()
            .detail(),
        "distrust: more than 1000 entries"
    );
    for (issuer, serial) in [
        (&intermediate[..63], "02"),
        (&format!("{intermediate}0")[..], "02"),
        (&format!("g{}", &intermediate[1..])[..], "02"),
        (&intermediate[..], ""),
        (&intermediate[..], "0x02"),
        (&intermediate[..], "02 "),
        (&intermediate[..], "-2"),
    ] {
        let error = setup
            .builder()
            .distrust([
                (issuer.to_owned(), "01".to_owned()),
                (issuer.to_owned(), serial.to_owned()),
            ])
            .build();
        assert!(error.is_err(), "{issuer} {serial:?}");
    }
    // Odd digit counts, leading zeros and either case are one serial.
    let leaf = serial_hex(&setup.pki.leaf);
    for written in [
        format!("000{leaf}"),
        leaf.to_ascii_lowercase(),
        leaf.trim_start_matches('0').to_owned(),
    ] {
        assert_eq!(
            setup
                .verify(
                    setup
                        .builder()
                        .distrust([(intermediate.clone(), written.clone())])
                )
                .map_err(|(reason, _)| reason),
            Err(Reason::CertificateRevoked),
            "{written}"
        );
    }
}

#[test]
fn refusals_are_reported_lists_first_then_issuers_then_distrust() {
    let setup = setup();
    let bad_distrust = [("not an id".to_owned(), "02".to_owned())];
    let without_marker = Pki::receipt_with(NOW - DAY_MS, NOW + DAY_MS, true, false);
    let detail = |builder: ConfigBuilder| builder.build().unwrap_err().detail().to_owned();
    let both = detail(
        setup
            .builder()
            .revocation_lists([b"not a list".to_vec()])
            .revocation_issuers([common::anchor_from_der(&without_marker.intermediate)])
            .distrust(bad_distrust.clone()),
    );
    assert!(both.starts_with("revocation_lists[0]: "), "{both}");
    let issuers = detail(
        setup
            .builder()
            .revocation_issuers([
                common::anchor_from_der(&setup.pki.intermediate),
                common::anchor_from_der(&without_marker.intermediate),
            ])
            .distrust(bad_distrust.clone()),
    );
    assert!(issuers.starts_with("revocation_issuers[1]: "), "{issuers}");
    let distrust = detail(setup.builder().distrust(bad_distrust));
    assert!(distrust.starts_with("distrust[0]: "), "{distrust}");
}

#[test]
fn a_revoked_added_issuer_and_its_own_list_are_set_aside_not_refused() {
    // The build has no clock (§6), so an issuer on its root's list is not
    // accepted whatever the entry's reason, certificateHold included; only
    // removeFromCRL lets it through. A revoked added issuer is set aside as
    // a revoked built-in one is: the configuration builds, its own list is
    // neither held nor refused, it is not an expected issuer of
    // revocationValidUntil, and its path fails on the issuer itself.
    // Refusing it would keep a host on its old verifier, which accepts it.
    let setup = setup();
    let root_id = issuer_id(&setup.pki.root);
    let intermediate_serial = pki::cert_fields(&setup.pki.intermediate).serial;
    let intermediate_hex = serial_hex(&setup.pki.intermediate);
    let own_list = setup.intermediate_list(1, &[], KEY_COMPROMISE);
    for (reason, revoked_by) in [
        (Some(KEY_COMPROMISE), Some("Apple's list")),
        (Some(CERTIFICATE_HOLD), Some("Apple's list")),
        (None, Some("Apple's list")),
        (Some(8), None),
    ] {
        let root_list = list(
            &subject(&setup.pki.root),
            &setup.pki.root_key,
            NOW - DAY_MS,
            NOW + 30 * DAY_MS,
            Some(1),
            &[Entry {
                serial: intermediate_serial.clone(),
                reason,
            }],
        );
        let config = setup
            .builder()
            .revocation_lists([own_list.clone(), root_list])
            .revocation_issuers([common::anchor_from_der(&setup.pki.intermediate)])
            .build()
            .unwrap_or_else(|error| panic!("{reason:?}: {}", error.detail()));
        let verifier = Verifier::new(config);
        let outcome = verifier
            .verify_receipt(&setup.receipt)
            .map(|_| ())
            .map_err(|failure| (failure.reason(), failure.message().to_owned()));
        match revoked_by {
            Some(layer) => {
                assert_eq!(verifier.revocation_valid_until(), None, "{reason:?}");
                assert_eq!(
                    outcome,
                    Err((
                        Reason::CertificateRevoked,
                        format!("revoked: {layer}, serial {intermediate_hex}")
                    )),
                    "{reason:?}"
                );
            }
            None => {
                // Accepted: its own list is held and expected.
                assert_eq!(
                    verifier.revocation_valid_until(),
                    Some(NOW + 14 * DAY_MS),
                    "{reason:?}"
                );
                assert_eq!(outcome, Ok(()), "{reason:?}");
            }
        }
    }
    // distrust revokes it the same way.
    let config = setup
        .builder()
        .revocation_lists([own_list])
        .revocation_issuers([common::anchor_from_der(&setup.pki.intermediate)])
        .distrust([(root_id, intermediate_hex.clone())])
        .build()
        .unwrap_or_else(|error| panic!("distrust: {}", error.detail()));
    let verifier = Verifier::new(config);
    assert_eq!(verifier.revocation_valid_until(), None);
    let failure = verifier.verify_receipt(&setup.receipt).unwrap_err();
    assert_eq!(
        (failure.reason(), failure.message()),
        (
            Reason::CertificateRevoked,
            format!("revoked: distrust, serial {intermediate_hex}").as_str()
        )
    );
}

#[test]
fn a_revoked_built_in_issuers_own_list_is_set_aside_not_refused() {
    // A built-in issuer that its root's list or distrust revokes is dropped
    // (§6). Its own list, which a host keeps downloading from the URL the
    // previous verifier reported, must not refuse the configuration: that
    // would keep the host on its old verifier, which accepts the issuer. The
    // list is set aside; the issuer's path fails on the issuer itself.
    let setup = setup();
    let root_id = issuer_id(&setup.pki.root);
    let intermediate_serial = pki::cert_fields(&setup.pki.intermediate).serial;
    let built_in = serde_json::json!({
        "comment": "a test list",
        "issuers": [
            {"id": root_id, "name": "Fake Apple Inc Root", "certificate": null,
             "list": "http://crl.example.test/root.crl",
             "newest": {"crlNumber": null, "thisUpdate": "2026-01-01T00:00:00Z"}},
            {"id": issuer_id(&setup.pki.intermediate), "name": "Fake WWDR", "certificate": "wwdr.cer",
             "list": "http://crl.example.test/wwdr.crl",
             "newest": {"crlNumber": null, "thisUpdate": "2026-01-01T00:00:00Z"}},
        ],
        "revoked": [],
    })
    .to_string()
    .into_bytes();
    let own_list = setup.intermediate_list(1, &[], KEY_COMPROMISE);
    let builder = || {
        setup
            .builder()
            .built_in_revocations(&built_in, &[&setup.pki.intermediate])
    };
    // Not revoked: the issuer is accepted and its list held.
    let verifier = Verifier::new(
        builder()
            .revocation_lists([own_list.clone()])
            .build()
            .expect("the configuration builds"),
    );
    assert_eq!(verifier.revocation_valid_until(), None, "no root list held");
    assert_eq!(
        verifier.revocation_urls(),
        [
            "http://crl.example.test/root.crl",
            "http://crl.example.test/wwdr.crl"
        ]
    );
    let intermediate_hex = serial_hex(&setup.pki.intermediate);
    for (reason, layer) in [
        (Some(KEY_COMPROMISE), "Apple's list"),
        (Some(CERTIFICATE_HOLD), "Apple's list"),
        (None, "distrust"),
    ] {
        let mut lists = vec![own_list.clone()];
        let mut builder = builder();
        if let Some(reason) = reason {
            lists.push(list(
                &subject(&setup.pki.root),
                &setup.pki.root_key,
                NOW - DAY_MS,
                NOW + 30 * DAY_MS,
                Some(1),
                &[Entry {
                    serial: intermediate_serial.clone(),
                    reason: Some(reason),
                }],
            ));
        } else {
            builder = builder.distrust([(root_id.clone(), intermediate_hex.clone())]);
        }
        let config = builder
            .revocation_lists(lists)
            .build()
            .unwrap_or_else(|error| panic!("{reason:?}: {}", error.detail()));
        let verifier = Verifier::new(config);
        assert_eq!(
            verifier.revocation_urls(),
            ["http://crl.example.test/root.crl"],
            "{reason:?}: the dropped issuer's URL is no longer reported"
        );
        let failure = verifier.verify_receipt(&setup.receipt).unwrap_err();
        assert_eq!(
            (failure.reason(), failure.message()),
            (
                Reason::CertificateRevoked,
                format!("revoked: {layer}, serial {intermediate_hex}").as_str()
            ),
            "{reason:?}"
        );
    }
}

#[test]
fn an_issuer_with_a_negative_serial_is_accepted_and_never_revoked() {
    // A negative serial is never matched (§2), so an added issuer whose
    // serial is negative is accepted (Java judges it the same way) and no
    // list or distrust entry can name it. Its own list is still read.
    let setup = setup();
    let key = pki::Key::rsa();
    let mut spec = pki::CertSpec::new(
        pki::name("Negative Serial WWDR CA"),
        subject(&setup.pki.root),
        key.spki(),
    );
    spec.serial = vec![0xFF]; // -1
    spec.extensions.push(pki::basic_constraints(true, None));
    spec.extensions.push(pki::marker(pki::WWDR_OID, pki::NULL));
    let issuer = spec.sign(&setup.pki.root_key);
    let root_id = issuer_id(&setup.pki.root);
    let root_list = list(
        &subject(&setup.pki.root),
        &setup.pki.root_key,
        NOW - DAY_MS,
        NOW + 30 * DAY_MS,
        Some(1),
        &[Entry {
            serial: vec![0xFF],
            reason: Some(KEY_COMPROMISE),
        }],
    );
    let own_list = list(
        &pki::name("Negative Serial WWDR CA"),
        &key,
        NOW - DAY_MS,
        NOW + 14 * DAY_MS,
        Some(1),
        &[],
    );
    let verifier = Verifier::new(
        setup
            .builder()
            .revocation_lists([root_list, own_list])
            .revocation_issuers([common::anchor_from_der(&issuer)])
            .distrust([(root_id, "FF".to_owned())])
            .build()
            .expect("an issuer with a negative serial is accepted"),
    );
    assert_eq!(
        verifier.revocation_valid_until(),
        Some(NOW + 14 * DAY_MS),
        "the issuer's own list is held"
    );
}

#[test]
fn the_clock_is_read_only_for_a_matching_hold() {
    // The receipt carries its creation date, so only a certificateHold entry
    // that matches its signer needs the time: a clock that panics shows
    // when it is read.
    let setup = setup();
    let panicking = || -> i64 { panic!("the clock was read") };
    let verify = |list: Vec<u8>| {
        let config = Config::builder()
            .roots([common::anchor_from_der(&setup.pki.root)])
            .revocation_lists([list])
            .revocation_issuers([common::anchor_from_der(&setup.pki.intermediate)])
            .clock(panicking)
            .build()
            .unwrap();
        Verifier::new(config)
            .verify_receipt(&setup.receipt)
            .map(|_| ())
            .map_err(|failure| failure.reason())
    };
    let other = pki::unsigned_integer(&[0x7f, 0x01]);
    assert_eq!(
        verify(setup.intermediate_list(1, &[&other], CERTIFICATE_HOLD)),
        Ok(())
    );
    assert_eq!(
        verify(setup.intermediate_list(1, &[&setup.leaf_serial()], KEY_COMPROMISE)),
        Err(Reason::CertificateRevoked)
    );
    assert_eq!(
        verify(setup.intermediate_list(1, &[&setup.leaf_serial()], CERTIFICATE_HOLD)),
        Err(Reason::InternalError)
    );
    // With a clock, the hold revokes while the list is fresh and not after.
    let held = setup.intermediate_list(1, &[&setup.leaf_serial()], CERTIFICATE_HOLD);
    let verifier = Verifier::new(
        setup
            .builder()
            .revocation_lists([held])
            .revocation_issuers([common::anchor_from_der(&setup.pki.intermediate)])
            .build()
            .unwrap(),
    );
    let at = |now: i64| {
        verifier
            .verify_receipt_at(&setup.receipt, now)
            .map(|_| ())
            .map_err(|failure| failure.reason())
    };
    assert_eq!(at(NOW + 14 * DAY_MS), Err(Reason::CertificateRevoked));
    assert_eq!(at(NOW + 14 * DAY_MS + 1), Ok(()));
}

#[test]
fn the_default_configuration_and_the_default_builder_report_the_same() {
    let default = Verifier::new(Config::default());
    let built = Verifier::new(Config::builder().build().unwrap());
    assert_eq!(default.revocation_urls(), built.revocation_urls());
    assert_eq!(default.revocation_urls().len(), 4);
    assert!(default
        .revocation_urls()
        .iter()
        .all(|url| url.starts_with("http") && url.contains("crl.apple.com")));
    assert_eq!(default.revocation_valid_until(), None);
    assert_eq!(built.revocation_valid_until(), None);
}

#[test]
fn a_built_in_list_that_does_not_read_fails_the_build() {
    let error = Config::builder()
        .built_in_revocations(b"{}", &[])
        .build()
        .unwrap_err();
    assert_eq!(error.detail(), "the built-in revocation list did not load");
}

#[test]
fn an_entry_with_an_unknown_or_unreadable_reason_code_revokes() {
    // §4: an entry whose reasonCode is unknown (7, or above 10) or does not
    // read revokes, as any reason other than removeFromCRL and
    // certificateHold does.
    let setup = setup();
    let leaf = setup.leaf_serial();
    let revoked = (Err(Reason::CertificateRevoked), Some(NOW + 14 * DAY_MS));
    for code in [7, 11] {
        assert_eq!(
            setup.held(setup.intermediate_list(1, &[&leaf], code)),
            revoked,
            "reasonCode {code}"
        );
    }
    // The control: removeFromCRL, the one reason that does not revoke.
    let removed = setup.held(setup.intermediate_list(1, &[&leaf], 8));
    assert_eq!(removed.0, Ok(()));
    // A reasonCode that does not read. Both carry the value 8, where a
    // reader of the leading value alone would see removeFromCRL.
    let unreadable = [
        (
            "an INTEGER where an ENUMERATED belongs",
            der(tag::INTEGER, &[8]),
        ),
        (
            "octets after the ENUMERATED",
            [der(0x0a, &[8]), vec![0]].concat(),
        ),
    ];
    for (what, value) in unreadable {
        let list = raw_list(
            &subject(&setup.pki.intermediate),
            &setup.pki.intermediate_key,
            NOW - DAY_MS,
            NOW + 14 * DAY_MS,
            &[extension(CRL_NUMBER, false, &der_int(1))],
            &[RawEntry {
                serial: leaf.clone(),
                extensions: vec![extension(REASON_CODE, false, &value)],
            }],
        );
        assert_eq!(setup.held(list), revoked, "{what}");
    }
}

#[test]
fn critical_is_allowed_on_the_extensions_the_profile_reads() {
    // §4: critical is allowed only on a list's AuthorityKeyIdentifier and
    // CRL Number and an entry's reasonCode and invalidityDate. A list with
    // one of them critical stays inside the profile: it is held, its entry
    // revokes and `revocation_valid_until` reports it. Each case runs
    // without the flag first, so only the flag differs.
    let key_id = [0x5a; 20];
    let setup = setup_with_key_identifier(&key_id);
    let leaf = setup.leaf_serial();
    let name = subject(&setup.pki.intermediate);
    let key = &setup.pki.intermediate_key;
    let key_compromise = der(0x0a, &[KEY_COMPROMISE]);
    let reason = |critical: bool| extension(REASON_CODE, critical, &key_compromise);
    let listing = |extensions: Vec<Vec<u8>>, entry_extensions: Vec<Vec<u8>>| {
        raw_list(
            &name,
            key,
            NOW - DAY_MS,
            NOW + 14 * DAY_MS,
            &extensions,
            &[RawEntry {
                serial: leaf.clone(),
                extensions: entry_extensions,
            }],
        )
    };
    let revoked = (Err(Reason::CertificateRevoked), Some(NOW + 14 * DAY_MS));
    for critical in [false, true] {
        let lists = [
            (
                "CRL Number",
                listing(
                    vec![extension(CRL_NUMBER, critical, &der_int(5))],
                    vec![reason(false)],
                ),
            ),
            (
                "AuthorityKeyIdentifier",
                listing(
                    vec![extension(
                        AUTHORITY_KEY_IDENTIFIER,
                        critical,
                        &der_seq(&[der(0x80, &key_id)]),
                    )],
                    vec![reason(false)],
                ),
            ),
            ("reasonCode", listing(vec![], vec![reason(critical)])),
            (
                "invalidityDate",
                listing(
                    vec![],
                    vec![
                        reason(false),
                        extension(INVALIDITY_DATE, critical, &der(0x18, b"20261001000000Z")),
                    ],
                ),
            ),
        ];
        for (what, list) in lists {
            assert_eq!(setup.held(list), revoked, "{what}, critical={critical}");
        }
    }
}

#[test]
fn a_revoked_leaf_is_judged_after_the_signature_and_the_markers() {
    // §3: the check runs once the path, the Apple markers and the signature
    // have passed. A revoked leaf whose signature is bad is
    // INVALID_SIGNATURE, and one without the receipt-signing marker is
    // INVALID_CERTIFICATE_PURPOSE: neither is CERTIFICATE_REVOKED.
    let verdict = |setup: &Setup, receipt: &str| {
        let revoking = [(
            issuer_id(&setup.pki.intermediate),
            serial_hex(&setup.pki.leaf),
        )];
        Verifier::new(setup.builder().distrust(revoking).build().unwrap())
            .verify_receipt(receipt)
            .map(|_| ())
            .map_err(|failure| failure.reason())
    };
    let setup = setup();
    assert_eq!(
        setup.verify(setup.builder()),
        Ok(()),
        "the control: nothing revokes the receipt"
    );
    assert_eq!(
        verdict(&setup, &setup.receipt),
        Err(Reason::CertificateRevoked),
        "the control: the revoked leaf with nothing else wrong"
    );
    let signed = setup
        .pki
        .sign_receipt_at(&payload_at("2026-10-01T00:00:00Z"), NOW);
    let tampered = base64_encode(&pki::corrupt_signatures(&signed, 1));
    assert_eq!(
        verdict(&setup, &tampered),
        Err(Reason::InvalidSignature),
        "a revoked leaf with a bad signature"
    );

    let without_marker = Pki::receipt_with(NOW - 365 * DAY_MS, NOW + 365 * DAY_MS, false, true);
    let unmarked = setup_from(without_marker);
    assert_eq!(
        verdict(&unmarked, &unmarked.receipt),
        Err(Reason::InvalidCertificatePurpose),
        "a revoked leaf without the receipt-signing marker"
    );
}

/// What building a verifier with Apple's four lists costs. Apple's lists
/// are not fixtures (they change daily), so this reads them from the
/// directory `APRV_APPLE_CRLS` names, each saved as `<name>.crl` from
/// `http://crl.apple.com/<name>.crl`, and prints the time per build. Run
/// it in a release build:
///
/// ```sh
/// APRV_APPLE_CRLS=<dir> cargo test --release --test revocation -- \
///   --ignored --nocapture apples_four_lists
/// ```
#[test]
#[ignore = "measures with Apple's live lists from APRV_APPLE_CRLS"]
fn apples_four_lists_build_cost() {
    let dir = std::env::var_os("APRV_APPLE_CRLS").expect("APRV_APPLE_CRLS names a directory");
    let dir = std::path::PathBuf::from(dir);
    let lists: Vec<Vec<u8>> = ["root", "applerootcag3", "wwdrg5", "wwdrg6"]
        .iter()
        .map(|name| std::fs::read(dir.join(format!("{name}.crl"))).expect("a list"))
        .collect();
    let build = || {
        Config::builder()
            .revocation_lists(lists.clone())
            .build()
            .expect("Apple's lists build")
    };
    let verifier = Verifier::new(build());
    println!(
        "revocation_valid_until = {:?}",
        verifier.revocation_valid_until()
    );
    for (label, runs) in [("warm-up", 5), ("measured", 200)] {
        let start = std::time::Instant::now();
        for _ in 0..runs {
            std::hint::black_box(build());
        }
        let per = start.elapsed() / runs;
        println!("{label}: {per:?} per build with the four lists ({runs} runs)");
    }
    let start = std::time::Instant::now();
    for _ in 0..200 {
        std::hint::black_box(Config::builder().build().unwrap());
    }
    println!("no lists: {:?} per build (200 runs)", start.elapsed() / 200);
}
