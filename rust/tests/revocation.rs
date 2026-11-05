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

/// A receipt PKI, valid around 2026-11-05, and its receipt.
struct Setup {
    pki: Pki,
    receipt: String,
}

/// 2026-11-05T00:00:00Z.
const NOW: i64 = 1_793_836_800_000;

fn setup() -> Setup {
    let pki = Pki::receipt_with(NOW - 365 * DAY_MS, NOW + 365 * DAY_MS, true, true);
    let receipt = base64_encode(&pki.sign_receipt_at(&payload_at("2026-10-01T00:00:00Z"), NOW));
    Setup { pki, receipt }
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
fn more_than_100000_entries_in_all_are_refused() {
    let setup = setup();
    // Three lists of 33,334 entries (100,002 in all), each under 1 MiB.
    let lists: Vec<Vec<u8>> = (0..3u64)
        .map(|index| {
            let entries: Vec<Entry> = (0..33_334u64)
                .map(|n| Entry {
                    serial: pki::unsigned_integer(&(index * 1_000_000 + n + 1).to_be_bytes()),
                    reason: None,
                })
                .collect();
            list(
                &subject(&setup.pki.intermediate),
                &setup.pki.intermediate_key,
                NOW - DAY_MS,
                NOW + 14 * DAY_MS,
                Some(index + 1),
                &entries,
            )
        })
        .collect();
    assert!(lists.iter().all(|list| list.len() < 1_048_576));
    let error = setup
        .builder()
        .revocation_lists(lists.clone())
        .revocation_issuers([common::anchor_from_der(&setup.pki.intermediate)])
        .build()
        .unwrap_err();
    assert_eq!(
        error.detail(),
        "revocation_lists[2]: the lists hold more than 100,000 entries in all"
    );
    // Two of them, 66,668 entries, build: the larger one is kept.
    let config = setup
        .builder()
        .revocation_lists(lists.into_iter().take(2))
        .revocation_issuers([common::anchor_from_der(&setup.pki.intermediate)])
        .build()
        .unwrap();
    assert_eq!(
        Verifier::new(config).revocation_valid_until(),
        Some(NOW + 14 * DAY_MS)
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
        (&intermediate.replacen('a', "g", 1)[..], "02"),
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
fn an_issuer_its_root_holds_is_refused_when_the_configuration_is_built() {
    // The build has no clock (§6), so an issuer on its root's list is not
    // accepted whatever the entry's reason, certificateHold included; only
    // removeFromCRL lets it through.
    let setup = setup();
    let intermediate_serial = pki::cert_fields(&setup.pki.intermediate).serial;
    for (reason, accepted) in [
        (Some(KEY_COMPROMISE), false),
        (Some(CERTIFICATE_HOLD), false),
        (None, false),
        (Some(8), true),
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
        let built = setup
            .builder()
            .revocation_lists([root_list])
            .revocation_issuers([common::anchor_from_der(&setup.pki.intermediate)])
            .build();
        assert_eq!(built.is_ok(), accepted, "{reason:?}");
        if let Err(error) = built {
            assert_eq!(
                error.detail(),
                "revocation_issuers[0]: the certificate is revoked"
            );
        }
    }
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
