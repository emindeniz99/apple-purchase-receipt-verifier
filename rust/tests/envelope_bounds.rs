//! The CMS envelope's bounds, and the order in which they run.
//!
//! Before OpenSSL's full decode (`d2i_CMS_ContentInfo`) builds any embedded
//! certificate's key, the adapter walks every header of the whole envelope
//! under 0.7's depth bound (32 constructed values, the `ContentInfo`
//! counted as 1) and node budget (100,000 values), then decodes the
//! envelope shallowly and counts its members. Each test here states one
//! input the core reviews found (docs/evidence/2026-09-29-core-review-fixes.md),
//! the verdict 0.7 gave it, and, through the adapter's full-decode counter,
//! that a refusal happened before the full decode. A timing bound can drift
//! with the machine; the counter cannot.

mod common;

use apple_purchase_receipt_verifier::__internal::cms_full_decodes_during;
use apple_purchase_receipt_verifier::{Failure, Reason, ReceiptPayload};
use common::ber::{parse_exact, Tlv};
use common::{der, der_int, der_oid, der_seq, der_set, tag, CmsBuilder};
use std::time::{Duration, Instant};

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_ENVELOPED_DATA: &str = "1.2.840.113549.1.7.3";
const OID_DATA: &str = "1.2.840.113549.1.7.1";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";

/// The shared receipt's verdict and how many full CMS decodes it took.
fn verify(der: &[u8]) -> (Result<ReceiptPayload, Failure>, usize) {
    let verifier = common::receipt_verifier();
    cms_full_decodes_during(|| common::verify_der(&verifier, der))
}

/// Refused as `MALFORMED` with `message` in the detail, before the full
/// decode.
fn assert_refused_early(der: &[u8], message: &str) {
    let (result, full_decodes) = verify(der);
    let failure = result.expect_err("must be refused");
    assert_eq!(failure.reason(), Reason::Malformed, "{failure}");
    assert!(failure.to_string().contains(message), "{failure}");
    assert_eq!(
        full_decodes, 0,
        "{failure}: refused only after the full decode"
    );
}

fn assert_verifies(der: &[u8]) {
    let (result, full_decodes) = verify(der);
    let payload = result.unwrap_or_else(|failure| panic!("must verify: {failure}"));
    assert_eq!(payload.bundle_id.as_deref(), Some("com.example.app"));
    assert_eq!(full_decodes, 1);
}

/// `levels` nested SEQUENCEs, the innermost empty.
fn nested(levels: usize) -> Vec<u8> {
    nested_in(tag::SEQUENCE, levels)
}

/// `levels` nested constructed values with identifier `identifier`, the
/// innermost empty.
fn nested_in(identifier: u8, levels: usize) -> Vec<u8> {
    let mut value = der(identifier, &[]);
    for _ in 1..levels {
        value = der(identifier, &value);
    }
    value
}

/// The shared receipt rebuilt with the parts `CmsBuilder` does not expose:
/// the `digestAlgorithms` set, extra `CertificateChoices`, a `crls` field
/// and unsigned attributes. The signature covers none of them.
struct Envelope {
    builder: CmsBuilder,
    digest_algorithms: Vec<u8>,
    extra_choices: Vec<Vec<u8>>,
    crls: Option<Vec<u8>>,
    unsigned_attributes: Option<Vec<u8>>,
    /// Encoded values written after the one `SignerInfo`, inside its SET.
    extra_signer_infos: Vec<u8>,
}

impl Envelope {
    fn shared() -> Envelope {
        Envelope {
            builder: CmsBuilder::from_shared(),
            digest_algorithms: der_set(&[der_seq(&[der_oid(OID_SHA256)])]),
            extra_choices: Vec::new(),
            crls: None,
            unsigned_attributes: None,
            extra_signer_infos: Vec::new(),
        }
    }

    fn build(&self) -> Vec<u8> {
        let content = self.builder.content.clone().unwrap();
        let encap = der_seq(&[
            der_oid(OID_DATA),
            der(tag::CONTEXT_0, &der(tag::OCTET_STRING, &content)),
        ]);
        let mut choices = self.builder.certificates.concat();
        for extra in &self.extra_choices {
            choices.extend_from_slice(extra);
        }
        let mut signer_info = self.builder.signer_info();
        if let Some(unsigned) = &self.unsigned_attributes {
            let mut body = parse_exact(&signer_info).unwrap().contents.to_vec();
            body.extend_from_slice(unsigned);
            signer_info = der(tag::SEQUENCE, &body);
        }
        let mut parts = vec![
            der_int(1),
            self.digest_algorithms.clone(),
            encap,
            der(tag::CONTEXT_0, &choices),
        ];
        if let Some(crls) = &self.crls {
            parts.push(crls.clone());
        }
        signer_info.extend_from_slice(&self.extra_signer_infos);
        parts.push(der(tag::SET, &signer_info));
        der_seq(&[
            der_oid(OID_SIGNED_DATA),
            der(tag::CONTEXT_0, &der_seq(&parts)),
        ])
    }
}

/// `[1] IMPLICIT` unsigned attributes holding one attribute whose one value
/// is `value`.
fn unsigned_attribute(value: &[u8]) -> Vec<u8> {
    der(
        tag::CONTEXT_1,
        &der_seq(&[der_oid("1.2.3.4"), der_set(&[value.to_vec()])]),
    )
}

/// A minimal `CertificateList` whose signature algorithm carries
/// `parameters`.
fn crl(parameters: &[u8]) -> Vec<u8> {
    let algorithm = der_seq(&[der_oid(SHA256_WITH_RSA), parameters.to_vec()]);
    let tbs = der_seq(&[
        algorithm.clone(),
        common::mint::name("CRL Issuer"),
        der(tag::UTC_TIME, b"240101000000Z"),
    ]);
    der_seq(&[tbs, algorithm, der(tag::BIT_STRING, &[0, 1, 2, 3])])
}

fn count_nodes(value: &Tlv<'_>) -> usize {
    1 + value.children().iter().map(count_nodes).sum::<usize>()
}

#[test]
fn the_genuine_receipt_takes_one_full_decode() {
    // The seam's control: the counter sees the one full decode a receipt
    // that reaches it takes.
    assert_verifies(&common::receipt_der());
    assert_verifies(&Envelope::shared().build());
}

#[test]
fn a_certificate_flood_behind_a_broken_envelope_never_reaches_the_full_decode() {
    // C-F1, Rust-F2, Policy-F3: the ten-certificate bound used to run only
    // on an envelope the shallow decode accepted, so one trailing byte, a
    // broken signerInfos or another content type sent 1,057 certificates
    // (or 5,440 with explicit curves) through the full decode, 85 to 120
    // times the bounded cost, before the input was refused anyway.
    let mut flood = CmsBuilder::from_shared();
    let original = flood.certificates[0].clone();
    while flood.certificates.len() < 1057 {
        flood.certificates.push(original.clone());
    }
    let well_formed = flood.build();
    assert_refused_early(&well_formed, "1057 certificates");

    let mut trailing = well_formed.clone();
    trailing.push(0x00);
    assert_refused_early(&trailing, "bytes follow the CMS ContentInfo");

    // signerInfos written as a SEQUENCE, where the grammar has a SET.
    let broken = {
        let content = flood.content.clone().unwrap();
        let encap = der_seq(&[
            der_oid(OID_DATA),
            der(tag::CONTEXT_0, &der(tag::OCTET_STRING, &content)),
        ]);
        let signed_data = der_seq(&[
            der_int(1),
            der_set(&[der_seq(&[der_oid(OID_SHA256)])]),
            encap,
            der(tag::CONTEXT_0, &flood.certificates.concat()),
            der_seq(&[flood.signer_info()]),
        ]);
        der_seq(&[der_oid(OID_SIGNED_DATA), der(tag::CONTEXT_0, &signed_data)])
    };
    assert_refused_early(&broken, "not a CMS ContentInfo");

    // An EnvelopedData whose originatorInfo carries the certificates:
    // OpenSSL's full decode builds them there too.
    let enveloped = {
        let originator = der(
            tag::CONTEXT_0,
            &der(tag::CONTEXT_0, &flood.certificates.concat()),
        );
        let encrypted = der_seq(&[
            der_oid(OID_DATA),
            der_seq(&[der_oid("2.16.840.1.101.3.4.1.42")]),
        ]);
        let body = der_seq(&[der_int(2), originator, der_set(&[]), encrypted]);
        der_seq(&[der_oid(OID_ENVELOPED_DATA), der(tag::CONTEXT_0, &body)])
    };
    let (result, full_decodes) = verify(&enveloped);
    assert_eq!(result.unwrap_err().reason(), Reason::Malformed);
    assert_eq!(full_decodes, 0);

    // Eleven certificates and a trailing byte: the smallest input of the
    // shape, for a port that states the bound on the count.
    let mut eleven = CmsBuilder::from_shared();
    while eleven.certificates.len() < 11 {
        eleven.certificates.push(original.clone());
    }
    let mut eleven = eleven.build();
    eleven.push(0x00);
    assert_refused_early(&eleven, "bytes follow the CMS ContentInfo");
}

#[test]
fn the_depth_bound_counts_every_constructed_value_of_the_envelope() {
    // C-F2, Rust-F3, Policy-F2: the depth used to be measured only in
    // SignerInfo attribute values and algorithm parameters, and only through
    // universal SEQUENCEs and SETs, so these places verified at depth 33 and
    // at depth 2,000. 0.7 and Java refuse each one; 32 verifies.
    //
    // ContentInfo 1, [0] 2, SignedData 3, then per place:
    // digestAlgorithms: SET 4, AlgorithmIdentifier 5, parameters from 6.
    for (levels, refused) in [(27, false), (28, true), (2_000, true)] {
        let mut envelope = Envelope::shared();
        envelope.digest_algorithms = der_set(&[der_seq(&[der_oid(OID_SHA256), nested(levels)])]);
        check_depth(&envelope.build(), refused);
    }
    // certificates: [0] 4, a [2] choice 5, its content from 6.
    for (levels, refused) in [(27, false), (28, true)] {
        let mut envelope = Envelope::shared();
        envelope.extra_choices = vec![der(tag::CONTEXT_2, &nested(levels))];
        check_depth(&envelope.build(), refused);
    }
    // crls: [1] 4, CertificateList 5, TBSCertList 6, AlgorithmIdentifier
    // 7, parameters from 8.
    for (levels, refused) in [(25, false), (26, true)] {
        let mut envelope = Envelope::shared();
        envelope.crls = Some(der(tag::CONTEXT_1, &crl(&nested(levels))));
        check_depth(&envelope.build(), refused);
    }
    // An unsigned attribute value nested in context tags, or in an
    // application tag, or a context tag under a SEQUENCE: signerInfos 4,
    // SignerInfo 5, [1] 6, Attribute 7, SET 8, the value from 9.
    for identifier in [0xa0, 0x61] {
        for (levels, refused) in [(24, false), (25, true)] {
            let mut envelope = Envelope::shared();
            envelope.unsigned_attributes = Some(unsigned_attribute(&nested_in(identifier, levels)));
            check_depth(&envelope.build(), refused);
        }
    }
    let mut envelope = Envelope::shared();
    envelope.unsigned_attributes = Some(unsigned_attribute(&der_seq(&[nested_in(0xa0, 24)])));
    check_depth(&envelope.build(), true);
    // An embedded certificate's outer signature algorithm parameters:
    // [0] 4, Certificate 5, AlgorithmIdentifier 6, parameters from 7.
    let intermediate = Envelope::shared().builder.certificates[1].clone();
    let certificate = parse_exact(&intermediate).unwrap();
    let copy = der_seq(&[
        certificate.child(0).unwrap().full.to_vec(),
        der_seq(&[
            certificate
                .child(1)
                .unwrap()
                .child(0)
                .unwrap()
                .full
                .to_vec(),
            nested(27),
        ]),
        certificate.child(2).unwrap().full.to_vec(),
    ]);
    let mut envelope = Envelope::shared();
    envelope.extra_choices = vec![copy];
    check_depth(&envelope.build(), true);
}

fn check_depth(der: &[u8], refused: bool) {
    if refused {
        assert_refused_early(der, "nested deeper than 32 constructed values");
    } else {
        assert_verifies(der);
    }
}

#[test]
fn the_envelope_holds_at_most_100000_values() {
    // Rust-F4, Policy-F6: the node budget of 0.7's reader was gone, so an
    // unsigned attribute of 1.17 million empty SEQUENCEs cost 0.6 s and
    // about 130 MB before any cryptography, and verified. The walk restores
    // the budget over the whole envelope: 100,000 values verify, 100,001 are
    // MALFORMED before the full decode.
    let base = Envelope::shared().build();
    let base_nodes = count_nodes(&parse_exact(&base).unwrap());
    // [1], the Attribute, its OID and its SET, then the values.
    let values = 100_000 - base_nodes - 4;
    for (count, refused) in [(values, false), (values + 1, true)] {
        let mut envelope = Envelope::shared();
        envelope.unsigned_attributes = Some(der(
            tag::CONTEXT_1,
            &der_seq(&[
                der_oid("1.2.3.4"),
                der(tag::SET, &[0x05, 0x00].repeat(count)),
            ]),
        ));
        let der = envelope.build();
        if refused {
            assert_refused_early(&der, "more than 100000 ASN.1 values");
        } else {
            assert_verifies(&der);
        }
    }
}

#[test]
fn at_most_ten_crls_are_embedded() {
    // C-F5: the crls field was neither counted nor bounded, so a genuine
    // receipt padded with 39,121 junk CRLs verified after 319 ms of CRL
    // decoding. Apple's receipts carry none; the certificate bound applies.
    let ten = der(tag::CONTEXT_1, &crl(&der(0x05, &[])).repeat(10));
    let mut envelope = Envelope::shared();
    envelope.crls = Some(ten);
    assert_verifies(&envelope.build());
    envelope.crls = Some(der(tag::CONTEXT_1, &crl(&der(0x05, &[])).repeat(11)));
    assert_refused_early(&envelope.build(), "embeds 11 CRLs");
}

/// The shared receipt with its eContent re-chunked into `levels`
/// constructed `OCTET STRING`s around the original octets, `leaf` the
/// innermost chunk's identifier. The signature covers the joined octets,
/// which do not change.
fn rechunked(levels: usize, leaf: u8) -> Vec<u8> {
    let mut builder = CmsBuilder::from_shared();
    let mut value = der(leaf, builder.content.as_ref().unwrap());
    for _ in 0..levels {
        value = der(tag::OCTET_STRING_CONSTRUCTED, &value);
    }
    builder.content_tlv = Some(value);
    builder.build()
}

#[test]
fn econtent_rechunked_into_six_constructed_levels_verifies() {
    // Rust-F1, C-F4, Policy-F4: OpenSSL decodes six constructed levels of
    // OCTET STRING (its ASN1_MAX_STRING_NEST is 5, counted from 0), and the
    // adapter's chunk check stopped at five, with a message that blamed a
    // chunk's type. Seven is refused by OpenSSL's own bound, which 0.7 and
    // Java do not have (DECISIONS.md R20).
    for levels in [1, 5, 6] {
        let (result, _) = verify(&rechunked(levels, tag::OCTET_STRING));
        assert!(result.is_ok(), "{levels} levels: {result:?}");
    }
    // The walk refuses the seventh level before any decode, and names it.
    assert_refused_early(
        &rechunked(7, tag::OCTET_STRING),
        "a constructed string nests deeper than OpenSSL decodes",
    );
    // A chunk of another tag, or of another class, is joined as OpenSSL
    // joins it: `asn1_collect` runs with tag -1, so neither the tag nor the
    // class of a chunk is checked. The signature covers the joined octets,
    // which do not change (DECISIONS.md R20).
    for leaf in [tag::UTF8_STRING, 0x80] {
        let (result, _) = verify(&rechunked(6, leaf));
        assert!(result.is_ok(), "leaf {leaf:#04x}: {result:?}");
    }
}

#[test]
fn values_kept_whole_in_the_envelope_are_valid_asn1() {
    // OpenSSL keeps unsigned attribute values, algorithm parameters and
    // the like whole, as raw ANY values, without looking inside; the
    // header walk hands every primitive of a constrained type it passes to
    // OpenSSL's own decoder, as the removed per-level re-decode did for
    // SEQUENCEs and SETs. A padded INTEGER (X.690 section 8.3.2) or a
    // BOOLEAN of two octets is not a value, whatever tag it sits under.
    for value in [
        der_seq(&[vec![0x02, 0x02, 0x00, 0x01]]),
        der(0xa0, &[0x01, 0x02, 0x00, 0x00]),
        vec![0x05, 0x01, 0x00],
    ] {
        let mut envelope = Envelope::shared();
        envelope.unsigned_attributes = Some(unsigned_attribute(&value));
        assert_refused_early(&envelope.build(), "not a CMS ContentInfo");
    }
    let mut envelope = Envelope::shared();
    envelope.unsigned_attributes = Some(unsigned_attribute(&der(
        0xa0,
        &[der_int(1), der(0x01, &[0xff]), der(0x05, &[])].concat(),
    )));
    assert_verifies(&envelope.build());
}

/// The shared receipt with `count` two-octet `30 00` entries added to one of
/// the three sets the shallow decode keeps as `SET OF ANY`, each of which
/// would cost it an allocation.
fn tiny_entry_flood(set: &str, count: usize) -> Vec<u8> {
    let entries = [0x30, 0x00].repeat(count);
    let mut envelope = Envelope::shared();
    match set {
        "certificates" => envelope.extra_choices = vec![entries],
        "crls" => envelope.crls = Some(der(tag::CONTEXT_1, &entries)),
        "signerInfos" => envelope.extra_signer_infos = entries,
        other => unreachable!("{other}"),
    }
    envelope.build()
}

/// As many two-octet entries as keep the envelope inside the 3 MiB base64
/// cap on receipts: about 1.17 million.
const TINY_ENTRIES: usize = (2_359_296 - 8_000) / 2;

#[test]
fn a_million_tiny_set_entries_are_refused_by_the_node_budget_first() {
    // Round-2 review F1: the shallow decode keeps the certificates, crls
    // and signerInfos sets as SET OF ANY, so OpenSSL allocated a value per
    // entry, 1.17 million of them (0.6 to 0.95 s and about 114 MB), before
    // the member bounds refused the count. The walk now runs first, so the
    // node budget refuses the set after 100,000 values; the answer names
    // the budget, not the member count, which is the order this pins.
    for set in ["certificates", "crls", "signerInfos"] {
        assert_refused_early(
            &tiny_entry_flood(set, TINY_ENTRIES),
            "more than 100000 ASN.1 values",
        );
    }
    // Under the budget, the member bounds still answer, with the count.
    assert_refused_early(
        &tiny_entry_flood("certificates", 20),
        "embeds 23 certificates",
    );
    assert_refused_early(&tiny_entry_flood("crls", 11), "embeds 11 CRLs");
    assert_refused_early(&tiny_entry_flood("signerInfos", 4), "carries 5 SignerInfos");
}

#[test]
fn a_tiny_entry_flood_costs_what_junk_of_its_size_costs() {
    // F1's cost, end to end through `verify_receipt`, base64 included: the
    // reviewer measured about 770 ms a call for the certificates flood
    // against 5 ms for junk of the same size, and the process's peak memory
    // grew from 21 to 146 MB. The junk is refused at its first header, so
    // what it costs is decoding 3 MiB of base64, which any reader of the
    // flood pays; the flood may add the walk of 100,000 values on top.
    // Half the junk's cost again, plus ten genuine verifications, is
    // headroom for that walk and for timing noise; a shallow decode of the
    // 1.17 million entries costs several times more.
    let verifier = common::receipt_verifier();
    let encode = apple_purchase_receipt_verifier::__internal::base64_encode;
    let floods: Vec<String> = ["certificates", "crls", "signerInfos"]
        .into_iter()
        .map(|set| encode(&tiny_entry_flood(set, TINY_ENTRIES)))
        .collect();
    let mut junk_der = tiny_entry_flood("certificates", TINY_ENTRIES);
    junk_der[0] = 0x04;
    let (junk, genuine) = (encode(&junk_der), encode(&common::receipt_der()));

    let mut genuine_cost = Duration::ZERO;
    let mut junk_cost = Duration::ZERO;
    let mut flood_costs = [Duration::ZERO; 3];
    for _ in 0..3 {
        let started = Instant::now();
        verifier.verify_receipt(&genuine).unwrap();
        genuine_cost += started.elapsed();

        let started = Instant::now();
        let refused = verifier.verify_receipt(&junk).unwrap_err();
        junk_cost += started.elapsed();
        assert_eq!(refused.reason(), Reason::Malformed);

        for (flood, cost) in floods.iter().zip(&mut flood_costs) {
            let started = Instant::now();
            let refused = verifier.verify_receipt(flood).unwrap_err();
            *cost += started.elapsed();
            assert_eq!(refused.reason(), Reason::Malformed);
            assert!(
                refused
                    .to_string()
                    .contains("more than 100000 ASN.1 values"),
                "{refused}"
            );
        }
    }
    for (set, cost) in ["certificates", "crls", "signerInfos"]
        .into_iter()
        .zip(flood_costs)
    {
        assert!(
            cost < junk_cost * 3 / 2 + genuine_cost * 10,
            "a flood of {TINY_ENTRIES} tiny {set} entries cost {cost:?}, against {junk_cost:?} \
             for junk of the same size and {genuine_cost:?} for a genuine receipt: the shallow \
             decode is building the set before the node budget refuses it"
        );
    }
}

#[test]
fn what_openssl_refuses_on_its_own_is_refused_in_the_envelope_at_every_depth() {
    // Round-2 review F3: an unsigned attribute value OpenSSL's ANY decoder
    // refuses (a short UTCTime or GeneralizedTime, a constructed INTEGER,
    // NULL or OID, a string of seven constructed levels) was MALFORMED
    // directly and verified inside one SEQUENCE, which OpenSSL keeps whole.
    // The walk now applies OpenSSL's rules at every depth. Six levels, and
    // a constructed time of 13 joined octets, verify at both.
    let seven_levels = rechunked_value(7);
    let refused = [
        (vec![0x17, 0x01, 0x30], "not a CMS ContentInfo"),
        (vec![0x18, 0x02, 0x32, 0x30], "not a CMS ContentInfo"),
        (vec![0x22, 0x03, 0x02, 0x01, 0x05], "not a CMS ContentInfo"),
        (vec![0x25, 0x02, 0x05, 0x00], "not a CMS ContentInfo"),
        (vec![0x26, 0x03, 0x06, 0x01, 0x2a], "not a CMS ContentInfo"),
        (vec![0x10, 0x00], "not a CMS ContentInfo"),
        (
            seven_levels,
            "a constructed string nests deeper than OpenSSL decodes",
        ),
    ];
    for (value, message) in &refused {
        for placed in [value.clone(), der_seq(std::slice::from_ref(value))] {
            let mut envelope = Envelope::shared();
            envelope.unsigned_attributes = Some(unsigned_attribute(&placed));
            assert_refused_early(&envelope.build(), message);
        }
    }
    let time = [
        &[0x37, 0x11][..],
        &der(tag::OCTET_STRING, b"240101"),
        &der(tag::OCTET_STRING, b"000000Z"),
    ]
    .concat();
    for value in [rechunked_value(6), time] {
        for placed in [value.clone(), der_seq(std::slice::from_ref(&value))] {
            let mut envelope = Envelope::shared();
            envelope.unsigned_attributes = Some(unsigned_attribute(&placed));
            assert_verifies(&envelope.build());
        }
    }
}

/// An `OCTET STRING` of `levels` constructed levels around one octet.
fn rechunked_value(levels: usize) -> Vec<u8> {
    let mut value = der(tag::OCTET_STRING, b"x");
    for _ in 0..levels {
        value = der(tag::OCTET_STRING_CONSTRUCTED, &value);
    }
    value
}

#[test]
fn the_full_decode_counter_survives_a_panic_inside_it() {
    // Round-2 review N3: a panic in the counted body left the thread's
    // counter replaced, so an enclosing count lost what it had counted.
    let verifier = common::receipt_verifier();
    let receipt = common::receipt_der();
    let ((), outer) = cms_full_decodes_during(|| {
        assert!(common::verify_der(&verifier, &receipt).is_ok());
        let inner = std::panic::catch_unwind(|| {
            cms_full_decodes_during(|| panic!("a test body that panics"))
        });
        assert!(inner.is_err());
        assert!(common::verify_der(&verifier, &receipt).is_ok());
    });
    assert_eq!(outer, 2);
}

/// `levels` nested indefinite-length values with identifier `identifier`,
/// the innermost empty.
fn nested_indefinite(identifier: u8, levels: usize) -> Vec<u8> {
    let mut value = vec![identifier, 0x80, 0, 0];
    for _ in 1..levels {
        value = [&[identifier, 0x80][..], &value, &[0, 0]].concat();
    }
    value
}

#[test]
fn indefinite_lengths_meet_the_same_bounds_and_must_end() {
    // Round-2 review N4: the walk follows indefinite lengths to their
    // end-of-contents under the same depth and node bounds; nothing pinned
    // it. The unsigned value starts at depth 9 (see the depth test above).
    for (levels, refused) in [(24, false), (25, true), (3_000, true)] {
        let mut envelope = Envelope::shared();
        envelope.unsigned_attributes = Some(unsigned_attribute(&nested_indefinite(
            tag::SEQUENCE,
            levels,
        )));
        check_depth(&envelope.build(), refused);
    }
    // Values of indefinite length count one each, their end-of-contents
    // none: 100,000 verify, one more is refused.
    let base_nodes = count_nodes(&parse_exact(&Envelope::shared().build()).unwrap());
    let values = 100_000 - base_nodes - 4;
    for (count, refused) in [(values, false), (values + 1, true)] {
        let mut envelope = Envelope::shared();
        envelope.unsigned_attributes = Some(der(
            tag::CONTEXT_1,
            &der_seq(&[
                der_oid("1.2.3.4"),
                der(tag::SET, &[0x30, 0x80, 0x00, 0x00].repeat(count)),
            ]),
        ));
        if refused {
            assert_refused_early(&envelope.build(), "more than 100000 ASN.1 values");
        } else {
            assert_verifies(&envelope.build());
        }
    }
    // The unsigned attributes in indefinite form, with and without their
    // end-of-contents: without it the value runs past its SignerInfo.
    let attribute = der_seq(&[der_oid("1.2.3.4"), der_set(&[vec![0x05, 0x00]])]);
    let mut envelope = Envelope::shared();
    envelope.unsigned_attributes =
        Some([&[tag::CONTEXT_1, 0x80][..], &attribute, &[0, 0]].concat());
    assert_verifies(&envelope.build());
    envelope.unsigned_attributes = Some([&[tag::CONTEXT_1, 0x80][..], &attribute].concat());
    assert_refused_early(&envelope.build(), "not a CMS ContentInfo");
    // An end-of-contents in a value of definite length is refused too, as
    // OpenSSL refuses it wherever it decodes one.
    let mut envelope = Envelope::shared();
    envelope.unsigned_attributes = Some(unsigned_attribute(&der_seq(&[vec![0x00, 0x00]])));
    assert_refused_early(&envelope.build(), "not a CMS ContentInfo");
}

#[test]
fn a_length_one_octet_past_its_container_is_refused() {
    // Round-2 review N4: a value whose length runs one octet past the value
    // around it, here an OCTET STRING of two octets declared as three
    // inside its SET, is refused before any decode.
    let mut attribute = der_seq(&[der_oid("1.2.3.4"), der_set(&[vec![0x04, 0x02, 0xaa, 0xbb]])]);
    let length = attribute.len() - 3;
    attribute[length] = 0x03;
    let mut envelope = Envelope::shared();
    envelope.unsigned_attributes = Some(der(tag::CONTEXT_1, &attribute));
    assert_refused_early(&envelope.build(), "not a CMS ContentInfo");
}

/// A certificate with its outer signature `BIT STRING` (outside the signed
/// TBS) re-encoded as a constructed `BIT STRING` of two chunks, `03 01 00`
/// and `03 L sig`: OpenSSL joins the chunks to the same `00 || sig`.
fn signature_in_two_chunks(certificate: &[u8]) -> Vec<u8> {
    let parsed = parse_exact(certificate).unwrap();
    let bits = parsed.child(2).unwrap();
    assert_eq!((bits.tag, bits.contents[0]), (0x03, 0));
    let chunks = [der(0x03, &[0x00]), der(0x03, &bits.contents[1..])].concat();
    der_seq(&[
        parsed.child(0).unwrap().full.to_vec(),
        parsed.child(1).unwrap().full.to_vec(),
        der(0x23, &chunks),
    ])
}

#[test]
fn chunks_inside_a_constructed_string_are_joined_not_judged() {
    // Round-3 review F2: the walk judged each primitive chunk of a
    // constructed string as a value of its own. OpenSSL's `asn1_collect`
    // joins chunk contents whatever their tags, and the walk already hands
    // the whole string to OpenSSL. So a certificate whose signature
    // BIT STRING was split in two verified or was MALFORMED by the
    // signature's first octet (above 7, it read as an unused-bits count).
    let shared = CmsBuilder::from_shared();
    let mut pinned = 0;
    for index in 0..shared.certificates.len() {
        let original = &shared.certificates[index];
        let first_octet = parse_exact(original).unwrap().child(2).unwrap().contents[1];
        pinned += usize::from(first_octet > 7);
        let mut builder = CmsBuilder::from_shared();
        builder.certificates[index] = signature_in_two_chunks(original);
        assert_verifies(&builder.build());
    }
    assert!(
        pinned > 0,
        "no signature starts above 7: the test pins nothing"
    );
    // The same inside an unsigned attribute value: a constructed OCTET
    // STRING whose chunks are a padded INTEGER and a short UTCTime by tag.
    // Each alone is a value OpenSSL refuses; as chunks they are octets.
    let chunks = [
        der(0x02, &[0x00, 0x00, 0x01]),
        der(0x17, b"0"),
        der(tag::OCTET_STRING, b"x"),
    ]
    .concat();
    let value = der(tag::OCTET_STRING_CONSTRUCTED, &chunks);
    for placed in [value.clone(), der_seq(std::slice::from_ref(&value))] {
        let mut envelope = Envelope::shared();
        envelope.unsigned_attributes = Some(unsigned_attribute(&placed));
        assert_verifies(&envelope.build());
    }
}
