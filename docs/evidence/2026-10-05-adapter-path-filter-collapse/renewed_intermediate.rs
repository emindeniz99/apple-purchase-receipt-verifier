//! Evidence only (2026-10-05). A genuine receipt whose unsigned bag holds
//! two certificates for one intermediate key: a renewal, valid at the
//! chain instant, and the expired certificate it replaced. Both are issued
//! by the pinned root, and either one's key verifies the signer. Copy to
//! `rust/tests/renewed_intermediate.rs` and run `cargo test -p
//! apple-purchase-receipt-verifier --test renewed_intermediate --
//! --nocapture`.

mod common;

use apple_purchase_receipt_verifier::{Config, TrustAnchor, Verifier};
use common::mint::{
    assemble, certificate, key, name, spki, ECDSA_WITH_SHA256, RECEIPT_SIGNER_MARKER, WWDR_MARKER,
};
use common::{der, der_int, der_oid, der_seq};

#[test]
fn renewed_intermediate() {
    let (root_key, intermediate_key, signer_key) = (key(81), key(82), key(83));
    let root = certificate("Renewal Root", &root_key, "Renewal Root", &root_key, 1, true, None);
    let renewed = certificate(
        "Renewal WWDR",
        &intermediate_key,
        "Renewal Root",
        &root_key,
        2,
        true,
        Some(WWDR_MARKER),
    );
    // The same subject and key, valid 2010 to 2015 only.
    let algorithm = der_seq(&[der_oid(ECDSA_WITH_SHA256)]);
    let tbs = der_seq(&[
        der(0xA0, &der_int(2)),
        der_int(4),
        algorithm.clone(),
        name("Renewal Root"),
        der_seq(&[der(0x17, b"100101000000Z"), der(0x17, b"150101000000Z")]),
        name("Renewal WWDR"),
        spki(&intermediate_key),
        der(
            0xA3,
            &der_seq(&[
                der_seq(&[
                    der_oid("2.5.29.19"),
                    der(0x01, &[0xFF]),
                    der(0x04, &der_seq(&[der(0x01, &[0xFF])])),
                ]),
                der_seq(&[der_oid(WWDR_MARKER), der(0x04, &[0x05, 0x00])]),
            ]),
        ),
    ]);
    let expired = assemble(tbs.clone(), algorithm, &root_key.sign_der(&tbs));
    let signer = certificate(
        "Renewal Signer",
        &signer_key,
        "Renewal WWDR",
        &intermediate_key,
        3,
        false,
        Some(RECEIPT_SIGNER_MARKER),
    );
    // No attribute 12: the receipt is judged at the clock, 2025-01-01.
    let content = common::der_set(&[der_seq(&[
        der_int(2),
        der_int(1),
        der(0x04, &der(0x0c, b"com.example.app")),
    ])]);
    let verifier = Verifier::new(
        Config::builder()
            .roots([TrustAnchor::from_der(&root).unwrap()])
            .clock(|| 1_735_689_600_000)
            .build()
            .unwrap(),
    );
    for (order, bag) in [
        ("renewed first", vec![renewed.clone(), expired.clone(), signer.clone()]),
        ("expired first", vec![expired.clone(), renewed.clone(), signer.clone()]),
    ] {
        let mut builder = common::CmsBuilder::from_shared();
        builder.certificates = bag;
        builder.signer_issuer = name("Renewal WWDR");
        builder.signer_serial = vec![3];
        builder.signed_attrs = None;
        builder.signature_algorithm = der_seq(&[der_oid(ECDSA_WITH_SHA256)]);
        builder.signature = signer_key.sign_der(&content);
        builder.content = Some(content.clone());
        let answer = common::verify_der(&verifier, &builder.build())
            .map(|_| "ok".to_owned())
            .unwrap_or_else(|failure| failure.to_string());
        eprintln!("RENEWAL {order}: {answer}");
    }
}
