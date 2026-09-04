//! Trust comes from the caller's anchors and from the three bundled Apple
//! roots. From nowhere else, on any code path.
//!
//! This is the rule the whole library exists to hold, so it is asserted
//! three ways: behaviourally, on a chain that is well-formed in every
//! respect except its anchor; structurally, over the crate's own sources and
//! its declared dependencies; and against this machine's operating-system
//! trust store, which must have no influence at all.

mod common;

use apple_purchase_receipt_verifier::{
    apple_jws_roots, apple_receipt_roots, apple_root_der, chain, datetime, x509::Certificate,
    Environment, JwsVerifier, Reason, ReceiptVerifier, TrustAnchor,
};
use std::time::SystemTime;

fn now_millis() -> i64 {
    datetime::unix_millis_of(SystemTime::now())
}

fn test_data(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
}

/// A chain from a certificate authority this library was not given: a
/// self-signed root, a `CA:true` intermediate carrying Apple's WWDR marker
/// OID, and a leaf carrying Apple's App Store signing marker OID. Every
/// check except the anchor passes, so the only thing that can reject it is
/// the pinning.
fn public_style_chain() -> (Certificate, Certificate, TrustAnchor) {
    (
        Certificate::from_der(&test_data("public-style-leaf.der")).unwrap(),
        Certificate::from_der(&test_data("public-style-intermediate.der")).unwrap(),
        TrustAnchor::from_der(&test_data("public-style-root.der")).unwrap(),
    )
}

#[test]
fn the_public_style_chain_is_genuinely_valid_under_its_own_root() {
    // Without this half, the rejection below would prove nothing: it could
    // be failing for any reason at all.
    let (leaf, intermediate, root) = public_style_chain();
    assert!(leaf.has_extension(apple_purchase_receipt_verifier::LEAF_OID));
    assert!(intermediate.has_extension(apple_purchase_receipt_verifier::INTERMEDIATE_OID));
    assert!(intermediate.is_ca());
    chain::validate_pair(&leaf, &intermediate, &[root], now_millis())
        .expect("the chain must validate against its own root");
}

#[test]
fn the_same_chain_is_rejected_against_apples_pinned_roots() {
    let (leaf, intermediate, _) = public_style_chain();
    for anchors in [apple_jws_roots(), apple_receipt_roots()] {
        let error = chain::validate_pair(&leaf, &intermediate, anchors, now_millis()).unwrap_err();
        assert_eq!(error.reason(), Reason::InvalidChain);
    }
    // And with no anchors at all — there is no ambient set to fall back to.
    let error = chain::validate_pair(&leaf, &intermediate, &[], now_millis()).unwrap_err();
    assert_eq!(error.reason(), Reason::InvalidChain);
}

#[test]
fn the_path_builder_refuses_the_same_chain_too() {
    let (leaf, intermediate, root) = public_style_chain();
    let candidates = vec![leaf.clone(), intermediate.clone()];
    assert!(
        chain::build_and_validate_path(&leaf, &candidates, &[root], now_millis()).is_ok(),
        "the path builder must reach an explicitly supplied anchor"
    );
    assert_eq!(
        chain::build_and_validate_path(&leaf, &candidates, apple_jws_roots(), now_millis())
            .unwrap_err()
            .reason(),
        Reason::InvalidChain
    );
}

#[test]
fn no_root_of_this_machines_trust_store_is_a_bundled_anchor() {
    // If the crate ever started folding the operating system's roots into
    // its own set, this is the first thing that would change.
    let bundled: Vec<&[u8]> = apple_root_der().to_vec();
    let mut checked = 0usize;
    for root in os_trust_store_roots() {
        assert!(
            !bundled.contains(&root.as_slice()),
            "a root from the OS trust store is among the bundled Apple anchors"
        );
        checked += 1;
    }
    if checked == 0 {
        eprintln!("note: no OS trust store found at the conventional paths; skipping the scan");
    }
}

#[test]
fn os_trust_store_roots_do_not_verify_apple_signed_material() {
    // The complement of the pinning test: hand the library the operating
    // system's roots as its anchors and the genuine Apple material is
    // rejected, because those roots did not issue it.
    let roots: Vec<TrustAnchor> = os_trust_store_roots()
        .iter()
        .filter_map(|der| TrustAnchor::from_der(der).ok())
        .collect();
    if roots.is_empty() {
        eprintln!("note: no OS trust store found at the conventional paths; skipping");
        return;
    }
    let receipt = ReceiptVerifier::builder()
        .trusted_roots(roots.clone())
        .bundle_id("dev.bonzer.weeka.app")
        .build()
        .unwrap();
    let genuine = common::read_base64_fixture("public-receipts/receipt-sandbox-g5.b64");
    assert_eq!(
        receipt.verify(&genuine).unwrap_err().reason(),
        Reason::InvalidChain
    );

    let jws = JwsVerifier::builder()
        .trusted_roots(roots)
        .bundle_id("com.example.app")
        .accepted_environments([Environment::Sandbox])
        .build()
        .unwrap();
    assert_eq!(
        jws.verify_transaction(&common::transaction_jws())
            .unwrap_err()
            .reason(),
        Reason::InvalidChain
    );
}

/// Every root in this machine's trust store, as DER, or an empty list where
/// no bundle exists.
fn os_trust_store_roots() -> Vec<Vec<u8>> {
    const BUNDLES: [&str; 4] = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
    ];
    for path in BUNDLES {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let mut out = Vec::new();
        let mut rest = text.as_str();
        while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
            let after = &rest[start..];
            let Some(end) = after.find("-----END CERTIFICATE-----") else {
                break;
            };
            let block = &after[..end + "-----END CERTIFICATE-----".len()];
            if let Ok(cert) = Certificate::from_pem(block) {
                out.push(cert.der().to_vec());
            }
            rest = &after[end..];
        }
        if !out.is_empty() {
            return out;
        }
    }
    Vec::new()
}

// --- the structural half -------------------------------------------------

fn crate_sources() -> Vec<(String, String)> {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                out.push((path.display().to_string(), text));
            }
        }
    }
    assert!(
        out.len() >= 10,
        "the source scan found only {} files",
        out.len()
    );
    out
}

#[test]
fn no_source_file_names_a_system_trust_store_or_a_network_client() {
    // The mechanised form of "pinned anchors only, no network ever". A
    // dependency bump cannot introduce these either: deny.toml refuses the
    // crates that would carry them.
    const FORBIDDEN: [&str; 16] = [
        "rustls_native_certs",
        "rustls-native-certs",
        "webpki_roots",
        "webpki-roots",
        "openssl_sys",
        "openssl-sys",
        "native_tls",
        "native-tls",
        "reqwest",
        "set_default_paths",
        "SystemCertPool",
        "TcpStream",
        "UdpSocket",
        "/etc/ssl",
        "ca-certificates",
        "http://",
    ];
    for (path, text) in crate_sources() {
        for needle in FORBIDDEN {
            assert!(
                !text.contains(needle),
                "{path} names \"{needle}\"; anchors come only from the caller or the bundled roots"
            );
        }
    }
}

#[test]
fn no_source_file_constructs_an_rsa_private_key() {
    // RUSTSEC-2023-0071 (Marvin) is a timing oracle on RSA *private-key*
    // operations. This crate holds no secret and never decrypts: the only
    // `rsa` API it touches is public-key verification. That is what makes
    // the advisory inapplicable, so it is asserted rather than asserted-in-
    // a-comment.
    for (path, text) in crate_sources() {
        for needle in ["RsaPrivateKey", ".decrypt(", "SigningKey", "sign_with_rng"] {
            assert!(!text.contains(needle), "{path} names \"{needle}\"");
        }
    }
}

#[test]
fn the_direct_dependency_set_is_exactly_the_reviewed_one() {
    // A new direct dependency is a supply-chain decision, and it should not
    // be possible to make one by accident.
    const EXPECTED: [&str; 8] = [
        "rsa",
        "p256",
        "p384",
        "sha1",
        "sha2",
        "digest",
        "subtle",
        "serde_json",
    ];
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .unwrap();
    let dependencies = manifest
        .split("[dependencies]")
        .nth(1)
        .unwrap()
        .split("\n[")
        .next()
        .unwrap()
        .lines()
        .filter_map(|line| line.split('=').next())
        .map(str::trim)
        .filter(|name| !name.is_empty() && !name.starts_with('#'))
        .collect::<Vec<_>>();
    assert_eq!(dependencies, EXPECTED, "the direct dependency set changed");
}

#[test]
fn the_bundled_anchors_are_apples_three_published_roots() {
    assert_eq!(apple_jws_roots().len(), 3);
    assert_eq!(apple_receipt_roots().len(), 3);
    // Both sets are the same three (PLAN.md D15): Apple does not commit to a
    // specific root for either path, so anchoring on one would break
    // silently the day a chain were re-anchored under another.
    let jws: Vec<&[u8]> = apple_jws_roots()
        .iter()
        .map(|a| a.certificate().der())
        .collect();
    let receipt: Vec<&[u8]> = apple_receipt_roots()
        .iter()
        .map(|a| a.certificate().der())
        .collect();
    assert_eq!(jws, receipt);
    for anchor in apple_jws_roots() {
        let cert = anchor.certificate();
        assert!(cert.is_ca(), "a bundled anchor must be a CA");
        assert_eq!(
            cert.issuer_der(),
            cert.subject_der(),
            "a bundled anchor is self-issued"
        );
    }
}

#[test]
fn the_bundled_certs_directory_matches_the_repository_root() {
    // `cargo package` cannot reach outside the package directory, so
    // rust/certs/ is a copy. A copy that drifts ships stale trust anchors.
    let repo_certs = common::fixtures_dir().parent().unwrap().join("certs");
    let port_certs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("certs");
    let mut names: Vec<String> = std::fs::read_dir(&repo_certs)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "AppleIncRootCertificate.cer",
            "AppleRootCA-G2.cer",
            "AppleRootCA-G3.cer"
        ]
    );
    for name in &names {
        assert_eq!(
            std::fs::read(repo_certs.join(name)).unwrap(),
            std::fs::read(port_certs.join(name)).unwrap(),
            "rust/certs/{name} has drifted from the repository's certs/{name}"
        );
    }
    // And what is embedded is what is on disk.
    let embedded = apple_root_der();
    for (index, name) in names.iter().enumerate() {
        assert_eq!(
            embedded[index],
            std::fs::read(port_certs.join(name)).unwrap().as_slice()
        );
    }
}

#[test]
fn a_trust_anchors_own_expiry_is_not_checked() {
    // Standard PKIX trust-anchor semantics, and what lets a receipt signed
    // years ago under a since-expired chain verify at its own creation date.
    let verifier = ReceiptVerifier::builder()
        .trusted_roots([common::anchor("generated/receipt-expired-root.der")])
        .bundle_id("com.example.app")
        .build()
        .unwrap();
    let historical = common::read_fixture("generated/receipt-expired-historical.der");
    assert!(verifier.verify(&historical).is_ok());
}
