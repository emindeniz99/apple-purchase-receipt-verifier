//! Trust comes from the caller's anchors and from the three bundled Apple
//! roots. From nowhere else, on any code path.
//!
//! This is the rule the whole library exists to hold, so it is asserted
//! three ways: behaviourally, on a chain that is well-formed in every
//! respect except its anchor; structurally, over the sources and declared
//! dependencies of the crate and of its OpenSSL adapter; and against this
//! machine's operating-system trust store, which must have no influence at
//! all. The OpenSSL adapter's own test (openssl/tests/isolation.rs) plants
//! that trust store, a hostile OpenSSL configuration and more in the
//! environment and checks OpenSSL reads none of them.

mod common;

use apple_purchase_receipt_verifier::__internal::datetime;
use apple_purchase_receipt_verifier::__internal::path::{self, Certificate};
use apple_purchase_receipt_verifier::{Config, Reason, TrustAnchor};
use std::time::SystemTime;

const LEAF_OID: &str = "1.2.840.113635.100.6.11.1";
const INTERMEDIATE_OID: &str = "1.2.840.113635.100.6.2.1";

fn apple_roots() -> Vec<TrustAnchor> {
    Config::defaults().roots().to_vec()
}

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
    assert!(leaf.has_extension(LEAF_OID));
    assert!(intermediate.has_extension(INTERMEDIATE_OID));
    assert!(intermediate.may_issue_certificates());
    path::validate_pair(&leaf, &intermediate, &[root], now_millis())
        .expect("the chain must validate against its own root");
}

#[test]
fn the_same_chain_is_rejected_against_apples_pinned_roots() {
    let (leaf, intermediate, _) = public_style_chain();
    let error =
        path::validate_pair(&leaf, &intermediate, &apple_roots(), now_millis()).unwrap_err();
    assert_eq!(error.reason(), Reason::UntrustedChain);
    // And with no anchors at all: there is no ambient set to fall back to.
    let error = path::validate_pair(&leaf, &intermediate, &[], now_millis()).unwrap_err();
    assert_eq!(error.reason(), Reason::UntrustedChain);
}

#[test]
fn the_path_builder_refuses_the_same_chain_too() {
    let (leaf, intermediate, root) = public_style_chain();
    let embedded = vec![leaf.clone(), intermediate.clone()];
    let roots = [root];
    let candidates = path::authenticated_top_down(&embedded, &roots);
    assert_eq!(candidates.len(), 2, "both certificates chain to the root");
    assert!(
        path::receipt_path(&leaf, &candidates, &roots, now_millis()).is_ok(),
        "the path builder must reach an explicitly supplied anchor"
    );
    let apple = apple_roots();
    let candidates = path::authenticated_top_down(&embedded, &apple);
    assert!(
        candidates.is_empty(),
        "nothing here is vouched for by Apple"
    );
    assert_eq!(
        path::receipt_path(&leaf, &candidates, &apple, now_millis())
            .unwrap_err()
            .reason(),
        Reason::UntrustedChain
    );
}

#[test]
fn no_root_of_this_machines_trust_store_is_a_bundled_anchor() {
    // If the crate ever started folding the operating system's roots into
    // its own set, this is the first thing that would change.
    let roots = apple_roots();
    let bundled: Vec<&[u8]> = roots.iter().map(TrustAnchor::der).collect();
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
    let verifier = common::verifier(roots);
    let genuine = common::read_base64_fixture("public-receipts/receipt-sandbox-g5.b64");
    assert_eq!(
        common::verify_der(&verifier, &genuine)
            .unwrap_err()
            .reason(),
        Reason::UntrustedChain
    );
    assert_eq!(
        verifier
            .verify_signed_data(&common::transaction_jws())
            .unwrap_err()
            .reason(),
        Reason::UntrustedChain
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
            if let Ok(anchor) = TrustAnchor::from_pem(block) {
                out.push(anchor.der().to_vec());
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

/// The `.rs` files under `dir` of this crate's directory, as (path, text).
fn sources(dir: &str) -> Vec<(String, String)> {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(dir);
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
    out
}

fn crate_sources() -> Vec<(String, String)> {
    let out = sources("src");
    assert!(
        out.len() >= 10,
        "the source scan found only {} files",
        out.len()
    );
    out
}

/// The adapter's sources, comment lines dropped: its documentation names
/// the calls it never makes.
fn adapter_code() -> Vec<(String, String)> {
    let out: Vec<(String, String)> = sources("openssl/src")
        .into_iter()
        .map(|(path, text)| {
            let code = text
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            (path, code)
        })
        .collect();
    assert!(
        out.len() >= 5,
        "the adapter scan found only {} files",
        out.len()
    );
    out
}

#[test]
fn no_source_file_names_a_system_trust_store_or_a_network_client() {
    // The mechanised form of "pinned anchors only, no network ever". A
    // dependency bump cannot introduce these either: deny.toml refuses the
    // crates that would carry them. The core reaches OpenSSL only through
    // its adapter.
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
fn the_openssl_adapter_never_loads_a_trust_path_a_configuration_or_a_socket() {
    // What would let OpenSSL trust or read anything the caller did not
    // hand over: the default certificate paths, a lookup method or file
    // loader on a store, the configuration file, a provider or engine
    // load, a network BIO.
    const FORBIDDEN: [&str; 19] = [
        "set_default_paths",
        "X509_STORE_load",
        "load_locations",
        "add_lookup",
        "X509_LOOKUP",
        "set_default_verify",
        "CONF_modules",
        "INIT_LOAD_CONFIG",
        "OPENSSL_config",
        "OSSL_LIB_CTX_load_config",
        "OSSL_PROVIDER",
        "ENGINE_",
        "SSL_CERT",
        "BIO_new_connect",
        "BIO_s_connect",
        "OCSP",
        "TcpStream",
        "UdpSocket",
        "http://",
    ];
    for (path, code) in adapter_code() {
        for needle in FORBIDDEN {
            assert!(!code.contains(needle), "{path} names \"{needle}\"");
        }
    }
    // And it does initialise OpenSSL without its configuration.
    assert!(
        adapter_code()
            .iter()
            .any(|(_, code)| code.contains("OPENSSL_init_crypto(sys::OPENSSL_INIT_NO_LOAD_CONFIG")),
        "the adapter no longer initialises OpenSSL with NO_LOAD_CONFIG"
    );
}

#[test]
fn no_source_file_holds_a_private_key_or_decrypts() {
    // The library verifies public-key signatures over public data: no
    // private key in the process, nothing to decrypt, nothing to sign, and
    // so no private-key timing oracle to worry about.
    for (path, text) in crate_sources().into_iter().chain(adapter_code()) {
        for needle in [
            "Private>",
            "private_key",
            "decrypt",
            "EVP_PKEY_sign",
            "EVP_DigestSign",
            "sign::Signer",
        ] {
            assert!(!text.contains(needle), "{path} names \"{needle}\"");
        }
    }
}

/// The names under `[dependencies]` of a manifest in this crate's
/// directory.
fn direct_dependencies(manifest: &str) -> Vec<String> {
    let manifest =
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(manifest))
            .unwrap();
    manifest
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
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_direct_dependency_set_is_exactly_the_reviewed_one() {
    // A new direct dependency is a supply-chain decision, and it should not
    // be possible to make one by accident. serde_json writes
    // ReceiptPayload::to_json() (owner, 2026-09-27: the same JSON value
    // across ports, each through its standard encoder); aprv-openssl is the
    // OpenSSL adapter, and its own set is pinned beside it.
    assert_eq!(
        direct_dependencies("Cargo.toml"),
        ["aprv-openssl", "base64", "serde_json"],
        "the core's direct dependency set changed"
    );
    assert_eq!(
        direct_dependencies("openssl/Cargo.toml"),
        ["openssl", "openssl-sys", "foreign-types", "libc"],
        "the adapter's direct dependency set changed"
    );
}

#[test]
fn the_bundled_anchors_are_apples_three_published_roots() {
    // One set for both formats: Apple does not commit to a specific root for
    // either path, so anchoring on one would break silently the day a chain
    // were re-anchored under another.
    let roots = apple_roots();
    assert_eq!(roots.len(), 3);
    for anchor in &roots {
        let cert = Certificate::from_der(anchor.der()).unwrap();
        assert!(
            cert.may_issue_certificates(),
            "a bundled anchor must be a CA"
        );
        assert!(cert.issued_by(&cert), "a bundled anchor is self-signed");
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
    let embedded = apple_roots();
    for (index, name) in names.iter().enumerate() {
        assert_eq!(
            embedded[index].der(),
            std::fs::read(port_certs.join(name)).unwrap().as_slice()
        );
    }
}

#[test]
fn a_trust_anchors_own_expiry_is_not_checked() {
    // Standard PKIX trust-anchor semantics, and what lets a receipt signed
    // years ago under a since-expired chain verify at its own creation date.
    let verifier = common::verifier([common::anchor("generated-0.7/receipt-expired-root.der")]);
    let historical = common::read_fixture("generated-0.7/receipt-expired-historical.der");
    assert!(common::verify_der(&verifier, &historical).is_ok());
}

/// A chain verifies when its root is anywhere in the configured set, in
/// any order, even beside another pinned root with the same subject name.
/// OpenSSL's issuer lookup takes the first store certificate whose name
/// matches and does not try the next after its signature fails, so the
/// fixtures' same-named "Fake Apple" roots verified in one order and not
/// the other (the Swift host's G1 run).
#[test]
fn a_root_verifies_beside_another_root_with_the_same_subject_in_either_order() {
    let receipt = common::read_fixture("generated-0.7/receipt.der");
    let (right, twin) = (
        common::anchor("generated-0.7/receipt-root.der"),
        common::anchor("generated-0.7/api-receipt-root.der"),
    );
    assert_ne!(right.der(), twin.der(), "two different roots");
    for roots in [[twin.clone(), right.clone()], [right, twin]] {
        let verifier = common::verifier(roots);
        assert!(common::verify_der(&verifier, &receipt).is_ok());
    }
    let jws = common::transaction_jws();
    let (right, twin) = (
        common::anchor("generated/jws-root.der"),
        common::anchor("generated-0.7/api-jws-root.der"),
    );
    for roots in [[twin.clone(), right.clone()], [right, twin]] {
        assert!(common::verifier(roots).verify_signed_data(&jws).is_ok());
    }
}

/// Two pinned roots with one subject name and different keys, a receipt
/// chain under the first, a certificate the second issued, and a
/// self-signed anchor that carries the intermediate's subject name. P-256,
/// minted here, none with key identifiers.
struct Lookalikes {
    first_root: TrustAnchor,
    second_root: TrustAnchor,
    decoy: TrustAnchor,
    intermediate: Certificate,
    other: Certificate,
    leaf: Certificate,
}

fn lookalikes() -> Lookalikes {
    use common::mint;
    let (first_key, second_key, intermediate_key, other_key, leaf_key, decoy_key) = (
        mint::key(41),
        mint::key(42),
        mint::key(43),
        mint::key(44),
        mint::key(45),
        mint::key(46),
    );
    let root =
        |key, serial| mint::certificate("Twin Root", key, "Twin Root", key, serial, true, None);
    let certificate = |der: Vec<u8>| Certificate::from_der(&der).unwrap();
    let anchor = |der: Vec<u8>| TrustAnchor::from_der(&der).unwrap();
    Lookalikes {
        first_root: anchor(root(&first_key, 1)),
        second_root: anchor(root(&second_key, 2)),
        decoy: anchor(mint::certificate(
            "Twin WWDR",
            &decoy_key,
            "Twin WWDR",
            &decoy_key,
            6,
            true,
            None,
        )),
        intermediate: certificate(mint::certificate(
            "Twin WWDR",
            &intermediate_key,
            "Twin Root",
            &first_key,
            3,
            true,
            Some(mint::WWDR_MARKER),
        )),
        other: certificate(mint::certificate(
            "Twin Other",
            &other_key,
            "Twin Root",
            &second_key,
            4,
            true,
            None,
        )),
        leaf: certificate(mint::certificate(
            "Twin Leaf",
            &leaf_key,
            "Twin WWDR",
            &intermediate_key,
            5,
            false,
            Some(mint::RECEIPT_SIGNER_MARKER),
        )),
    }
}

/// Round-2 review F2 (a): OpenSSL's issuer lookup takes the first store
/// certificate with the right name and never tries a second, so with both
/// same-named roots in one store the order decided, and a certificate the
/// second root issued, appended to the unsigned certificates bag, kept both
/// in the store. Each root now gets a store of its own.
#[test]
fn a_certificate_from_a_same_named_roots_pki_in_the_bag_does_not_decide_the_path() {
    let pki = lookalikes();
    let embedded = [
        pki.leaf.clone(),
        pki.intermediate.clone(),
        pki.other.clone(),
    ];
    let orders = [
        vec![pki.first_root.clone(), pki.second_root.clone()],
        vec![pki.second_root.clone(), pki.first_root.clone()],
    ];
    for roots in &orders {
        let authenticated = path::authenticated_top_down(&embedded, roots);
        assert_eq!(authenticated.len(), 3, "both roots vouch for something");
        let chain = path::receipt_path(&pki.leaf, &authenticated, roots, now_millis());
        assert_eq!(chain.map(|chain| chain.len()).ok(), Some(2));
    }
    // A failing path fails for the same reason in either order: the
    // problems come from the run whose links hold, under the first root,
    // not from the second root's broken signature. 2100-01-01, when every
    // minted certificate has expired.
    let late = 4_102_444_800_000;
    for roots in &orders {
        let authenticated = path::authenticated_top_down(&embedded, roots);
        let failure = path::receipt_path(&pki.leaf, &authenticated, roots, late).unwrap_err();
        assert_eq!(failure.reason(), Reason::InvalidCertificate, "{failure}");
    }
}

/// Round-2 review F2 (b): a pinned self-signed anchor carrying the
/// intermediate's subject name was, under OpenSSL's trusted-first lookup,
/// taken as the leaf's issuer, and the path to the real root never
/// verified, for receipts and for the JWS pair alike.
#[test]
fn an_anchor_named_as_the_intermediate_does_not_change_the_verdict() {
    let pki = lookalikes();
    let embedded = [pki.leaf.clone(), pki.intermediate.clone()];
    for roots in [
        vec![pki.first_root.clone()],
        vec![pki.first_root.clone(), pki.decoy.clone()],
        vec![pki.decoy.clone(), pki.first_root.clone()],
    ] {
        let authenticated = path::authenticated_top_down(&embedded, &roots);
        let chain = path::receipt_path(&pki.leaf, &authenticated, &roots, now_millis());
        assert_eq!(chain.map(|chain| chain.len()).ok(), Some(2));
        assert!(path::validate_pair(&pki.leaf, &pki.intermediate, &roots, now_millis()).is_ok());
    }
    // The decoy alone anchors nothing.
    let roots = [pki.decoy.clone()];
    let failure =
        path::validate_pair(&pki.leaf, &pki.intermediate, &roots, now_millis()).unwrap_err();
    assert_eq!(failure.reason(), Reason::UntrustedChain, "{failure}");
}
