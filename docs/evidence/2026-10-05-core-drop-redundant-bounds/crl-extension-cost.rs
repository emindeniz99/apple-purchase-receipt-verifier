
// Appended to rust/tests/envelope_bounds.rs, which supplies `Envelope`,
// `verify`, `count_nodes` and the imports. Not part of the suite. Run each
// test alone, in a process of its own, so its peak resident set is its
// own: `cargo test ... --test envelope_bounds <name> -- --exact --nocapture`.

/// The process's peak resident set so far (`VmHWM`), in KiB.
fn peak_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap()
}

/// Verifies `der` once and prints its size, the time and the peak resident
/// set before and after; asserts the verdict.
fn measure(name: &str, der: &[u8], verifies: bool) {
    let before = peak_kib();
    let started = Instant::now();
    let (result, _) = verify(der);
    let elapsed = started.elapsed();
    let after = peak_kib();
    assert_eq!(result.is_ok(), verifies, "{name}: {result:?}");
    eprintln!(
        "COST {name}: {} bytes of DER, {:?}, peak RSS {} MiB before and {} MiB after",
        der.len(),
        elapsed,
        before / 1024,
        after / 1024
    );
}

/// `count` empty `dNSName`s ([2] IMPLICIT IA5String) as one GeneralNames
/// SEQUENCE's contents.
fn empty_dns_names(count: usize) -> Vec<u8> {
    [0x82, 0x00].repeat(count)
}

/// A CRL whose `crlExtensions` hold `extensions` (each a whole Extension).
fn crl_with_extensions(extensions: &[Vec<u8>]) -> Vec<u8> {
    let algorithm = der_seq(&[der_oid(SHA256_WITH_RSA)]);
    let tbs = der_seq(&[
        der_int(1),
        algorithm.clone(),
        common::mint::name("CRL Issuer"),
        der(tag::UTC_TIME, b"240101000000Z"),
        der(tag::CONTEXT_0, &der_seq(extensions)),
    ]);
    der_seq(&[tbs, algorithm, der(tag::BIT_STRING, &[0, 1, 2, 3])])
}

#[test]
fn cost_control() {
    measure("control", &Envelope::shared().build(), true);
}

#[test]
fn cost_crl_with_a_two_megabyte_authority_key_identifier() {
    // AuthorityKeyIdentifier ::= SEQUENCE { authorityCertIssuer [1]
    // GeneralNames }, 1,000,000 empty dNSNames, in one extnValue.
    let akid = der_seq(&[der(0xa1, &empty_dns_names(1_000_000))]);
    let extension = der_seq(&[der_oid("2.5.29.35"), der(tag::OCTET_STRING, &akid)]);
    let mut envelope = Envelope::shared();
    envelope.crls = Some(der(tag::CONTEXT_1, &crl_with_extensions(&[extension])));
    let der = envelope.build();
    eprintln!(
        "COST akid: {} values in the envelope",
        count_nodes(&parse_exact(&der).unwrap())
    );
    measure("crl-akid-1000000-names", &der, true);
}

#[test]
fn cost_minimal_crl_flood() {
    // The smallest CRL OpenSSL parses: an AlgorithmIdentifier without
    // parameters and an empty issuer Name, nine values.
    let algorithm = der_seq(&[der_oid(SHA256_WITH_RSA)]);
    let one = der_seq(&[
        der_seq(&[
            algorithm.clone(),
            der_seq(&[]),
            der(tag::UTC_TIME, b"240101000000Z"),
        ]),
        algorithm,
        der(tag::BIT_STRING, &[0]),
    ]);
    let base_nodes = count_nodes(&parse_exact(&Envelope::shared().build()).unwrap());
    let per_crl = count_nodes(&parse_exact(&one).unwrap());
    let crls = (100_000 - base_nodes - 1) / per_crl;
    eprintln!("COST flood: {} bytes and {per_crl} values a CRL, {crls} CRLs", one.len());
    let mut envelope = Envelope::shared();
    envelope.crls = Some(der(tag::CONTEXT_1, &one.repeat(crls)));
    measure("minimal-crl-flood", &envelope.build(), true);
}

/// A bag certificate whose subjectAltName holds `names` empty dNSNames,
/// signed by nobody (the signature is junk), naming `issuer` as its issuer.
fn certificate_with_san(issuer: &[u8], names: usize) -> Vec<u8> {
    let algorithm = der_seq(&[der_oid(common::mint::ECDSA_WITH_SHA256)]);
    // SubjectAltName ::= GeneralNames, a SEQUENCE OF GeneralName.
    let san = der(0x30, &empty_dns_names(names));
    let tbs = der_seq(&[
        der(tag::CONTEXT_0, &der_int(2)),
        der_int(99),
        algorithm.clone(),
        issuer.to_vec(),
        der_seq(&[der(0x17, b"200101000000Z"), der(0x18, b"20991231000000Z")]),
        common::mint::name("SAN Stranger"),
        common::mint::spki(&common::mint::key(99)),
        der(
            0xa3,
            &der_seq(&[der_seq(&[
                der_oid("2.5.29.17"),
                der(tag::OCTET_STRING, &san),
            ])]),
        ),
    ]);
    common::mint::assemble(tbs, algorithm, &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
}

#[test]
fn cost_bag_certificate_with_a_two_megabyte_subject_alt_name() {
    // Named as issued by the pinned root, so the top-down walk pairs it
    // with the root (X509_check_issued) before any signature is checked.
    let root = common::receipt_root();
    let (_, root_name) = common::certificate_identity(root.der()).unwrap();
    let mut envelope = Envelope::shared();
    envelope.extra_choices = vec![certificate_with_san(&root_name, 1_000_000)];
    measure("bag-certificate-san-1000000-names", &envelope.build(), true);
}

#[test]
fn cost_bag_certificate_with_a_two_megabyte_subject_alt_name_issued_by_nobody() {
    // The same certificate naming an issuer nobody pinned: X509_check_issued
    // stops at the name comparison, before it caches the extensions.
    let mut envelope = Envelope::shared();
    envelope.extra_choices = vec![certificate_with_san(&common::mint::name("Nobody"), 1_000_000)];
    measure("bag-certificate-san-1000000-names-issuer-nobody", &envelope.build(), true);
}
