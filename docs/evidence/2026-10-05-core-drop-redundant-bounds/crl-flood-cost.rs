
// Appended to rust/tests/envelope_bounds.rs, which supplies `Envelope`,
// `crl`, `count_nodes`, `verify` and the imports. Not part of the suite.

/// The largest flood of minimal CRLs the envelope's 100,000-value budget
/// lets through, against a flood of NULLs that fills the same budget in an
/// unsigned attribute, and the genuine receipt. Both floods verify.
#[test]
fn crl_flood_cost() {
    const CALLS: u32 = 5;
    let base = Envelope::shared().build();
    let base_nodes = count_nodes(&parse_exact(&base).unwrap());
    let one = crl(&der(0x05, &[]));
    let per_crl = count_nodes(&parse_exact(&one).unwrap());
    // The crls field's own [1] header is one value.
    let crls = (100_000 - base_nodes - 1) / per_crl;
    let mut envelope = Envelope::shared();
    envelope.crls = Some(der(tag::CONTEXT_1, &one.repeat(crls)));
    let crl_flood = envelope.build();
    // [1], the Attribute, its OID and its SET, then the values.
    let nulls = 100_000 - base_nodes - 4;
    let mut envelope = Envelope::shared();
    envelope.unsigned_attributes = Some(der(
        tag::CONTEXT_1,
        &der_seq(&[der_oid("1.2.3.4"), der(tag::SET, &[0x05, 0x00].repeat(nulls))]),
    ));
    let null_flood = envelope.build();
    eprintln!("COST base {base_nodes} values, {per_crl} values a CRL, {crls} CRLs, {nulls} NULLs");
    for (name, input) in [("genuine", &base), ("crls", &crl_flood), ("nulls", &null_flood)] {
        let (result, full_decodes) = verify(input);
        assert!(result.is_ok(), "{name}: {result:?}");
        assert_eq!(full_decodes, 1, "{name}");
        let started = Instant::now();
        for _ in 0..CALLS {
            let _ = verify(input);
        }
        eprintln!(
            "COST {name}: {} bytes of DER, {:?} a verification",
            input.len(),
            started.elapsed() / CALLS
        );
    }
}
