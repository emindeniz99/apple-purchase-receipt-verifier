# Test inventory

MIGRATION.md step 1.11: every behaviour test that exists in one port's
suite only, set against `fixtures/cases.json`. When the ports become
wrappers over one core (Phase 7), their verification tests go with their
verifiers. Behaviour those tests pinned must then live where every host
runs it: a shared case. A host's own API shape, pooling or packaging stays
with that host.

Written 2026-09-29 by lane A3 from the host lanes' hand-backs and from the
suites of `rust/` and `java/` at lane/core. The shared cases are those of
`fixtures/cases.json` at the same commit (360).

## How to read a row

| Column | Meaning |
|---|---|
| Port | Where the test lives. "Java -wasm" is the Java lane's new artifact; "Java" is the 0.7 Java implementation (`java/`), which stays (R33) |
| Test | The file and test name, or the name the lane's hand-back gave it |
| Pins | What the test holds, where the name does not say it |
| Target | `covered: <case>`: a shared case holds it. `added: <case>`: this lane added the case (below). `to add` (Go: `PROPOSE`): no case yet, with the case the lane proposed. `stays with the host` (Go: `HOST`), or with the core or Java for their own internals (Go: `CORE`). The corpus and the differential run, where the property is "no input escapes" rather than one input's answer |

Sources: the Go lane's per-test list (`go-inventory.md` of the lane
hand-backs), the Ruby lane's
`docs/evidence/2026-09-29-ruby-host/results/test-inventory.tsv` (on its
branch; its categories map C to covered, K and H to stays with the host,
F to the corpus, D to removed, P to to add), and the proposals the Python,
Java, Swift, PHP, Node and .NET lanes listed in their hand-backs. Those six
lanes named proposals and families rather than every test; their deleted
suites are in git history on their branches, and a per-test pass over them
is left open (below).

The Rust and Java rows are mechanical
(`docs/evidence/2026-09-29-differential-campaign/scripts/inventory.py`):
every `#[test]` of `rust/` and every `@Test` of `java/src/test`, matched to
the cases that use a fixture file the test names. A test that names none
builds its input in code; its row says so, and it stays with the core or
with Java. The core is the implementation every host runs, so a core test
protects every host already; Java is the independent oracle, and the
differential run compares it with the core over the corpora and the cases
(`tools/differential.sh`).

## Counts

| Port | Rows | Covered | Added here | To add | Stays with the host, the core, Java, or the corpus |
|---|---|---|---|---|---|
| Go | 80 | 42 | 0 | 22 | 16 |
| Ruby | 184 | 82 | 4 | 30 | 68 |
| Python | 23 | 5 | 9 | 9 | 0 |
| Java -wasm | 8 | 1 | 4 | 2 | 1 |
| Swift | 23 | 12 | 6 | 4 | 1 |
| PHP | 22 | 4 | 6 | 11 | 1 |
| Node | 6 | 1 | 2 | 0 | 3 |
| .NET | 2 | 0 | 0 | 0 | 2 |
| Rust | 315 | 43 | 0 | 0 | 272 |
| Java | 201 | 11 | 0 | 0 | 190 |
| All | 864 | 201 | 31 | 78 | 554 |

## The cases this lane added

Twenty cases, all from generated fixtures already in the repository (the
shared receipt and transaction, the expired-chain receipt, the review
fixtures), cut or recombined by
`docs/evidence/2026-09-29-differential-campaign/scripts/add_cases.py`, so
nothing is signed and a rerun writes the same bytes. The core, the C ABI's
ctypes and C++ harnesses, `aprv.wasm` through the trap host and the Java
implementation each pass every one. The other hosts' runners see them when
they take this branch's `fixtures/` at integration.

| Case | From |
|---|---|
| `endpoint/empty-body-answers-21002` | Python, Java -wasm, Swift |
| `endpoint/body-that-is-not-json-answers-21002` | Python, Swift |
| `endpoint/truncated-object-answers-21002` | Python |
| `endpoint/literal-status-body-answers-21002` | PHP |
| `endpoint/brackets-inside-a-string-are-not-nesting-answers-0` | Python, Swift, PHP |
| `endpoint/intro-offer-and-trial-flags-are-the-strings-true-and-false` | Java -wasm, Python, Swift, Ruby |
| `endpoint/pinned-clock-does-not-rescue-a-fresh-creation-date-answers-21003` | Python |
| `receipt/pinned-clock-does-not-rescue-a-fresh-creation-date` | Java -wasm, Python, Swift |
| `receipt/reject-receipt-truncated-to-200-bytes` | Python |
| `transaction/reject-signature-of-63-bytes` | Ruby, PHP |
| `transaction/reject-signature-of-65-bytes` | Ruby, PHP |
| `transaction/reject-an-all-zero-signature` | Ruby, PHP |
| `transaction/reject-a-payload-swapped-for-an-array` | PHP |
| `transaction/reject-broken-signature-segment-under-a-foreign-chain` | Java -wasm |
| `signed-data/reject-x5c-that-is-an-object` | PHP |
| `signed-data/reject-x5c-of-numbers` | Python |
| `signed-data/reject-x5c-with-null-and-a-list` | Python |
| `signed-data/reject-a-four-certificate-x5c` | Ruby |
| `signed-data/reject-alg-in-lower-case` | PHP |
| `signed-data/reject-x5c-leaf-behind-a-byte-order-mark` | Swift |

The differential run added two more, for a core bug it found:
`receipt/verify-with-a-stranger-vouched-by-a-same-named-root-listed-first`
and `-second`.

## Open

- **The `to add` rows.** Most need a minted input: a signer with hostile
  signed attributes or SignerInfo fields, X.509 time and encoding defects,
  an RSA key under ES256, unknown and MD5 digests, a foreign chain with an
  unmarked signer, an intermediate that is not a CA, Pacific-time
  rendering either side of each US daylight-saving transition. The
  generator of the core review's cases
  (`docs/evidence/2026-09-29-core-review-fixes/gen_fixtures.py`) mints the
  P-256 PKI they need. Inputs over 100 KB (the nesting bombs, the floods,
  the million-digit dates) stay Rust tests under R20's rule for bounds.
- **A failure message never echoes the input** needs the schema's
  `messageMustNotContain` to take strings; today it takes code points.
- **Go's 8,192-bit RSA modulus cap** is a Go-only policy, not in the 0.7
  bounds table: the owner decides whether it becomes a case.
- **Per-test lists for Python, Java -wasm, Swift, PHP, Node and .NET**:
  their hand-backs named proposals, not every test.

## Rows

### The hosts

| Port | Test | Pins | Target |
|---|---|---|---|
| Go | root package: amplification_test |  | NestedReceiptDoesNotAmplify: COVERED receipt/accept-an-envelope-nested-32-deep, reject-an-envelope-nested-33-deep; the linear-allocation property is CORE. |
| Go | root package: bench_test |  | benchmarks HOST (replaced); RejectionCostIsBounded COVERED by the maxMillis cases (reject-untrusted-oversized-intermediates, reject-cross-signed-mesh, signed-data/reject-untrusted-oversized-x5c); AllocationsOnTheHappyPathsAreBounded HOST (Go allocations, dropped). |
| Go | root package: certbag_test UnparseableStrangerCertificateIsTolerated / ...AtEveryPosition |  | PROPOSE receipt/verify-with-an-unparseable-stranger-first\|middle\|last (COVERED in part: verify-with-a-stranger-whose-key-is-unreadable, verify-genuine-padded-with-oversized-strangers) |
| Go | root package: certbag_test NonCanonicalCertificateSignatureIsFatalAtEveryPosition |  | PROPOSE receipt/reject-noncanonical-signature-on-leaf\|intermediate (stranger COVERED: reject-a-stranger-whose-signature-bit-string-is-unaligned; JWS COVERED: signed-data/reject-an-x5c-leaf-with-an-unaligned-signature) |
| Go | root package: certbag_test CorruptedCertificateInGenuineReceipt |  | PROPOSE receipt/verify-genuine-g5-with-a-corrupted-redundant-root-copy and receipt/reject-genuine-g5-with-a-corrupted-signer (offset 4044 of the public g5 receipt) |
| Go | root package: certbag_test CertificateCountIsStillCheckedBeforeDecoding |  | COVERED reject-eleven-embedded-certificates; PROPOSE reject-sixty-four-junk-certificates-as-malformed (junk entries, the count wins) |
| Go | root package: certbag_test AnAbsentSignerIsNotBlamedOnAMalformedStranger |  | COVERED receipt/reject-signer-absent-beside-a-malformed-stranger |
| Go | root package: certbag_test AMalformedSignerIsACertificateDefect |  | PROPOSE receipt/reject-a-signer-that-is-named-but-unreadable (INVALID_CERTIFICATE) |
| Go | root package: chain_test AnchorsArePinnedInBothDirections |  | COVERED in part (receipt/reject-foreign-root, transaction/reject-foreign-root); PROPOSE receipt/verify-with-two-anchors-only-one-used |
| Go | root package: chain_test ExpiredAnchorStillAnchors |  | PROPOSE receipt/verify-under-an-expired-anchor (COVERED in part: accept-historical-creation-date-under-expired-chain) |
| Go | root package: chain_test IntermediateMustBeAUsableCA |  | COVERED reject-intermediate-whose-key-usage-lacks-key-cert-sign; PROPOSE receipt/reject-an-intermediate-that-is-not-a-ca (basicConstraints cA false) |
| Go | root package: chain_test IssuerNameMustMatchByBytes |  | PROPOSE receipt/reject-an-intermediate-with-a-reencoded-issuer-name (COVERED in part: reject-twin-certificate) |
| Go | root package: chain_test NoSignatureAlgorithmAllowlist |  | COVERED verify-genuine-legacy-sha1-chain, verify-signer-ecdsa-p256, verify-signer-sha384-digest, verify-signer-sha512 |
| Go | root package: chain_test SelfIssuedCertificateTerminatesTheWalk |  | COVERED reject-a-path-of-seven-with-a-self-issued-tail, reject-cross-signed-mesh |
| Go | root package: chain_test MissingIntermediateIsNotFetched |  | COVERED receipt/reject-chain-missing-the-intermediate |
| Go | root package: concurrency_test |  | HOST (kept, rewritten over the case set). |
| Go | root package: crossport_bench_test |  | HOST (benchmark; the cross-port table is BENCHMARKS.md's). |
| Go | root package: encoding_internal_test.StdEncodingAloneIsNotTheRule |  | COVERED base64/reject-* and receipt-base64/reject-*. |
| Go | root package: endpoint_test MalformedBodies |  | COVERED endpoint/body-that-is-an-array\|null\|a-scalar-answers-21002, receipt-data-missing\|not-a-string |
| Go | root package: endpoint_test AcceptsAndIgnoresTheCompatibilityFields |  | COVERED endpoint/password-and-exclude-old-transactions-are-ignored |
| Go | root package: endpoint_test SuccessBodyCarriesAnExplicitZeroStatus |  | COVERED (every status-0 endpoint case pins /status) |
| Go | root package: endpoint_test EndpointJSONIsDeterministic |  | CORE (the corpus compares bytes) |
| Go | root package: endpoint_test RequestDateComesFromTheInjectedClock |  | COVERED endpoint/request-date-is-the-verification-clock |
| Go | root package: endpoint_test EndpointClockCannotAuthenticateAnExpiredChain |  | COVERED endpoint/clock-past-the-window-rejects-a-dateless-receipt, clock-inside-the-window-verifies-a-dateless-receipt |
| Go | root package: endpoint_test EndpointEnvironmentRouting |  | COVERED the vpp-*, missing-receipt-type-* and sandbox/production cases |
| Go | root package: endpoint_test EndpointStatusesForFailedVerification |  | COVERED foreign-root-answers-21003, unreadable-payload-answers-21009, attribute-type-above-int32-max-answers-21009 |
| Go | root package: endpoint_test EndpointDoesNotCheckTheBundleID |  | COVERED by the API shape (no bundle parameter); no case |
| Go | root package: endpoint_test EndpointNeverPanicsOverTheHostileCorpus |  | COVERED by the hostile cases and the corpus |
| Go | root package: endpoint_test SignatureAlgorithmIdentifierIsNotConsulted |  | PROPOSE receipt/relabelled-signature-algorithm-still-verifies (COVERED only as "does not crash": relabelled-signature-algorithm-does-not-crash) |
| Go | root package: endpoint_test AppleDateTripleShape |  | PROPOSE endpoint/dates-render-apples-triple-in-pacific-time (purchase_date, _ms, _pst, PST/PDT switch; COVERED in part by ids-echo-apples-keys) |
| Go | root package: endpoint_test EndpointIdsExactDigits |  | COVERED receipt/integers-at-the-64-bit-edge, endpoint/ids-echo-apples-keys; PROPOSE endpoint/ids-at-the-64-bit-edge |
| Go | root package: endpoint_test EndpointIdsAbsentAreOmitted |  | COVERED endpoint/ids-absent-are-omitted |
| Go | root package: endpoint_test EndpointReadsTheClockOncePerCall |  | HOST (facade TheClockIsReadOnceBeforeTheInputEveryCall); one reading serving both chain and request_date: COVERED by clock-inside-the-window-verifies-a-dateless-receipt + request-date-is-the-verification-clock |
| Go | root package: endpoint_test PanickingClockBecomesAnInternalError |  | HOST (facade AClockThatBreaksIsInternalError...) |
| Go | root package: errors_test |  | ReasonTokens, AllReasonsFreshSlice, Unwrap, NilFailure, FailureFormats: HOST (kept); ErrorReadingStyles, OnlyFailuresEscapeTheEntryPoints: HOST (facade); ErrorMessagesLeakNothingFromTheInput: PROPOSE a case family receipt/failure-message-does-not-quote-the-input (needs the schema's messageMustNotContain to take strings, today code points only) |
| Go | root package: example_test |  | HOST (kept). |
| Go | root package: fips_test.FIPSOnlyModeDoesNotCrashTheCaller |  | HOST (moot: no Go crypto arithmetic left); CI-NOTES suggests a GODEBUG=fips140=only leg. |
| Go | root package: fuzz_test |  | HOST (kept, over the new implementation). |
| Go | root package: inputcaps_test |  | CapNumbersMatchTheOtherPorts HOST (kept in apisurface_test); ReceiptBase64Cap... COVERED receipt-base64/accept-at-the-size-cap, reject-one-byte-over-the-size-cap, pass-the-size-cap-then-fail-as-malformed; RequestBodyCap..., ...MeasuredInUTF8Bytes, ...NestingCounted... COVERED endpoint/request-body-*; JWSSizeCap COVERED raw/jws-at-the-size-cap-reaches-the-signature-check, reject-jws-one-byte-over-the-size-cap; JWSHeaderNesting COVERED signed-data/accept-a-header-nested-64-deep, reject-a-header-nested-65-deep; JWSPayloadNesting COVERED signed-data/accept-a-payload-nested-64-deep, unreadable-payload-nested-65-deep, reject-an-unsigned-payload-nested-65-deep |
| Go | root package: jws_test SynthesizedJWSVerifies |  | COVERED transaction/verify-shared-sandbox |
| Go | root package: jws_test ShapeRejections / HeaderRejections / SignatureRejections |  | COVERED reject-four-segment-jws, reject-all-segments-empty, reject-empty-*-segment, reject-header-that-is-a-json-array\|scalar, signed-data/reject-alg-rs256, reject-a-utf16-header, reject-a-header-behind-a-bom, reject-signature-segment-*, reject-tampered-payload |
| Go | root package: jws_test PayloadNotAnObjectIsUnreadableOnceSignatureVerifies |  | COVERED signed-data/unreadable-json-array-payload, unreadable-empty-payload |
| Go | root package: jws_test MarkerOIDsAreCheckedAfterTheChain, IntermediateNeedsTheWWDRMarker |  | COVERED transaction/reject-leaf-without-apple-marker-oid, reject-intermediate-without-wwdr-marker-oid, signed-data/reject-foreign-chain-without-markers |
| Go | root package: jws_test ThirdX5CEntryIsUntrustedButMustParse |  | COVERED signed-data/reject-a-two-certificate-x5c, transaction/reject-x5c-root-that-is-not-a-certificate; PROPOSE transaction/accept-a-third-x5c-entry-from-a-stranger-root |
| Go | root package: jws_test EverySpellingOfASignedDateIsRead |  | COVERED accept-signed-date-decimal-spelling, signed-date-fractional; PROPOSE transaction/accept-signed-date-exponent-spelling |
| Go | root package: jws_test UnrepresentableSignedDateFallsBackToTheClock |  | COVERED signed-date-out-of-range-falls-back-to-the-clock; PROPOSE the -1e300 and 30-digit spellings |
| Go | root package: jws_test SignedDateOutsideTheChainWindowIsAChainFailure |  | COVERED reject-fresh-payload-under-expired-chain, signed-data/reject-real-apple-chain-outside-validity |
| Go | root package: jws_test DatelessPayloadIsJudgedAtTheSystemClock |  | COVERED transaction/reject-dateless-payload-under-an-expired-chain |
| Go | root package: jws_test HistoricalPayloadUnderAnExpiredChainStillVerifies |  | COVERED transaction/accept-historical-payload-under-expired-chain |
| Go | root package: jws_test PayloadJSONIsPassedThroughVerbatim |  | COVERED raw/return-claims-of-any-type, signed-data/verify-non-ascii-claims |
| Go | root package: jws_test TrustAnchorsAreCopiedAtConstruction |  | HOST (Config copies its roots; the Verifier sends them to init at NewVerifier; roots_test covers the Config copy) |
| Go | root package: mutation_test |  | MutatedReceiptsNeverChangeTheAnswer, MutatedJWSNeverVerify: CORE (fuzz.jsonl's 5,000 mutants); ForgedReceiptsAreRejected: COVERED reject-tampered-payload, reject-foreign-root |
| Go | root package: receipt_test SynthesizedReceiptVerifies |  | COVERED receipt/verify-shared-with-device-hash |
| Go | root package: receipt_test ReceiptWithoutSignedAttributesVerifies |  | PROPOSE receipt/verify-without-signed-attributes |
| Go | root package: receipt_test ReceiptHostileStructures |  | COVERED in part by the reject-* cases (reject-empty-cms-signature, reject-zero-signer-infos, reject-one-trailing-byte-after-the-der, ...); the exact 25-shape table is PROPOSE if the owner wants each shape pinned |
| Go | root package: receipt_test UnparseableAttributeValuesAreKeptRawNotFatal |  | COVERED unparseable-in-app-purchase-is-kept-raw, in-app-unparseable-fields-are-kept-raw, malformed-integers-are-kept-raw, invalid-utf8-strings-are-kept-raw |
| Go | root package: receipt_test CertificateFloodIsRejectedBeforeDecoding, ExactlyTenEmbeddedCertificatesIsExamined |  | COVERED reject-eleven-embedded-certificates, accept-ten-embedded-certificates |
| Go | root package: receipt_test LineWrappedBase64IsRefused |  | COVERED receipt-base64/reject-pem-64-lf, reject-pem-76-crlf |
| Go | root package: receipt_test VerifyReceiptRejectsAnEmptyAnchorSet, NewVerifierRejectsANilConfig, NewVerifierRejectsANilRoot |  | HOST (facade TestMisuseIsAPlainErrorAtCreate) |
| Go | root package: receipt_test ResultDoesNotAliasTheInput |  | HOST (moot: every result is built from the module's answer) |
| Go | root package: receipt_test UnknownAttributesArePreserved |  | COVERED expose-unknown-attributes |
| Go | root package: receipt_test ReceiptIdsAreDecoded / AbsentAreNil |  | COVERED ids-are-decoded, ids-absent-when-not-carried, integers-at-the-64-bit-edge |
| Go | root package: receipt_test EmptyDateStringMeansAbsent |  | PROPOSE receipt/empty-date-string-means-absent (lead 2026-09-27; date-grammar does not name it) |
| Go | root package: receipt_test ReceiptChainIsCheckedBeforeTheMarkerOID |  | COVERED in part by receipt/reject-foreign-root; PROPOSE receipt/reject-foreign-chain-with-an-unmarked-signer (UNTRUSTED_CHAIN, not INVALID_CERTIFICATE_PURPOSE) |
| Go | root package: receipt_test ReceiptSignerMustCarryTheMarkerOID, ReceiptIntermediateMustCarryTheWWDRMarker |  | COVERED receipt/reject-signer-without-receipt-signing-oid, reject-intermediate-without-wwdr-marker-oid |
| Go | root package: receipt_test NoPartialResultOnFailure |  | HOST (facade asserts a nil payload with every failure) |
| Go | root package: receipt_test UnreadablePayloadCarriesTheParserError |  | HOST, changed: Failure.Cause is nil for the module's verdicts now (SURFACE.md section 8: the cause chain is Rust-only, the wire carries the message) |
| Go | root package: receipt_test BundleIDValueThatIsNotASN1IsKeptRaw |  | PROPOSE receipt/bundle-id-that-is-not-asn1-is-kept-raw (COVERED in part: printable-string-attributes-are-kept-raw) |
| Go | root package: roots_test |  | HOST (kept; Phase 7 deletes it with go/roots). |
| Go | root package: sha1_canary_test |  | HOST, moot (a Go standard-library canary); the behaviour is COVERED by receipt/verify-genuine-legacy-sha1-chain. |
| Go | root package: sizebound_test |  | COVERED endpoint/receipt-data-over-the-receipt-cap-answers-21002, receipt-base64/reject-one-byte-over-the-size-cap; the "allocation stays small" half is CORE. |
| Go | root package: systemtrust_test.SystemTrustStoreIsNeverConsulted |  | HOST, moot (the module cannot read files); CI-NOTES suggests an isolation leg (planted SSL_CERT_FILE, transaction/reject-foreign-root). |
| Go | root package: testhelpers_test, testpki_test |  | test material generators (ASN.1/CMS/JWS builders, synthetic PKIs). Not tests; the source for generating the PROPOSE cases' fixtures (Phase 7 step 1). ac000fd:go/testpki_test.go. |
| Go | internal/chain: ValidAtIsInclusiveAtBothEnds |  | PROPOSE receipt/verify-at-not-before-instant, verify-at-not-after-instant, reject-one-millisecond-after-not-after |
| Go | internal/chain: FailuresCarryTheirReason, HappyPathsSucceed |  | COVERED by the chain cases above |
| Go | internal/chain: PathAcceptsSixAndRejectsSeven |  | COVERED receipt/accept-a-path-of-six, reject-a-path-of-seven |
| Go | internal/chain: AnOversizedKeyIsNeverUsedToCheckASignature |  | COVERED reject-untrusted-oversized-intermediates (maxMillis), signed-data/reject-untrusted-oversized-x5c |
| Go | internal/chain: StrangerCertificatesAreIgnoredNotFatal |  | COVERED (see certbag) |
| Go | internal/chain: RSAModulusCap (8,192 bits) |  | Go-only policy, not in the 0.7 bounds table. Decision for the owner: pin it as a case (PROPOSE receipt/reject-a-stranger-with-a-16384-bit-modulus-quickly) or leave it to OpenSSL's own behaviour. |
| Go | internal/der: The DER reader's unit, property and fuzz tests (truncation at every offset, byte flips never panic, node budget 100,000, allocation linear in the input, aliasing) |  | CORE. The 100,000-node budget and the reader's own depth of 32 are Go-port numbers; the 0.7 bounds table keeps depth 32 (COVERED accept-an-envelope-nested-32-deep / reject-...-33-deep). |
| Ruby | api_shape_test.rb test_the_public_classes_exist |  | stays with the host: api_shape_test |
| Ruby | api_shape_test.rb test_the_three_entry_points_exist |  | stays with the host: api_shape_test |
| Ruby | api_shape_test.rb test_the_reason_vocabulary_equals_the_shared_schema |  | stays with the host: api_shape_test |
| Ruby | api_shape_test.rb test_the_environment_vocabulary_is_production_and_sandbox_only |  | stays with the host: api_shape_test |
| Ruby | api_shape_test.rb test_a_verification_error_carries_its_reason_as_data_and_in_its_message |  | none (removed with the Ruby verifier): tested the private VerificationError class, removed |
| Ruby | api_shape_test.rb test_misconfiguration_raises_argument_error_never_verification_error |  | stays with the host: api_shape_test |
| Ruby | api_shape_test.rb test_verify_receipt_and_verify_signed_data_take_no_clock_parameter |  | stays with the host: api_shape_test |
| Ruby | api_shape_test.rb test_config_and_verifier_instances_are_frozen |  | stays with the host: api_shape_test |
| Ruby | api_shape_test.rb test_one_verifier_is_usable_from_many_threads_at_once |  | stays with the host: thread_test (one Verifier from several threads) |
| Ruby | api_shape_test.rb test_returned_value_objects_are_frozen |  | stays with the host: api_shape_test |
| Ruby | api_shape_test.rb test_a_result_carries_exactly_one_of_payload_and_failure |  | stays with the host: api_shape_test |
| Ruby | api_shape_test.rb test_input_that_is_not_valid_utf8_is_malformed_not_a_raise |  | stays with the host: api_shape_test (invalid UTF-8 is passed on and answered as a value; MALFORMED once the real module is in) |
| Ruby | api_shape_test.rb test_the_dashed_require_path_works_too |  | stays with the host: api_shape_test |
| Ruby | api_shape_test.rb test_the_version_is_a_semver_string |  | stays with the host: api_shape_test |
| Ruby | certificate_flood_test.rb test_exactly_ten_embedded_certificates_is_admitted |  | covered: receipt/accept-ten-embedded-certificates |
| Ruby | certificate_flood_test.rb test_eleven_embedded_certificates_is_rejected_as_malformed |  | covered: receipt/reject-eleven-embedded-certificates |
| Ruby | certificate_flood_test.rb test_a_thousand_certificate_flood_is_refused_before_the_certificates_are_decoded |  | to add, or a Rust test when the input is over 100 KB (R20's rule for bounds): receipt/reject-a-thousand-certificate-flood with maxMillis |
| Ruby | certificate_flood_test.rb test_the_decode_counter_sees_a_receipt_that_is_actually_verified |  | none (removed with the Ruby verifier): counted X509 decodes inside the old Ruby code |
| Ruby | certificate_flood_test.rb test_the_bound_clears_every_genuine_chain_in_the_corpus |  | covered: receipt/verify-genuine-sandbox-g5-against-apple-roots, receipt/verify-genuine-legacy-sha1-chain |
| Ruby | certificate_flood_test.rb test_a_cross_signed_certificate_mesh_is_rejected_in_bounded_time |  | covered: receipt/reject-cross-signed-mesh |
| Ruby | certificate_flood_test.rb test_the_bound_is_reported_before_the_signer_lookup |  | to add: receipt/reject-eleven-certificates-with-the-signer-absent (the count is reported before the signer lookup) |
| Ruby | chain_hardening_test.rb test_a_key_usage_extension_that_does_not_decode_fails_closed |  | none (removed with the Ruby verifier): called the private Chain.cert_sign_permitted? on a fake certificate |
| Ruby | chain_hardening_test.rb test_no_key_usage_extension_at_all_is_still_permitted |  | none (removed with the Ruby verifier): called the private Chain.cert_sign_permitted? on a fake certificate |
| Ruby | chain_hardening_test.rb test_an_intermediate_with_a_malformed_key_usage_is_refused_end_to_end |  | covered: receipt/intermediate-with-a-malformed-key-usage-does-not-crash, signed-data/intermediate-with-a-malformed-key-usage-does-not-crash |
| Ruby | clock_test.rb test_a_payload_is_never_rejected_for_its_age |  | covered: transaction/accept-historical-payload-under-expired-chain |
| Ruby | clock_test.rb test_a_dateless_payload_under_a_live_chain_verifies_at_the_default_clock |  | covered: transaction/accept-payload-without-a-signed-date, receipt/accept-missing-creation-date |
| Ruby | clock_test.rb test_a_dateless_payload_under_an_expired_chain_is_judged_at_the_configured_clock |  | covered: transaction/reject-dateless-payload-under-an-expired-chain |
| Ruby | clock_test.rb test_a_dateless_receipt_is_judged_at_the_configured_clock |  | covered: endpoint/clock-inside-the-window-verifies-a-dateless-receipt, endpoint/clock-past-the-window-rejects-a-dateless-receipt |
| Ruby | clock_test.rb test_an_omitted_clock_reads_the_real_system_clock |  | stays with the host: facade_test (the default clock is the system clock) |
| Ruby | clock_test.rb test_a_clock_must_respond_to_call |  | stays with the host: facade_test / api_shape_test (a clock must respond to #call) |
| Ruby | clock_test.rb test_the_clock_is_read_at_most_once_per_call |  | stays with the host: facade_test (the clock is read once per call, before the input) |
| Ruby | clock_test.rb test_a_clock_that_raises_is_internal_error_never_a_verdict_about_the_input |  | stays with the host: facade_test (a clock that raises is INTERNAL_ERROR) |
| Ruby | clock_test.rb test_a_clock_that_does_not_return_an_integer_is_internal_error |  | stays with the host: facade_test (a clock that is not an Integer is INTERNAL_ERROR) |
| Ruby | clock_test.rb test_a_clock_that_raises_answers_endpoint_status_21009 |  | stays with the host: facade_test (a clock that raises answers 21009) |
| Ruby | clock_test.rb test_the_endpoint_clock_drives_request_date_and_the_chain_fallback_alike |  | covered: endpoint/request-date-is-the-verification-clock |
| Ruby | endpoint_test.rb test_status_zero_body_matches_the_documented_contract |  | covered: endpoint/sandbox-receipt-on-sandbox-answers-0 |
| Ruby | endpoint_test.rb test_wire_types_are_apples_wire_types |  | covered: endpoint/ids-echo-apples-keys |
| Ruby | endpoint_test.rb test_is_in_intro_offer_period_is_the_string_true_or_false |  | added: `endpoint/intro-offer-and-trial-flags-are-the-strings-true-and-false` |
| Ruby | endpoint_test.rb test_legacy_receipt_ids_are_wire_numbers_with_exact_digits |  | covered: endpoint/ids-echo-apples-keys |
| Ruby | endpoint_test.rb test_legacy_receipt_id_keys_are_omitted_not_null_when_absent |  | covered: endpoint/ids-absent-are-omitted |
| Ruby | endpoint_test.rb test_malformed_receipt_data_answers_21002 |  | covered: endpoint/receipt-data-missing-answers-21002, receipt-data-empty, receipt-data-not-a-string, body-that-is-* |
| Ruby | endpoint_test.rb test_undecodable_base64_answers_21002 |  | covered: endpoint/receipt-data-junk-after-padding, receipt-data-urlsafe-padded |
| Ruby | endpoint_test.rb test_unauthenticated_receipt_answers_21003 |  | covered: endpoint/foreign-root-answers-21003 |
| Ruby | endpoint_test.rb test_environment_routing_both_directions |  | covered: endpoint/sandbox-receipt-on-production-answers-21007, production-receipt-on-sandbox-answers-21008 |
| Ruby | endpoint_test.rb test_vpp_sandbox_routes_as_sandbox |  | covered: endpoint/vpp-sandbox-receipt-on-sandbox-answers-0 |
| Ruby | endpoint_test.rb test_a_missing_receipt_type_routes_as_sandbox |  | covered: endpoint/missing-receipt-type-on-sandbox-answers-0 |
| Ruby | endpoint_test.rb test_non_zero_status_bodies_carry_neither_receipt_nor_environment |  | covered: `endpoint/receipt-data-leading-byte-order-mark-answers-21002` pins `/receipt` and `/environment` absent on a 21002 |
| Ruby | endpoint_test.rb test_verify_receipt_endpoint_answers_21002_for_anything_that_is_not_a_json_object |  | covered: endpoint/receipt-data-missing-answers-21002, receipt-data-empty, receipt-data-not-a-string, body-that-is-* |
| Ruby | endpoint_test.rb test_password_and_exclude_old_transactions_are_accepted_and_ignored |  | covered: endpoint/password-and-exclude-old-transactions-are-ignored |
| Ruby | endpoint_test.rb test_the_endpoint_never_raises_for_hostile_input |  | the corpus and the differential run, not a case: corpus: hostile endpoint rows |
| Ruby | endpoint_test.rb test_environment_must_be_production_or_sandbox |  | stays with the host: api_shape_test / facade_test (environment must be PRODUCTION or SANDBOX) |
| Ruby | endpoint_test.rb test_verify_receipt_endpoint_answers_21002_for_a_non_string_request_body |  | stays with the host: api_shape_test (non-String request body answers 21002) |
| Ruby | endpoint_test.rb test_an_unexpected_error_inside_verification_answers_21009_not_a_raise |  | stays with the host: facade_test (a trap at the endpoint answers 21009) |
| Ruby | endpoint_test.rb test_status_codes_out_of_scope_are_never_produced |  | the corpus and the differential run, not a case: corpus: no status outside the six appears in any of the 6,179 rows; AppleStatus is a Ruby constants table (covered by the wrapper's own test below) |
| Ruby | hostile_input_test.rb test_indefinite_length_nesting_bomb |  | to add, or a Rust test when the input is over 100 KB (R20's rule for bounds): receipt/reject-an-indefinite-length-nesting-bomb with maxMillis (500,000 nested 30 80 opens) |
| Ruby | hostile_input_test.rb test_definite_length_nesting_bomb |  | to add, or a Rust test when the input is over 100 KB (R20's rule for bounds): receipt/reject-a-definite-length-nesting-bomb with maxMillis (100,000 nested SEQUENCEs) |
| Ruby | hostile_input_test.rb test_the_scanner_rejects_before_openssl_is_reached |  | none (removed with the Ruby verifier): tested the hand-written scanner's ordering against OpenSSL's recursion; the two bombs above pin the behaviour |
| Ruby | hostile_input_test.rb test_depth_thirty_two_is_accepted_and_thirty_three_is_not |  | covered: receipt/accept-an-envelope-nested-32-deep, receipt/reject-an-envelope-nested-33-deep |
| Ruby | hostile_input_test.rb test_a_length_claiming_two_gigabytes_on_a_forty_byte_input |  | to add: receipt/reject-a-length-claiming-two-gigabytes (oneOf MALFORMED) |
| Ruby | hostile_input_test.rb test_an_unterminated_indefinite_length_container |  | to add: receipt/reject-an-unterminated-indefinite-length-container |
| Ruby | hostile_input_test.rb test_an_end_of_contents_with_no_open_container |  | to add: receipt/reject-an-end-of-contents-with-no-open-container |
| Ruby | hostile_input_test.rb test_multi_byte_tags_are_refused_rather_than_interpreted |  | to add: receipt/reject-a-multi-byte-tag (core decides: oneOf if OpenSSL accepts it) |
| Ruby | hostile_input_test.rb test_length_fields_wider_than_four_octets_are_refused |  | to add: receipt/reject-a-length-field-wider-than-four-octets (core decides) |
| Ruby | hostile_input_test.rb test_truncation_at_every_offset_of_a_genuine_receipt_is_contained |  | the corpus and the differential run, not a case: corpus: the 5,000 mutants include truncations; the differential job runs them |
| Ruby | hostile_input_test.rb test_trailing_bytes_after_a_genuine_receipt |  | covered: receipt/reject-one-trailing-byte-after-the-der |
| Ruby | hostile_input_test.rb test_a_payload_with_invalid_utf8_in_the_bundle_id |  | covered: receipt/invalid-utf8-strings-are-kept-raw |
| Ruby | hostile_input_test.rb test_a_message_digest_attribute_that_does_not_match_the_content |  | covered: receipt/reject-genuine-content-byte-flip |
| Ruby | hostile_input_test.rb test_no_source_file_can_reach_the_operating_systems_trust_store |  | stays with the host: api_shape_test: the library holds no verification code (greps lib/ for crypto, X.509, ASN.1, trust-store names) |
| Ruby | hostile_input_test.rb test_no_source_file_performs_network_io |  | stays with the host: api_shape_test: the library holds no verification code (greps lib/ for crypto, X.509, ASN.1, trust-store names) |
| Ruby | hostile_input_test.rb test_a_chain_the_platform_trust_store_accepts_is_still_rejected |  | stays with the host: the core's isolation test (ARCHITECTURE section 9: SSL_CERT_FILE, SSL_CERT_DIR, OPENSSL_CONF planted and ignored) replaces the platform-store trick |
| Ruby | hostile_input_test.rb test_the_same_pinning_holds_on_the_jws_path |  | stays with the host: the core's isolation test (ARCHITECTURE section 9: SSL_CERT_FILE, SSL_CERT_DIR, OPENSSL_CONF planted and ignored) replaces the platform-store trick |
| Ruby | hostile_input_test.rb test_a_receipt_whose_payload_is_a_huge_flat_set_is_bounded |  | to add, or a Rust test when the input is over 100 KB (R20's rule for bounds): receipt/a-huge-flat-attribute-set-is-bounded with maxMillis (5,000 valid attributes) |
| Ruby | hostile_input_test.rb test_a_ber_chunked_attribute_value_is_bounded |  | to add: receipt/a-ber-chunked-attribute-value-is-bounded with maxMillis (80 nested constructed OCTET STRINGs) |
| Ruby | hostile_input_test.rb test_the_node_budget_ceiling_costs_a_bounded_amount |  | to add, or a Rust test when the input is over 100 KB (R20's rule for bounds): receipt/reject-a-node-budget-flood with maxMillis (199,000 NULLs in one SEQUENCE) |
| Ruby | hostile_input_test.rb test_a_date_with_a_million_fractional_digits_is_not_superlinear |  | to add, or a Rust test when the input is over 100 KB (R20's rule for bounds): receipt/a-date-with-a-million-fractional-digits-is-bounded with maxMillis |
| Ruby | hostile_input_test.rb test_the_endpoint_is_not_superlinear_on_a_long_fractional_second |  | to add, or a Rust test when the input is over 100 KB (R20's rule for bounds): endpoint/a-date-with-1500000-fractional-digits-is-bounded with maxMillis |
| Ruby | hostile_input_test.rb test_the_containment_boundary_converts_every_foreign_error |  | stays with the host: facade_test: an exception inside the wrapper is INTERNAL_ERROR, never a raise; the trap and unreadable-answer tests |
| Ruby | hostile_input_test.rb test_the_containment_boundary_covers_system_stack_error |  | stays with the host: facade_test: an exception inside the wrapper is INTERNAL_ERROR, never a raise; the trap and unreadable-answer tests |
| Ruby | hostile_input_test.rb test_a_foreign_error_in_the_signed_payload_parse_is_unreadable_payload |  | stays with the host: facade_test: an exception inside the wrapper is INTERNAL_ERROR, never a raise; the trap and unreadable-answer tests |
| Ruby | hostile_input_test.rb test_a_verification_error_passes_through_the_boundary_unchanged |  | none (removed with the Ruby verifier): tested the private Receipt.contained boundary |
| Ruby | hostile_input_test.rb test_the_jws_boundary_contains_foreign_errors_too |  | stays with the host: facade_test: an exception inside the wrapper is INTERNAL_ERROR, never a raise; the trap and unreadable-answer tests |
| Ruby | input_size_bounds_test.rb test_the_caps_are_public_and_carry_the_cross_port_numbers |  | none (removed with the Ruby verifier): asserted Ruby constants that no longer exist; the caps are the module's and the cases below pin them |
| Ruby | input_size_bounds_test.rb test_a_base64_receipt_one_byte_over_the_cap_is_refused_before_decoding |  | covered: receipt-base64/reject-one-byte-over-the-size-cap |
| Ruby | input_size_bounds_test.rb test_the_base64_cap_counts_utf8_bytes_not_characters |  | covered: receipt-base64/reject-one-utf8-byte-over-the-size-cap, receipt-base64/pass-the-size-cap-then-fail-as-malformed |
| Ruby | input_size_bounds_test.rb test_a_base64_receipt_exactly_at_the_cap_is_decoded |  | covered: receipt-base64/accept-at-the-size-cap, receipt-base64/pass-the-size-cap-then-fail-as-malformed |
| Ruby | input_size_bounds_test.rb test_the_byte_floor_receipt_verifies_through_every_entry_point |  | covered: receipt/verify-at-the-byte-floor, endpoint/verify-at-the-byte-floor |
| Ruby | input_size_bounds_test.rb test_receipt_data_over_the_cap_answers_21002_without_decoding |  | covered: endpoint/receipt-data-over-the-receipt-cap-answers-21002 |
| Ruby | input_size_bounds_test.rb test_a_body_one_byte_over_the_cap_answers_21002_without_parsing |  | covered: endpoint/request-body-one-byte-over-the-size-cap-answers-21002 |
| Ruby | input_size_bounds_test.rb test_an_oversized_malformed_body_answers_21002_without_parsing |  | to add: endpoint/an-oversized-body-that-is-not-json-answers-21002 (size is decided before parsing) |
| Ruby | input_size_bounds_test.rb test_a_body_exactly_at_the_cap_is_parsed |  | covered: endpoint/request-body-at-the-size-cap-answers-0 |
| Ruby | input_size_bounds_test.rb test_the_body_cap_counts_utf8_bytes_not_characters |  | covered: endpoint/request-body-at-the-size-cap-in-two-byte-characters-answers-0, endpoint/request-body-over-the-size-cap-in-two-byte-characters-answers-21002 |
| Ruby | input_size_bounds_test.rb test_a_binary_body_is_measured_in_its_bytes |  | stays with the host: the wrapper sends a String's bytes, so a binary-encoded body is measured in bytes; retest through the real module after G1 (endpoint over-cap case with a .b body) |
| Ruby | input_size_bounds_test.rb test_a_body_nested_exactly_64_deep_is_read |  | covered: endpoint/request-body-nested-64-deep-answers-0 |
| Ruby | input_size_bounds_test.rb test_a_body_nested_65_deep_answers_21002_without_decoding |  | covered: endpoint/request-body-nested-65-deep-answers-21002 |
| Ruby | input_size_bounds_test.rb test_a_jws_one_character_over_the_cap_is_refused_before_it_is_split |  | covered: raw/reject-jws-one-byte-over-the-size-cap |
| Ruby | input_size_bounds_test.rb test_a_jws_exactly_at_the_cap_is_split |  | covered: raw/jws-at-the-size-cap-reaches-the-signature-check |
| Ruby | input_size_bounds_test.rb test_a_jws_header_or_payload_nested_exactly_64_deep_verifies |  | covered: signed-data/accept-a-header-nested-64-deep, signed-data/accept-a-payload-nested-64-deep |
| Ruby | input_size_bounds_test.rb test_a_jws_header_nested_65_deep_is_malformed |  | covered: signed-data/reject-a-header-nested-65-deep |
| Ruby | input_size_bounds_test.rb test_a_jws_payload_nested_65_deep_is_unreadable_after_a_genuine_signature |  | covered: signed-data/unreadable-payload-nested-65-deep |
| Ruby | jws_test.rb test_verifies_the_apple_official_transaction_info_mock |  | covered: transaction/verify-apple-official-transaction-info |
| Ruby | jws_test.rb test_rejects_a_non_es256_alg |  | covered: signed-data/reject-alg-rs256 |
| Ruby | jws_test.rb test_rejects_x5c_with_two_or_four_entries |  | added: `signed-data/reject-a-four-certificate-x5c` |
| Ruby | jws_test.rb test_rejects_x5c_entries_that_are_not_strings |  | covered: transaction/reject-x5c-entry-that-is-not-a-string |
| Ruby | jws_test.rb test_rejects_an_x5c_entry_that_is_base64_but_not_a_certificate |  | covered: transaction/reject-x5c-leaf-that-is-not-a-certificate |
| Ruby | jws_test.rb test_rejects_an_x5c_certificate_carrying_one_extension_twice |  | covered: transaction/reject-x5c-duplicate-extension |
| Ruby | jws_test.rb test_rejects_a_segment_outside_the_base64url_alphabet |  | to add: transaction/reject-a-header-or-payload-segment-outside-the-base64url-alphabet (signature-segment variants exist) |
| Ruby | jws_test.rb test_rejects_a_segment_that_is_base64url_but_not_json |  | to add: transaction/reject-a-header-that-is-base64url-but-not-json (json array and scalar exist) |
| Ruby | jws_test.rb test_rejects_a_payload_that_is_json_but_not_an_object |  | covered: signed-data/unreadable-json-array-payload, transaction/reject-payload-that-is-a-json-array |
| Ruby | jws_test.rb test_rejects_a_leaf_without_the_apple_marker_oid |  | covered: transaction/reject-leaf-without-apple-marker-oid |
| Ruby | jws_test.rb test_rejects_an_intermediate_without_the_wwdr_marker_oid |  | covered: transaction/reject-intermediate-without-wwdr-marker-oid |
| Ruby | jws_test.rb test_chain_is_reported_before_the_marker_oid |  | covered: signed-data/reject-foreign-chain-without-markers |
| Ruby | jws_test.rb test_rejects_an_intermediate_that_is_not_a_ca |  | to add: signed-data/reject-an-intermediate-that-is-not-a-ca (basicConstraints cA false; receipt twin: receipt/reject-leaf-presented-as-intermediate) |
| Ruby | jws_test.rb test_rejects_signatures_that_are_not_sixty_four_bytes |  | added: `transaction/reject-signature-of-63-bytes`, `transaction/reject-signature-of-65-bytes` |
| Ruby | jws_test.rb test_rejects_a_signature_whose_scalars_are_zero_or_out_of_range |  | added: `transaction/reject-an-all-zero-signature`; the group-order scalar: to add |
| Ruby | jws_test.rb test_rejects_a_tampered_payload |  | covered: transaction/reject-tampered-payload |
| Ruby | jws_test.rb test_x5c_third_element_is_ignored |  | to add: transaction/ignore-a-third-x5c-element (a foreign root as x5c[2] changes nothing) |
| Ruby | jws_test.rb test_no_claim_is_enforced_only_the_signature |  | covered: transaction/return-bundle-id-for-the-caller, raw/skip-claim-checks-but-not-signature |
| Ruby | jws_test.rb test_dates_are_epoch_millisecond_numbers_not_strings |  | covered: transaction/verify-shared-sandbox (numeric claims), raw/return-claims-of-any-type |
| Ruby | jws_test.rb test_json_exposes_every_claim_unchanged_including_ones_this_library_does_not_model |  | covered: transaction/accept-null-and-unmodelled-claims |
| Ruby | jws_test.rb test_the_json_payload_is_frozen |  | stays with the host: api_shape_test (frozen values) |
| Ruby | jws_test.rb test_rejects_inputs_that_are_not_three_segments |  | to add: raw/reject-a-jws-with-fewer-or-more-than-three-segments (four: signed-data/reject-four-segment-jws; empty: transaction/reject-all-segments-empty) |
| Ruby | jws_test.rb test_rejects_a_non_string_input |  | stays with the host: api_shape_test (non-String is MALFORMED) |
| Ruby | mutation_test.rb test_mutations_of_the_genuine_legacy_receipt_never_escape |  | the corpus and the differential run, not a case: corpus: the 5,000 mutants and the hostile rows, byte for byte against native; rust/fuzz |
| Ruby | mutation_test.rb test_mutations_of_the_genuine_sandbox_receipt_never_escape |  | the corpus and the differential run, not a case: corpus: the 5,000 mutants and the hostile rows, byte for byte against native; rust/fuzz |
| Ruby | mutation_test.rb test_mutations_of_a_generated_receipt_never_escape |  | the corpus and the differential run, not a case: corpus: the 5,000 mutants and the hostile rows, byte for byte against native; rust/fuzz |
| Ruby | mutation_test.rb test_mutations_of_the_shared_transaction_jws_never_escape |  | the corpus and the differential run, not a case: corpus: the 5,000 mutants and the hostile rows, byte for byte against native; rust/fuzz |
| Ruby | mutation_test.rb test_segment_swaps_and_reorderings_of_a_jws_never_escape |  | the corpus and the differential run, not a case: corpus: the 5,000 mutants and the hostile rows, byte for byte against native; rust/fuzz |
| Ruby | mutation_test.rb test_a_mutation_that_still_verifies_returns_an_identical_payload |  | the corpus and the differential run, not a case: differential check (Phase 1 runner): a mutant that still verifies returns the payload of the unmutated input |
| Ruby | mutation_test.rb test_random_bytes_never_escape |  | the corpus and the differential run, not a case: corpus: the 5,000 mutants and the hostile rows, byte for byte against native; rust/fuzz |
| Ruby | mutation_test.rb test_random_strings_never_escape_the_jws_path |  | the corpus and the differential run, not a case: corpus: the 5,000 mutants and the hostile rows, byte for byte against native; rust/fuzz |
| Ruby | mutation_test.rb test_the_endpoint_never_raises_across_the_same_sweep |  | the corpus and the differential run, not a case: corpus: the 5,000 mutants and the hostile rows, byte for byte against native; rust/fuzz |
| Ruby | pacific_time_test.rb test_every_tzdata_vector_renders_identically |  | to add: endpoint/request-date-pst-* : pinned-clock cases either side of each US DST transition, and 2007 and 2040 (the tzdata vectors of the old file) |
| Ruby | pacific_time_test.rb test_the_offset_is_only_ever_seven_or_eight_hours_west |  | to add: endpoint/request-date-pst-* : pinned-clock cases either side of each US DST transition, and 2007 and 2040 (the tzdata vectors of the old file) |
| Ruby | pacific_time_test.rb test_the_offset_actually_changes_across_a_year |  | to add: endpoint/request-date-pst-* : pinned-clock cases either side of each US DST transition, and 2007 and 2040 (the tzdata vectors of the old file) |
| Ruby | pacific_time_test.rb test_transitions_land_on_a_sunday_at_two_am_local |  | to add: endpoint/request-date-pst-* : pinned-clock cases either side of each US DST transition, and 2007 and 2040 (the tzdata vectors of the old file) |
| Ruby | pacific_time_test.rb test_a_non_utc_time_is_converted_before_the_rule_is_applied |  | to add: endpoint/request-date-pst-* : pinned-clock cases either side of each US DST transition, and 2007 and 2040 (the tzdata vectors of the old file) |
| Ruby | packaging_test.rb test_the_gemspec_declares_every_file_a_consumer_needs |  | stays with the host: packaging_test |
| Ruby | packaging_test.rb test_the_gemspec_ships_no_test_or_tooling_files |  | stays with the host: packaging_test |
| Ruby | packaging_test.rb test_the_built_gem_verifies_a_genuine_receipt_from_a_clean_gem_home |  | stays with the host: packaging_test |
| Ruby | performance_test.rb test_the_largest_genuine_receipt_stays_inside_its_budget |  | stays with the host: bench/startup.rb and the maxMillis cases replace CPU budgets; per-call cost is the module's |
| Ruby | performance_test.rb test_a_typical_receipt_stays_inside_its_budget |  | stays with the host: bench/startup.rb and the maxMillis cases replace CPU budgets; per-call cost is the module's |
| Ruby | performance_test.rb test_a_transaction_jws_stays_inside_its_budget |  | stays with the host: bench/startup.rb and the maxMillis cases replace CPU budgets; per-call cost is the module's |
| Ruby | performance_test.rb test_rejecting_a_nesting_bomb_costs_almost_nothing |  | to add, or a Rust test when the input is over 100 KB (R20's rule for bounds): covered by the two nesting-bomb cases above (maxMillis) |
| Ruby | port_divergence_test.rb test_a_ber_chunked_attribute_value_reads_as_its_concatenation |  | covered since the core review: `receipt/accept-attribute-value-as-a-constructed-octet-string`, `receipt/accept-attribute-value-rechunked-into-6-constructed-levels`, `receipt/unreadable-attribute-value-with-a-utf8string-chunk` |
| Ruby | port_divergence_test.rb test_a_ber_chunked_attribute_value_survives_a_single_chunk_and_an_empty_one |  | covered since the core review: `receipt/accept-attribute-value-as-a-constructed-octet-string`, `receipt/accept-attribute-value-rechunked-into-6-constructed-levels`, `receipt/unreadable-attribute-value-with-a-utf8string-chunk` |
| Ruby | port_divergence_test.rb test_a_ber_chunked_attribute_value_with_a_non_octet_string_chunk_is_kept_raw |  | covered since the core review: `receipt/accept-attribute-value-as-a-constructed-octet-string`, `receipt/accept-attribute-value-rechunked-into-6-constructed-levels`, `receipt/unreadable-attribute-value-with-a-utf8string-chunk` |
| Ruby | port_divergence_test.rb test_a_non_integer_signed_date_still_drives_the_chain_instant |  | covered: signed-data/signed-date-fractional |
| Ruby | port_divergence_test.rb test_a_non_integer_signed_date_is_reported_unchanged_in_the_payload |  | covered: signed-data/signed-date-fractional |
| Ruby | port_divergence_test.rb test_a_non_finite_or_out_of_range_signed_date_falls_back_to_the_clock |  | covered: transaction/signed-date-out-of-range-falls-back-to-the-clock |
| Ruby | receipt_base64_test.rb test_bytes_outside_the_base64_alphabet_are_refused |  | covered: receipt-base64/reject-*, base64/reject-* |
| Ruby | receipt_base64_test.rb test_neither_ruby_decoder_alone_is_the_rule |  | none (removed with the Ruby verifier): tested the Ruby decoder Receipt.decode_canonical_base64 |
| Ruby | receipt_test.rb test_verifies_the_genuine_sandbox_receipt |  | covered: receipt/verify-genuine-sandbox-g5-against-apple-roots |
| Ruby | receipt_test.rb test_verifies_the_genuine_legacy_sha1_receipt |  | covered: receipt/verify-genuine-legacy-sha1-chain |
| Ruby | receipt_test.rb test_the_caller_can_compute_the_device_hash_from_the_returned_fields |  | covered: receipt/verify-genuine-sandbox-g5-device-hash |
| Ruby | receipt_test.rb test_rejects_trailing_bytes_after_the_cms_blob |  | covered: receipt/reject-one-trailing-byte-after-the-der |
| Ruby | receipt_test.rb test_rejects_zero_signer_infos |  | covered: receipt/reject-zero-signer-infos |
| Ruby | receipt_test.rb test_a_duplicated_genuine_signer_info_still_verifies |  | to add: receipt/accept-a-duplicated-genuine-signer-info (closest today: accept-four-signers-at-the-cap) |
| Ruby | receipt_test.rb test_accepts_an_ec_signer_key |  | covered: receipt/verify-signer-ecdsa-p256 |
| Ruby | receipt_test.rb test_rejects_a_signer_certificate_that_is_not_embedded |  | to add: receipt/reject-a-signer-certificate-that-is-not-embedded (closest today: reject-signer-absent-beside-a-malformed-stranger) |
| Ruby | receipt_test.rb test_twin_certificate_with_the_signers_serial_is_not_accepted_as_the_signer |  | covered: receipt/reject-twin-certificate |
| Ruby | receipt_test.rb test_chain_is_reported_before_the_signer_marker_oid |  | to add: receipt/reject-a-foreign-chain-whose-signer-lacks-the-marker (UNTRUSTED_CHAIN before INVALID_CERTIFICATE_PURPOSE; the JWS twin is signed-data/reject-foreign-chain-without-markers) |
| Ruby | receipt_test.rb test_attribute_integers_at_the_edges |  | covered: receipt/integers-at-the-64-bit-edge |
| Ruby | receipt_test.rb test_rejects_an_attribute_type_above_the_32_bit_signed_range |  | covered: receipt/reject-attribute-type-above-int32-max, receipt/attribute-type-int32-max-is-kept |
| Ruby | receipt_test.rb test_legacy_receipt_ids_are_decoded |  | covered: receipt/ids-are-decoded |
| Ruby | receipt_test.rb test_legacy_receipt_ids_are_absent_when_the_receipt_does_not_carry_them |  | covered: receipt/ids-absent-when-not-carried |
| Ruby | receipt_test.rb test_dates_outside_the_exact_grammar_are_kept_raw_not_an_error |  | covered: receipt/date-grammar |
| Ruby | receipt_test.rb test_an_empty_date_string_means_absent_and_is_not_kept_raw |  | covered: receipt/verify-genuine-sandbox-g5-against-apple-roots (attribute 1712 is an empty date) |
| Ruby | receipt_test.rb test_an_attribute_value_that_is_not_valid_utf8_is_kept_raw |  | covered: receipt/invalid-utf8-strings-are-kept-raw |
| Ruby | receipt_test.rb test_a_string_attribute_whose_value_is_the_wrong_asn1_type_is_kept_raw |  | covered: receipt/printable-string-attributes-are-kept-raw |
| Ruby | receipt_test.rb test_the_library_takes_no_bundle_id_and_judges_no_claim |  | covered: receipt/return-bundle-id-for-the-caller |
| Ruby | receipt_test.rb test_byte_fields_are_frozen_copies_of_the_input |  | stays with the host: facade_test / api_shape_test (frozen values); the copy-from-input concern cannot arise, the bytes come from the module |
| Ruby | receipt_test.rb test_receipt_dates_are_epoch_millisecond_integers |  | covered: receipt/verify-genuine-sandbox-g5-against-apple-roots (toJson dates) |
| Ruby | receipt_test.rb test_an_anchor_is_not_rejected_for_being_expired |  | to add: receipt/accept-an-expired-trust-anchor (an anchor's own validity window is not examined) |
| Ruby | receipt_test.rb test_rejects_input_that_is_not_a_string_or_is_empty |  | stays with the host: api_shape_test (non-String is MALFORMED); receipt-base64/reject-empty |
| Ruby | receipt_test.rb test_rejects_text_that_is_not_canonical_base64 |  | covered: receipt-base64/reject-*, base64/reject-* |
| Ruby | receipt_test.rb test_rejects_base64_that_does_not_hold_a_cms_blob |  | covered: base64/decodes-to-not-a-certificate, base64/decodes-to-not-a-certificate-at-all |
| Ruby | roots_test.rb test_config_defaults_returns_all_three_published_apple_roots |  | stays with the host: the core's AppleRootCerts-style test: three roots pinned by fingerprint (Rust); the gem carries none |
| Ruby | roots_test.rb test_the_inlined_roots_equal_the_packaged_certificate_files |  | stays with the host: tools/check-cert-copies.mjs (certs/ and its copies), until Phase 7 deletes ruby/certs |
| Ruby | roots_test.rb test_the_packaged_certificates_match_the_repository_roots |  | stays with the host: tools/check-cert-copies.mjs (certs/ and its copies), until Phase 7 deletes ruby/certs |
| Ruby | roots_test.rb test_every_bundled_root_matches_its_pinned_fingerprint |  | stays with the host: the core's AppleRootCerts-style test: three roots pinned by fingerprint (Rust); the gem carries none |
| Ruby | roots_test.rb test_a_swapped_root_empties_the_whole_set_rather_than_silently_dropping_one |  | none (removed with the Ruby verifier): tested the Ruby roots loader |
| Ruby | roots_test.rb test_each_call_returns_fresh_certificate_objects_so_a_caller_cannot_poison_another_config |  | none (removed with the Ruby verifier): tested the Ruby roots loader |
| Ruby | roots_test.rb test_the_roots_are_self_signed_and_carry_ca_true |  | stays with the host: the core's AppleRootCerts-style test: three roots pinned by fingerprint (Rust); the gem carries none |
| Ruby | roots_test.rb test_the_bundled_roots_are_not_expired |  | stays with the host: the core's AppleRootCerts-style test: three roots pinned by fingerprint (Rust); the gem carries none |
| Python | reject-eleven-non-certificate-embedded-entries-as-malformed | the certificate count is taken before any entry is decoded | covered: `receipt/reject-eleven-embedded-certificates`; the all-junk variant: to add |
| Python | signed attributes: empty message-digest set | a hostile SignerInfo is a refusal | to add (needs a minted signer; `receipt/reject-signed-attributes-with-two-message-digests` is the nearest) |
| Python | signed attributes: message-digest not an OCTET STRING | as above | to add |
| Python | signed attributes: signing-time month 13 | as above | to add |
| Python | signed attributes: unknown attribute with invalid UTF-8 | as above | to add |
| Python | signed attributes: unknown attribute nested 5,000 deep | depth bound inside SignerInfo values | covered: the depth-33 envelope cases (`receipt/reject-an-envelope-nested-33-deep` and the core review's family) |
| Python | SignerInfo: digest algorithm not an OID | a hostile SignerInfo is a refusal | to add |
| Python | SignerInfo: signature not an OCTET STRING | as above | to add |
| Python | reject-truncated-receipt-at-200-bytes | a cut envelope is MALFORMED | added: `receipt/reject-receipt-truncated-to-200-bytes` |
| Python | reject-anonymous-blob-with-an-unconvertible-creation-date | an unreadable date never rejects by itself | covered: `receipt/unreadable-creation-date-decodes-to-null`, `receipt/reject-unreadable-creation-date-under-an-expired-chain` |
| Python | reject-negative-attribute-type | a negative type is not a modelled one | to add (`receipt/reject-attribute-type-above-int32-max` is the other end) |
| Python | signed-data NaN and Infinity signed dates | an unrepresentable signedDate falls back to the clock | covered in part: `transaction/signed-date-out-of-range-falls-back-to-the-clock`; NaN and Infinity are not JSON, so a JWS carrying them is MALFORMED: to add |
| Python | x5c entries that are numbers | x5c holds three strings | added: `signed-data/reject-x5c-of-numbers` |
| Python | x5c entries that are containers and null | as above | added: `signed-data/reject-x5c-with-null-and-a-list` |
| Python | header and payload nested 20,000 deep | JSON depth bound | covered: `signed-data/reject-a-header-nested-65-deep`, `signed-data/unreadable-payload-nested-65-deep` (the bound is 64) |
| Python | endpoint 21002 for an empty body | a body that cannot be read | added: `endpoint/empty-body-answers-21002` |
| Python | endpoint 21002 for invalid JSON | as above | added: `endpoint/body-that-is-not-json-answers-21002` |
| Python | endpoint 21002 for a truncated object | as above | added: `endpoint/truncated-object-answers-21002` |
| Python | endpoint 21002 for a body nested 100,000 deep | depth and cost | covered: `endpoint/request-body-nested-65-deep-answers-21002`; the 100,000-deep cost is a Rust test (a 200 KB input, R20's rule) |
| Python | brackets inside a string are not nesting | JSON depth counts structure, not characters | added: `endpoint/brackets-inside-a-string-are-not-nesting-answers-0` |
| Python | intro-offer flag is the string "false" | Apple's rendering of flags | added: `endpoint/intro-offer-and-trial-flags-are-the-strings-true-and-false` |
| Python | fresh creation date under an expired chain, clock inside the window | the clock never replaces a readable creation date | added: `receipt/pinned-clock-does-not-rescue-a-fresh-creation-date`, `endpoint/pinned-clock-does-not-rescue-a-fresh-creation-date-answers-21003` |
| Python | over-cap inputs with maxMillis 2000 | a cap is decided on the length | covered: the `*-one-byte-over-the-size-cap` cases, each with maxMillis |
| Java -wasm | countsEmbeddedCertificatesBeforeDecodingAnyOfThem | the count bound comes before any decode | to add: `receipt/reject-eleven-embedded-certificates-mostly-undecodable` (needs a respliced envelope) |
| Java -wasm | theClockDoesNotOverrideACreationDate | the clock never replaces a readable creation date | added: `receipt/pinned-clock-does-not-rescue-a-fresh-creation-date`, `endpoint/pinned-clock-does-not-rescue-a-fresh-creation-date-answers-21003` |
| Java -wasm | rejectsABrokenSignatureSegmentBeforeTheChain | segments are decoded before the chain | added: `transaction/reject-broken-signature-segment-under-a-foreign-chain` |
| Java -wasm | jwsIsMeasuredInUtf8Bytes | the JWS cap counts UTF-8 bytes | covered in part: `raw/jws-at-the-size-cap-reaches-the-signature-check`, `raw/reject-jws-one-byte-over-the-size-cap`; the multi-byte variant is a 256 KB fixture: to add as a generated fixture or a Rust test |
| Java -wasm | endpoint is_in_intro_offer_period and is_trial_period as strings | Apple's rendering of flags | added: `endpoint/intro-offer-and-trial-flags-are-the-strings-true-and-false` |
| Java -wasm | an empty JWS is MALFORMED | empty input | covered: `transaction/reject-all-segments-empty` (and `base64/reject-empty` for receipts) |
| Java -wasm | an empty body answers 21002 | empty request | added: `endpoint/empty-body-answers-21002` |
| Java -wasm | GuestPool, EndiveGuest, ClasspathGuard, Engine and ServerSource tests | pooling, the hand-rolled call, packaging | stays with the host |
| Swift | x5c entry behind a byte order mark | x5c entries are strict base64 | added: `signed-data/reject-x5c-leaf-behind-a-byte-order-mark` |
| Swift | a refused RSA key | a key OpenSSL cannot use is INVALID_CERTIFICATE | covered: `receipt/reject-signer-with-an-even-rsa-modulus` |
| Swift | a ContentInfo holding only the OID | a cut envelope is MALFORMED | covered: `receipt/reject-receipt-truncated-to-200-bytes` (added) and `receipt/reject-empty-encapsulated-content`; the OID-only shape: to add |
| Swift | intro-offer flag as a string | Apple's rendering of flags | added: `endpoint/intro-offer-and-trial-flags-are-the-strings-true-and-false` |
| Swift | six non-object bodies answer 21002 | a body that is not an object | covered: `endpoint/body-that-is-an-array-answers-21002`, `endpoint/body-that-is-null-answers-21002`, `endpoint/body-that-is-a-scalar-answers-21002`; added: `endpoint/empty-body-answers-21002`, `endpoint/body-that-is-not-json-answers-21002` |
| Swift | an escaped BOM before receipt-data | receipt-data is strict base64 | covered: `endpoint/receipt-data-leading-byte-order-mark-answers-21002` |
| Swift | the verdict follows the roots | pinning | covered: `receipt/reject-foreign-root`, `transaction/reject-foreign-root` |
| Swift | the clock moves no verdict for a dated receipt | the creation date is the chain instant | added: `receipt/pinned-clock-does-not-rescue-a-fresh-creation-date`, `endpoint/pinned-clock-does-not-rescue-a-fresh-creation-date-answers-21003` |
| Swift | in-app attribute type 2^31 and 2^31 - 1 | type range | covered: `receipt/attribute-type-int32-max-is-kept`, `receipt/reject-attribute-type-above-int32-max`; the in-app level: to add |
| Swift | ASN.1 depth through BER indefinite lengths | depth bound | covered: the depth-32/33 envelope cases |
| Swift | brackets inside strings | JSON depth counts structure | added: `endpoint/brackets-inside-a-string-are-not-nesting-answers-0` |
| Swift | Pacific time at the DST transitions | request_date_pst rendering | to add: pinned-clock endpoint cases either side of each US transition (or a core unit test) |
| Swift | chain-walk bounds: eleven certificates, one not a certificate | count before decode | covered: `receipt/reject-eleven-embedded-certificates` |
| Swift | chain-walk bounds: bag over the bound without a signer | count before the signer lookup | to add |
| Swift | chain-walk bounds: an empty SEQUENCE in the bag | an unreadable bag entry | covered in part: `receipt/reject-signer-absent-beside-a-malformed-stranger` |
| Swift | chain-walk bounds: the bag stops at the intermediate | no fetching | covered: `receipt/reject-chain-missing-the-intermediate` |
| Swift | chain-walk bounds: issuer-name collision at index 0, 1, 2 | same-named issuers | covered: `receipt/reject-twin-certificate`, the same-subject root cases, and `receipt/verify-with-a-stranger-vouched-by-a-same-named-root-listed-first`, `receipt/verify-with-a-stranger-vouched-by-a-same-named-root-listed-second` (added by the differential run) |
| Swift | chain-walk bounds: key clone at index 0, 1, 2 | a clone's key is never used before its chain | covered: `receipt/genuine-signer-behind-a-copy-of-its-identity-does-not-crash` |
| Swift | chain-walk bounds: self-issued fan-out with maxMillis | cost bound | covered: `receipt/reject-cross-signed-mesh` |
| Swift | chain-walk bounds: a signature cycle inside and outside the path | no loop | covered: `receipt/reject-a-path-of-seven-with-a-self-issued-tail` |
| Swift | dated receipt and signed date ignore the clock | the clock is only a fallback | covered: `endpoint/clock-inside-the-window-verifies-a-dateless-receipt`; added: receipt/pinned-clock-does-not-rescue-a-fresh-creation-date |
| Swift | same-subject root order, even RSA modulus (G1 findings) | root order decides nothing; an even modulus is a certificate defect | covered since the core review: `receipt/verify-under-the-first-of-two-roots-sharing-a-subject`, `receipt/reject-signer-with-an-even-rsa-modulus` |
| Swift | Guest, pool, WasmKit and bounds-checking tests | the host | stays with the host |
| PHP | Pacific time rendering at five clocks | request_date_pst | to add (as Swift's) |
| PHP | JWS header x5c as an object | x5c is an array | added: `signed-data/reject-x5c-that-is-an-object` |
| PHP | JWS header alg es256 | alg is case-sensitive | added: `signed-data/reject-alg-in-lower-case` |
| PHP | JWS payload [] | the signature covers the payload | added: `transaction/reject-a-payload-swapped-for-an-array` |
| PHP | an RSA leaf in a JWS | ES256 only | covered: `signed-data/reject-alg-rs256`; an RSA key under alg ES256: to add |
| PHP | ES256 signatures of 0, 63, 65 and 128 bytes | a signature is 64 bytes | added: `transaction/reject-signature-of-63-bytes`, `transaction/reject-signature-of-65-bytes`, added: `transaction/reject-an-all-zero-signature`; 128 bytes: to add |
| PHP | rsaEncryption label on an EC key | the key decides, not the label | covered: `receipt/relabelled-signature-algorithm-does-not-crash` |
| PHP | unknown digest OID in a SignerInfo | a digest the adapter cannot run | to add (the differential run's `java-catch-all` row is this shape) |
| PHP | MD5 digest | an algorithm OpenSSL refuses | to add |
| PHP | SignerInfo naming a certificate that is not embedded | no fetching | covered: `receipt/reject-signer-absent-beside-a-malformed-stranger`; the plain case: to add |
| PHP | an empty date attribute is absent | date grammar | to add (Go's `receipt/empty-date-string-means-absent` too) |
| PHP | a date with an offset | date grammar | covered: `receipt/date-grammar` |
| PHP | inner and outer signature algorithms disagree | X.509 consistency | to add |
| PHP | a validity month 13 | X.509 time | to add |
| PHP | the UTCTime pivot | X.509 time | to add |
| PHP | a validity of the wrong tag | X.509 time | to add |
| PHP | issuer name matches, signature does not | names never stand in for signatures | covered: `receipt/reject-twin-certificate` |
| PHP | the marker OID on the encoded bytes | marker OIDs | covered: `receipt/reject-signer-without-receipt-signing-oid`, `transaction/reject-leaf-without-apple-marker-oid` |
| PHP | JSON depth is nesting, not bracket count | JSON depth | added: `endpoint/brackets-inside-a-string-are-not-nesting-answers-0` |
| PHP | a failure message never echoes the input | log safety | to add; the schema's `messageMustNotContain` takes code points only today |
| PHP | a literal {"status":21002} body | a response body is not a request | added: `endpoint/literal-status-body-answers-21002` |
| PHP | CliTransport, HttpTransport, aprv-install tests | the transport | stays with the host |
| Node | endpoint-wire tests | Apple's response shape | covered by the endpoint cases; the flag strings: added: `endpoint/intro-offer-and-trial-flags-are-the-strings-true-and-false` |
| Node | clock tests | the clock's two uses | covered: `endpoint/request-date-is-the-verification-clock`, the dateless-receipt clock cases; added: `receipt/pinned-clock-does-not-rescue-a-fresh-creation-date`, `endpoint/pinned-clock-does-not-rescue-a-fresh-creation-date-answers-21003` |
| Node | hostile-input tests | bounds and refusals | covered by the depth, count and cap cases; the rest by the corpus |
| Node | trust-store-isolation tests | no OS trust store | the core's isolation test (`rust/openssl/tests/isolation.rs`); stays with the core |
| Node | apple-date tests | Apple's date rendering | Rust unit tests of `rust/src/datetime.rs` and `rust/tests/datetime.rs` |
| Node | jco facade, instance and runtime smoke tests | the host | stays with the host |
| .NET | verification tests of the removed verifier | the 0.7 behaviour | the lane mapped them to the shared cases and to core unit tests (its evidence README of the first round); no per-test list survives on its branch |
| .NET | host, pool, Floor and packaging tests | the host | stays with the host |

### Rust and Java

| Port | Test | Target |
|---|---|---|
| Rust | `rust/src/base64.rs` `the_engines_match_the_hand_written_routines` | input built in code: stays with the Rust |
| Rust | `rust/src/json.rs` `the_depth_limit_itself_is_allowed_and_one_more_is_not` | input built in code: stays with the Rust |
| Rust | `rust/src/json.rs` `brackets_inside_strings_are_data` | input built in code: stays with the Rust |
| Rust | `rust/src/json.rs` `anything_after_the_object_is_not_read` | input built in code: stays with the Rust |
| Rust | `rust/src/json.rs` `a_whole_object_allows_only_whitespace_after_it` | input built in code: stays with the Rust |
| Rust | `rust/src/json.rs` `grammar_errors_inside_the_object_are_refused` | input built in code: stays with the Rust |
| Rust | `rust/src/json.rs` `members_keep_document_order_and_duplicates` | input built in code: stays with the Rust |
| Rust | `rust/src/json.rs` `escapes_decode_and_names_compare_decoded` | input built in code: stays with the Rust |
| Rust | `rust/src/json.rs` `instants_follow_the_reference_conversion` | input built in code: stays with the Rust |
| Rust | `rust/src/jws.rs` `a_header_with_a_byte_order_mark_or_trailing_text_is_malformed` | input built in code: stays with the Rust |
| Rust | `rust/src/jws.rs` `a_payload_with_trailing_text_is_unreadable` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `a_payload_whose_set_or_attribute_does_not_parse_is_unreadable` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `the_first_copy_of_a_known_attribute_wins_and_later_ones_are_kept_raw` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `a_value_that_does_not_decode_is_null_and_kept_raw` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `an_ia5_string_with_a_byte_from_0x80_up_is_kept_raw` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `an_integer_or_flag_that_is_not_minimally_encoded_is_kept_raw` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `a_date_in_any_other_form_is_kept_raw_and_does_not_set_the_chain_instant` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `signed_content_nested_past_the_asn1_bound_is_unreadable` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `signed_content_nested_33_deep_is_unreadable_whatever_the_tags` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `the_payload_holds_at_most_100000_values` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `a_value_or_a_wrap_with_a_chunk_that_is_not_an_octet_string_is_unreadable` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `a_constructed_string_value_is_kept_raw` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `a_tag_in_high_tag_form_or_a_five_octet_length_is_not_read` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `fields_after_the_value_are_valid_asn1_at_every_depth` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `an_empty_date_means_not_set_and_is_not_kept` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `integers_are_reported_as_they_are_negative_ones_included` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `an_in_app_purchase_that_does_not_parse_is_kept_raw_under_17` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `the_bundle_id_octets_are_kept_even_when_the_string_does_not_decode` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `the_first_creation_date_is_the_chain_instant` | input built in code: stays with the Rust |
| Rust | `rust/src/receipt_payload.rs` `an_empty_purchase_writes_every_key_as_null` | input built in code: stays with the Rust |
| Rust | `rust/src/roots.rs` `every_bundled_root_parses` | input built in code: stays with the Rust |
| Rust | `rust/src/roots.rs` `the_bundled_roots_are_the_ones_apple_publishes` | input built in code: stays with the Rust |
| Rust | `rust/src/roots.rs` `one_root_that_does_not_load_empties_the_set` | input built in code: stays with the Rust |
| Rust | `rust/src/verifier.rs` `a_verifier_without_anchors_answers_internal_error` | input built in code: stays with the Rust |
| Rust | `rust/src/verifier.rs` `a_panic_is_judged_by_the_stage_it_happened_in` | input built in code: stays with the Rust |
| Rust | `rust/src/verifier.rs` `every_verification_starts_before_the_signature_and_restores_the_caller` | input built in code: stays with the Rust |
| Rust | `rust/src/verifier.rs` `the_clock_is_read_once_and_its_panic_is_an_internal_error` | input built in code: stays with the Rust |
| Rust | `rust/openssl/tests/isolation.rs` `child` | same fixture as `endpoint/ids-absent-are-omitted`, `endpoint/request-date-is-the-verification-clock`, `endpoint/sandbox-receipt-on-production-answers-21007` and 9 more |
| Rust | `rust/openssl/tests/isolation.rs` `a_planted_trust_store_configuration_and_module_path_are_ignored` | input built in code: stays with the Rust |
| Rust | `rust/openssl/tests/isolation.rs` `the_detectors_see_a_loaded_configuration_and_a_loaded_trust_store` | same fixture as `endpoint/ids-absent-are-omitted`, `endpoint/request-date-is-the-verification-clock`, `endpoint/sandbox-receipt-on-production-answers-21007` and 9 more |
| Rust | `rust/tests/allocation.rs` `verification_allocates_a_bounded_multiple_of_the_input` | same fixture as `receipt/verify-genuine-legacy-sha1-chain` |
| Rust | `rust/tests/api.rs` `every_reason_spells_the_canonical_token` | input built in code: stays with the Rust |
| Rust | `rust/tests/api.rs` `reason_round_trips_through_from_str_and_display` | input built in code: stays with the Rust |
| Rust | `rust/tests/api.rs` `a_payload_states_the_environment_apples_value_names` (was `environment_helpers_state_what_apples_strings_mean`; the helpers left the public API in R42) | input built in code: stays with the Rust; the rule itself is pinned by every ok case's `expected.environment` and the `signed-data/environment-*` cases |
| Rust | `rust/tests/api.rs` `apple_status_names_every_documented_code` | input built in code: stays with the Rust |
| Rust | `rust/tests/api.rs` `version_is_the_manifest_version` | input built in code: stays with the Rust |
| Rust | `rust/tests/api.rs` `a_failure_displays_as_reason_colon_message_and_carries_its_source` | same fixture as `receipt/unreadable-payload-under-a-valid-signature` |
| Rust | `rust/tests/api.rs` `an_empty_root_set_is_a_config_error_not_a_verdict` | input built in code: stays with the Rust |
| Rust | `rust/tests/api.rs` `a_bad_trust_anchor_is_a_config_error` | input built in code: stays with the Rust |
| Rust | `rust/tests/api.rs` `der_and_pem_anchors_are_interchangeable` | fixture registered, no case uses it: stays with the Rust |
| Rust | `rust/tests/api.rs` `the_api_types_are_send_sync_and_static` | input built in code: stays with the Rust |
| Rust | `rust/tests/api.rs` `one_verifier_answers_identically_from_sixteen_threads` | input built in code: stays with the Rust |
| Rust | `rust/tests/api.rs` `bundled_roots_are_parsed_once_and_shared` | input built in code: stays with the Rust |
| Rust | `rust/tests/api.rs` `the_clock_is_read_only_when_a_verdict_needs_it` | same fixture as `endpoint/clock-past-the-window-rejects-a-dateless-receipt`, `receipt/accept-missing-creation-date` |
| Rust | `rust/tests/api.rs` `the_device_hash_is_computable_from_the_returned_fields` | input built in code: stays with the Rust |
| Rust | `rust/tests/api.rs` `returned_byte_fields_are_copies_not_views_into_the_input` | input built in code: stays with the Rust |
| Rust | `rust/tests/api.rs` `a_verified_jws_is_returned_exactly_as_signed` | input built in code: stays with the Rust |
| Rust | `rust/tests/api.rs` `payloads_can_be_built_by_hand_and_write_their_json_value` | input built in code: stays with the Rust |
| Rust | `rust/tests/api.rs` `fresh_verifiers_answer_their_first_concurrent_calls_as_one_thread_would` | same fixture as `endpoint/genuine-sandbox-receipt-echoes-zero-ids`, `receipt/genuine-sandbox-ids-are-zero`, `receipt/return-genuine-sandbox-g5-device-hash-inputs` and 2 more |
| Rust | `rust/tests/api.rs` `the_byte_entry_points_answer_as_the_text_ones` | input built in code: stays with the Rust |
| Rust | `rust/tests/api.rs` `decode_receipt_data_is_the_receipt_rule` | input built in code: stays with the Rust |
| Rust | `rust/tests/datetime.rs` `the_pacific_rendering_matches_the_iana_database` | input built in code: stays with the Rust |
| Rust | `rust/tests/datetime.rs` `the_pacific_offset_is_minus_seven_or_minus_eight` | input built in code: stays with the Rust |
| Rust | `rust/tests/datetime.rs` `the_transition_is_exact_to_the_second` | input built in code: stays with the Rust |
| Rust | `rust/tests/datetime.rs` `summer_1980_is_daylight_time_not_standard_time` | input built in code: stays with the Rust |
| Rust | `rust/tests/datetime.rs` `the_gmt_rendering_is_apples_etc_gmt_form` | input built in code: stays with the Rust |
| Rust | `rust/tests/datetime.rs` `iso_8601_drops_a_zero_millisecond_component` | input built in code: stays with the Rust |
| Rust | `rust/tests/datetime.rs` `system_time_round_trips_through_epoch_millis` | input built in code: stays with the Rust |
| Rust | `rust/tests/datetime.rs` `a_receipt_date_is_exactly_the_one_form` | input built in code: stays with the Rust |
| Rust | `rust/tests/datetime.rs` `rfc_3339_requires_a_timezone_designator` | input built in code: stays with the Rust |
| Rust | `rust/tests/datetime.rs` `rfc_3339_accepts_the_forms_receipts_actually_carry` | input built in code: stays with the Rust |
| Rust | `rust/tests/datetime.rs` `rfc_3339_rejects_impossible_dates` | input built in code: stays with the Rust |
| Rust | `rust/tests/datetime.rs` `rfc_3339_rejects_malformed_shapes` | input built in code: stays with the Rust |
| Rust | `rust/tests/datetime.rs` `parse_and_render_round_trip_across_a_century` | input built in code: stays with the Rust |
| Rust | `rust/tests/datetime.rs` `every_day_of_2024_round_trips` | input built in code: stays with the Rust |
| Rust | `rust/tests/datetime.rs` `the_us_pacific_rules_match_the_iana_database_at_every_transition` | input built in code: stays with the Rust |
| Rust | `rust/tests/datetime.rs` `pre_1987_daylight_time_is_observed` | input built in code: stays with the Rust |
| Rust | `rust/tests/endpoint.rs` `a_sandbox_receipt_on_sandbox_answers_zero_with_the_full_body` | same fixture as `endpoint/ids-absent-are-omitted`, `endpoint/request-date-is-the-verification-clock`, `endpoint/sandbox-receipt-on-production-answers-21007` and 9 more |
| Rust | `rust/tests/endpoint.rs` `in_app_scalars_are_rendered_as_apple_renders_them` | input built in code: stays with the Rust |
| Rust | `rust/tests/endpoint.rs` `the_legacy_ids_cross_the_wire_as_bare_numbers` | input built in code: stays with the Rust |
| Rust | `rust/tests/endpoint.rs` `is_trial_period_is_a_string_like_is_in_intro_offer_period` | input built in code: stays with the Rust |
| Rust | `rust/tests/endpoint.rs` `ids_a_receipt_does_not_carry_are_omitted_never_null` | input built in code: stays with the Rust |
| Rust | `rust/tests/endpoint.rs` `a_web_order_line_item_id_of_zero_is_omitted_as_apple_omits_it` | same fixture as `endpoint/web-order-line-item-id-zero-is-omitted`, `receipt/web-order-line-item-id-zero-is-kept` |
| Rust | `rust/tests/endpoint.rs` `the_request_date_triple_comes_from_the_config_clock` | input built in code: stays with the Rust |
| Rust | `rust/tests/endpoint.rs` `the_request_date_crosses_both_dst_boundaries_correctly` | input built in code: stays with the Rust |
| Rust | `rust/tests/endpoint.rs` `hostile_bodies_never_escape_the_never_fails_contract` | input built in code: stays with the Rust |
| Rust | `rust/tests/endpoint.rs` `the_endpoint_never_produces_a_status_outside_its_documented_set` | input built in code: stays with the Rust |
| Rust | `rust/tests/endpoint.rs` `the_endpoint_does_not_check_the_bundle_id` | input built in code: stays with the Rust |
| Rust | `rust/tests/endpoint.rs` `the_clock_stands_in_for_a_missing_creation_date` | same fixture as `endpoint/clock-inside-the-window-verifies-a-dateless-receipt`, `endpoint/clock-past-the-window-rejects-a-dateless-receipt`, `receipt/accept-missing-creation-date` |
| Rust | `rust/tests/endpoint_status.rs` `routes_from_the_receipts_own_type` | same fixture as `endpoint/foreign-root-answers-21003`, `endpoint/ids-absent-are-omitted`, `endpoint/missing-receipt-type-on-production-answers-21007` and 19 more |
| Rust | `rust/tests/endpoint_status.rs` `only_status_zero_carries_the_receipt` | same fixture as `endpoint/foreign-root-answers-21003`, `endpoint/ids-absent-are-omitted`, `endpoint/production-receipt-on-production-answers-0` and 17 more |
| Rust | `rust/tests/endpoint_status.rs` `each_failure_answers_the_status_of_its_reason` | same fixture as `endpoint/foreign-root-answers-21003`, `receipt/pinned-clock-does-not-rescue-a-fresh-creation-date`, `receipt/reject-foreign-root` and 3 more |
| Rust | `rust/tests/endpoint_status.rs` `a_body_without_usable_receipt_data_answers_21002` | same fixture as `endpoint/ids-absent-are-omitted`, `endpoint/request-date-is-the-verification-clock`, `endpoint/sandbox-receipt-on-production-answers-21007` and 9 more |
| Rust | `rust/tests/endpoint_status.rs` `password_exclude_old_transactions_and_trailing_text_are_not_read` | same fixture as `endpoint/ids-absent-are-omitted`, `endpoint/request-date-is-the-verification-clock`, `endpoint/sandbox-receipt-on-production-answers-21007` and 9 more |
| Rust | `rust/tests/endpoint_status.rs` `the_response_is_byte_stable_for_the_same_call` | same fixture as `endpoint/ids-absent-are-omitted`, `endpoint/request-date-is-the-verification-clock`, `endpoint/sandbox-receipt-on-production-answers-21007` and 9 more |
| Rust | `rust/tests/endpoint_status.rs` `the_clock_is_read_at_most_once_per_call_and_only_when_needed` | same fixture as `endpoint/ids-absent-are-omitted`, `endpoint/request-date-is-the-verification-clock`, `endpoint/sandbox-receipt-on-production-answers-21007` and 9 more |
| Rust | `rust/tests/envelope_bounds.rs` `the_genuine_receipt_takes_one_full_decode` | input built in code: stays with the Rust |
| Rust | `rust/tests/envelope_bounds.rs` `a_certificate_flood_behind_a_broken_envelope_never_reaches_the_full_decode` | input built in code: stays with the Rust |
| Rust | `rust/tests/envelope_bounds.rs` `the_depth_bound_counts_every_constructed_value_of_the_envelope` | input built in code: stays with the Rust |
| Rust | `rust/tests/envelope_bounds.rs` `the_envelope_holds_at_most_100000_values` | input built in code: stays with the Rust |
| Rust | `rust/tests/envelope_bounds.rs` `embedded_crls_are_bounded_by_the_node_budget_alone` | input built in code: stays with the Rust |
| Rust | `rust/tests/envelope_bounds.rs` `econtent_rechunked_into_six_constructed_levels_verifies` | input built in code: stays with the Rust |
| Rust | `rust/tests/envelope_bounds.rs` `values_kept_whole_in_the_envelope_are_valid_asn1` | input built in code: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `eleven_characters_of_base64_do_not_escape_the_contract` | input built in code: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `deeply_nested_asn1_is_refused_rather_than_recursed` | input built in code: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `a_thousand_levels_of_nesting_does_not_overflow_the_stack` | input built in code: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `an_unterminated_indefinite_length_value_is_refused` | input built in code: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `a_declared_length_larger_than_the_input_is_refused_without_allocating` | input built in code: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `multi_byte_tags_are_refused` | input built in code: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `a_megabyte_of_zeros_is_refused_quickly` | input built in code: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `a_wide_flat_structure_is_refused_at_a_bounded_cost` | input built in code: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `a_certificate_flood_is_rejected_at_a_bounded_cost` | input built in code: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `unsigned_content_of_tiny_attributes_is_refused_at_a_bounded_cost` | input built in code: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `a_cross_signed_certificate_mesh_stays_flat` | input built in code: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `five_thousand_mutations_of_a_genuine_receipt_never_panic_and_never_verify` | input built in code: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `the_embedded_root_copy_is_never_trusted` | fixture registered, no case uses it: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `two_thousand_mutations_of_a_genuine_jws_never_panic_and_never_verify` | input built in code: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `every_truncation_of_a_genuine_receipt_is_refused_without_panicking` | input built in code: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `arbitrary_byte_strings_never_panic_in_either_entry_point` | input built in code: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `every_single_byte_mutation_of_the_first_kilobyte_is_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/hostile.rs` `no_respelling_of_a_genuine_jws_is_accepted` | input built in code: stays with the Rust |
| Rust | `rust/tests/input_size_caps.rs` `a_receipt_string_one_byte_over_the_cap_is_refused_before_decoding` | input built in code: stays with the Rust |
| Rust | `rust/tests/input_size_caps.rs` `a_receipt_string_exactly_at_the_cap_is_decoded` | input built in code: stays with the Rust |
| Rust | `rust/tests/input_size_caps.rs` `the_receipt_cap_counts_utf8_bytes_not_characters` | input built in code: stays with the Rust |
| Rust | `rust/tests/input_size_caps.rs` `receipt_data_over_the_cap_answers_21002_at_the_endpoint_before_decoding` | input built in code: stays with the Rust |
| Rust | `rust/tests/input_size_caps.rs` `the_byte_floor_receipt_still_verifies_through_every_receipt_entry_point` | same fixture as `endpoint/verify-at-the-byte-floor`, `receipt/verify-at-the-byte-floor` |
| Rust | `rust/tests/input_size_caps.rs` `a_body_one_byte_over_the_cap_answers_21002_without_being_parsed` | input built in code: stays with the Rust |
| Rust | `rust/tests/input_size_caps.rs` `a_body_exactly_at_the_cap_verifies` | input built in code: stays with the Rust |
| Rust | `rust/tests/input_size_caps.rs` `the_body_cap_counts_utf8_bytes_not_characters` | input built in code: stays with the Rust |
| Rust | `rust/tests/input_size_caps.rs` `an_oversized_body_is_too_large_before_it_is_malformed` | input built in code: stays with the Rust |
| Rust | `rust/tests/input_size_caps.rs` `a_body_nested_to_the_limit_verifies` | input built in code: stays with the Rust |
| Rust | `rust/tests/input_size_caps.rs` `a_body_nested_past_the_limit_answers_21002` | input built in code: stays with the Rust |
| Rust | `rust/tests/input_size_caps.rs` `brackets_inside_a_body_string_are_not_nesting` | input built in code: stays with the Rust |
| Rust | `rust/tests/input_size_caps.rs` `a_jws_one_byte_over_the_cap_is_refused_before_decoding` | input built in code: stays with the Rust |
| Rust | `rust/tests/input_size_caps.rs` `a_jws_exactly_at_the_cap_reaches_the_signature_check` | input built in code: stays with the Rust |
| Rust | `rust/tests/input_size_caps.rs` `jws_json_nested_to_the_limit_reaches_the_signature_check` | input built in code: stays with the Rust |
| Rust | `rust/tests/input_size_caps.rs` `jws_json_nested_past_the_limit_is_refused` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `the_shared_transaction_verifies` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `an_empty_string_is_not_a_jws` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `two_segments_are_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `four_segments_are_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `a_header_that_is_not_json_is_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `a_header_that_is_a_json_array_is_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `alg_must_be_es256` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `alg_must_be_a_string` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `x5c_must_be_present_and_hold_exactly_three_entries` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `x5c_must_be_an_array_of_strings` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `an_x5c_entry_that_is_not_a_certificate_is_invalid_certificate` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `an_x5c_entry_that_is_not_base64_is_invalid_certificate` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `an_x5c_certificate_carrying_one_extension_twice_is_invalid_certificate` | same fixture as `transaction/reject-x5c-duplicate-extension` |
| Rust | `rust/tests/jws_negative.rs` `the_third_x5c_entry_is_never_trusted_but_must_be_a_certificate` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `a_payload_that_is_not_a_json_object_is_carried_to_the_signature_check` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `a_signed_payload_that_is_not_a_json_object_is_unreadable` | same fixture as `signed-data/unreadable-empty-payload`, `signed-data/unreadable-json-array-payload` |
| Rust | `rust/tests/jws_negative.rs` `a_signature_of_the_wrong_length_is_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `a_single_flipped_signature_byte_is_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `a_flipped_payload_byte_is_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `a_foreign_root_is_an_untrusted_chain_not_a_purpose_error` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `marker_oids_are_checked_after_the_chain` | same fixture as `transaction/reject-intermediate-without-wwdr-marker-oid`, `transaction/reject-leaf-without-apple-marker-oid` |
| Rust | `rust/tests/jws_negative.rs` `an_expired_chain_outranks_a_broken_signature` | same fixture as `transaction/reject-fresh-payload-under-expired-chain` |
| Rust | `rust/tests/jws_negative.rs` `a_payload_is_never_rejected_for_its_age` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `the_chain_is_judged_at_the_signing_date` | same fixture as `transaction/accept-historical-payload-under-expired-chain`, `transaction/reject-fresh-payload-under-expired-chain` |
| Rust | `rust/tests/jws_negative.rs` `claims_are_returned_for_the_caller_to_judge` | same fixture as `app-transaction/return-app-apple-id-for-the-caller`, `app-transaction/verify-production` |
| Rust | `rust/tests/jws_negative.rs` `a_broken_signature_is_refused_whatever_the_claims` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `junk_in_the_signature_segment_is_not_a_signature` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `only_the_canonical_spelling_of_the_signature_verifies` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `a_segment_that_is_not_base64url_is_a_format_error` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `a_signed_date_is_read_by_value_whatever_its_json_spelling` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `an_unrepresentable_signed_date_is_replaced_by_the_clock` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `the_third_x5c_entry_must_be_a_certificate` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `x5c_entries_with_line_breaks_are_not_certificates` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `non_ascii_claims_round_trip_as_utf8` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `attacker_text_never_reaches_a_failure_message` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `an_unimplemented_curve_is_judged_only_on_a_vouched_key` | input built in code: stays with the Rust |
| Rust | `rust/tests/jws_negative.rs` `validity_is_judged_to_the_millisecond` | input built in code: stays with the Rust |
| Rust | `rust/tests/public_receipts.rs` `the_genuine_sandbox_g5_receipt_verifies_against_the_bundled_roots` | input built in code: stays with the Rust |
| Rust | `rust/tests/public_receipts.rs` `the_genuine_legacy_sha1_chain_verifies` | input built in code: stays with the Rust |
| Rust | `rust/tests/public_receipts.rs` `a_genuine_receipt_is_returned_whatever_bundle_the_caller_expects` | input built in code: stays with the Rust |
| Rust | `rust/tests/public_receipts.rs` `the_xcode_receipt_is_not_apple_signed_and_is_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/public_receipts.rs` `the_genuine_receipts_survive_a_round_trip_through_the_endpoint` | input built in code: stays with the Rust |
| Rust | `rust/tests/public_receipts.rs` `verifying_the_largest_genuine_receipt_is_fast_and_repeatable` | input built in code: stays with the Rust |
| Rust | `rust/tests/public_receipts.rs` `apples_official_jws_fixtures_verify_against_apples_test_ca` | fixture registered, no case uses it: stays with the Rust |
| Rust | `rust/tests/public_receipts.rs` `a_genuine_receipt_with_one_content_byte_changed_is_an_invalid_signature` | same fixture as `endpoint/genuine-sandbox-receipt-echoes-zero-ids`, `receipt/genuine-sandbox-ids-are-zero`, `receipt/return-genuine-sandbox-g5-device-hash-inputs` and 2 more |
| Rust | `rust/tests/public_receipts.rs` `the_legacy_purchase_info_transaction_receipt_is_not_a_receipt` | input built in code: stays with the Rust |
| Rust | `rust/tests/public_receipts.rs` `apples_real_production_chain_passes_at_its_effective_date` | input built in code: stays with the Rust |
| Rust | `rust/tests/public_receipts.rs` `apples_real_production_chain_fails_outside_its_validity` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `the_rebuilt_receipt_is_still_a_valid_receipt` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `an_empty_receipt_is_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `trailing_bytes_after_the_cms_blob_are_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `a_truncated_receipt_is_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `a_sequence_that_is_not_a_cms_is_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `a_truncated_sequence_header_is_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `a_receipt_with_no_encapsulated_content_is_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `content_that_is_not_an_octet_string_is_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `a_receipt_with_no_signer_info_is_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `a_signer_named_by_an_unembedded_issuer_and_serial_is_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `a_relabelled_digest_algorithm_fails_as_a_signature` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `more_than_ten_embedded_certificates_is_malformed` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `a_copy_of_the_signer_identity_ahead_of_the_signer_does_not_decide_the_verdict` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `an_unparseable_embedded_certificate_is_rejected` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `a_message_digest_that_does_not_match_the_content_is_an_invalid_signature` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `a_tampered_signature_is_an_invalid_signature` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `a_signature_of_the_wrong_length_is_an_invalid_signature` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `a_foreign_root_is_an_untrusted_chain_and_not_a_purpose_error` | same fixture as `endpoint/foreign-root-answers-21003`, `receipt/reject-foreign-root` |
| Rust | `rust/tests/receipt_negative.rs` `a_signer_without_the_receipt_marker_oid_is_a_purpose_error` | same fixture as `receipt/reject-signer-without-receipt-signing-oid` |
| Rust | `rust/tests/receipt_negative.rs` `chain_validity_is_judged_at_the_receipts_own_creation_date` | same fixture as `receipt/accept-historical-creation-date-under-expired-chain`, `receipt/pinned-clock-does-not-rescue-a-fresh-creation-date`, `receipt/reject-fresh-creation-date-under-expired-chain` |
| Rust | `rust/tests/receipt_negative.rs` `an_expired_chain_outranks_a_broken_signature` | same fixture as `receipt/accept-historical-creation-date-under-expired-chain`, `receipt/pinned-clock-does-not-rescue-a-fresh-creation-date`, `receipt/reject-fresh-creation-date-under-expired-chain` |
| Rust | `rust/tests/receipt_negative.rs` `a_receipt_stripped_of_its_device_hash_attribute_is_never_accepted` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `an_attribute_type_above_the_signed_32_bit_range_is_an_unreadable_payload` | same fixture as `endpoint/attribute-type-above-int32-max-answers-21009`, `receipt/reject-attribute-type-above-int32-max` |
| Rust | `rust/tests/receipt_negative.rs` `a_receipt_with_no_creation_date_still_verifies` | same fixture as `endpoint/clock-past-the-window-rejects-a-dateless-receipt`, `receipt/accept-missing-creation-date` |
| Rust | `rust/tests/receipt_negative.rs` `a_double_wrapped_payload_is_unwrapped_once` | same fixture as `receipt/accept-double-wrapped-payload` |
| Rust | `rust/tests/receipt_negative.rs` `unmodelled_attributes_are_exposed_verbatim` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `the_legacy_ids_are_decoded_with_every_digit` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `is_trial_period_is_read_on_both_sides_of_the_boolean` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `the_four_modelled_ids_leave_the_unknown_attribute_map` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `ids_a_receipt_does_not_carry_are_absent_rather_than_zero` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `the_receipt_size_bound_rejects_before_decoding` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `line_wrapped_base64_is_refused` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `a_constructed_octet_string_with_foreign_children_is_joined` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `signed_attrs_forged_from_the_payload_set_are_refused` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `signed_attrs_without_content_type_or_message_digest_are_refused` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `a_broken_signed_attrs_set_is_malformed_in_either_signer_position` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `an_unvouched_signer_on_an_unimplemented_curve_is_an_untrusted_chain` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `a_vouched_signer_on_an_unimplemented_curve_is_judged_on_its_key_first` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_negative.rs` `a_dateless_receipt_is_judged_at_the_clock_to_the_millisecond` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_signer_algorithms.rs` `the_control_an_ec_signer_under_the_pinned_root_verifies` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_signer_algorithms.rs` `a_digest_apple_does_not_use_today_verifies_when_the_signature_holds` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_signer_algorithms.rs` `a_signature_that_does_not_hold_as_labelled_is_an_invalid_signature` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_signer_algorithms.rs` `an_md5_digest_under_the_pinned_root_verifies` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_signer_algorithms.rs` `a_digest_openssl_does_not_implement_is_an_invalid_signature` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_signer_algorithms.rs` `an_ecdsa_signature_verifies_under_its_digest_whatever_the_label_names` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_signer_algorithms.rs` `the_control_signed_attributes_built_here_verify` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_signer_algorithms.rs` `a_content_type_attribute_twice_is_an_invalid_signature` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_signer_algorithms.rs` `a_content_type_attribute_with_two_values_is_an_invalid_signature` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_signer_algorithms.rs` `a_message_digest_attribute_with_two_values_is_an_invalid_signature` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_signer_algorithms.rs` `an_empty_signed_attrs_set_is_an_invalid_signature` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_signer_algorithms.rs` `an_rsa_pss_signer_under_the_pinned_root_verifies` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_signer_algorithms.rs` `an_rsa_pss_signature_over_other_content_or_parameters_is_an_invalid_signature` | input built in code: stays with the Rust |
| Rust | `rust/tests/receipt_signer_algorithms.rs` `every_certificate_signature_algorithm_openssl_verifies_is_accepted` | input built in code: stays with the Rust |
| Rust | `rust/tests/trust_pinning.rs` `the_public_style_chain_is_genuinely_valid_under_its_own_root` | input built in code: stays with the Rust |
| Rust | `rust/tests/trust_pinning.rs` `the_same_chain_is_rejected_against_apples_pinned_roots` | input built in code: stays with the Rust |
| Rust | `rust/tests/trust_pinning.rs` `the_path_builder_refuses_the_same_chain_too` | input built in code: stays with the Rust |
| Rust | `rust/tests/trust_pinning.rs` `no_root_of_this_machines_trust_store_is_a_bundled_anchor` | input built in code: stays with the Rust |
| Rust | `rust/tests/trust_pinning.rs` `os_trust_store_roots_do_not_verify_apple_signed_material` | same fixture as `endpoint/genuine-sandbox-receipt-echoes-zero-ids`, `receipt/genuine-sandbox-ids-are-zero`, `receipt/return-genuine-sandbox-g5-device-hash-inputs` and 2 more |
| Rust | `rust/tests/trust_pinning.rs` `no_source_file_names_a_system_trust_store_or_a_network_client` | input built in code: stays with the Rust |
| Rust | `rust/tests/trust_pinning.rs` `the_openssl_adapter_never_loads_a_trust_path_a_configuration_or_a_socket` | input built in code: stays with the Rust |
| Rust | `rust/tests/trust_pinning.rs` `no_source_file_holds_a_private_key_or_decrypts` | input built in code: stays with the Rust |
| Rust | `rust/tests/trust_pinning.rs` `the_direct_dependency_set_is_exactly_the_reviewed_one` | input built in code: stays with the Rust |
| Rust | `rust/tests/trust_pinning.rs` `the_bundled_anchors_are_apples_three_published_roots` | input built in code: stays with the Rust |
| Rust | `rust/tests/trust_pinning.rs` `the_bundled_certs_directory_matches_the_repository_root` | input built in code: stays with the Rust |
| Rust | `rust/tests/trust_pinning.rs` `a_trust_anchors_own_expiry_is_not_checked` | same fixture as `receipt/accept-historical-creation-date-under-expired-chain` |
| Rust | `rust/tests/trust_pinning.rs` `a_root_verifies_beside_another_root_with_the_same_subject_in_either_order` | same fixture as `endpoint/ids-absent-are-omitted`, `endpoint/request-date-is-the-verification-clock`, `endpoint/sandbox-receipt-on-production-answers-21007` and 9 more |
| Rust | `rust/tests/trust_pinning.rs` `a_root_verifies_when_a_same_named_root_vouches_for_a_stranger_in_the_bag` | same fixture as `receipt/verify-with-a-stranger-vouched-by-a-same-named-root-listed-first`, `receipt/verify-with-a-stranger-vouched-by-a-same-named-root-listed-second`, `receipt/verify-with-a-stranger-whose-key-is-unreadable` |
| Rust | `rust/tests/trust_pinning.rs` `a_renewed_intermediate_verifies_beside_its_expired_twin_in_either_order` | input built in code: stays with the Rust |
| Rust | `rust/tests/unauthenticated_key_cost.rs` `a_genuine_receipt_padded_with_stranger_keys_verifies_quickly` | input built in code: stays with the Rust |
| Rust | `rust/tests/unauthenticated_key_cost.rs` `a_receipt_whose_only_issuers_have_expensive_keys_is_refused_quickly` | input built in code: stays with the Rust |
| Rust | `rust/tests/unauthenticated_key_cost.rs` `a_jws_whose_certificates_have_expensive_keys_is_refused_quickly` | input built in code: stays with the Rust |
| Rust | `rust/tests/unauthenticated_key_cost.rs` `only_certificates_a_root_vouched_for_reach_the_path_builder` | input built in code: stays with the Rust |
| Rust | `rust/tests/unauthenticated_key_cost.rs` `a_genuine_apple_receipt_padded_with_stranger_keys_still_verifies` | same fixture as `endpoint/genuine-sandbox-receipt-echoes-zero-ids`, `receipt/genuine-sandbox-ids-are-zero`, `receipt/return-genuine-sandbox-g5-device-hash-inputs` and 2 more |
| Rust | `rust/tests/unauthenticated_key_cost.rs` `the_es256_check_is_recorded_as_a_key_use` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `reason_codes_mirror_the_library` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `abi_status_tokens_are_distinct_from_the_reason_band` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `the_error_document_escapes_its_message` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `a_panic_inside_the_guard_becomes_a_status` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `every_exported_function_is_guarded` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `anchor_arguments_that_disagree_are_refused` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `a_null_verifier_handle_is_reported_not_dereferenced` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `a_null_input_string_is_reported` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `invalid_utf8_is_its_own_status_and_never_a_verdict` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `a_null_out_parameter_still_returns_the_status` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `a_malformed_jws_is_a_verdict_with_the_canonical_token` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `an_empty_receipt_is_a_format_verdict_not_a_crash` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `a_verified_receipt_is_exactly_the_wire_payload` | same fixture as `endpoint/ids-absent-are-omitted`, `endpoint/request-date-is-the-verification-clock`, `endpoint/sandbox-receipt-on-production-answers-21007` and 9 more |
| Rust | `rust/ffi/src/lib.rs` `a_verified_jws_is_the_signed_payload_text` | same fixture as `raw/skip-claim-checks-but-not-signature`, `transaction/reject-foreign-root`, `transaction/return-bundle-id-for-the-caller` and 4 more |
| Rust | `rust/ffi/src/lib.rs` `the_endpoint_answers_a_body_for_junk` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `the_endpoint_takes_exactly_production_or_sandbox` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `a_null_endpoint_handle_leaves_the_out_parameter_untouched` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `a_pinned_clock_stamps_the_endpoint_request_date` | same fixture as `endpoint/ids-absent-are-omitted`, `endpoint/request-date-is-the-verification-clock`, `endpoint/sandbox-receipt-on-production-answers-21007` and 9 more |
| Rust | `rust/ffi/src/lib.rs` `a_pinned_clock_judges_a_dateless_receipt` | same fixture as `endpoint/clock-past-the-window-rejects-a-dateless-receipt`, `receipt/accept-missing-creation-date` |
| Rust | `rust/ffi/src/lib.rs` `the_version_is_the_library_version` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `freeing_null_is_a_no_op` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `the_bundled_roots_do_not_accept_the_fixture_chain` | same fixture as `raw/skip-claim-checks-but-not-signature`, `transaction/reject-foreign-root`, `transaction/return-bundle-id-for-the-caller` and 4 more |
| Rust | `rust/ffi/src/lib.rs` `a_bytes_call_answers_the_modules_document` | same fixture as `endpoint/ids-absent-are-omitted`, `endpoint/request-date-is-the-verification-clock`, `endpoint/sandbox-receipt-on-production-answers-21007` and 9 more |
| Rust | `rust/ffi/src/lib.rs` `an_embedded_nul_is_part_of_the_input` | same fixture as `endpoint/ids-absent-are-omitted`, `endpoint/request-date-is-the-verification-clock`, `endpoint/sandbox-receipt-on-production-answers-21007` and 9 more |
| Rust | `rust/ffi/src/lib.rs` `bytes_that_are_not_utf8_are_a_verdict` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `a_null_range_is_empty_only_at_length_zero` | input built in code: stays with the Rust |
| Rust | `rust/ffi/src/lib.rs` `the_committed_header_declares_exactly_the_exports` | input built in code: stays with the Rust |
| Rust | `rust/ffi/tests/exported_symbols.rs` `the_library_exports_exactly_the_allowlist` | input built in code: stays with the Rust |
| Rust | `rust/bindings/abi/tests/tests/abi.rs` `the_module_imports_random_get_and_exports_the_interface_only` | input built in code: stays with the Rust |
| Rust | `rust/bindings/abi/tests/tests/abi.rs` `no_start_function_is_needed_and_the_calls_answer_the_wire` | input built in code: stays with the Rust |
| Rust | `rust/bindings/abi/tests/tests/abi.rs` `an_environment_other_than_0_or_1_traps` | input built in code: stays with the Rust |
| Rust | `rust/bindings/abi/tests/tests/abi.rs` `a_verify_before_init_traps` | input built in code: stays with the Rust |
| Rust | `rust/bindings/abi/tests/tests/abi.rs` `a_second_init_after_a_successful_one_traps` | input built in code: stays with the Rust |
| Rust | `rust/bindings/abi/tests/tests/abi.rs` `a_refused_configuration_is_a_value_and_init_may_be_retried` | input built in code: stays with the Rust |
| Rust | `rust/bindings/abi/tests/tests/abi.rs` `a_random_get_answer_of_the_wrong_length_traps` | input built in code: stays with the Rust |
| Rust | `rust/bindings/abi/tests/tests/abi.rs` `a_trap_in_one_instance_leaves_another_verifying` | input built in code: stays with the Rust |
| Rust | `rust/bindings/abi/tests/tests/abi.rs` `two_thousand_calls_leave_linear_memory_the_same_size` | input built in code: stays with the Rust |
| Rust | `rust/bindings/abi/tests/tests/abi.rs` `input_that_is_not_utf8_is_a_value` | input built in code: stays with the Rust |
| Rust | `rust/bindings/abi/tests/tests/abi.rs` `a_clock_beyond_i64_is_an_internal_error` | input built in code: stays with the Rust |
| Rust | `rust/bindings/wire/src/lib.rs` `a_failure_carries_exactly_three_members_in_a_fixed_order` | input built in code: stays with the Rust |
| Rust | `rust/bindings/wire/src/lib.rs` `a_verified_jws_carries_its_payload_as_a_string_holding_the_signed_text` | input built in code: stays with the Rust |
| Rust | `rust/bindings/wire/src/lib.rs` `an_empty_receipt_writes_every_key_as_null_or_empty` | input built in code: stays with the Rust |
| Rust | `rust/bindings/wire/src/lib.rs` `ids_are_decimal_strings_dates_numbers_bytes_padded_base64` | input built in code: stays with the Rust |
| Rust | `rust/bindings/wire/src/lib.rs` `init_answers_ok_or_a_message` | input built in code: stays with the Rust |
| Rust | `rust/bindings/wire/src/lib.rs` `the_configuration_names_roots_or_nothing` | input built in code: stays with the Rust |
| Rust | `rust/bindings/wire/tests/schema.rs` `the_four_schemas_are_json_schema_2020_12_with_their_ids` | input built in code: stays with the Rust |
| Rust | `rust/bindings/wire/tests/schema.rs` `every_answer_to_every_shared_case_validates` | input built in code: stays with the Rust |
| Rust | `rust/bindings/wire/tests/schema.rs` `every_expected_value_in_the_shared_cases_fits_the_schemas` | input built in code: stays with the Rust |
| Rust | `rust/bindings/wire/tests/schema.rs` `a_planted_wrong_type_fails_every_rule` | input built in code: stays with the Rust |
| Rust | `rust/bindings/surface/src/lib.rs` `the_eight_reasons_are_the_cores_eight_in_the_same_order` | input built in code: stays with the Rust |
| Rust | `rust/bindings/surface/src/lib.rs` `an_empty_root_list_means_the_three_apple_roots` | input built in code: stays with the Rust |
| Rust | `rust/bindings/surface/src/lib.rs` `a_root_that_is_not_a_certificate_is_named_by_its_index` | input built in code: stays with the Rust |
| Rust | `rust/bindings/surface/src/lib.rs` `bytes_that_are_not_utf8_are_input_and_fail_as_the_core_says` | input built in code: stays with the Rust |
| Rust | `rust/bindings/surface/src/lib.rs` `the_instant_of_each_call_is_its_own_argument` | input built in code: stays with the Rust |
| Rust | `rust/bindings/surface/src/lib.rs` `attribute_types_cross_as_signed_integers_in_ascending_order` | input built in code: stays with the Rust |
| Rust | `rust/bindings/surface/src/lib.rs` `a_clock_beyond_i64_is_an_internal_error_never_an_instant` | input built in code: stays with the Rust |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/AppleRootCertsTest.java` `defaultRootsAreAllThreePublishedAppleRoots` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/AppleRootCertsTest.java` `bundledRootsMatchTheirPinnedFingerprints` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/AppleRootCertsTest.java` `theDefaultRootsAreParsedOnceAndCannotBeChanged` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/AppleRootCertsTest.java` `bundledRootsAreTheRepositorysCertsDirectory` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/AppleRootCertsTest.java` `acceptsApplesRealProductionChainAtItsEffectiveDate` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/AppleRootCertsTest.java` `rejectsApplesRealProductionChainOutsideItsValidity` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/CertificateDecodeTest.java` `aNonSignerCertificateWithAnUnreadableKeyIsIgnored` | same fixture as `receipt/reject-signer-on-an-unimplemented-curve` |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/CertificateDecodeTest.java` `aNonSignerCertificateWithAnUnalignedSignatureIsInvalidReceiptFormat` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/CertificateDecodeTest.java` `anX5cLeafWithAnUnalignedSignatureIsInvalidCertificate` | same fixture as `raw/skip-claim-checks-but-not-signature`, `transaction/reject-foreign-root`, `transaction/return-bundle-id-for-the-caller` and 4 more |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ConcurrencyTest.java` `oneSharedVerifierServesManyThreadsIdentically` | same fixture as `endpoint/genuine-sandbox-receipt-echoes-zero-ids`, `raw/skip-claim-checks-but-not-signature`, `receipt/genuine-sandbox-ids-are-zero` and 11 more |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ConcurrencyTest.java` `freshInstancesAnswerTheirFirstConcurrentCallsAsOneThreadWould` | same fixture as `endpoint/genuine-sandbox-receipt-echoes-zero-ids`, `raw/skip-claim-checks-but-not-signature`, `receipt/genuine-sandbox-ids-are-zero` and 11 more |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ConformanceCasesTest.java` `everyFixtureMatchesItsRecordedContentDigest` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/EndpointJsonReadTest.java` `readsEveryBodyAsTheDatabindMapReadDid` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/EndpointStatusTest.java` `routesFromTheReceiptsOwnType` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/EndpointStatusTest.java` `aNonProductionReceiptNeverAnswersAProductionZero` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/EndpointStatusTest.java` `onlyStatusZeroCarriesTheReceipt` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/EndpointStatusTest.java` `answersTheSameBytesForTheSameCall` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/EndpointStatusTest.java` `eachFailureAnswersTheStatusOfItsReason` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/FailureMessageTest.java` `aHostileAlgorithmClaimCannotSetTheSizeOrTheShapeOfTheMessage` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/FailureMessageTest.java` `aHostileNameInTheChainCannotForgeALogLineThroughTheValidatorsMessage` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/FixtureGeneratorTest.java` `generate` | same fixture as `app-transaction/return-app-apple-id-for-the-caller`, `app-transaction/verify-production`, `app-transaction/verify-shared-sandbox` and 38 more |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/HostPolicyTest.java` `theJdkBuildsTheLegacyChainUnderThisJvmsPolicy` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/HostPolicyTest.java` `aHostPolicyThatDisablesSha1MovesNoVerdict` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/HostileReceiptInputTest.java` `containsBitStringPadFailureFromElevenCharactersOfBase64` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/HostileReceiptInputTest.java` `containsInvalidUtf8AttributeValue` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/HostileReceiptInputTest.java` `nothingEscapesStructurallyHostileBlobs` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/HostileReceiptInputTest.java` `nothingEscapesMutationsOfAGenuineReceipt` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/InputSizeBoundsTest.java` `jwsOverTheSizeLimitIsRefusedBeforeAnySegmentIsDecoded` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/InputSizeBoundsTest.java` `jwsAtTheSizeLimitIsNotRefusedForItsSize` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/InputSizeBoundsTest.java` `jwsIsMeasuredInUtf8Bytes` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/InputSizeBoundsTest.java` `jwsHeaderNestedDeeperThanTheLimitIsRefusedAsMalformed` | fixture registered, no case uses it: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/InputSizeBoundsTest.java` `jwsHeaderNestedJustUnderTheLimitReachesTheAlgorithmCheck` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/InputSizeBoundsTest.java` `receiptStringOverTheSizeLimitIsRefusedBeforeItIsDecoded` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/InputSizeBoundsTest.java` `receiptStringAtTheSizeLimitStillVerifies` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/InputSizeBoundsTest.java` `receiptStringIsMeasuredInUtf8Bytes` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/InputSizeBoundsTest.java` `theBoundsAreApplesThreeMebibytes` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/InputSizeBoundsTest.java` `requestBodyOverTheSizeLimitAnswers21002WithoutParsingIt` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/InputSizeBoundsTest.java` `requestBodyIsMeasuredInUtf8BytesNotCharacters` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/InputSizeBoundsTest.java` `requestBodyNestedDeeperThanTheLimitAnswers21002` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/InputSizeBoundsTest.java` `requestBodyNestedJustUnderTheLimitVerifies` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/JwsJsonReadTest.java` `readsEveryHeaderAsTheDatabindTreeDid` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/JwsJsonReadTest.java` `readsEveryPayloadAsTheDatabindTreeDid` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/JwsJsonReadTest.java` `aHeaderIsStrictUtf8WithNoByteOrderMarkAndNothingAfterIt` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/JwsJsonReadTest.java` `aPayloadWithTextAfterItsObjectOrAByteOrderMarkIsUnreadable` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/JwsJsonReadTest.java` `memberNamesAndNumbersAreBounded` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/PublicReceiptsTest.java` `theEmbeddedCertificateBoundClearsEveryGenuineChain` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/PublicReceiptsTest.java` `aGenuineReceiptWithOneContentByteChangedIsAnInvalidSignature` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReadmeSyntheticReceiptExampleTest.java` `verifiesASyntheticReceipt` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptBase64Test.java` `nullIsInvalidReceiptFormat` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptContentInfoTest.java` `buildsTheSameCmsAsTheByteArrayConstructor` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptDecoderTest.java` `aStringThatIsNotUtf8IsKeptRawTopLevelAndInApp` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptDecoderTest.java` `anIa5StringWithAByteFrom0x80UpIsKeptRaw` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptDecoderTest.java` `anIntegerOrFlagThatIsNotMinimallyEncodedIsKeptRaw` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptDecoderTest.java` `anInAppSetThatBouncyCastleRefusesUncheckedIsKeptRaw` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptDecoderTest.java` `aReceiptDateIsExactlyTheOneForm` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptDecoderTest.java` `aDateInAnyOtherFormIsKeptRawAndDoesNotSetTheChainInstant` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptDecoderTest.java` `asn1NestsAtMost32ConstructedValues` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptDecoderTest.java` `anAttributeValueNestedPastTheBoundIsKeptRawAndIsNoCreationDate` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptSignerInfoTest.java` `aSignerWithAnEcKeyUnderThePinnedRootVerifies` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptSignerInfoTest.java` `aSha512SignatureUnderThePinnedRootVerifies` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptSignerInfoTest.java` `aSignatureAlgorithmThatContradictsTheDigestIsAnInvalidSignature` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptSignerInfoTest.java` `aReceiptWithNoSignerInfoIsAnInvalidReceiptFormat` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptSignerInfoTest.java` `theSameConstructionWithAnRsaKeyAndSha256Verifies` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptSignerInfoTest.java` `anyVerifyingSignerInfoIsEnoughInEitherPosition` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptSignerInfoTest.java` `whenNoSignerInfoVerifiesTheFirstOnesFailureIsTheVerdict` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptSignerVerifierTest.java` `reachesTheBuildersVerdictOnEveryReceipt` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `verifiesGenuineReceipt` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `decodesTheLegacyIdAttributes` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `legacyIdAttributesAreNullWhenTheReceiptDoesNotCarryThem` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `verifiesBase64Transport` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `returnsWhateverBundleIdAppleSignedWithoutJudgingIt` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `rejectsTamperedPayload` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `rejectsReceiptFromForeignRoot` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `aValidatorTheRuntimeCannotBuildIsAnInternalErrorNotAChainVerdict` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `rejectsTwinCertificateForgery` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `aCopyOfTheSignerIdentityAheadOfTheGenuineLeafFailsClosed` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `rejectsReceiptEmbeddingMoreCertificatesThanTheLimit` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `admitsAReceiptEmbeddingExactlyTheMaximum` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `countsEmbeddedCertificatesBeforeDecodingAnyOfThem` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `countsEmbeddedCertificatesBeforeResolvingTheSigner` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `rejectsCrossSignedCertificateMeshWithoutWalkingIt` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `acceptsAPathOfExactlyTheMaximumLength` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `rejectsAPathOneHopOverTheMaximumLength` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `countsSelfIssuedCertificatesTowardsTheMaximumLength` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `rejectsCorruptedSignatureBytes` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `exposesEverythingTheDeviceHashNeeds` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `rejectsTrailingBytesAfterCms` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `exposesUnknownAttributesForForwardCompatibility` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `rejectsGarbageBytes` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `decodesADateOutsideRepresentableRangeAsMissing` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `rejectsAttributeTypeTooWideToHoldRatherThanTruncatingIt` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `rejectsAttributeTypeBeyondIntRangeRatherThanRenamingIt` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `acceptsOnlyUtf8OrIa5StringsForStringAttributes` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `keepsAnAttributeTypeAtIntMaxAsItselfRatherThanRejectingIt` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `receiptWithoutACreationDateIsJudgedAgainstTheConfigClock` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `theClockDoesNotOverrideACreationDate` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `anEmptyRootSetIsRefusedAtStartup` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `boundsAttributeIntegersAtTheEdgeOfALong` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `rejectsUnsignedBase64Garbage` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `rejectsTheLegacyPurchaseInfoTransactionReceipt` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `acceptsHistoricalReceiptSignedByNowExpiredCert` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `rejectsFreshReceiptFromExpiredCert` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `anExpiredChainOutranksABrokenSignature` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `verifiesWhenOneSignerVerifiesBesideABrokenOne` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `verifiesWhenTheSecondSignerIsTheOneThatVerifies` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `failsWithInvalidSignatureWhenEverySignerIsBroken` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `refusesMoreThanFourSignerInfosBeforeCheckingAny` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `rejectsAnIntermediateWithoutTheWwdrMarker` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `rejectsASignerIssuedStraightByTheRoot` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `reportsNegativeIntegersAndReadsAnyNonZeroFlagAsTrue` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptVerificationTest.java` `anIntegerWiderThanALongIsKeptRaw` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `verifiesGenuineTransaction` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `returnsThePayloadExactlyAsSigned` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `returnsWhateverEnvironmentAndBundleIdAppleSignedWithoutJudgingThem` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `rejectsTamperedPayload` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `rejectsChainFromForeignRoot` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `aVerifierTheRuntimeCannotBuildIsAnInternalErrorNotASignatureVerdict` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `aValidatorTheRuntimeCannotBuildIsAnInternalErrorNotAChainVerdict` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `rejectsNonEs256Algorithm` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `rejectsShortCertificateChain` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `rejectsLeafWithoutAppleMarkerOid` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `rejectsIntermediateWithoutAppleMarkerOid` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `aForeignChainWithoutMarkersIsAnUntrustedChain` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `anExpiredChainOutranksABrokenSignature` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `acceptsHistoricalPayloadSignedByNowExpiredCert` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `rejectsFreshPayloadClaimingExpiredCertPeriod` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `neverRejectsAPayloadForItsAge` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `rejectsGarbageInput` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `rejectsFourSegments` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `rejectsABrokenSignatureSegmentBeforeTheChain` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `nonAsciiClaimsRoundTripAsUtf8` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `returnsClaimsOfAnyType` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `rejectsEmptyTrustAnchors` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `aSignedPayloadThatIsNotAnObjectIsUnreadable` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `anUnsignedPayloadThatIsNotAnObjectFailsTheSignature` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `aSignedPayloadThatIsNotUtf8IsUnreadable` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `certificateValidityIsJudgedAtTheSignedDate` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/SignedDataTest.java` `aDatelessPayloadIsJudgedAtTheConfigClock` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/TrustStoreIsolationTest.java` `aTrustStoreThisJvmGenuinelyTrustsMovesNoVerdict` | same fixture as `endpoint/ids-absent-are-omitted`, `endpoint/request-date-is-the-verification-clock`, `endpoint/sandbox-receipt-on-production-answers-21007` and 9 more |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/TrustStoreIsolationTest.java` `theJdksOwnCacertsConferNoStanding` | same fixture as `endpoint/genuine-sandbox-receipt-echoes-zero-ids`, `raw/skip-claim-checks-but-not-signature`, `receipt/genuine-sandbox-ids-are-zero` and 9 more |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/TrustStoreIsolationTest.java` `anEmptyAnchorSetIsAConfigurationErrorNotAFallback` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/TrustStoreIsolationTest.java` `noMainSourceCanReachATrustStoreOrTheNetwork` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/TrustStoreIsolationTest.java` `pkixParametersAreOnlyEverBuiltFromTheCallersAnchorSet` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/TrustStoreIsolationTest.java` `everyCryptographicLookupNamesTheLibrarysOwnProvider` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/TrustStoreIsolationTest.java` `theReceiptChainIsAnchoredOnlyByTheCallersRoots` | same fixture as `raw/skip-claim-checks-but-not-signature`, `transaction/reject-foreign-root`, `transaction/return-bundle-id-for-the-caller` and 4 more |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/TrustStoreIsolationTest.java` `theJwsChainIsAnchoredOnlyByTheCallersRoots` | same fixture as `raw/skip-claim-checks-but-not-signature`, `transaction/reject-foreign-root`, `transaction/return-bundle-id-for-the-caller` and 4 more |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/UnauthenticatedKeyCostTest.java` `aGenuineReceiptPaddedWithHugeKeysVerifiesQuickly` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/UnauthenticatedKeyCostTest.java` `aReceiptWhoseOnlyIntermediatesHaveHugeKeysIsRefusedQuickly` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/UnauthenticatedKeyCostTest.java` `aJwsWhoseCertificatesHaveHugeKeysIsRefusedQuickly` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/Utf8LengthTest.java` `theCapIsApplesMeasuredRequestLimit` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/Utf8LengthTest.java` `asciiIsOneBytePerCharacterRightAtTheCap` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/Utf8LengthTest.java` `twoByteCharactersAreCountedInBytesNotCharacters` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/Utf8LengthTest.java` `threeByteCharactersAtTheBoundary` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/Utf8LengthTest.java` `aSurrogatePairIsFourBytes` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/Utf8LengthTest.java` `aLoneSurrogateCountsThreeBytes` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/Utf8LengthTest.java` `theShortcutsAgreeWithTheWalkAtTheirEdges` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/Utf8LengthTest.java` `agreesWithEncodingOnGeneratedWellFormedText` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `aNullOrEmptyInputIsMalformedNotAThrow` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `aNullConfigOrEnvironmentIsAProgrammingError` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `anEmptyRootSetIsRefusedAtCreate` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `theDefaultsAreApplesThreeRootsAndTheSystemClock` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `theConfigCopiesItsRootsAndHandsOutAnUnmodifiableSet` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `aResultCarriesExactlyOneOfPayloadAndFailure` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `resultsAndFailuresCanBeBuiltForAMockedVerifier` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `theCauseIsKeptBehindUnreadablePayloadAndDroppedBehindVerdictsOnInput` (was `theCauseIsKeptOnlyBehindUnreadablePayloadAndInternalError`; renamed when a MALFORMED from an unchecked BouncyCastle or Jackson exception began keeping its cause, pinned by `HostileReceiptInputTest` `anUncheckedExceptionBeforeTrustIsTheCauseOfItsMalformed`) | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `anUnparseableReceiptPayloadIsJudgedAfterTheSignature` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `aBrokenEnvelopeIsMalformed` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `toJsonWritesEveryKeyWithNullForMissing` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `toJsonHasTheDesignsValue` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `toJsonIsValidUtf8EvenForALoneSurrogate` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `unknownAttributesAreEqualExactlyWhenTheirJsonValueIs` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `toJsonOfAVerifiedReceiptMatchesItsGetters` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `bytesAndUnknownAttributesAreCopiedInAndOut` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `theModelsCompareByValue` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `environmentMapsApplesValuesAndDecidesNothing` | input built in code: stays with the Java (since R42 it tests the implementation's rule, `ReceiptDecoder.environment` and `JwsCore.jwsEnvironment`, and that the public enum has none) |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `appleStatusNamesApplesCodes` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `theVersionConstantIsThePomVersion` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `aClassWhoseStaticStateFailsFailsConstructionWithTheDependencyFloor` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `theStaticStateLoadsEveryBouncyCastleClassTheDecodersName` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `eachBundledRootVerifiesItsOwnSignatureOnBouncyCastle` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `aProviderWithoutTheEnginesFailsTheProbe` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `aProviderThatThrowsUncheckedFailsTheProbeAsIllegalState` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `theRuntimeProbeIsOnByDefaultAndCanBeTurnedOff` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifierApiTest.java` `onlyTheApiTypesArePublic` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifyReceiptEndpointTest.java` `emitsTheRequestDateAndEveryDateCompanionField` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifyReceiptEndpointTest.java` `reportsMalformedRequestsAs21002` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifyReceiptEndpointTest.java` `aNullEnvironmentIsAProgrammingErrorNotAStatus` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifyReceiptEndpointTest.java` `rawJsonPinsTheWireTypes` | same fixture as `endpoint/genuine-sandbox-receipt-echoes-zero-ids`, `receipt/genuine-sandbox-ids-are-zero`, `receipt/return-genuine-sandbox-g5-device-hash-inputs` and 2 more |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifyReceiptEndpointTest.java` `rendersIsInIntroOfferPeriodAsAString` | same fixture as `endpoint/genuine-sandbox-receipt-echoes-zero-ids`, `receipt/genuine-sandbox-ids-are-zero`, `receipt/return-genuine-sandbox-g5-device-hash-inputs` and 2 more |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifyReceiptEndpointTest.java` `emitsTheLegacyIdsAsNumbersAndIsTrialPeriodAsAString` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifyReceiptEndpointTest.java` `omitsTheLegacyIdKeysWhenTheReceiptCarriesNone` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifyReceiptEndpointTest.java` `omitsWebOrderLineItemIdWhenItIsZero` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifyReceiptEndpointTest.java` `omitsReceiptAndEnvironmentOnNonZeroStatus` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifyReceiptEndpointTest.java` `answers21002ForABodyThatIsNotAnObject` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifyReceiptEndpointTest.java` `ignoresPasswordAndExcludeOldTransactions` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifyReceiptEndpointTest.java` `mapsEveryReasonToAppleStatusAsTheTableSays` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifyReceiptEndpointTest.java` `unreadableSignedContentAnswers21009` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifyReceiptEndpointTest.java` `aClockThatThrowsAnswers21009` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifyReceiptEndpointTest.java` `theConfigClockDrivesTheRequestDate` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifyReceiptEndpointTest.java` `routesOnTheTypedEnvironment` | input built in code: stays with the Java |
| Java | `java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/VerifyReceiptEndpointTest.java` `theConfigClockJudgesADatelessReceiptsChain` | input built in code: stays with the Java |
