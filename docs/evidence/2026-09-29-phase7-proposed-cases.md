# Shared cases for the port-only tests Phase 7 deleted

**Question.** MIGRATION.md Phase 7 step 1 deletes the hand-written
verifiers with their tests. `docs/rust-core/TEST-INVENTORY.md` marks 78 of
those tests "to add": behaviour no shared case in `fixtures/cases.json`
pins yet. For each, what case would pin it, built from generated material,
and what does `aprv.wasm` answer for it today? This feeds the orchestrator's
decision on which cases join `cases.json` (this lane does not edit it).

**Setup, 2026-09-29.** The G1c module (`aprv.wasm`, 2,760,476 bytes, SHA-256
`a35b9fce333311f7da722f02e027f89880b9b581e59752163c4434ef137a40a1`, built at
rust-core b863252), run through the Python package of lane P7-code's branch
(Python 3.11.15, wasmtime 49.0.0); inputs minted with `cryptography` 50.0.1.
Code: [`2026-09-29-phase7-proposed-cases/probe.py`](2026-09-29-phase7-proposed-cases/probe.py);
the run: [`results.jsonl`](2026-09-29-phase7-proposed-cases/results.jsonl).

## Method

Every input comes from generated material:

- the shared generated receipt (`generated-0.7/receipt.der` under
  `receipt-root`) with its certificate bag or SignerInfos respliced and its
  SignerInfo kept byte for byte, so the signature still holds;
- the generated transaction (`generated/transaction.jws` under `jws-root`)
  with a segment changed;
- receipts and JWSs signed by a P-256 PKI minted by the probe (root, WWDR
  with the marker OID, signer with the marker OID; fixed private scalars;
  valid 2024-01-01 to 2050-01-01 unless the recipe says otherwise;
  creation date and `signedDate` 2024-08-06T12:00:00Z), its certificates
  written field by field so that any field can be hostile.

Four controls run first and all verify: the minted receipt without and with
signed attributes, the minted JWS, and the shared receipt respliced
unchanged. So each refusal below is the recipe's doing. The clock is
2025-01-01T00:00:00Z unless the recipe pins another. Every input is under
100 KB; the largest are 98,935 bytes (49,000 NULLs) and 90,922 bytes (the
90,000-digit date). An endpoint case takes the receipt fixture, as
`endpoint/ids-echo-apples-keys` does.

## Proposed cases and the module's answer

"Answer" is what the module said; it is the proposed expectation unless the
next section says otherwise. Field values are JSON.

| Case id | Inventory row(s) | Recipe | Answer |
|---|---|---|---|
| `receipt/reject-an-unparseable-stranger-first` | Go certbag_test UnparseableStrangerCertificateIsTolerated...AtEveryPosition | shared receipt, `30 03 02 01 00` inserted first in the certificates bag | MALFORMED |
| `receipt/reject-an-unparseable-stranger-middle` | Go certbag_test UnparseableStrangerCertificateIsTolerated...AtEveryPosition | shared receipt, `30 03 02 01 00` inserted middle in the certificates bag | MALFORMED |
| `receipt/reject-an-unparseable-stranger-last` | Go certbag_test UnparseableStrangerCertificateIsTolerated...AtEveryPosition | shared receipt, `30 03 02 01 00` inserted last in the certificates bag | MALFORMED |
| `receipt/reject-noncanonical-signature-on-leaf` | Go certbag_test NonCanonicalCertificateSignatureIsFatalAtEveryPosition | minted receipt; the signer certificate's ECDSA r carries a redundant leading zero | UNTRUSTED_CHAIN |
| `receipt/reject-noncanonical-signature-on-intermediate` | Go certbag_test NonCanonicalCertificateSignatureIsFatalAtEveryPosition | minted receipt; the intermediate's ECDSA r carries a redundant leading zero | UNTRUSTED_CHAIN |
| `receipt/verify-with-a-corrupted-redundant-root-copy` | Go certbag_test CorruptedCertificateInGenuineReceipt | shared receipt, the last byte of the bag's copy of the root flipped | ok; `/bundle_id` "com.example.app" |
| `receipt/reject-a-corrupted-signer-certificate` | Go certbag_test CorruptedCertificateInGenuineReceipt | shared receipt, the last byte of the signer certificate's signature flipped | UNTRUSTED_CHAIN |
| `receipt/reject-sixty-four-junk-certificates-as-malformed` | Go certbag_test CertificateCountIsStillCheckedBeforeDecoding | shared receipt, its three certificates and 64 junk entries | MALFORMED |
| `receipt/reject-a-signer-that-is-named-but-unreadable` | Go certbag_test AMalformedSignerIsACertificateDefect | minted receipt; the signer certificate's public key is a 3-byte EC point | INVALID_CERTIFICATE |
| `receipt/verify-with-two-anchors-only-one-used` | Go chain_test AnchorsArePinnedInBothDirections | shared receipt; trusted roots receipt-root and jws-root | ok; `/bundle_id` "com.example.app" |
| `receipt/accept-an-expired-trust-anchor` | Go chain_test ExpiredAnchorStillAnchors; Ruby receipt_test test_an_anchor_is_not_rejected_for_being_expired | minted receipt (created 2024-08-06) under a root valid 2023-01-01 to 2024-06-01; the WWDR and signer valid 2024-2050 | ok; `/bundle_id` "com.example.app" |
| `receipt/reject-an-intermediate-that-is-not-a-ca` | Go chain_test IntermediateMustBeAUsableCA | minted receipt; the WWDR has basicConstraints cA FALSE | UNTRUSTED_CHAIN |
| `signed-data/reject-an-intermediate-that-is-not-a-ca` | Ruby jws_test test_rejects_an_intermediate_that_is_not_a_ca | minted JWS; the WWDR has basicConstraints cA FALSE | UNTRUSTED_CHAIN |
| `receipt/verify-a-signer-whose-issuer-name-is-reencoded` | Go chain_test IssuerNameMustMatchByBytes | minted receipt; the signer's issuer name is the WWDR's subject text as a PrintableString (the WWDR's subject is a UTF8String); the SignerInfo names the issuer as UTF8String | ok |
| `receipt/relabelled-signature-algorithm-still-verifies` | Go endpoint_test SignatureAlgorithmIdentifierIsNotConsulted | the fixture of receipt/relabelled-signature-algorithm-does-not-crash (today oneOf ok|INVALID_SIGNATURE) | INVALID_SIGNATURE |
| `endpoint/pacific-time-2026-spring-before` | Go endpoint_test AppleDateTripleShape; Ruby pacific_time_test (5 rows); Swift and PHP Pacific-time rows | minted receipt created 2026-03-08T09:59:59Z, clock pinned at 2026-03-08T09:59:59Z; zoneinfo renders the clock 2026-03-08 01:59:59 America/Los_Angeles | body status 0; `/receipt/request_date` "2026-03-08 09:59:59 Etc/GMT", `/receipt/request_date_ms` "1772963999000", `/receipt/request_date_pst` "2026-03-08 01:59:59 America/Los_Angeles", `/receipt/receipt_creation_date` "2026-03-08 09:59:59 Etc/GMT", `/receipt/receipt_creation_date_ms` "1772963999000", `/receipt/receipt_creation_date_pst` "2026-03-08 01:59:59 America/Los_Angeles" |
| `endpoint/pacific-time-2026-spring-after` | Go endpoint_test AppleDateTripleShape; Ruby pacific_time_test (5 rows); Swift and PHP Pacific-time rows | minted receipt created 2026-03-08T10:00:00Z, clock pinned at 2026-03-08T10:00:00Z; zoneinfo renders the clock 2026-03-08 03:00:00 America/Los_Angeles | body status 0; `/receipt/request_date` "2026-03-08 10:00:00 Etc/GMT", `/receipt/request_date_ms` "1772964000000", `/receipt/request_date_pst` "2026-03-08 03:00:00 America/Los_Angeles", `/receipt/receipt_creation_date` "2026-03-08 10:00:00 Etc/GMT", `/receipt/receipt_creation_date_ms` "1772964000000", `/receipt/receipt_creation_date_pst` "2026-03-08 03:00:00 America/Los_Angeles" |
| `endpoint/pacific-time-2026-autumn-before` | Go endpoint_test AppleDateTripleShape; Ruby pacific_time_test (5 rows); Swift and PHP Pacific-time rows | minted receipt created 2026-11-01T08:59:59Z, clock pinned at 2026-11-01T08:59:59Z; zoneinfo renders the clock 2026-11-01 01:59:59 America/Los_Angeles | body status 0; `/receipt/request_date` "2026-11-01 08:59:59 Etc/GMT", `/receipt/request_date_ms` "1793523599000", `/receipt/request_date_pst` "2026-11-01 01:59:59 America/Los_Angeles", `/receipt/receipt_creation_date` "2026-11-01 08:59:59 Etc/GMT", `/receipt/receipt_creation_date_ms` "1793523599000", `/receipt/receipt_creation_date_pst` "2026-11-01 01:59:59 America/Los_Angeles" |
| `endpoint/pacific-time-2026-autumn-after` | Go endpoint_test AppleDateTripleShape; Ruby pacific_time_test (5 rows); Swift and PHP Pacific-time rows | minted receipt created 2026-11-01T09:00:00Z, clock pinned at 2026-11-01T09:00:00Z; zoneinfo renders the clock 2026-11-01 01:00:00 America/Los_Angeles | body status 0; `/receipt/request_date` "2026-11-01 09:00:00 Etc/GMT", `/receipt/request_date_ms` "1793523600000", `/receipt/request_date_pst` "2026-11-01 01:00:00 America/Los_Angeles", `/receipt/receipt_creation_date` "2026-11-01 09:00:00 Etc/GMT", `/receipt/receipt_creation_date_ms` "1793523600000", `/receipt/receipt_creation_date_pst` "2026-11-01 01:00:00 America/Los_Angeles" |
| `endpoint/pacific-time-2007-spring-after` | Go endpoint_test AppleDateTripleShape; Ruby pacific_time_test (5 rows); Swift and PHP Pacific-time rows | minted receipt created 2024-08-06T12:00:00Z, clock pinned at 2007-03-11T10:00:00Z; zoneinfo renders the clock 2007-03-11 03:00:00 America/Los_Angeles | body status 0; `/receipt/request_date` "2007-03-11 10:00:00 Etc/GMT", `/receipt/request_date_ms` "1173607200000", `/receipt/request_date_pst` "2007-03-11 03:00:00 America/Los_Angeles", `/receipt/receipt_creation_date` "2024-08-06 12:00:00 Etc/GMT", `/receipt/receipt_creation_date_ms` "1722945600000", `/receipt/receipt_creation_date_pst` "2024-08-06 05:00:00 America/Los_Angeles" |
| `endpoint/pacific-time-2040-summer` | Go endpoint_test AppleDateTripleShape; Ruby pacific_time_test (5 rows); Swift and PHP Pacific-time rows | minted receipt created 2040-07-01T12:00:00Z, clock pinned at 2040-07-01T12:00:00Z; zoneinfo renders the clock 2040-07-01 05:00:00 America/Los_Angeles | body status 0; `/receipt/request_date` "2040-07-01 12:00:00 Etc/GMT", `/receipt/request_date_ms` "2224756800000", `/receipt/request_date_pst` "2040-07-01 05:00:00 America/Los_Angeles", `/receipt/receipt_creation_date` "2040-07-01 12:00:00 Etc/GMT", `/receipt/receipt_creation_date_ms` "2224756800000", `/receipt/receipt_creation_date_pst` "2040-07-01 05:00:00 America/Los_Angeles" |
| `endpoint/ids-at-the-64-bit-edge` | Go endpoint_test EndpointIdsExactDigits | the fixture of receipt/integers-at-the-64-bit-edge through the endpoint | body status 0; `/receipt/app_item_id` 9223372036854775807, `/receipt/download_id` -9223372036854775808 |
| `transaction/accept-a-third-x5c-entry-from-a-stranger-root` | Go jws_test ThirdX5CEntryIsUntrustedButMustParse; Ruby jws_test test_x5c_third_element_is_ignored | minted JWS whose x5c is [leaf, WWDR, a self-signed root nobody trusts] instead of [leaf, WWDR, root] | ok; `/signedDate` 1722945600000 |
| `transaction/accept-signed-date-exponent-spelling` | Go jws_test EverySpellingOfASignedDateIsRead | minted JWS, signedDate written 1.7229456E12 | ok; `/signedDate` 1722945600000.0 |
| `transaction/signed-date-minus-1e300-falls-back-to-the-clock` | Go jws_test UnrepresentableSignedDateFallsBackToTheClock | minted JWS, signedDate -1e300 | ok; `/signedDate` -1e+300 |
| `transaction/signed-date-30-digits-falls-back-to-the-clock` | Go jws_test UnrepresentableSignedDateFallsBackToTheClock | minted JWS, signedDate 100000000000000000000000000000 | ok; `/signedDate` 100000000000000000000000000000 |
| `receipt/empty-date-string-means-absent` | Go receipt_test EmptyDateStringMeansAbsent; PHP "an empty date attribute is absent" | minted receipt whose creation-date attribute (12) is an empty IA5String | ok; `/bundle_id` "com.example.app", `/receipt_creation_date_ms` null, `/unknown_attributes` {} |
| `receipt/reject-foreign-chain-with-an-unmarked-signer` | Go receipt_test ReceiptChainIsCheckedBeforeTheMarkerOID; Ruby receipt_test test_chain_is_reported_before_the_signer_marker_oid | minted receipt under a foreign root, the signer without the marker OID; trusted: the P7 root | UNTRUSTED_CHAIN |
| `receipt/bundle-id-that-is-not-asn1-is-kept-raw` | Go receipt_test BundleIDValueThatIsNotASN1IsKeptRaw | minted receipt whose bundle id attribute (2) value is the octets ff fe 00 41 | ok; `/bundle_id` null, `/bundle_id_bytes` "//4AQQ==" |
| `receipt/verify-at-not-before-instant` | Go internal/chain ValidAtIsInclusiveAtBothEnds | minted receipt created 2024-08-06T12:00:00Z, the signer valid 2024-08-06T12:00:00Z to 2050-01-01T00:00:00Z | ok; `/bundle_id` "com.example.app" |
| `receipt/verify-at-not-after-instant` | Go internal/chain ValidAtIsInclusiveAtBothEnds | minted receipt created 2024-08-06T12:00:00Z, the signer valid 2024-01-01T00:00:00Z to 2024-08-06T12:00:00Z | ok; `/bundle_id` "com.example.app" |
| `receipt/reject-one-second-after-not-after` | Go internal/chain ValidAtIsInclusiveAtBothEnds | minted receipt created 2024-08-06T12:00:01Z, the signer valid 2024-01-01T00:00:00Z to 2024-08-06T12:00:00Z | INVALID_CERTIFICATE |
| `receipt/verify-beside-a-stranger-with-a-16384-bit-modulus` | Go internal/chain RSAModulusCap | shared receipt with a self-issued stranger carrying a 16,384-bit RSA modulus added to the bag | ok; `/bundle_id` "com.example.app" |
| `receipt/reject-a-thousand-junk-certificates` | Ruby certificate_flood_test (thousand certificates) | shared receipt, its three certificates and 1,000 junk entries | MALFORMED |
| `receipt/reject-eleven-junk-certificates-with-the-signer-absent` | Ruby certificate_flood_test test_the_bound_is_reported_before_the_signer_lookup; Python reject-eleven-non-certificate-embedded-entries-as-malformed; Java -wasm countsEmbeddedCertificatesBeforeDecodingAnyOfThem; Swift chain-walk bounds | shared receipt whose bag is 11 junk entries and nothing else | MALFORMED |
| `receipt/reject-an-indefinite-length-nesting-bomb` | Ruby hostile_input_test test_indefinite_length_nesting_bomb; performance_test | 40,000 nested `30 80` opens, no end-of-contents (80 KB) | MALFORMED |
| `receipt/reject-a-definite-length-nesting-bomb` | Ruby hostile_input_test test_definite_length_nesting_bomb; performance_test | 10,000 nested definite-length SEQUENCEs | MALFORMED |
| `receipt/reject-a-length-claiming-two-gigabytes` | Ruby hostile_input_test test_a_length_claiming_two_gigabytes_on_a_forty_byte_input | `30 84 7f ff ff ff` and 34 zero octets | MALFORMED |
| `receipt/reject-an-unterminated-indefinite-length-container` | Ruby hostile_input_test test_an_unterminated_indefinite_length_container | `30 80 30 80 02 01 00` | MALFORMED |
| `receipt/reject-an-end-of-contents-with-no-open-container` | Ruby hostile_input_test test_an_end_of_contents_with_no_open_container | `30 02 00 00` | MALFORMED |
| `receipt/reject-a-multi-byte-tag` | Ruby hostile_input_test test_multi_byte_tags_are_refused_rather_than_interpreted | `1f 81 00 01 00` | MALFORMED |
| `receipt/reject-a-length-field-wider-than-four-octets` | Ruby hostile_input_test test_length_fields_wider_than_four_octets_are_refused | `30 85 00 00 00 00 03 02 01 00` | MALFORMED |
| `receipt/reject-a-contentinfo-holding-only-the-oid` | Swift "a ContentInfo holding only the OID" | SEQUENCE { signedData OID } | MALFORMED |
| `receipt/a-huge-flat-attribute-set-is-bounded` | Ruby hostile_input_test test_a_receipt_whose_payload_is_a_huge_flat_set_is_bounded | minted receipt with 5,000 extra valid attributes | ok; `/bundle_id` "com.example.app" |
| `receipt/unreadable-attribute-value-in-80-constructed-levels` | Ruby hostile_input_test test_a_ber_chunked_attribute_value_is_bounded | minted receipt, an attribute value written as 80 nested constructed OCTET STRINGs | UNREADABLE_PAYLOAD |
| `receipt/a-node-budget-flood-is-bounded` | Ruby hostile_input_test test_the_node_budget_ceiling_costs_a_bounded_amount (scaled to 49,000 NULLs, 98 KB) | minted receipt, an attribute value holding one SEQUENCE of 49,000 NULLs | ok; `/bundle_id` "com.example.app" |
| `receipt/a-date-with-90000-fractional-digits-is-bounded` | Ruby hostile_input_test test_a_date_with_a_million_fractional_digits_is_not_superlinear (scaled to 90,000 digits) | minted receipt whose creation date has 90,000 fractional-second digits | ok; `/bundle_id` "com.example.app", `/receipt_creation_date_ms` null |
| `endpoint/a-date-with-90000-fractional-digits-is-bounded` | Ruby hostile_input_test test_the_endpoint_is_not_superlinear_on_a_long_fractional_second (scaled) | the receipt above through the endpoint | body status 0 |
| `transaction/reject-a-header-segment-outside-the-base64url-alphabet` | Ruby jws_test test_rejects_a_segment_outside_the_base64url_alphabet | the generated transaction with its header's first character replaced by '+' | MALFORMED |
| `transaction/reject-a-payload-segment-outside-the-base64url-alphabet` | Ruby jws_test test_rejects_a_segment_outside_the_base64url_alphabet | the generated transaction with its payload's first character replaced by '/' | MALFORMED |
| `transaction/reject-a-header-that-is-base64url-but-not-json` | Ruby jws_test test_rejects_a_segment_that_is_base64url_but_not_json | the generated transaction with its header replaced by base64url("not json") | MALFORMED |
| `transaction/reject-a-signature-whose-r-is-the-group-order` | Ruby jws_test test_rejects_a_signature_whose_scalars_are_zero_or_out_of_range | the generated transaction with its signature replaced by r = n (the P-256 order), s = 1 | INVALID_SIGNATURE |
| `raw/reject-a-jws-with-two-segments` | Ruby jws_test test_rejects_inputs_that_are_not_three_segments | the generated transaction without its signature segment | MALFORMED |
| `raw/reject-a-jws-with-one-segment` | Ruby jws_test test_rejects_inputs_that_are_not_three_segments | the generated transaction's header segment alone | MALFORMED |
| `receipt/accept-a-duplicated-genuine-signer-info` | Ruby receipt_test test_a_duplicated_genuine_signer_info_still_verifies | shared receipt whose SignerInfos SET holds its SignerInfo twice | ok; `/bundle_id` "com.example.app" |
| `receipt/reject-a-signer-certificate-that-is-not-embedded` | Ruby receipt_test test_rejects_a_signer_certificate_that_is_not_embedded; PHP "SignerInfo naming a certificate that is not embedded" | shared receipt, the signer certificate removed from the bag | MALFORMED |
| `receipt/reject-an-empty-message-digest-set` | Python "signed attributes: empty message-digest set" | minted receipt with signed attributes; reject an empty message digest set | INVALID_SIGNATURE |
| `receipt/reject-a-message-digest-that-is-not-an-octet-string` | Python "message-digest not an OCTET STRING" | minted receipt with signed attributes; reject a message digest that is not an octet string | INVALID_SIGNATURE |
| `receipt/verify-with-a-signing-time-in-month-13` | Python "signing-time month 13" | minted receipt with signed attributes; verify with a signing time in month 13 | ok; `/bundle_id` "com.example.app" |
| `receipt/verify-with-an-unknown-signed-attribute-holding-invalid-utf8` | Python "unknown attribute with invalid UTF-8" | minted receipt with signed attributes; verify with an unknown signed attribute holding invalid utf8 | ok; `/bundle_id` "com.example.app" |
| `receipt/reject-a-digest-algorithm-that-is-not-an-oid` | Python "SignerInfo: digest algorithm not an OID" | minted receipt; the SignerInfo's digestAlgorithm is SEQUENCE { INTEGER 1 } | MALFORMED |
| `receipt/reject-a-signature-that-is-not-an-octet-string` | Python "SignerInfo: signature not an OCTET STRING" | minted receipt; the SignerInfo's signature is a BIT STRING | MALFORMED |
| `receipt/reject-a-negative-attribute-type` | Python reject-negative-attribute-type | minted receipt with an attribute of type -1 | UNREADABLE_PAYLOAD |
| `transaction/reject-a-signed-date-of-nan` | Python "signed-data NaN and Infinity signed dates" | minted JWS whose claims say "signedDate":NaN (not JSON) | UNREADABLE_PAYLOAD |
| `transaction/reject-a-signed-date-of-infinity` | Python "signed-data NaN and Infinity signed dates" | minted JWS whose claims say "signedDate":Infinity (not JSON) | UNREADABLE_PAYLOAD |
| `receipt/in-app-attribute-type-int32-max-is-kept` | Swift "in-app attribute type 2^31 and 2^31 - 1" | minted receipt with one in-app purchase (17) holding an attribute of type 2147483647 | ok; `/in_app/0/product_id` "com.example.coins", `/in_app/0/unknown_attributes/2147483647/0` "AgEB" |
| `receipt/in-app-attribute-type-above-int32-max-keeps-the-purchase-raw` | Swift "in-app attribute type 2^31 and 2^31 - 1" | minted receipt with one in-app purchase (17) holding an attribute of type 2147483648 | ok; `/unknown_attributes/17/0` "MS8wHAICBqYCAQEEEwwRY29tLmV4YW1wbGUuY29pbnMwDwIFAIAAAAACAQEEAwIBAQ==" |
| `signed-data/reject-an-rsa-leaf-under-es256` | PHP "an RSA leaf in a JWS" | minted JWS, alg ES256, whose leaf carries an RSA key | INVALID_SIGNATURE |
| `transaction/reject-signature-of-128-bytes` | PHP "ES256 signatures of 0, 63, 65 and 128 bytes" | the generated transaction with a 128-byte signature (its own, twice) | INVALID_SIGNATURE |
| `receipt/reject-an-unknown-digest-algorithm` | PHP "unknown digest OID in a SignerInfo" | shared receipt, the SignerInfo's digestAlgorithm replaced by 1.2.3.4 | INVALID_SIGNATURE |
| `receipt/reject-an-md5-digest-algorithm` | PHP "MD5 digest" | shared receipt, the SignerInfo's digestAlgorithm replaced by md5 | INVALID_SIGNATURE |
| `receipt/reject-a-signer-whose-signature-algorithms-disagree` | PHP "inner and outer signature algorithms disagree" | minted receipt; the signer certificate's outer signatureAlgorithm says ecdsa-with-SHA384, its TBS says ecdsa-with-SHA256 | UNTRUSTED_CHAIN |
| `receipt/reject-a-signer-valid-from-month-13` | PHP "a validity month 13" | minted receipt; the signer validity is 3020170d3234313330313030303030305a180f32303530303130313030303030305a | INVALID_CERTIFICATE |
| `receipt/reject-a-signer-whose-utctime-50-means-1950` | PHP "the UTCTime pivot" | minted receipt; the signer validity is 301e170d3234303130313030303030305a170d3530303130313030303030305a | INVALID_CERTIFICATE |
| `receipt/verify-a-signer-whose-utctime-49-means-2049` | PHP "the UTCTime pivot" | minted receipt; the signer validity is 301e170d3234303130313030303030305a170d3439313233313233353935395a | ok; `/bundle_id` "com.example.app" |
| `receipt/reject-a-signer-validity-of-the-wrong-tag` | PHP "a validity of the wrong tag" | minted receipt; the signer validity is 3020160d3234303130313030303030305a180f32303530303130313030303030305a | MALFORMED |

## Answers that differ from the deleted test

The contract is the core and Java together (DECISIONS.md R20, R33), so a
row where the module now answers differently from the 0.7 port's own test
is a finding, not a failing case. Run each through the Java implementation
(`tools/differential.sh`) before adding it; where Java disagrees the case
becomes `oneOf` or an R20 entry.

1. **An unparseable stranger in the bag** (`30 03 02 01 00`, at any
   position) is `MALFORMED`. Go 0.7 skipped it and verified. OpenSSL
   decodes the whole `certificates` SET; the existing
   `receipt/reject-signer-absent-beside-a-malformed-stranger` is `MALFORMED`
   for the same reason.
2. **A signer whose issuer name is re-encoded** (PrintableString where the
   WWDR's subject is a UTF8String, same text) verifies. Go 0.7 compared
   names byte for byte and refused; OpenSSL compares canonical names.
3. **The relabelled signature algorithm** fixture is `INVALID_SIGNATURE`.
   Go 0.7 never read the identifier and verified. The existing case stays
   `oneOf ["ok", "INVALID_SIGNATURE"]` unless Java answers the same.
4. **A signing time in month 13, and an unknown signed attribute holding
   invalid UTF-8,** verify. Python 0.7 refused both. The core does not read
   `signingTime`: the validity instant is the receipt's creation date.
5. **`signedDate` NaN or Infinity** (not JSON) is `UNREADABLE_PAYLOAD`, not
   the `MALFORMED` the inventory guessed: the signature holds, the payload
   does not parse.
6. **An in-app attribute of type 2^31** keeps the whole in-app purchase raw
   under `unknown_attributes/17` and the receipt verifies (`in_app` is
   empty). The receipt-level twin, `receipt/reject-attribute-type-above-int32-max`,
   is `UNREADABLE_PAYLOAD`.
7. **Fractional seconds in a creation date are not read**: the date comes
   back `null` and the validity instant falls back to the clock (probed by
   hand: `2024-08-06T12:00:00.000Z` against a signer that expires at
   12:00:00 is `INVALID_CERTIFICATE`, `2024-08-06T12:00:00Z` verifies). So
   Go's "one millisecond after notAfter" is not expressible through a
   receipt; the proposal uses one second.

The Pacific-time family agrees with the IANA database (Python `zoneinfo`)
at all six clocks, both sides of each 2026 transition, 2007 (the first year
of the current US rule) and 2040. `request_date` is written
`YYYY-MM-DD HH:MM:SS Etc/GMT`, as Apple writes it.

## Rows that need no case

| Inventory row | Why |
|---|---|
| Go receipt_test ReceiptWithoutSignedAttributesVerifies | Covered: the core review's minted receipts carry no signed attributes and verify (for example `receipt/accept-double-wrap-rechunked-into-6-constructed-levels`); so does this probe's control. |
| Go receipt_test ReceiptHostileStructures (the 25-shape table) | Moot as cases: the hostile corpus (811 rows) runs through every host byte for byte on every change, and the shapes a case would pin are the ones the proposals above name. Pinning all 25 is the owner's call the row already names. |
| Go errors_test ErrorMessagesLeakNothingFromTheInput; PHP "a failure message never echoes the input" | Needs the schema first: `messageMustNotContain` takes code points, not strings. A schema change, then one case per failure path. |
| Go testhelpers_test, testpki_test | Not tests: the builders this probe replaces. |
| Go endpoint_test SignatureAlgorithmIdentifierIsNotConsulted | See finding 3: the existing `oneOf` case stays until Java's answer is known. |
| Ruby input_size_bounds_test test_an_oversized_malformed_body_answers_21002_without_parsing | Over 100 KB by construction (the body cap is 3 MiB): a Rust test, R20's rule for bounds. |
| Java -wasm jwsIsMeasuredInUtf8Bytes (the multi-byte variant) | A 256 KB fixture: a Rust test. |
| Ruby performance_test test_rejecting_a_nesting_bomb_costs_almost_nothing | The two nesting-bomb proposals, with `maxMillis`. |
| Ruby rows marked "or a Rust test when the input is over 100 KB" (thousand certificates, both nesting bombs, node budget, a million fractional digits, 1.5 million on the endpoint) | Proposed above scaled below 100 KB (1,000 junk certificates, 40,000 indefinite opens, 10,000 definite levels, 49,000 NULLs, 90,000 digits); the full sizes stay a Rust test if wanted. The slowest of them took 74 ms here (5,000 attributes); `maxMillis` 2,000 as the other bound cases use. |

Rows several ports shared map to one proposal: the eleven-junk-certificate
case serves Ruby, Python, Java -wasm and Swift; the expired-anchor case Go
and Ruby; the foreign-chain-unmarked-signer case Go and Ruby; the
signer-not-embedded case Ruby and PHP; the empty-date case Go and PHP; the
third-x5c case Go and Ruby; the Pacific-time family Go, Ruby (five rows),
Swift and PHP.

## Where this stops holding

The answers are the G1c module's. A later core that changes one changes the
proposal, which is the point of turning it into a case. Java was not run;
see the findings above. The probe drives the Python host only; every host
passes the same module the same bytes (6,179 of 6,179 corpus rows identical
on each), so the answer is the module's rather than the host's.
