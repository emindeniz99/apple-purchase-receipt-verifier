# Changelog

## [0.6.0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/compare/v0.5.1...v0.6.0) (2026-09-24)

### Read first

* **Breaking release.** Every port drops its max-signed-age freshness policy (`STALE_PAYLOAD`, the JWS clock options) and its `isActiveAt` entitlement helper, returns a result object from the verifyReceipt endpoint, caps requests and receipts at Apple's 3 MiB, accepts only canonical standard base64, and reports Apple-signed content it cannot read as `INTERNAL_ERROR` (21009). Each port's README has an "Upgrading from 0.5" section; the entries below give the exact changes.
* **Known issue: legacy receipts fail on RHEL 9 in five ports.** RHEL 9's DEFAULT crypto policy makes the system OpenSSL refuse SHA-1 signatures, and Apple's legacy receipt chain and signature use SHA-1, so a genuine legacy receipt answers `INVALID_CHAIN`. Affected: Ruby, PHP and .NET always; Python with the distro `cryptography` package; Node with RHEL's `nodejs` package. Rust, Go, Swift and Java are unaffected, and so are StoreKit 2 JWS and modern receipts. Workaround until the fix: `update-crypto-policies --set DEFAULT:SHA1`.
* **Swift users of 0.4.0 to 0.5.1: upgrade.** Release builds of those versions crash on a genuine receipt on Linux x86_64 under Swift 6.3.3 (a miscompiled throw path, fixed in #126). Debug builds and tests pass, so CI does not show it.
* **Java: the receipt signer's algorithm is no longer restricted.** Any algorithm verifies when the signer chains to a pinned Apple root and carries Apple's marker OID, so a change on Apple's side cannot reject genuine receipts. The other ports still accept RSA with SHA-1 or SHA-256 only.
* **Java: certificate keys are decoded only after a pinned root vouches for them.** A receipt or JWS padded with huge RSA keys no longer costs seconds of CPU, and an extra certificate the chain does not use is ignored instead of making a genuine receipt `INVALID_RECEIPT_FORMAT`.
* **Java runs all cryptography on its private BouncyCastle provider**, so `jdk.certpath.disabledAlgorithms` and the JVM provider list no longer affect a verdict. Entries below about a JVM start-up check and a Java signature-algorithm allowlist describe steps this release later replaced.


### ⚠ BREAKING CHANGES

* **java:** TransactionPayload.isActiveAt(Date) is removed. Read revocationDate() and expiresDate() yourself, and handle grace periods, upgrades and refunds from renewal info or Apple's server APIs.
* **swift:** TransactionPayload.isActive(at:) is removed. Read revocationDate and expiresDate yourself, and handle grace periods, upgrades and refunds from renewal info or Apple's server APIs.
* **rust:** TransactionPayload::is_active_at is removed. Read revocation_date and expires_date yourself, and handle grace periods, upgrades and refunds from renewal info or Apple's server APIs. The C ABI never exposed it and is unchanged.
* **dotnet:** TransactionPayload.IsActiveAt is removed. Read RevocationDate and ExpiresDate yourself, and handle grace periods, upgrades and refunds from renewal info or Apple's server APIs.
* **php:** TransactionPayload::isActiveAt() is removed. Read revocationDate and expiresDate yourself, and handle grace periods, upgrades and refunds from renewal info or Apple's server APIs.
* **ruby:** TransactionPayload#active_at? is removed. Read revocation_date and expires_date yourself, and handle grace periods, upgrades and refunds from renewal info or Apple's server APIs.
* **python:** is_transaction_active_at is removed. Read revocationDate and expiresDate yourself, and handle grace periods, upgrades and refunds from renewal info or Apple's server APIs.
* **node:** isTransactionActiveAt is removed from both entry points. Read revocationDate and expiresDate yourself, and handle grace periods, upgrades and refunds from renewal info or Apple's server APIs.
* **go:** (*TransactionPayload).IsActiveAt is removed. Read RevocationDate and ExpiresDate yourself, and handle grace periods, upgrades and refunds from renewal info or Apple's server APIs.
* **java:** the five- and six-argument JwsVerifier constructors (maxSignedAge, clock) are replaced by one four-argument constructor taking appAppleId, and Reason.STALE_PAYLOAD no longer exists. Check signedDate() yourself where a freshness window fits.
* **swift:** JwsVerifier.init no longer takes maxSignedAgeMillis or clock, and VerificationError.Reason.stalePayload no longer exists. Check signedDate yourself where a freshness window fits.
* **rust:** JwsVerifierBuilder::max_signed_age and JwsVerifierBuilder::clock are removed, and Reason::StalePayload no longer exists. In the C ABI, aprv_verifier_new_jws and aprv_verifier_new_jws_with_roots no longer take max_signed_age_secs, aprv_verifier_new_jws_with_roots_and_clock is removed and APRV_REASON_STALE_PAYLOAD (11) is retired. Check signed_date yourself where a freshness window fits.
* **dotnet:** the JwsVerifier constructor no longer takes maxSignedAge or clock, and VerificationReason.StalePayload no longer exists. Check SignedDate yourself where a freshness window fits.
* **php:** JwsVerifier no longer takes maxSignedAgeSeconds or clock (passing them throws InvalidArgumentException), and Reason::StalePayload no longer exists. Check signedDate yourself where a freshness window fits.
* **ruby:** JwsVerifier.new no longer accepts max_signed_age_seconds: or clock: (both now raise ArgumentError), and Reason::STALE_PAYLOAD no longer exists. Check signed_date yourself where a freshness window fits.
* **python:** JwsVerifier no longer accepts max_signed_age_millis or clock, and Reason.STALE_PAYLOAD no longer exists. Check the payload's signedDate yourself where a freshness window fits.
* **node:** JwsVerifierOptions.maxSignedAgeMillis and JwsVerifierOptions.clock are removed (maxSignedAgeMillis now throws a TypeError), and Reason.STALE_PAYLOAD no longer exists. Check payload.signedDate yourself where a freshness window fits.
* **go:** JWSVerifierOptions.MaxSignedAge and JWSVerifierOptions.Now are removed, and ReasonStalePayload is no longer part of the vocabulary. Check payload.SignedDate yourself where a freshness window fits.
* **repo:** fixtures/cases.json drops maxSignedAgeSeconds, the STALE_PAYLOAD reason and clocks on verifyTransaction, verifyAppTransaction and verifyRaw cases; the C ABI manifest drops the maxSignedAgeSecs key. Runners must stop passing these.
* **rust:** TransactionPayload::from_claims and AppTransactionPayload::from_claims return Result<Self>. Callers add ? or handle the INTERNAL_ERROR.
* **repo:** INTERNAL_ERROR is now a verifier reason. Receipts whose chain and signature verify but whose payload does not parse (bad attribute shape, an attribute type above 2^31-1, an unreadable date or value, a malformed in-app purchase, zero-length content, a bound hit in the payload) move from INVALID_RECEIPT_FORMAT / 21002 to INTERNAL_ERROR / 21009. Payload defects under an untrusted or expired chain now report the chain reason, and spliced payloads under a valid chain report INVALID_SIGNATURE. Changed vectors: receipt/reject-attribute-type-above-int32-max, receipt/reject-attribute-type-that-truncates-to-a-modelled-type and receipt/reject-empty-encapsulated-content (now INTERNAL_ERROR), and endpoint/attribute-type-above-int32-max-answers-21002, renamed ...-answers-21009 (21002 to 21009). Integrators must not deny a user on INTERNAL_ERROR; it is deterministic, so alert and escalate rather than retry.
* **repo:** receipt-data, at the ReceiptVerifier string entry points and at the verifyReceipt endpoint, must be canonical standard base64. Whitespace anywhere (a trailing newline, line breaks at 64 or 76 columns, surrounding spaces), the base64url alphabet and omitted padding were accepted before and now return INVALID_RECEIPT_FORMAT, 21002 at the endpoint, as Apple does. A client that sends base64EncodedString() with no options is unaffected. An x5c entry with omitted or extra '=' padding is now INVALID_CERTIFICATE.
* **rust:** MAX_REQUEST_BYTES is 3145728 (was 1048576) and MAX_RECEIPT_BYTES is 3145728 (was 2097152), both in UTF-8 bytes. A body over the request cap fails with Reason::RequestTooLarge instead of Reason::MalformedRequest. Reason is #[non_exhaustive], so matches keep compiling; a caller that wants Apple's HTTP status should map RequestTooLarge to 413.
* **swift:** VerifyReceiptEndpoint.maxRequestBytes is 3145728 (was 1048576) and ReceiptVerifier.maxReceiptBytes is 3145728 (was 2097152). A body over the cap fails with requestTooLarge rather than malformedRequest, and VerificationError.Reason gains that case, so an exhaustive switch over it must add one; map it to HTTP 413 to answer as Apple does.
* **dotnet:** VerifyReceiptEndpoint.MaxRequestBytes is 3145728 (was 1048576) and ReceiptVerifier.MaxReceiptBytes is 3145728 (was 2097152), both counted in UTF-8 bytes instead of characters. A body over the cap fails with VerificationReason.RequestTooLarge rather than MalformedRequest. VerificationReason gains that member, so a switch over it that throws on unknown values must add a case; map it to HTTP 413 to answer as Apple does.
* **php:** VerifyReceiptEndpoint::MAX_REQUEST_BYTES is 3145728 (was 1048576). ReceiptVerifier::DEFAULT_MAX_RECEIPT_BYTES (2097152) is replaced by the fixed ReceiptVerifier::MAX_RECEIPT_BYTES (3145728), and the $maxReceiptBytes parameter of the ReceiptVerifier constructor and of verifyReceiptCore() is removed; $nodeBudget moves up to its place. Drop that argument: a leftover positional size value would now be read as the node budget, so pass nodeBudget by name if you set it. A body over the cap fails with Reason::RequestTooLarge instead of MalformedRequest, and a match over failureReason() without a default arm needs that case.
* **ruby:** VerifyReceiptEndpoint::MAX_REQUEST_BYTES is 3145728 (was 1048576) and ReceiptVerifier::MAX_RECEIPT_BYTES is 3145728 (was 2097152), both in UTF-8 bytes; the receipt string was counted in characters. A body over the cap fails with REQUEST_TOO_LARGE instead of MALFORMED_REQUEST, so a case over failure_reason needs a branch.
* **go:** MaxRequestBytes is 3145728 (was 1048576) and the receipt cap is 3145728 (was 2097152), both in UTF-8 bytes. DefaultMaxReceiptBytes is renamed to the constant MaxReceiptBytes, and the MaxReceiptBytes field is removed from ReceiptVerifierOptions and VerifyReceiptEndpointOptions; the cap is no longer configurable. A body over the cap fails with ReasonRequestTooLarge instead of ReasonMalformedRequest.
* **node:** VerifyReceiptEndpoint.MAX_REQUEST_BYTES is 3145728 (was 1048576) and ReceiptVerifier.MAX_RECEIPT_BYTES is 3145728 (was 2097152), both in UTF-8 bytes. A body over the cap fails with REQUEST_TOO_LARGE instead of MALFORMED_REQUEST, and Reason gains that member, so an exhaustive switch over Reason must handle it.
* **python:** VerifyReceiptEndpoint.MAX_REQUEST_BYTES is 3145728 (was 1048576) and ReceiptVerifier.MAX_RECEIPT_BYTES is 3145728 (was 2097152), both in UTF-8 bytes instead of code points. A body over the cap fails with Reason.REQUEST_TOO_LARGE instead of MALFORMED_REQUEST.
* **java:** VerifyReceiptEndpoint.MAX_REQUEST_BYTES is 3145728 (was 1048576) and ReceiptVerifier.MAX_RECEIPT_BYTES is 3145728 (was 2097152), both counted in UTF-8 bytes instead of characters. A body over the cap now fails with Reason.REQUEST_TOO_LARGE rather than MALFORMED_REQUEST, and Reason gains that constant, so an exhaustive Kotlin when or Scala match over Reason must add a branch.
* **php:** VerifyReceiptEndpoint::verifyReceipt(mixed $body): array is removed. Replace $endpoint->verifyReceipt($body) with $endpoint->verifyReceiptResult($body)->toResponse(). A string argument to verifyReceiptResult is parsed as the raw JSON body; the removed method answered 21002 for any string. Reason has two new cases, so an exhaustive match over Reason::cases() needs arms for MalformedRequest and InternalError.
* **dotnet:** VerifyReceiptEndpoint.VerifyReceipt(body) is removed. Replace endpoint.VerifyReceipt(body) with endpoint.VerifyReceiptResult(body).ToResponse(); a literal null argument now needs a cast to IReadOnlyDictionary<string, object?>? to pick the overload. VerificationReason gains MalformedRequest and InternalError, so an exhaustive switch over it needs two more cases. The port had no boolean production option, so nothing else is removed.
* **ruby:** VerifyReceiptEndpoint#verify_receipt is removed. Replace endpoint.verify_receipt(body) with endpoint.verify_receipt_result(body).to_response, which returns the same Hash. verify_receipt_json is unchanged.
* **swift:** VerifyReceiptEndpoint.verifyReceipt(_:) is removed; replace await endpoint.verifyReceipt(body) with await endpoint.verifyReceiptResult(body).response(). The deprecated init(trustedRoots:production:clock:) is removed; pass environment: .production for true and .sandbox for false. VerificationError.Reason gains two cases, so an exhaustive switch over it needs .malformedRequest and .internalError or a default.
* **go:** VerifyReceiptEndpoint.VerifyReceipt returns *VerifyReceiptResult instead of VerifyReceiptResponse. Replace endpoint.VerifyReceipt(request) with endpoint.VerifyReceipt(request).Response() to keep the old value. VerifyReceiptJSON is unchanged.
* **rust:** VerifyReceiptEndpoint::verify_receipt is removed. Replace endpoint.verify_receipt(&request) with endpoint.verify_receipt_result(&request).to_response(), which returns the same VerifyReceiptResponse. Code that matches on Reason exhaustively inside the crate's own match needs no change (Reason is non_exhaustive), but a _ arm now also covers the two new values.
* **node:** VerifyReceiptEndpoint.verifyReceipt(body) is removed; replace endpoint.verifyReceipt(body) with endpoint.verifyReceiptResult(body).toResponse(). A string passed to verifyReceiptResult is parsed as the raw JSON request body. The Reason union gains MALFORMED_REQUEST and INTERNAL_ERROR, so an exhaustive switch over Reason needs two more cases.
* **python:** VerifyReceiptEndpoint.verify_receipt(request_body) is removed. Replace endpoint.verify_receipt(body) with endpoint.verify_receipt_result(body).to_response(). The port had no boolean production option, so nothing else is removed.
* **java:** VerifyReceiptEndpoint.verifyReceipt(Map) is removed; replace endpoint.verifyReceipt(body) with endpoint.verifyReceiptResult(body).toResponse(). The constructors VerifyReceiptEndpoint(Set, boolean) and (Set, boolean, Clock) are removed; replace true with Environment.PRODUCTION and false with Environment.SANDBOX. verifyReceiptResult(null) is ambiguous between the Map and String overloads; cast the null.

### Features

* **dotnet:** match Apple's 3 MiB request limit, counted in UTF-8 bytes ([a5ed3b3](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/a5ed3b34a8d7259e8c5f95d61b7b3a7221b30712))
* **dotnet:** remove the isActiveAt entitlement helper ([2f43792](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/2f43792916c2e94ea4e176d659b8d71809b7e047))
* **dotnet:** remove the maxSignedAge freshness policy ([f2c9235](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/f2c92359daf5bc0ca9f88cfe057c18a0dcb5dfe8))
* **dotnet:** return a VerifyReceiptResult from the verifyReceipt API ([3eae043](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/3eae0438354cdfa0405a456806c2e94528a62164))
* **go:** match Apple's 3 MiB request limit, counted in UTF-8 bytes ([8fb3610](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8fb361009fee35a0d45c980cf8ff0fa0a0306801))
* **go:** remove the isActiveAt entitlement helper ([4feeccc](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/4feecccdc00231a822b4bc8b8e7e33126162ba69))
* **go:** remove the MaxSignedAge freshness policy ([2a1587a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/2a1587a7d46ad08184b7332e0e4cfb02aec296d9))
* **go:** return a verification result from the verifyReceipt endpoint ([b12f2df](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b12f2df57956843ebd42564d84a17321fe9d8677))
* **java:** accept any receipt signer algorithm under the pinned chain ([2ba48bc](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/2ba48bc3e1b835d45a79a6298e31bfdcc2eac1f4))
* **java:** add isVerified to VerifyReceiptResult ([b413fb3](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b413fb3d74a00970e329a9f89b20e32c2b5f191f))
* **java:** check chain signature algorithms against the JVM at startup ([c5d2246](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/c5d224606838260b2dec84eedc9d81a1a63df662))
* **java:** match Apple's 3 MiB request limit, counted in UTF-8 bytes ([cc0a8e6](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/cc0a8e6010b20f275345b369e26d5ce37b3365a9))
* **java:** remove the isActiveAt entitlement helper ([e26f509](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/e26f5092e6ee3180ba78d41bff720e6d0f327dbb))
* **java:** remove the maxSignedAge freshness policy ([8ac4a5b](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8ac4a5b8ce3164134a47e888ee40a875ee327357))
* **java:** return a verification result from the verifyReceipt endpoint ([bc66fd4](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/bc66fd41d3f08efa5db86bdfb68a3ce6ef4e1606))
* **node:** match Apple's 3 MiB request limit, counted in UTF-8 bytes ([972c6ed](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/972c6ed70b601cecc6ec05bc30dd5c8816808f8d))
* **node:** remove the isActiveAt entitlement helper ([7cc7ee4](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7cc7ee40cb1f31c422bf5a91de9ec465eb945202))
* **node:** remove the maxSignedAgeMillis freshness policy ([0422c83](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/0422c832d2e6a4314ba77f211cb2b9b1a22a2dd3))
* **node:** return a verification result from the verifyReceipt endpoint ([04dbea0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/04dbea060aa3fddcb3342941b142248c0aa4d34f))
* **php:** match Apple's 3 MiB request limit and drop the cap option ([746f282](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/746f28296a67ed0adbc4b90bb53327d161618c91))
* **php:** remove the isActiveAt entitlement helper ([321e34b](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/321e34be96fbdfc0fe9e29ea2d77a1be3b4d5379))
* **php:** remove the maxSignedAgeSeconds freshness policy ([8e135c4](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8e135c482cac348feeccbbc0547400615a7b7c21))
* **php:** return a verification result from the verifyReceipt endpoint ([7d5fd92](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7d5fd920ddbaba0ad151fc2905682e54f0b9bfec))
* **python:** match Apple's 3 MiB request limit in UTF-8 bytes ([0249019](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/0249019bc77245eaa43b93d9e5734bf659694e2f))
* **python:** remove the isActiveAt entitlement helper ([232946d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/232946d16d3ec36b4f142b8a1c212cbbaaac6052))
* **python:** remove the max_signed_age_millis freshness policy ([465938f](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/465938f3767c83fa5c1ecc9075e2daad31250b19))
* **python:** return a verification result from the verifyReceipt endpoint ([a426f0f](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/a426f0f3ad2a0568733f011f9ebb9073bbebdf35))
* **repo:** check receipt chain first, unreadable payload is 21009 ([95af97c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/95af97c3d8ca51e3e4e84852aaed0847aa3b7726))
* **repo:** drop the max-signed-age policy from the shared contract ([9e60711](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9e607114dbf8b6d8458720593c6687724a6b2990))
* **ruby:** match Apple's 3 MiB request limit, counted in UTF-8 bytes ([ec42a24](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/ec42a24e67bd42854717ff776d93ca8f6dce6302))
* **ruby:** remove the isActiveAt entitlement helper ([00eaa12](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/00eaa1216fc00b61e8fbc65404cf9e8a6eb29c20))
* **ruby:** remove the max_signed_age_seconds freshness policy ([68fc5d7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/68fc5d76aeb4d650a9878e4580b0cc02e3d0c154))
* **ruby:** return a verification result from the verifyReceipt endpoint ([daddf56](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/daddf56a5ac8cc73aadcf9d7a107862e6451920d))
* **rust:** match Apple's 3 MiB request limit, counted in UTF-8 bytes ([21df15a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/21df15a249e762cee8dc8c2e396e57b6a05ff288))
* **rust:** remove the isActiveAt entitlement helper ([d3de677](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d3de677020112b1f88b0422a3214029391e69b45))
* **rust:** remove the max_signed_age freshness policy ([1d085d2](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/1d085d22b2b060bb35a9e569daa19404eaa289dd))
* **rust:** return a verification result from the verifyReceipt endpoint ([c1feb15](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/c1feb1583732feb9ef4c8401d55f7b103d7762d9))
* **swift:** match Apple's 3 MiB request limit, counted in UTF-8 bytes ([5eab2bb](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/5eab2bb5c9228a4e45ac75102f4f7069588c6029))
* **swift:** remove the isActiveAt entitlement helper ([7aaaba3](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7aaaba35a59084b3ff51d8f9175a7ebf0481cbd4))
* **swift:** remove the maxSignedAgeMillis freshness policy ([6a98457](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/6a984578173f79ba9e30e95bdc707c2336ad65ab))
* **swift:** return a verification result from the verifyReceipt endpoint ([15957b7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/15957b75829e5cb0071bcd3f3fd7eaca276b28c0))


### Bug Fixes

* **dotnet:** answer INTERNAL_ERROR for a signed claim of the wrong type ([5515263](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/551526337a5f8c742ebcbba3199242285e6bb8be))
* **dotnet:** answer INTERNAL_ERROR when SHA-1 is unavailable ([54ca75e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/54ca75e1524b7e2a08d2d988981e32c847005a74))
* **dotnet:** cap receipt, request and JWS size before decoding ([6df8549](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/6df8549c912c3197ec7a21c807616df4624ba5cb))
* **go:** answer INTERNAL_ERROR for a signed claim of the wrong type ([002fc8f](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/002fc8f324a24783ba32a3a14cfccd8cf48cb518))
* **go:** answer INTERNAL_ERROR when SHA-1 is unavailable ([73329e3](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/73329e3c049fdfd20c86f0db7bd10ba802b3d023))
* **go:** cap receipt, request and JWS size before decoding ([bce2c0b](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/bce2c0b120a5640800a87c95f18843194d674b5f))
* **java:** accept only UTF8String and IA5String receipt strings ([83b09d4](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/83b09d463e61233120d62487abd1623758a4082f))
* **java:** allowlist the receipt signature algorithm, not only the digest ([db68e13](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/db68e13b02dfd51ce4eb6f052681bb282ca6b4b9))
* **java:** answer INTERNAL_ERROR for a signed claim of the wrong type ([514e27a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/514e27ab09ee7673ba07c344c264afd5e19d6535))
* **java:** answer INTERNAL_ERROR when the runtime lacks an algorithm ([498447b](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/498447b22ffe5e33016120f12628ce8cf7970a4a))
* **java:** contain unchecked errors before the JWS signature passes ([bcdd3cd](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/bcdd3cda84232b873e5ee9c74cc15ced0b78349f))
* **java:** decode certificate keys only after a pinned root vouches ([bd52b42](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/bd52b42599574b06b12bc05de0fc6c1688427378))
* **java:** decode certificate signatures early and guard the chain check ([ccdc172](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/ccdc17214a92404e258c60a799955421c7d4752d))
* **java:** decode x5c entries as strict standard base64 ([a852b10](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/a852b1056358d8d817a937b4bd958abfa0af8830))
* **java:** give an unreadable receipt certificate one verdict ([a2bac88](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/a2bac886ad65211c08f6b4b232888db6f375712f))
* **java:** keep the raw cause chain out of failureCause ([6150da0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/6150da041a26f7cd063236e107c0f7cda6bb4165))
* **java:** keep the verification exception as the endpoint failure cause ([7e96cca](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7e96cca211284d8c2922c76339b4825562044f87))
* **java:** map verifyRaw claim conversion failures to INTERNAL_ERROR ([2334793](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/233479360c42c2ad43ed14476feeeb4f6b6c6f37))
* **java:** replace C1 controls and Unicode line separators in messages ([9972f25](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9972f25bde29e351d7f788a55868607681eb03ed))
* **java:** report an unreadable bundled root as IllegalStateException ([099f164](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/099f164c2beb823ee1eb0ff964e37231e9304d31))
* **java:** run all cryptography on the pinned BouncyCastle provider ([dae21b2](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/dae21b29c441722a71153ca9cf064ca16c016758))
* **java:** sanitize third-party exception text in verification messages ([e3785f9](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/e3785f9d0e1dac27b1e21892c05911a8a410d0e8))
* **node:** answer INTERNAL_ERROR for a signed claim of the wrong type ([6f851e3](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/6f851e3c66550bd8dafb6c3b9638c381e10c55b6))
* **node:** answer INTERNAL_ERROR when the runtime lacks a digest ([37406ff](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/37406ffbeef7d2d1555c1703dc078cee059ae475))
* **node:** cap receipt, request and JWS size before decoding ([3ab44fe](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/3ab44fea102c5eb811d627fb5183f4be7d1ffd0d))
* **node:** format Pacific-time dates without Intl time-zone data ([60cde45](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/60cde45b131c917b7d314063a08bda933e7ea53c))
* **php:** answer INTERNAL_ERROR for a signed claim of the wrong type ([fbc4265](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/fbc426533b8ef8b0270303ff5b4264635295f2bf))
* **php:** give PHP 8.1 the memory its packed arrays need at the body cap ([4fa8c1c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/4fa8c1c6c4a15afbc1a7ea6acf92b11ea9c99acf))
* **php:** raise the DER byte budget so a 3 MiB receipt is parsed ([25d31f5](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/25d31f52e955f815530bd11e04d554b6915e782e))
* **python:** answer INTERNAL_ERROR for a signed claim of the wrong type ([14f1081](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/14f1081c18c8c017c637eb25095d99897138cad5))
* **python:** answer INTERNAL_ERROR when the runtime lacks a digest ([2c5d9be](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/2c5d9be83e4c18d2369b0dbc5b77cf17d32d0480))
* **python:** cap JWS size and depth before decoding ([992b8d6](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/992b8d6bc83d7266bc51e5230a3132a1f4d923a5))
* **python:** cap receipt and request size before decoding ([04bfc8d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/04bfc8d65801a1642c3fc79688b382d40e98d182))
* **repo:** accept receipt base64 exactly as Apple's verifyReceipt does ([5ce3d14](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/5ce3d14b7e00370dd903d44876c4f281fdd22df3))
* **repo:** record the new digest of the public receipts README ([d5270ff](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d5270ff1c220521e6b6ae882b8eb6ad40d7cdcd5))
* **repo:** reject x5c entries with non-base64 characters in every port ([3d85379](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/3d85379b616f739e2d52abb0602676f484228ecc))
* **ruby:** answer INTERNAL_ERROR for a signed claim of the wrong type ([fe1c71c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/fe1c71c6571d191cb6287df805226012f1533cff))
* **ruby:** answer INTERNAL_ERROR when the runtime lacks a digest ([07df631](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/07df631248c3bbacfd263d230c88c2102df84a45))
* **ruby:** cap receipt, request and JWS size before decoding ([d0b1821](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d0b182164337694a425d4f1f783ed0736211031b))
* **rust:** answer INTERNAL_ERROR for a signed claim of the wrong type ([ed1e661](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/ed1e6613bb6ac798ea652c3e050d9ca62f597dcd))
* **rust:** cap receipt, request and JWS size before decoding ([f9f4823](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/f9f4823aa39c08af192f27c597c96b7d48123cf2))
* **swift:** answer INTERNAL_ERROR for a signed claim of the wrong type ([403680c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/403680c5c85214a3437b9a51f4d91907029d9b8d))
* **swift:** avoid miscompiled throw path in receipt signer lookup ([85add14](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/85add14878c84ac58b279dd927d0ed07a034e26c))
* **swift:** cap receipt, request and JWS size before decoding ([f04c5d7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/f04c5d7ba26f714fcdb3d0d1ebfe61c84ad25a5b))
* **swift:** keep a leading byte-order mark in a parsed request body ([92ccbc7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/92ccbc7787b53da7b836d9b508a8e5b1ad2cc999))


### Performance

* **dotnet:** decode clean base64 receipts on a strict fast path ([c972c8b](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/c972c8b4bbdc7feb973cd9b740041964340ff9a7))
* **dotnet:** stop re-decoding certificates on every receipt ([40b44a8](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/40b44a8064922382cabc47d706317cd826612dad))
* **go:** decode clean base64 receipts on a strict fast path ([8045090](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8045090e375942fd9c6bcea9e0183b5594fb6366))
* **java:** build the endpoint's trust anchors once ([9d1197a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9d1197a496e199bde7b203d1e2df9290b907a63c))
* **java:** convert the receipt signer certificate to JCA once ([7cec594](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7cec59405c7c28d8646cddc54cffcedd1f66967c))
* **java:** decode clean base64 receipts on the JDK fast path ([f082220](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/f0822209986d432526781972961323eee278d5bf))
* **java:** load and pin the bundled Apple roots once ([fed3998](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/fed3998b0a815a3556f9dffe83acc1ae5ad3e96f))
* **java:** parse each receipt once, without a lock per byte ([bb4513e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/bb4513e4f44a670e810cf175bdf383eea6489145))
* **java:** read large endpoint request bodies from one buffer ([8c25c32](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8c25c32511238afc7625d8ea5055fa8e2af765a8))
* **java:** read plain-DER receipt attribute sets without BouncyCastle ([7359c71](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7359c71352ad8cbf84ff989c165085afe1670778))
* **java:** read receipt dates without the ISO_INSTANT parser ([26dd257](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/26dd2577ddd3b63902ba28adbfbcdd11d6a19f8d))
* **java:** read short receipt strings and integers without a parser ([5f0d797](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/5f0d7976a7ecd2c3d523c366242cdff836f198be))
* **java:** render response dates without DateTimeFormatter ([c8de9b4](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/c8de9b4c204b2031deb43c8279a0f2cbee893d31))
* **java:** stop rebuilding CMS algorithm tables for every receipt ([17bc8f1](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/17bc8f102963c151eb5fd6e133a18c43ac714edd))
* **node:** decode clean base64 receipts on a strict fast path ([917ce8e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/917ce8e6c56a6dce375440f1638997d4b000b710))
* **php:** decode clean base64 receipts on a strict fast path ([60b6dd5](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/60b6dd525a093aabc9b922babfcc5c7885fe680b))
* **python:** decode clean base64 receipts on a strict fast path ([3a557e8](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/3a557e8c5f0ae9fe63b79ded202694546bb83100))
* **ruby:** decode clean base64 receipts on a strict fast path ([4d60df9](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/4d60df9ae849164bd8919952f3228e40ac74a43a))
* **rust:** decode clean base64 receipts on a strict fast path ([1c38361](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/1c3836154e434a577df57b8be0bca1b1820cc949))
* **rust:** restore rsa u64_digit so RSA verify uses 64-bit limbs ([9da47c1](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9da47c168ecdf922edb49088414aacfda6a042fe))
* **swift:** decode clean base64 receipts on a strict fast path ([2afcd25](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/2afcd2555b90dda39efd98737d9768ede2df6569))
* **swift:** parse canonical receipt dates with ISO8601FormatStyle ([b574901](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b574901d3b7d4c6df2aa96b1330a2147fd0d7449))
* **swift:** render response dates with shared VerbatimFormatStyles ([cf2340f](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/cf2340f1444bf1febe33dd7d1f0a005d7f9800e6))
* **swift:** stop building a date formatter for every receipt date ([ca518cd](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/ca518cddf517383279aa29019d4392fadb79be85))
* **swift:** write the verifyReceipt answer with JSONEncoder ([6526c84](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/6526c84cd3d6d9c28951b57a0c5fd75d7f667346))
* **swift:** write the verifyReceipt answer without JSONSerialization ([cec80fd](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/cec80fdc48cb9e738fe001025f6d0cb47cb5cbb2))


### Build & Dependencies

* **dotnet:** restore the lockfiles a local SDK rewrote ([68883c6](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/68883c6cac23c4e50f5cbe18f218c52c305fd163))


### Reverts

* **java:** drop the hand-written receipt parsers, keep BouncyCastle ([8d7c870](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8d7c8703000f5cf7a9ce99a94606063b9a8b3bbc))
* **swift:** drop the hand-written date parser and JSON writer ([3fcaa0c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/3fcaa0cc87a600b3c3e9f7e5ad2335c07cb7ce29))

## [0.5.1](https://github.com/emindeniz99/apple-purchase-receipt-verifier/compare/v0.5.0...v0.5.1) (2026-09-22)


### Build & Dependencies

* **rust:** bring the ffi lockfile in step with the 0.5.0 crate version ([654ccd4](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/654ccd4aa69780974409347f18b4e5b6b3217887))

## [0.5.0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/compare/v0.4.0...v0.5.0) (2026-09-22)


### ⚠ BREAKING CHANGES

* **rust:** building the crates needs Rust 1.85.0 or newer.
* **python:** the package no longer installs on Python 3.9. Stay on the last release that carried requires-python >= 3.9 if you need it.

### Features

* **dotnet:** model receipt attribute types 1, 15, 16 and 1713 ([7e3881c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7e3881c5085808b8b5e3d4fa44ad93dfe7901cbb))
* **go:** model receipt attribute types 1, 15, 16 and 1713 ([29e4e2c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/29e4e2c603d9bc26103d5d59e9dbe5142b1e4662))
* **java:** JSpecify nullness annotations on the public API ([05b7738](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/05b7738b2d23b17d654f80d764244bc0e6eb4917))
* **java:** model receipt attribute types 1, 15, 16 and 1713 ([88078ea](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/88078ea15d05e5b74b45de44644bd26d759c5437))
* **node:** model receipt attribute types 1, 15, 16 and 1713 ([9b364cb](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9b364cb0524805e6e9ca4492be7cefb0ac8f9d88))
* **php:** install from the repository root so Packagist can see the package ([c7fd7ed](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/c7fd7edf0b29253004fc52f13bbe4c465d38ad16))
* **php:** model receipt attribute types 1, 15, 16 and 1713 ([4e33d6d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/4e33d6defe937c58ea97ee369a3facc65280ce1b))
* **php:** publish the PHP port through a root composer.json (Packagist layout A) ([fee091c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/fee091c49206ee2cc02751db2dc23f147c81b5eb))
* **python:** model receipt attribute types 1, 15, 16 and 1713 ([a2d036d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/a2d036dd208a4f9b98935883063fe1b915b90e25))
* **python:** raise the floor to Python 3.10 ([8cfdeca](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8cfdeca4553854e254d8bbd7ffa8f102f0dbde68))
* **ruby:** model receipt attribute types 1, 15, 16 and 1713 ([5677c2f](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/5677c2fa3e2fb04b0167f982fb479d3b0317c23d))
* **ruby:** type the internals so steep check passes ([41ea944](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/41ea9442bcb434ae90d45fde01a58bacb39e9d44))
* **rust:** add a clock to the C ABI and raise the Elixir example to 1.18 ([dc00bb2](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/dc00bb2f72d0ec29a895d8f69fad4836d7d116dc))
* **rust:** add Elixir and Python examples over the C ABI ([6eb7c1a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/6eb7c1ae7fa1d19344528492ad736ed4a49348c5))
* **rust:** expose the verifier through a C ABI ([7c29885](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7c298856a9766e51e571950d81d660b23706cd09))
* **rust:** model receipt attribute types 1, 15, 16 and 1713 ([80483b0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/80483b0645f5e7b33b40d1126c002b654fa95fbe))
* **rust:** raise the floor to Rust 1.85 ([a52c00c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/a52c00ce76be9c071febc8c1e156acdc1b3a0c10))
* **swift:** model receipt attribute types 1, 15, 16 and 1713 ([8b94d00](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8b94d0075c4d258194a27a06f3b2fb9e8e5140b5))


### Bug Fixes

* **java:** declare serialVersionUID and null-mark the internal package ([fa2712e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/fa2712e72deaf461eefb6f55cace35017fe65383))
* **node:** refuse a non-numeric FASTLY_SMOKE_PORT in the Fastly smoke ([a00800c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/a00800c84b5b3380a6ecb2275c00d806aa8b62e0))
* **node:** unwrap PEM trust roots without a polynomial regex ([77f9b52](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/77f9b525a9806a7d382bc34445abefc222bb37e7))
* **repo:** keep integers above 2^53 exact in the cases manifest ([baf255a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/baf255af04e37c90c8da9541870926264075a7d9))
* **repo:** resolve the receipt signer by identity in every port ([d160f48](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d160f4803c121f1395fe5da1fbd1d524cae1be68))
* **repo:** resolve the receipt signer by identity in every port ([a96c1b1](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/a96c1b1d65a45f7db574deebc338258e78d55a7f))
* **swift:** name the fuzz manifest's path dependency for Dependabot ([a6a8ab7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/a6a8ab780dbb85b9bec81c3f98298130076008d9))


### Build & Dependencies

* **deps-dev:** Bump @fastly/js-compute from 3.45.0 to 3.45.1 in /node ([85293c1](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/85293c1d8991528a776e90051a483812d65c28c1))
* **deps-dev:** Bump @fastly/js-compute from 3.45.1 to 3.46.0 in /node ([8ef5ca9](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8ef5ca9a5f566b99a44a2ccf02818595291915a9))
* **deps-dev:** Bump com.diffplug.spotless:spotless-maven-plugin ([b883501](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b8835019c9260d17658a3c65297f5579dde1db95))
* **deps-dev:** Bump friendsofphp/php-cs-fixer in /php ([b3e3bee](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b3e3bee8b24db6c336f8a4ab7e693072ccf55470))
* **deps-dev:** Bump kotlin.version in /jvm-interop ([c82ccae](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/c82ccaef79365a1b3c4e8b7ed3703a2300550d88))
* **deps-dev:** Bump org.apache.maven.plugins:maven-compiler-plugin ([8fe28b4](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8fe28b4bb43843ba7495b28edaf091e3e5a1c1a2))
* **deps-dev:** Bump org.apache.maven.plugins:maven-compiler-plugin ([869082b](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/869082bc115d504b1e6f8b1bb44c2e3be5379fb4))
* **deps-dev:** Bump org.apache.maven.plugins:maven-jar-plugin in /java ([1e3d20a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/1e3d20acdcad26339f5cf89e9aec4392fe448e70))
* **deps-dev:** Bump org.apache.maven.plugins:maven-surefire-plugin ([8083e7d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8083e7d034e3cbf98f8475f2f9fb9e43074c30c6))
* **deps-dev:** Bump oxlint from 1.81.0 to 1.82.0 in /node ([1b2d941](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/1b2d941b84834c814565f910aa855e4ff1a4539e))
* **deps-dev:** Bump oxlint from 1.82.0 to 1.83.0 in /node ([aaf6f24](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/aaf6f247f7a8082f1d7104fec122320042842eba))
* **deps-dev:** Bump phpstan/phpstan from 2.2.13 to 2.2.14 in /php ([64bf48f](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/64bf48fb80d9aa0f92d728eb69f1e4f390c47045))
* **deps:** Bump actions/setup-java from 6.0.0 to 6.0.1 ([b7901b6](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b7901b6c4af0db6bd725f41d469fdb863131ffb8))
* **deps:** Bump astral-sh/setup-uv from 10.0.1 to 10.1.0 ([5369f25](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/5369f25daea4726ad6d7db0b2e4486b2b0ea0c9e))
* **deps:** Bump github.com/apple/swift-asn1 from 1.7.1 to 1.7.2 ([b87b0b3](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b87b0b37202a16b6520595fbb5973814d875c8f5))
* **deps:** Bump github.com/apple/swift-certificates ([3a6b600](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/3a6b600225e5d5ee7c4dfe05b89d4f9c15403882))
* **deps:** Bump github.com/apple/swift-crypto from 4.5.1 to 4.5.2 ([5832839](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/5832839bf636afda00c101ecdd65f9e464fed859))
* **deps:** Bump golang.org/x/vuln from 1.7.0 to 1.8.0 in /go/tools ([e714746](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/e7147461303f1a8ecf04b5461b0b3b9bbaa70629))
* **deps:** Bump org.apache.maven.plugins:maven-surefire-plugin ([21b8b0e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/21b8b0e4ae5b8b103c42fb49dd50a60cde8487f4))
* **deps:** Bump org.bouncycastle:bcpkix-jdk18on in /java ([4ebca87](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/4ebca87c116bb47fe74adbd1d422b7f723ba9d25))
* **deps:** Bump ruby/setup-ruby from 1.321.0 to 1.322.0 ([6a40207](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/6a402072f8a5d8a128b4035c77781b65b3d8d1fe))
* **deps:** Bump ruff from 0.16.6 to 0.16.7 in /python ([93d6565](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/93d656546148666bdd2e8bb74d0302df6687786a))
* **dotnet:** bump System.Formats.Asn1, Pkcs and xunit.v3 patch releases ([de75452](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/de75452af6962e642caeffc267758fd239984e6e))
* **dotnet:** regenerate lock files for the September SDK patches ([acbb40b](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/acbb40beafb6158826bc0490bba230ecab9525c5))
* **dotnet:** regenerate the fuzz project's lock file as well ([c5b4037](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/c5b4037b5780a51dfba5dd317db9140b88b077cf))
* **dotnet:** regenerate the library project's lock file as well ([166c6da](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/166c6da6f3849c4c114b080587e6141f48bca693))
* **go/tools:** refresh the transitive requirements of the tool module ([0005e9d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/0005e9d30aec5ef334ddf0563a631cfe2fa8bfe0))
* **java:** make the build reproducible and attach a CycloneDX SBOM ([c0af613](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/c0af613b626e8ab8952aa8401882451cf057f2a8))
* **node:** override weval to 0.5 so decompress leaves the dev tree ([65d20f3](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/65d20f348d701bfa8281b99aa1168247d883afb5))
* **python:** keep ast-serialize 0.11.2 after merging main ([329b055](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/329b055af2b44e8c5c48e1a696497697c9e185e8))
* **python:** refresh ast-serialize in uv.lock ([bbb177e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/bbb177e9b5fee640c2ce5030ba5ec0ed394b3f98))
* **ruby:** refresh the tools gemfile lock ([dcf6e94](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/dcf6e94a75fff489d14142db1313b410cfc08e98))
* **rust:** redo the lock refresh with the MSRV-aware resolver ([09d4816](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/09d4816ffd1f4523cfb272fa17d6baaf6cb3dc66))
* **rust:** refresh the three lockfiles within their compatible ranges ([ab5c5fc](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/ab5c5fc8c1ec81abfbbebffc3ba9a69822b9062e))

## [0.4.0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/compare/v0.3.0...v0.4.0) (2026-09-06)


### Features

* **dotnet:** add the C# port ([344a611](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/344a61172be2f30717c9b510692e1be075a11cf9))
* **fixtures:** make cases.json the normative cross-language contract ([afff3e0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/afff3e005e89fa31ec86ee4f4986b75f395c9580))
* **go:** add the Go port ([4e9fa65](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/4e9fa6522cb455bd0c9b1e6ae073ebc81e2c489b))
* **java:** make the verifiers' notion of now injectable ([beaf62d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/beaf62d447ccb747b217ef0248ad349296284970))
* **node:** add a WebCrypto entry point for edge runtimes ([d49eef0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d49eef0a3dccd5d2431c82eab16a26952b3b04a4))
* **node:** make the verifiers' notion of now injectable ([af20123](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/af20123ac7053712c34e14133d19f2ead81dde8b))
* **php:** add the PHP port ([e0f3ac0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/e0f3ac0bc9e84b6a8c380e49d063271fb80ed3ae))
* **python:** make the verifiers' notion of now injectable ([891e448](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/891e448bbbe91c36aef1047ee29fac947bd032b7))
* **ruby:** add the Ruby port ([3f49798](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/3f497980eee9d2d1ae55819e036d5b778accbe66))
* **rust:** add the Rust port ([9eae263](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9eae2637853f9ab0a48ff67dcf2e3f991cd3d3de))
* **swift:** make the verifiers' notion of now injectable ([5f27e5c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/5f27e5ce3c0cc5d2c7f93b6a6ea7385f7b1f3b1d))


### Bug Fixes

* **dotnet:** judge the receipt signer certificate before the platform CMS decoder ([4fac89b](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/4fac89ba3615812fe7203e67bc17529f13a6a5ce))
* **dotnet:** parse x5c[2], and read the receipt signer strictly ([65f228d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/65f228d459779f560ab4bfb6b44e5e08848f31b6))
* **dotnet:** read a whole extnValue, and let a readable non-RSA signer key be a signature verdict ([ba38caf](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/ba38caf3876bd9282300f7aa09f183e7304ed935))
* **dotnet:** refuse an x5c certificate carrying one extension twice ([a967de9](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/a967de9a5f02987610c9f89efb39ba23959d1032))
* **dotnet:** type the x5c entries and refuse a certificate it cannot read ([691e400](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/691e400578c943692051370672873b15d21ed57f))
* **go:** match the malformed entry's identity before blaming it ([ce05086](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/ce05086a8accdffce262660e46aca2bb5b7260b6))
* **go:** parse x5c[2], and name the signer before blaming the receipt ([7534f82](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7534f822dbea5337e5e6b67e772e521a667fbe5b))
* **go:** read a date claim's value, not the spelling of its literal ([be76865](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/be76865ea5056a9a7165f072d610d907c22c49c0))
* **go:** refuse a signing date that does not fit an int64 ([1350509](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/135050910990b6415cd176683fcfb82f481a331b))
* **go:** scope the system-trust premise to where a root can be planted ([a01168a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/a01168afc209a57367b57d4c4384aeb18c11dc7e))
* **java:** bound input size and JSON depth, sanitize echoed input ([4baf249](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/4baf249dd4df7b2e23b87fde72824f6a5437a27c))
* **java:** pin the bundled Apple roots by fingerprint ([54f72eb](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/54f72eb870a139508df8ff222ad972c352c81809))
* **java:** production-readiness findings and a Spring Boot smoke matrix ([7287a42](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7287a429e4fd91e9cfe38f8ff0866120123cdf9b))
* **java:** reject an empty or non-object JWS segment instead of throwing NPE ([d930be4](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d930be467fe4f1667ad8472ae1b75b0ef5c85c2e))
* **java:** report a defective receipt signer as a certificate defect ([30067ef](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/30067efae4450e603ffb9443355853cd004b1ca0))
* **java:** require the JWS header and payload to be JSON objects ([b59f02e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b59f02e3c101a68c8a7eaa05d17404006c141c39))
* **java:** state the chain length bound and count self-issued intermediates ([ea06db7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/ea06db7a2b4b3571b1cf6e65c0eaad23b4cb293e))
* **java:** type the x5c entries and refuse an unrepresentable signing date ([6d6d707](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/6d6d707ea4f22bea52814c2136b51e4c9bb4bde5))
* **node:** import certificate keys as JWK so the web build works on Fastly ([15c1193](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/15c1193a546c201a8e49a65bfce737ceaf029a25))
* **node:** inline the Apple roots so bundled runtimes can use them ([82c0cb6](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/82c0cb68579cc6db72b41d5dd2f464d53fbe9317))
* **node:** parse x5c[2], and read the receipt signer strictly ([c9ef2ec](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/c9ef2ec19111471db3e2df72981f0c69ed6f9dd5))
* **node:** pass the ES256 key to verify() as SPKI DER so workerd accepts it ([7246a4a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7246a4a273dfca3ce055516ee07929076dee0e75))
* **node:** refuse an x5c certificate carrying one extension twice ([d436a87](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d436a87ec2f3aee4b55b0c80d77b9739436f259b))
* **node:** reject an x5c certificate whose version or key it cannot read ([9b2cf72](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9b2cf72450d6519a6a27e81af99eab5cc104dee8))
* **node:** scope the web build's key check to the keys it builds ([47fb817](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/47fb81781e2be179f010d9f04a4102d021ac6556))
* **php:** make the committed cs-fixer config actually runnable ([23c2747](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/23c27475b7bcccb45203708eaf392dc62d030d1f))
* **php:** parse x5c[2], and blame the signer rather than the receipt ([3109113](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/3109113cc88dc85f44d994933ecae51c37ece74a))
* **php:** refuse an unrepresentable signing date and an unusable x5c key ([88baee1](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/88baee106147e306faa84d05749d4ba833cb2e27))
* **php:** refuse an x5c certificate carrying one extension twice ([5d27341](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/5d27341828c358bbb523b94ba6588c81d1e9f0e6))
* **php:** tighten the types the static analysis found loose ([fa63277](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/fa6327744423606e0ca7c53881a8043e865d5611))
* **python:** answer INVALID_CERTIFICATE for an unusable x5c public key ([8ce9ea2](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8ce9ea2fa13d7eeb66000954660a2ec9786a5a75))
* **python:** parse x5c[2], and read the receipt signer strictly ([bf24985](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/bf24985e6fdcaacfe2cb30eb68a25c3423c907c9))
* **python:** report a duplicate extension as a verdict, not a crash ([9cdf966](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9cdf96624de6b60bb892ac71002d5681249a94c5))
* **python:** turn five JWS-path exception escapes into typed verdicts ([84cfefd](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/84cfefd581d93db354bdc1e24a826baf03a8d014))
* **release:** bump jvm-interop's library version with every other manifest ([7234614](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7234614273cb2bdf07b975a71711dc0001a88e66))
* **repo:** accept receipt base64 padding only when omitted or canonical ([d0d80b3](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d0d80b39bd1b76a0408dd68f4ed31d27d3836de4))
* **repo:** check every copy of the Apple roots against certs/ ([774f8c5](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/774f8c58ff86675247c9825297224b27692ec3b8))
* **repo:** decode compact-JWS segments strictly in every port ([935f62d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/935f62d2b561ed7592095fdd7096b00c69da7fe4))
* **repo:** decode receipt base64 by Apple's rule, identically in every port ([1360a4e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/1360a4ed0d7b06b310a4bc6805cdd86da31110a8))
* **repo:** reconcile four places where the ports already disagreed ([141387b](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/141387b04f69bb9a7cffb80444eb395ef5c3abba))
* **repo:** stop git rewriting fixture bytes on a Windows checkout ([407d785](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/407d785a60334b044287a83a410116a54ce6a86e))
* **repo:** test the impossible base64 length on the data, not the padded string ([b8a6693](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b8a66932136931c729f8b83349898f51d245a07e))
* **ruby:** keep RuboCop's default excludes so a vendored bundle is not linted ([0d8afd5](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/0d8afd5fa4541ba8bf237aa8fccba49ce511d127))
* **ruby:** parse x5c[2], and read the receipt signer strictly ([0d8d4d5](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/0d8d4d5950c33bb5fbe8682354f9c6225576ab67))
* **ruby:** refuse an x5c certificate carrying one extension twice ([bf080e3](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/bf080e35e6dd61a1a22e21263d9152c18be4a037))
* **ruby:** reject an x5c certificate whose version or key it cannot read ([34abadd](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/34abadd5b200ccf321aa36e2abbc0595813a8595))
* **ruby:** repair three defects the tools job exposed on its first run ([251d101](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/251d1011704568e316e3e216b9b8ef44d009fc80))
* **rust:** keep whitespace in fuzz seed paths ([3a0a520](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/3a0a5206dab1eb1c55f83c9c603d6f3393617d3f))
* **rust:** parse x5c[2], and blame the signer rather than the receipt ([134dc5d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/134dc5d37bb4f3a72b371e346c8d67cfcff41052))
* **rust:** refuse an unrepresentable signing date and an unusable x5c key ([dea396a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/dea396aa6e979ed85ba6307a4ecd96e94c9462ac))
* **rust:** refuse an x5c certificate carrying one extension twice ([2dd1dd3](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/2dd1dd3a6c67352a7cc9a53c4bfc1f0fd1ba11a3))
* **swift:** apply the embedded-certificate bound before decoding ([7c6c20c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7c6c20cb10f1a272f834c579b83f0ef5f8244284))
* **swift:** call an unrepresentable signing date a chain failure ([33bb146](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/33bb1462eb3d9991bec8f90289ee0c04af99a9b6))
* **swift:** fail the validation-time range guard closed on a NaN instant ([5666056](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/56660560b7ce452b0d92d563ed394f75f363851f))
* **swift:** parse x5c[2], and read the receipt signer strictly ([7f62031](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7f620313d6929a83935a263d4362db4f5d77843f))
* **swift:** read a certificate's identity through a throwing accessor, not a subscript ([1c3e1d8](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/1c3e1d8d27b76ca2c9d9df4682ba1416cfa77750))
* **swift:** read a certificate's identity through a throwing accessor, not a subscript ([eaaecdf](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/eaaecdf7b64b8c116238a1128a4f0d82255f272a))
* **swift:** require the JWS payload to be a JSON object ([adebba2](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/adebba233f64e9bda56060d30d5c26a1b840c37b))


### Performance

* **node:** run the two TypeScript passes at once ([9003c09](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9003c093874b16db7d7cc6f383f0ae90aed15d86))


### Build & Dependencies

* **deps-dev:** Bump kotlin.version from 2.0.21 to 2.4.10 in /jvm-interop ([a34ce1e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/a34ce1efcb83e220411bc3c69ff25af6efe38df9))
* **deps-dev:** Bump kotlin.version in /jvm-interop ([0ddbb56](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/0ddbb56dfae4650929a3bde09dfde79b6a72ab8a))
* **deps-dev:** Bump net.alchim31.maven:scala-maven-plugin ([1af0113](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/1af0113b9120f99eec656dc0a8a8bca2da8ea64f))
* **deps-dev:** Bump net.alchim31.maven:scala-maven-plugin from 4.9.2 to 4.9.10 in /jvm-interop ([5772a87](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/5772a87b207602467c3a7f7a2cbd302063faacc3))
* **deps-dev:** Bump org.junit.jupiter:junit-jupiter from 5.14.4 to 6.1.3 in /jvm-interop ([bf43327](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/bf433276b880410f150f7860516654118dc38a18))
* **deps-dev:** Bump org.junit.jupiter:junit-jupiter in /jvm-interop ([20e95d7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/20e95d7302742953ef2f054dfed5cd36fd046064))
* **deps-dev:** Bump org.scala-lang:scala3-library_3 from 3.3.4 to 3.9.0 in /jvm-interop ([7667e87](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7667e876ab9a986b441548c22274df86fa1ba3de))
* **deps-dev:** Bump org.scala-lang:scala3-library_3 in /jvm-interop ([c7a0db3](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/c7a0db3fa183e3baed3ee8759bb415c2dfff5052))
* **deps:** Bump actions/setup-go from 6.5.0 to 7.0.0 ([af0673a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/af0673afefda6cc7a089330bb8f00b67b435a423))
* **deps:** Bump actions/setup-go from 6.5.0 to 7.0.0 ([0bb7937](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/0bb79377aef2372109533c9a728cc282d3932779))
* **dotnet:** enable NuGet lock files and locked restore in CI ([1b61d96](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/1b61d96fb34c505b0808687952f52378ad4b71f9))
* **dotnet:** keep the VSTest bridge for SDKs before 10 ([2a20ded](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/2a20ded9db5790573ede4604ccbc66c0c2e93f12))
* **dotnet:** move dotnet test to Microsoft.Testing.Platform for xunit.v3 4.0 ([f1b5b89](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/f1b5b89c901204489b2536075f70fb5f4169855b))
* **java:** emit parameter names in the published jar ([59e0d61](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/59e0d615d374ab26c850b14fb0f0d66453d9536c))
* **java:** set Automatic-Module-Name and Implementation-Version ([2714d62](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/2714d62aff39fc3e20ce67726d90c943b9ee0804))
* **php:** commit composer.lock resolved for the 8.1 floor ([4362430](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/4362430c11af6048a10ee0fa47f7043fb69b36a1))
* **php:** regenerate composer.lock from packagist only ([bc3e4b7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/bc3e4b797a2a0711cdaff146a7f3e6edd74da159))
* **python:** commit uv.lock so the matrix installs a pinned set ([caab8a4](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/caab8a441f772d041c200fa15a73a967cb7f3594))
* **release:** publish the four new packages, and say what only you can do ([1241d8b](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/1241d8bb93f2391ac2f037d38604e9a45c87ab6c))
* **repo:** commit lockfiles in every port and install from them in CI ([cfaaf56](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/cfaaf565e638ac6cb950c85a44f3617ddfe2dc00))
* **ruby:** commit the three bundler lockfiles and drop gemspec from the Gemfile ([7811000](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7811000618fcc97c55ac632de85045f320f958f8))
* **rust:** commit Cargo.lock and build every leg with --locked ([2a65036](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/2a65036f6a3ee8382049d9918435f7ce558576d0))

## [0.3.0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/compare/v0.2.2...v0.3.0) (2026-09-02)


### Features

* **endpoint:** accept and answer the raw verifyReceipt JSON body ([d6e2853](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d6e2853555c78180ae58bd140d9e8497ca2fddc2))


### Bug Fixes

* **endpoint:** correct the wire-contract account and close two parity gaps ([88857f9](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/88857f91b2a13c5bfea687f2ee5cd7e6b1796475))

## [0.2.2](https://github.com/emindeniz99/apple-purchase-receipt-verifier/compare/v0.2.1...v0.2.2) (2026-09-01)


### Build & Dependencies

* **deps:** Bump github.com/apple/swift-asn1 from 1.6.0 to 1.7.1 ([b9c1ace](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b9c1acefc74b2b2e9baf5f22d570d5bd5872de7d))
* **deps:** Bump github.com/apple/swift-asn1 from 1.6.0 to 1.7.1 ([8d65812](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8d65812ea257f77d7d738aceb88d9b2754df6fd3))
* **deps:** Bump github.com/apple/swift-certificates ([23a2e52](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/23a2e526fdb0efbce01b742cfc81a06747a5639d))
* **deps:** Bump github.com/apple/swift-certificates from 1.18.0 to 1.19.4 ([37ff90c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/37ff90c8cfb0c155b2a6b36074e96ae071680055))

## [0.2.1](https://github.com/emindeniz99/apple-purchase-receipt-verifier/compare/v0.2.0...v0.2.1) (2026-09-01)


### Bug Fixes

* **ci:** fail the root watch with a diagnosis when the PKI page changes shape ([3fc8674](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/3fc86741f238dd1c5b0a6626b66bf54b8e8e8dc1))
* **ci:** scope the new-root check to the PKI page's root section ([c56496e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/c56496e5eceeecbdcbc402ea33194d898afa4105))
* **receipt:** cap embedded certificates and bound attribute integers ([8b954df](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8b954df5c80b530749d787f0d2e91de82e0874a0))
* **receipt:** contain a receipt date that overflows epoch millis ([d88d98d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d88d98dec469cb20e5c4c84e35222691b6b5d156))
* **receipt:** keep hostile input behind the declared exception type ([b626782](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b6267826a5a5963ca6c913d7cbc74d665b4fa022))
* **release:** build node before publishing so the tarball has code in it ([61bee39](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/61bee399e806957c7eef2427e3da818daee21467))
* **swift:** stop a single receipt byte from killing the process ([feb8acd](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/feb8acdb68b63b365cdff74e82e0e4f98f6dda52))
* **swift:** walk one signature-selected path instead of searching the bag ([4ba160a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/4ba160a7af612c444f6ee1d4012004bb4c27c798))


### Build & Dependencies

* **deps:** Bump actions/setup-java from 5.7.0 to 6.0.0 ([33aab6d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/33aab6dc85be187087296d398d7803d3b4f22503))
* **deps:** Bump actions/setup-java from 5.7.0 to 6.0.0 ([d2766d7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/d2766d79a64e673a67143a220812203f2156814d))
* **deps:** Bump com.fasterxml.jackson.core:jackson-databind from 2.22.1 to 2.22.2 in /java ([b0fc796](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b0fc79662edab85e9339a77495857857ef3aeea1))
* **deps:** Bump com.fasterxml.jackson.core:jackson-databind in /java ([18ce6bc](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/18ce6bc9f58bdb2b2b2a0462844b1d3afd542d85))
* **swift:** require Swift 6.1, which the swift-crypto fix pulls in ([ea62fad](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/ea62fad5fadfd1c5c6b6f433f587271bea3b6c4a))

## [0.2.0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/compare/v0.1.1...v0.2.0) (2026-08-15)


### Features

* **certs:** pin all three published Apple roots, adding Apple Root CA - G2 ([00e191b](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/00e191ba5623b0b91622778ffc330f06298685d0))


### Bug Fixes

* **ci:** detect newly published Apple roots, not just pinned-cert changes ([715f473](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/715f47345d011eed10c941791d0c91bcb2f84acf))

## [0.1.1](https://github.com/emindeniz99/apple-purchase-receipt-verifier/compare/v0.1.0...v0.1.1) (2026-08-15)


### chore

* cut the 0.1.1 dependency and packaging release ([fae768f](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/fae768fef9811b189075c589894560a528095273))


### Build & Dependencies

* **deps-dev:** Bump org.apache.maven.plugins:maven-compiler-plugin ([8c14fe7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/8c14fe7b821b96f16a94b1231400066135e69d28))
* **deps-dev:** Bump org.apache.maven.plugins:maven-compiler-plugin from 3.13.0 to 3.15.0 in /java ([a3f4547](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/a3f45478d1911ebc8070ab9a08bb705275639d99))
* **deps-dev:** Bump org.apache.maven.plugins:maven-gpg-plugin from 3.2.7 to 3.2.8 in /java ([126b9b2](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/126b9b25d8f8d3827d7ee641a8085c8fdc18888d))
* **deps-dev:** Bump org.apache.maven.plugins:maven-gpg-plugin in /java ([e0bc114](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/e0bc114f94cb7f51fd168d9fbc6a5f7a5b987af9))
* **deps-dev:** Bump org.apache.maven.plugins:maven-javadoc-plugin ([b261790](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/b261790182dec1eb2fe55e20179467f8e077ed78))
* **deps-dev:** Bump org.apache.maven.plugins:maven-javadoc-plugin from 3.11.2 to 3.12.0 in /java ([bdb2077](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/bdb207741dacf267f66192939fef015754e0f0d2))
* **deps-dev:** Bump org.apache.maven.plugins:maven-source-plugin ([549e41f](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/549e41f6b5b581279d927ae6f9caa84358f2acfa))
* **deps-dev:** Bump org.apache.maven.plugins:maven-source-plugin from 3.3.1 to 3.4.0 in /java ([6f91f9d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/6f91f9d452c0963a787f04581a19ef89c131b728))
* **deps-dev:** Bump org.junit.jupiter:junit-jupiter from 5.11.4 to 5.14.4 in /java ([20dfff7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/20dfff79616d67c02fba830e780cbbbf7e9425ee))
* **deps-dev:** Bump org.junit.jupiter:junit-jupiter in /java ([2fdbe8e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/2fdbe8e68259796996c7f48ebe01bcdec37c6d18))
* **deps:** Bump com.fasterxml.jackson.core:jackson-databind from 2.18.2 to 2.22.1 in /java ([9967efd](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9967efd1de04f6ca106660635e574c5f379d6445))
* **deps:** Bump com.fasterxml.jackson.core:jackson-databind in /java ([cdb723c](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/cdb723c06bb6c6210dcd7dc367964fb5a2d45256))
* **deps:** Bump org.apache.maven.plugins:maven-surefire-plugin ([ade8f4e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/ade8f4e1236c7a77340f7a55c7768f1e50805996))
* **deps:** Bump org.apache.maven.plugins:maven-surefire-plugin from 3.5.2 to 3.5.6 in /java ([9c9460d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9c9460d25a013a2494bd37a8d6b127a7285a6ea6))
* **deps:** Bump org.bouncycastle:bcpkix-jdk18on from 1.80 to 1.85 in /java ([4518370](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/4518370dd6e4d0a383578ca8aeefc0b194cc5ebf))
* **deps:** Bump org.bouncycastle:bcpkix-jdk18on in /java ([e5c4b45](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/e5c4b453bfde1713712eab67d7c6a754771d69b2))
* **node:** type against the Node 20 engines floor, not latest Node ([7aa178e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/7aa178e87d67bc154bcb624815451ad18a34e9be))
