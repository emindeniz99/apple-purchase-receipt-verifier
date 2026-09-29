# Review log: the OpenSSL core

Status: written 2026-09-29 for the owner's one read at the final pull
request, in two rounds. Round 1 (sections 2 to 9) reviewed the OpenSSL
core; round 2 (section 10) reviewed round 1's fix commits and the ABI crate.
This log records what each review found, what was done about it, and what
nobody looked at. It works toward MIGRATION.md step 1.10, which is not
closed: section 10.9 names what still has no second reader.

The five reviews were done by agents that did not write the code. Their
findings files are not in the repository; this log is their record.
Everything each finding did to the code is in git and in the evidence note
[core review fixes](../evidence/2026-09-29-core-review-fixes.md), whose
"Round 2" section covers the second round.

## 1. The short version

- Five reviews read every line of the OpenSSL adapter, the core's policy
  layer, round 1's fix commits and the ABI crate, and tried to break them
  with crafted input. They reported 52 findings: 2 blocking, 21 fix before
  merge, 29 notes. Round 1 (three reviews, commit d5c2838) reported 34;
  round 2 (two reviews, commit c0a6e15) reported 18, none blocking.
- Nothing in memory safety, isolation or trust broke in either round. No
  double free, no per-call leak, no panic path, valgrind clean. No input
  verified without a valid signature under a pinned root, and none could move
  the instant at which the chain is judged.
- What did break in round 1 was the set of cheap checks before the full CMS
  decode. They covered less than 0.7's reader did: the certificate and
  SignerInfo bounds ran only on a well-formed `signedData`, the depth bound
  counted too little, the 100,000-node budget was gone, and some payload
  encodings changed verdict without a record. Three reviewers found the same
  gaps from three directions.
- Round 2 found that the round 1 fix was itself incomplete in three places:
  the header walk ran after a decode that still built a value per entry of
  three sets, the root-order fix still let anchor order decide two custom
  cases, and the walk checked fewer primitive rules than OpenSSL. In the ABI
  crate it found an unpinned compiler in the release build, an over-cap input
  copied whole into linear memory, and a C ABI that read C strings and
  answered in documents the wire schemas reject.
- Every blocking and fix-before-merge finding is fixed on `rust-core`, except
  that ABI-F2 (the input cap before the copy) is closed host by host in G1c
  and is not recorded here as finished. Four notes are not fixed and one is
  fixed in part, each with a reason (sections 6 and 10). The fixes are one
  `ASN1_get_object` header walk, 44 new shared cases from the two review
  rounds (377 cases in all) and nine rows in R20's divergence table.
- **Still open.** Round 1's fix commits were read in round 2. Round 2's own
  fixes and lane A3's ABI work (`c0a6e15..b863252`) have had no reader but
  their authors, and a third round is planned for them (section 10.9).

## 2. What was reviewed and how

Sections 2 to 9 describe round 1. Section 10 describes round 2, in the same
shape.

**Commit.** `lane/core` at d5c2838, lane A1's hand-back: the core moved
onto an OpenSSL 4.0.2 adapter, native build. The reviewers worked from a
read-only checkout and built copies of the tree in scratch space.

| Review | Files | Compared against |
|---|---|---|
| Adapter, Rust side | every line of `rust/openssl/src/*.rs`, `build.rs`, `envelope.c`, `payload.c` | OpenSSL 4.0.2 sources and headers: `init.c`, `tasn_dec.c`, `cms_sd.c`, `cms_lib.c`, `digest.c`, `bio_md.c`, `x509_vfy.c`, `x509_cmp.c` |
| Adapter, C templates | `payload.c`, `envelope.c`, `build.rs`, `payload.rs`, `envelope.rs`, `item.rs`, and the call sites in `cms.rs`, `receipt.rs`, `receipt_payload.rs` | OpenSSL's `tasn_dec.c` and `asn1_lib.c`, and the pre-migration reader (`rust/src/asn1.rs` at 07efdd1) |
| Core policy | every line of `rust/src` (verifier, receipt, receipt_payload, jws, path, endpoint, config, roots, base64, datetime, json, error, lib), plus the adapter code the policy relies on | the root THREAT-MODEL §3, the 0.7 API document, and three builds run on the same bytes: this branch, the pre-migration core (07efdd1) and the 0.7 Java jar |

**Method.**

1. Read every line of the assigned files. For each `unsafe` block, check the
   `// SAFETY:` claim against the OpenSSL 4 contract: ownership, lifetimes,
   null returns, the error queue, thread safety, partial failure.
2. For each policy rule, check it against the 0.7 API document and the
   fixture cases, and look for inputs that reach OpenSSL with a check
   missing or ordered after something expensive.
3. Reproduce every suspicion with crafted input in a scratch copy. A finding
   that was reproduced is CONFIRMED. One that could not be is PLAUSIBLE, with
   the reason.

**Severity.**

- Blocking: memory safety, a verdict that could flip for an Apple-signed
  input or accept an unsigned one, broken isolation, unbounded cost from a
  bounded input.
- Fix before merge: a correctness gap with an input a fixture can express,
  an undocumented behaviour change, a missing test for a THREAT-MODEL §3
  mitigation.
- Note: style, docs, a test that could be stronger.

**Where the reviewers disagreed.** The same defect got different ratings.
The certificate-bound bypass was blocking for the C-templates reviewer and
fix before merge for the other two. The policy reviewer read "a verdict that
could flip for an Apple-signed input" as bytes Apple actually sends, and
said Policy-F2, F4 and F5 would be blocking under the wider reading (any
input signed under a pinned root). The ratings below are the reviewers' own.
Since every one of these findings was fixed, the disagreement changed no
outcome.

**Reproduction.** The reviewers' probes lived in scratch copies of the tree
and their input generators are not in the repository. The fix lane rebuilt
each shape: `rust/tests/envelope_bounds.rs`, `rust/tests/hostile.rs` and the
unit tests in `rust/src/receipt_payload.rs` build the large inputs in code,
and [`gen_fixtures.py`](../evidence/2026-09-29-core-review-fixes/gen_fixtures.py)
mints the 27 shared cases. The commands that reproduce the fix lane's
measurements are in the
[evidence folder's README](../evidence/2026-09-29-core-review-fixes/README.md).

## 3. Counts

| Round | Review | Prefix | Blocking | Fix before merge | Notes | Total |
|---|---|---|---|---|---|---|
| 1 | Adapter, Rust side | `Rust-F`, `Rust-N` | 0 | 6 | 10 | 16 |
| 1 | Adapter, C templates | `C-F` | 1 | 2 | 5 | 8 |
| 1 | Core policy | `Policy-F` | 1 | 6 | 3 | 10 |
| | **Round 1** | | **2** | **14** | **18** | **34** |
| 2 | The fix commits | `Fix-F`, `Fix-N` | 0 | 3 | 4 | 7 |
| 2 | The ABI crate | `ABI-F` | 0 | 4 | 7 | 11 |
| | **Round 2** | | **0** | **7** | **11** | **18** |
| | **Both rounds** | | **2** | **21** | **29** | **52** |

Round 1 verdicts: 25 CONFIRMED, 3 PLAUSIBLE (Rust-N3, Rust-N7, Policy-F9) and 6
notes for which the review states no verdict (Rust-N4, N5, N6, N8, N9,
N10). The Rust review numbers its notes `N1` to `N10` and its other
findings `F1` to `F6`; the other two reviews number every finding `F1`
upward, whatever its severity. Round 2's verdicts are in section 10.2.

## 4. The problems behind the findings

Several findings describe one defect. Eight problems account for 21 of the
34 findings.

| Problem | Findings | Outcome |
|---|---|---|
| The certificate, SignerInfo and CRL bounds were skipped when the shallow decode refused the envelope (one trailing byte, no `signerInfos`, an `envelopedData` content type), so the full decode built every certificate's key first | C-F1, Rust-F2, Policy-F3 | Fixed |
| The ASN.1 depth bound counted only universal SEQUENCE and SET, and only inside SignerInfo values | C-F2, Rust-F3, Policy-F2 | Fixed |
| The 100,000-node budget was gone, and payload work before the signature check had no bound | Rust-F4, C-F6, Policy-F6 | Fixed |
| The eContent chunk check allowed one constructed level fewer than OpenSSL decodes, and named the wrong cause | Rust-F1, C-F4, Policy-F4 | Fixed |
| The payload joined chunks of any type and read header forms 0.7 refused | Rust-F6, C-F3, Policy-F5 | Fixed where 0.7's rule is cheap to state; the rest recorded in R20 |
| The vendored `openssl-sys` build script was never committed, so a clean checkout did not build | Rust-F5, Policy-F1 | Already fixed |
| `crls` were decoded in full and never counted | C-F5 | Fixed |
| THREAT-MODEL §3 named deleted code and stale figures | C-F7, Policy-F7, Rust-N10 | Fixed |

The first three share one repair: one `ASN1_get_object` header walk over the
whole envelope, run before `d2i_CMS_ContentInfo`, that decodes no value.
It counts every constructed value of any class (depth 32, outermost 1) and
every value (100,000), follows indefinite lengths, and hands the primitives
OpenSSL keeps whole inside an `ANY` back to OpenSSL to validate. The
envelope is first decoded shallowly, so the 10-certificate, 4-SignerInfo and
10-CRL bounds are counted before anything is decoded in full, and an
envelope the shallow decode refuses never reaches the full decode. A counter
behind `__internal::cms_full_decodes_during` pins that order. The payload
gets the same walk with 0.7's header rules.

## 5. Decisions taken

From STATUS.md "Review (step 1.10)":

1. One header walk over the envelope and the payload, carrying 0.7's depth
   and node budgets and the certificate, SignerInfo and CRL bounds, refusing
   where the shallow decode refuses.
2. Payload rules 0.7 had are restored where the walk can express them. Those
   it cannot express are recorded as R20 divergences, each with a fixture
   case or a Rust test.
3. ARCHITECTURE §9's row forbidding `ASN1_get_object` in the adapter was
   wrong as worded: A1's own `envelope.c` already used it, and every
   reviewer proposed it as the fix. The rule is now "not in `rust/src`; in
   the adapter only inside the documented header walk", enforced by rule 6 of
   `tools/check-layering.mjs`.
4. The findings files become this log, with each finding's disposition.

The R20 rows this produced are in
[DECISIONS.md](DECISIONS.md) (R20, "Recorded divergences from the core
review"). Four are inputs where Java answers differently from the core:

| Input | Core | Java |
|---|---|---|
| eContent as an `OCTET STRING` of seven or more constructed levels | `MALFORMED` | verifies |
| A payload attribute value of seven or more constructed levels | `UNREADABLE_PAYLOAD` | verifies |
| Eleven CRLs | `MALFORMED` | verifies |
| A payload string whose length takes five octets | kept raw | reads the value |

The first two are OpenSSL's `ASN1_MAX_STRING_NEST` and cannot change
without patching OpenSSL. The Java lane aligns the four.

## 6. Every finding

A disposition is "Fixed" (with the commit), "Documented", "Already fixed"
or "Not fixed" (with the reason). All commits are on `rust-core` through the
merge c0a6e15. The commits:

| Commit | Subject |
|---|---|
| 947a5bb | fix(rust): commit the vendored openssl-sys build script (lane A2, before the review fixes) |
| 45c10a0 | fix(rust): bound the envelope and payload with one header walk |
| 2615d5d | fix(rust): check the primitives inside values openssl keeps whole |
| 1aa7d98 | fix(rust): keep the pinned root order from deciding a verdict |
| 0ad5f57 | test(fixtures): add the core review's cases as shared vectors |
| 53f1991 | docs(rust): name the header walk and what the adapter does not check |
| b832120 | docs(repo): point the threat model's rust proofs at code that exists |
| 543ff0b | docs(docs): record the core review's divergences and the walk rule |
| 566b031 | docs(rust): say what a list argument range outside memory does |
| c4410c7 | docs(rust): record the core review's fixes, costs and module parity |

Shared cases are `fixtures/cases.json` ids under `receipt/`. Rust tests are
in `rust/tests/` unless a path says otherwise.

### 6.1 Adapter, Rust side

| Id | Severity | Defect | Verdict | Disposition | Pinned by |
|---|---|---|---|---|---|
| Rust-F1 | fix before merge | The constructed OCTET STRING check refuses at level 5 where OpenSSL decodes level 6, so a receipt re-chunked into six legal BER levels answers `MALFORMED` with a false cause | CONFIRMED | Fixed in 45c10a0: six levels verify, seven are OpenSSL's refusal, recorded as an R20 row | `accept-econtent-rechunked-into-6-constructed-levels`, `reject-econtent-rechunked-into-7-constructed-levels`, `econtent_rechunked_into_six_constructed_levels_verifies` in `envelope_bounds.rs` |
| Rust-F2 | fix before merge | The ten-certificate bound is skipped for any content type but `signedData`; an `envelopedData` with 3,271 certificates is decoded in full first | CONFIRMED | Fixed in 45c10a0: a shallow `ContentInfo` decode and the bounds run before the full decode | `a_certificate_flood_behind_a_broken_envelope_never_reaches_the_full_decode`, `the_genuine_receipt_takes_one_full_decode` in `envelope_bounds.rs` |
| Rust-F3 | fix before merge | The depth bound counts only universal SEQUENCE and SET in SignerInfo values; four placements of a 40-deep nest verify where 0.7 answered `MALFORMED` | CONFIRMED | Fixed in 45c10a0: the walk counts every constructed value of any class over the whole envelope | `reject-an-envelope-nested-33-deep-in-context-tags`, `reject-digest-algorithm-parameters-nested-33-deep`, `reject-a-crls-entry-nested-33-deep`, `reject-an-embedded-certificate-with-parameters-nested-33-deep`, their 32-deep twins, `the_depth_bound_counts_every_constructed_value_of_the_envelope` |
| Rust-F4 | fix before merge | `signer_nesting` has no node budget: an unsigned attribute of 1.18 million empty SEQUENCEs costs 0.6 s and about 130 MB before any cryptography | CONFIRMED | Fixed in 45c10a0: 100,000 values over the envelope and over each attribute SET | `the_envelope_holds_at_most_100000_values` in `envelope_bounds.rs`; R20 row (the input is over 200 KB, so no shared case) |
| Rust-F5 | fix before merge | The vendored `openssl-sys` is committed without its `build/` directory (the root `.gitignore` excludes `build/`); a clean checkout cannot build | CONFIRMED | Already fixed by 947a5bb; a fresh `git clone` of `lane/core` builds | [`fresh-clone-build.txt`](../evidence/2026-09-29-core-review-fixes/results/fresh-clone-build.txt) |
| Rust-F6 | fix before merge | Payload strings join chunks of any universal type, which 0.7 refused | CONFIRMED | Fixed in 45c10a0: the chunk rule runs over attribute values and the Xcode wrap | `unreadable-attribute-value-with-a-utf8string-chunk`, `unreadable-double-wrap-with-a-foreign-chunk`, `accept-attribute-value-as-a-constructed-octet-string`, unit test `a_value_or_a_wrap_with_a_chunk_that_is_not_an_octet_string_is_unreadable` |
| Rust-N1 | note | `BIO_set_md`'s result is ignored; the digest fails closed only because of OpenSSL internals | CONFIRMED, fails closed | Fixed in 45c10a0: the result is checked | none named |
| Rust-N2 | note | `signer_digest_known` is true for digests OpenSSL cannot run (md4, mdc2, whirlpool, shake128), so the message says "signature check failed" instead of "unsupported digest" | CONFIRMED | Not fixed: the answer is `INVALID_SIGNATURE` either way, and only the message would change, across corpus rows | the reviewer's inputs answer `INVALID_SIGNATURE` in 1.0 to 2.8 ms through `aprv.wasm` ([`review-inputs-wasm.txt`](../evidence/2026-09-29-core-review-fixes/results/review-inputs-wasm.txt)) |
| Rust-N3 | note | The verify callback drops a problem silently if it cannot record it; unreachable today | PLAUSIBLE | Fixed in 45c10a0: the callback stops the verification then | none named |
| Rust-N4 | note | `verify_path` needs pre-authenticated `untrusted` certificates; the contract does not say so | not stated | Documented in 2615d5d | none (documentation) |
| Rust-N5 | note | `init()` ignores `OPENSSL_init_crypto`'s return value | not stated | Not fixed: the call fails only once OpenSSL is unusable, and the fix lane touched no init code | none |
| Rust-N6 | note | The notAfter-second waiver is dead code on OpenSSL 4.0 | not stated | Comment in 2615d5d says so; kept as a guard should a later OpenSSL change back | `validity_is_judged_to_the_millisecond` in `jws_negative.rs`, `a_dateless_receipt_is_judged_at_the_clock_to_the_millisecond` in `receipt_negative.rs` |
| Rust-N7 | note | Isolation limits the README does not name: CPU-capability variables are still read natively; the isolation test proves the config rule only on the vendored build | PLAUSIBLE | Documented in `rust/openssl/README.md` (53f1991). The `OPENSSL_ia32cap` crash was not exercised | `rust/openssl/tests/isolation.rs` on the vendored leg |
| Rust-N8 | note | `keys_used_during` is not panic-safe; a caught panic leaves the recorder on | not stated | Fixed in 45c10a0: a drop guard restores it | none named |
| Rust-N9 | note | `has_extension` accepts names as well as dotted OIDs | not stated | Documented in 45c10a0: the core passes dotted constants only | none (documentation) |
| Rust-N10 | note | THREAT-MODEL §3.7's proof cites deleted code and "seven targets" | not stated | Fixed in b832120 | none (documentation) |

### 6.2 Adapter, C templates

| Id | Severity | Defect | Verdict | Disposition | Pinned by |
|---|---|---|---|---|---|
| C-F1 | blocking | The certificate and SignerInfo bounds are skipped for any envelope the shallow grammar refuses; the full decode then builds every certificate's key. About 0.7 s natively and 1.1 s under Wasmtime per unauthenticated 3 MiB receipt, against 8 ms when the bound fires | CONFIRMED | Fixed in 45c10a0: shallow decode and bounds before the full decode, and a refusal returns before it | as Rust-F2 |
| C-F2 | fix before merge | The depth bound counts only SEQUENCE and SET, and in the envelope only SignerInfo values; 40 nested context tags in a payload attribute or an unsigned value verify | CONFIRMED | Fixed in 45c10a0, as Rust-F3 | as Rust-F3, plus `unreadable-signed-content-nested-33-deep-in-context-tags` and `accept-signed-content-nested-32-deep-in-context-tags` |
| C-F3 | fix before merge | The payload reader accepts and refuses encodings differently from 0.7 (foreign chunks, a constructed UTF8String bundle id, high-tag-form and five-octet headers, invalid primitives in the fourth field), and nothing records it | CONFIRMED | Fixed in 45c10a0 and 2615d5d where 0.7's rule is cheap to state. Recorded in R20: the fourth-field primitives (Java agrees) and the five-octet length (Java reads the value) | `unreadable-attribute-type-in-high-tag-form`, `app-item-id-in-high-tag-form-is-kept-raw`, `bundle-id-as-a-constructed-utf8string-is-kept-raw`, `bundle-id-with-a-five-octet-length-is-kept-raw`, `unreadable-fourth-field-boolean-of-two-octets`, `unreadable-fourth-field-sequence-holding-a-padded-integer`, plus the Rust-F6 cases |
| C-F4 | note | The eContent chunk walker stops one level short of OpenSSL and names the wrong cause | CONFIRMED | Fixed in 45c10a0, as Rust-F1 | as Rust-F1 |
| C-F5 | note | The shallow decode neither counts nor bounds `crls`; a genuine receipt with 39,121 junk CRLs verifies in 319 ms natively and peaks at 53 MB | CONFIRMED | Fixed in 45c10a0: at most 10 CRLs, otherwise `MALFORMED`; R20 row. Wasm 435 ms before, 22.7 ms after | `accept-ten-embedded-crls`, `reject-eleven-embedded-crls`, `at_most_ten_crls_are_embedded` in `envelope_bounds.rs` |
| C-F6 | note | Payload work before the signature check has no node budget; the 0.7 refusal at 100,000 nodes is gone without a note | CONFIRMED | Fixed in 45c10a0: a payload budget, and the creation date is read only once a signer certificate is found | `unsigned_content_of_tiny_attributes_is_refused_at_a_bounded_cost` in `hostile.rs`, unit tests in `rust/src/receipt_payload.rs` |
| C-F7 | note | THREAT-MODEL §3.7's proof still points at the deleted reader | CONFIRMED | Fixed in b832120 | none (documentation) |
| C-F8 | note | An unused exported item (`APRV_SIGNED_DATA_it`), missing prototypes, and two hand-mirrored layouts | CONFIRMED | Fixed in 45c10a0: the item is used, `DECLARE_ASN1_ITEM` prototypes, `_Static_assert` and Rust `const` size and offset checks on both mirrors | the compile-time checks |

### 6.3 Core policy

| Id | Severity | Defect | Verdict | Disposition | Pinned by |
|---|---|---|---|---|---|
| Policy-F1 | blocking | The branch does not build from a clean checkout: the vendored `openssl-sys` build script fell under the root `.gitignore` | CONFIRMED | Already fixed by 947a5bb (lane A2) | as Rust-F5 |
| Policy-F2 | fix before merge | The depth bound (32) is applied only to SignerInfo values, not to the rest of the envelope; a 33-deep nest in `digestAlgorithms`, an extra certificate choice or a `crls` entry verifies | CONFIRMED | Fixed in 45c10a0, as Rust-F3 | as Rust-F3 |
| Policy-F3 | fix before merge | The shallow member bound is skipped whenever the shallow decode fails, so one trailing byte brings the certificate-flood cost back | CONFIRMED | Fixed in 45c10a0, as Rust-F2 | as Rust-F2 |
| Policy-F4 | fix before merge | Legal re-chunking of eContent: an off-by-one in the adapter's walk, and OpenSSL's five-level limit, refuse receipts that 0.7 and Java verify | CONFIRMED | Fixed in 45c10a0, as Rust-F1; the seven-level refusal is an R20 row | as Rust-F1 |
| Policy-F5 | fix before merge | Signed payload values and the Xcode double wrap accept foreign chunks where 0.7 and Java answer `UNREADABLE_PAYLOAD` | CONFIRMED | Fixed in 45c10a0, as Rust-F6 | as Rust-F6 |
| Policy-F6 | fix before merge | The 100,000-node budget is gone, and pre-trust payload reading costs 0.3 to 0.7 s and up to 140 MB per anonymous request; the parity note has no row for either | CONFIRMED | Fixed in 45c10a0: envelope and payload budgets, no payload read without a signer certificate; R20 row | as Rust-F4 and C-F6 |
| Policy-F7 | fix before merge | Root THREAT-MODEL §3 names deleted code (`parse_exact`), seven fuzz targets (four exist), "no port re-encodes" (OpenSSL re-encodes signedAttrs), and hand-written readers as the basis of pinned trust | CONFIRMED (by reading) | Fixed in b832120: each Rust mitigation names its code and test | none (documentation) |
| Policy-F8 | note | The millisecond validity boundary has no test; the behaviour is right | CONFIRMED | Fixed in 45c10a0: tests on both sides of the boundary for a JWS and a dateless receipt | `validity_is_judged_to_the_millisecond`, `a_dateless_receipt_is_judged_at_the_clock_to_the_millisecond` |
| Policy-F9 | note | The keyless-target path accepts issuers that `X509_verify_cert` would not (keyCertSign without basicConstraints) | PLAUSIBLE | Not fixed: the target on that path is refused afterwards whichever issuer it has (`INVALID_CERTIFICATE` for a receipt signer, a failed ES256 for a JWS leaf), so only the reason could change and nothing verifies | none |
| Policy-F10 | note | The README says critical extensions are "processed"; policies and extended key usage are not evaluated | CONFIRMED (by reading) | Fixed in 53f1991: "accepted", with the limits named | none (documentation) |

### 6.4 Findings from other lanes that went through the same fix

Two host lanes found core defects during their own gate runs. They were
folded into the same fix lane.

| Source | Defect | Disposition | Pinned by |
|---|---|---|---|
| Swift host | With two pinned roots of the same subject name, the shared receipt verified with its own root first and answered `UNTRUSTED_CHAIN` with it second. OpenSSL takes the first store certificate whose name matches | Fixed in 1aa7d98: among anchors that share a subject, only those that issued the chain are stored. Apple's three roots have distinct subjects, so production chains never met it | `verify-under-the-first-of-two-roots-sharing-a-subject` and `...-second-...`, for receipt and transaction; a test in `trust_pinning.rs` |
| Swift host | An even RSA modulus in the signer answers `UNTRUSTED_CHAIN` where the 0.7 Swift port said `INVALID_CERTIFICATE` | Case added; Java agrees | `reject-signer-with-an-even-rsa-modulus` |
| Go host | A raw call whose list argument runs past the end of linear memory can answer a value instead of trapping | Documented in 566b031 (`rust/bindings/abi/README.md`): the caps and early base64 failures decide before the first byte outside memory, and every read outside memory traps | none (documentation) |
| Go host | `init` costs 13 to 27 ms | Not touched: the fix lane changed no init code | none |

## 7. Costs before and after

The reviewers measured natively in release builds, and one also under
Wasmtime 49. The fix lane measured through `aprv.wasm` in V8, one input per
fresh instance, on a shared machine. The columns are not directly
comparable. The last two compare the module before and after the fixes.

| Input | Review measurement | Wasm before | Wasm after |
|---|---|---|---|
| 1,834 to 5,440 certificates behind a trailing byte, no `signerInfos`, or in an `envelopedData` | 59 to 725 ms native, 1,008 to 1,109 ms Wasmtime | 105 to 1,178 ms | 18.8 to 28.2 ms, `MALFORMED`, no full decode |
| 1.17 million empty SEQUENCEs in an unsigned attribute | 0.61 to 0.9 s and 138 to 144 MB native | 721 ms, 107 MB | 10.2 ms, 14.5 MB, `MALFORMED` |
| Unsigned content of 213,754 tiny attributes | 317 to 350 ms and 115 to 143 MB native | 287 to 352 ms, 58 to 123 MB | 40 to 45 ms, 19.2 MB, `INVALID_SIGNATURE` as before |
| The Node lane's `flat-max`: 3 MiB of tiny attributes, no signer | 0.8 s and 73.9 MiB in the Node host | 325 to 402 ms, linear memory 1.9 to 73.8 MiB | 16.5 to 26.1 ms, 1.9 to 16.1 MiB, same answer |
| A genuine receipt with 39,121 junk CRLs | 319 ms and 53 MB native | 435 ms | 22.7 ms, `MALFORMED` |
| 40-deep nests behind context tags, in `digestAlgorithms`, in a `crls` entry | verified where 0.7 refused | 1.3 to 1.7 ms | 0.1 ms, `MALFORMED` |

The rebuilt module (`aprv.wasm`, 3,009,278 bytes) answers as its native twin
on all 6,179 rows of the five corpora with no traps. Against lane A2's
module, 6,085 rows are identical, 93 differ in the message only, and one
differs in the verdict: `fuzz/4378/substrate/flood/unsigned-attribute-values-10000`
was `INVALID_CERTIFICATE_PURPOSE` and is `MALFORMED` again, as in 0.7. The
trap host answers the 338 cases (311 plus the new 27) with no trap. Java
answers 23 of the 27 new cases the same way as the core; the other four are
the R20 rows in section 5. The source figures are in the
[results folder](../evidence/2026-09-29-core-review-fixes/results/).

## 8. Verified as sound

What the three reviews checked and could not break, merged. Each line names
the review that made the check in brackets: R for the adapter's Rust side, C
for the C templates, P for the policy layer.

**Memory safety and ownership**

- Every `d2i` goes through one owner (`d2i_whole`, `Decoded`); a null result
  drains the error queue; a value is owned before the trailing-bytes check,
  so a refusal frees it; `ASN1_item_free` uses the same item; nothing is
  freed twice [R, C].
- Borrowed pointers from `elements` and `typed` never outlive their
  `Decoded`, at each call site [C].
- `CMS_SignerInfo_set1_signer_cert` raises the certificate's reference count
  and rebuilds the key, which is freed with the CMS. Repeated `verify_signer`
  calls on one SignerInfo reset the contexts correctly, so trying several
  matching certificates is safe [R, P].
- The digest BIO chain: `BIO_new_mem_buf` is read-only over content that
  outlives it, `BIO_push` returns the digest BIO, `BIO_free_all` frees both
  once, a length of 0 or of 2 GiB or more is handled, and a missing digest
  context fails closed [R].
- No panic path in the adapter: slice access goes through `get`, arithmetic
  stays within the input length, and the verify callback cannot panic [R].
  The core has `#![forbid(unsafe_code)]` and contains panics by stage [P].
- Valgrind with `--leak-check=full` reported 0 bytes definitely or indirectly
  lost and no invalid read or write over the probes and the
  `receipt_negative`, `jws_negative`, `receipt_signer_algorithms` and `api`
  suites. The one "possibly lost" block is the test harness's thread handle
  [R]. 20,000 calls each of five adapter entry points over ten inputs left
  the resident size flat and the error queue empty [C].

**FFI and layout**

- The declarations in `sys.rs` match the 4.0.2 headers, and `asn1_type_st`
  is still public with the layout `openssl-sys` mirrors [R, C]. The
  `APRV_SIGNED_DATA` and `APRV_ENVELOPE` templates match their C typedefs
  and their `#[repr(C)]` mirrors [C].
- `typed()` reads the union as a string for every type but BOOLEAN, OBJECT
  and NULL, which matches how `ASN1_TYPE` stores them [R, C].
- Integer width and sign: a negative attribute type stays negative and the
  core refuses it, a type wider than 64 bits is refused, `i64::MIN` decodes,
  empty and padded INTEGERs are refused [C].
- `build.rs` refuses OpenSSL below 4.0 and compiles against
  `DEP_OPENSSL_INCLUDE`; it builds for x86_64 and wasm32-wasip1 with no
  warnings under `-Wall -Wextra` [R, C].

**Isolation and initialisation**

- `OPENSSL_INIT_NO_LOAD_CONFIG` is claimed once, so a later implicit
  `OPENSSL_init_ssl` finds the config step done, and every public entry
  point calls `init()` before its first OpenSSL call [R].
- On the vendored build (autoload enabled, `OPENSSLDIR` set to a missing
  directory, no engines), `tests/isolation.rs` passed 3 of 3 under strace
  with `APRV_REQUIRE_STRACE=1`: 66 traced calls, no planted path or
  `OPENSSLDIR` touched, no socket, both controls bit. It also passed on the
  prebuilt build [R].
- No store with default paths or lookups. The store holds the anchors only,
  `set_time` sets `USE_CHECK_TIME`, and CMS never goes through `CMS_verify`
  [R, P].

**Trust and the chain**

- Trust is pinned: only the caller's anchors, `PARTIAL_CHAIN` on. The bag is
  authenticated top-down before OpenSSL sees it, so no key an anchor did not
  vouch for is used for signature arithmetic [P].
- The problem record decides the verdict: any problem not waived is
  structural, and a verdict needs an empty record and an anchored path.
  Waivers apply only to a certificate `X509_cmp` finds equal to an anchor, or
  to an expiry at the notAfter second [R, P].
- Path length: `set_depth(5)` allows six certificates below the anchor. The
  JWS path is exactly leaf, `x5c[1]`, anchor. An intermediate must have
  `cA` TRUE [P].
- Marker OIDs are checked after the chain and before any use of a leaf key,
  on both paths [P].
- The chain instant cannot be moved by an attacker: a receipt uses its first
  attribute 12 and a JWS its last top-level `signedDate`, both inside the
  signed bytes, and the clock is read only when no usable date exists. The
  millisecond edges are correct [P].
- The size caps (3,145,728 for the receipt and the endpoint body, 262,144
  for a JWS) come before any decode. Base64 is strict and canonical. JSON
  depth 64 holds [P].
- A1's recorded behaviour changes were each checked; none accepts unsigned
  data or a signature by a key no anchor vouched for: P-521 and SHA-3 chain
  signatures, canonical names, SKI-identified signers, the RSA cap of
  16,384, stricter `crls` handling, undecodable certificates, the
  critical-extension list, keyCertSign without basicConstraints, unusable
  keys [P].

**Signatures over the exact bytes**

- JWS: ES256 over the ASCII `header_b64.payload_b64`, a 64-byte raw
  signature, a P-256 key required; a wrong length, another curve or a
  non-EC key is refused [R, P].
- CMS: the joined eContent is digested with the SignerInfo's own
  digestAlgorithm and the same bytes go to the payload parser.
  `contentType` and `messageDigest` are each required once and
  single-valued, and `contentType` must equal the eContentType. Relabelling
  the payload SET as signedAttrs is refused [P].
- `signature_names_digest` returns false before the key is used. The
  refusal of a signatureAlgorithm that names a different digest holds, and
  RSA-PSS and Ed25519 name none [R, P].
- `decodes_if_present`: an absent extension, a duplicated one and one that
  fails to decode are told apart correctly, and the free matches the type
  [R].

**Concurrency**

- `X509_NAME_cmp` mutates nothing after decode, extension caching sits under
  the certificate's lock, and the path state is thread-local and used only
  synchronously. Eight threads with 300 core verifications each over one
  shared `Verifier` all answered correctly [R].

**Parsing**

- The header walk in `envelope.rs` (as it was at d5c2838): the `0x80` error
  bit is honoured, `head + content <= len` is checked with `checked_add`,
  indefinite length is accepted only on constructed values, every loop
  consumes at least two octets, and definite children stay inside the
  parent [R, C]. BER behaves as in 0.7: indefinite lengths on the SET, the
  attribute and a constructed value are accepted, and a missing or stray
  end-of-contents is refused [C].
- The payload template refuses a non-SET outer value, non-SEQUENCE
  attributes, fewer than three fields, a non-INTEGER type and a
  non-OCTET-STRING value [C].
- The shallow grammar accepts everything `d2i_CMS_ContentInfo` accepts,
  member for member, so no envelope passes the full decode while failing the
  shallow one [P]. On a well-formed envelope the certificate bound holds:
  3,819 certificates are refused in 8 ms natively and 9 ms under Wasmtime
  [C].
- No verdict accepts unsigned content [R, P].

These checks were made at d5c2838. Code the fixes replaced (`signer_nesting`
and the per-level re-decode) was checked in its old form. The walk that
replaced it was reviewed in round 2, and section 10.8 holds that round's
checks.

## 9. Not covered

- **Wasm.** No review ran anything under Wasm, except the C-templates
  reviewer's Wasmtime timings. Rust-F4's memory in a 128 MB workerd isolate
  was inferred, not measured. The fix lane measured the module in V8 only.
- **Interpreter hosts.** Timings on WasmKit and Endive were not taken. They
  run several times slower than Wasmtime, so the per-request costs in
  section 7 are lower bounds there.
- **Fuzzing.** The reviewers ran targeted probes and valgrind, no fuzz
  campaign, and none after the fixes.
- **The 1.85 floor, macOS and Windows.** No reviewer built for the Rust
  1.85 floor, or for macOS or Windows.
- **`OPENSSL_ia32cap` and its relatives.** A planted value can crash a
  native build with `SIGILL`; it cannot change a verdict. Not exercised
  (Rust-N7).
- **The signed-payload memory figure.** A signed payload still reaches the
  full payload decode after the walk and the signature (R21). The fix lane
  did not measure it, and `THREAT-MODEL.md` §5 says so.
- **`aprv-abi`, the C ABI and the link-time C file.** MIGRATION.md step 1.10
  names `aprv-abi`, which lane A2 wrote after d5c2838, so no round 1 review
  saw it. The adapter reviewer did not look at `rust/ffi` or the symbol
  visibility of the static libcrypto; the policy reviewer did not look at the
  C ABI or the fuzz targets. Round 2 reviewed `aprv-abi`, `wasi-none.c`, the
  surface, the wire crate and the C ABI (section 10); the symbol visibility
  of the static libcrypto in the C ABI has still had no reviewer.
- **The other eight ports.** How Java and the seven other ports answer the
  depth and payload rows was compared only against the 0.7 Rust reader and
  the 0.7 API text. The fix lane ran Java on the 27 new cases only. The
  policy reviewer's Java comparisons used the host-java lane's jar as found.
- **The rest of the policy layer.** The endpoint's rendering, and datetime
  and JSON beyond their bounds, are unchanged since rust-core and were not
  re-read line by line. The policy reviewer read the adapter only where the
  policy depends on it.
- **The fixes themselves.** When round 1 ended, no reviewer other than the
  author had read commits 45c10a0, 2615d5d or 1aa7d98; their evidence was
  the test suite (633 tests), clippy, `cargo deny`, `check-layering`, the
  shared cases and the parity runs. Round 2 read them (section 10.4). The
  same holds one level up: round 2's own fixes are unread (section 10.9).
- **Scratch material.** The reviewers' probe sources and generators stayed
  outside the repository, and the build directories were deleted to free
  disk.

## 10. Round 2: the fix commits and the ABI crate

Round 1's log said what it did not cover: the fix commits had no reader but
their author, and `aprv-abi` did not exist when the first reviews ran. Round
2 closes that gap for both. Its dispositions come from lane A-fix2 (the core
items, `lane/core-fix2`) and lane A3 (the ABI crate's items, `lane/core`),
both merged into `rust-core` before this section was written.

### 10.1 What was reviewed and how

**Commit.** `rust-core` at c0a6e15, the merge of round 1's fixes. Two
reviewers who had not written the code, in read-only checkouts with scratch
builds, under the same method, severity scale and verdict labels as round 1
(section 2). Their findings files are not in the repository either.

| Review | Prefix | Files | Compared against |
|---|---|---|---|
| The fix commits (reviewer 4) | `Fix-F`, `Fix-N` | every line of `walk.rs`, `cms.rs`, `envelope.rs`, `envelope.c`, `item.rs`, `payload.rs`, `payload.c`, `path.rs`, the changed parts of `rust/src/receipt.rs` and `receipt_payload.rs`, and the tests `envelope_bounds.rs`, `hostile.rs`, `trust_pinning.rs` (commits 45c10a0, 1aa7d98, 2615d5d) | OpenSSL 4.0.2's `tasn_dec.c` and `asn1_lib.c`, the 0.7 bounds table, and two mutation loops of 30,000 envelope and 50,000 payload mutants |
| The ABI crate (reviewer 5) | `ABI-F` | `rust/bindings/abi` (`lib.rs`, `wit/aprv.wit`, `wasi-none.c`, `build.sh`, README, tests), `rust/bindings/surface`, `rust/bindings/wire` and its four schemas, `rust/ffi/src/lib.rs` with its header and harnesses, `tools/wasm-trap-host.mjs` | the canonical ABI contract, ARCHITECTURE §7, MIGRATION steps 1.13 and 1.14; the module built twice with `build.sh` and driven through a hand-rolled Node host |

### 10.2 Counts

| Review | Blocking | Fix before merge | Notes | Total |
|---|---|---|---|---|
| The fix commits | 0 | 3 | 4 | 7 |
| The ABI crate | 0 | 4 | 7 | 11 |
| **Round 2** | **0** | **7** | **11** | **18** |
| Rounds 1 and 2 | 2 | 21 | 29 | 52 |

All 18 are CONFIRMED. Fix-N3 is confirmed by reading only, and ABI-F8, F9
and F10 by reading (F8 also by running the trap host). Fix-N4 confirmed that
the code is correct and untested.

Neither reviewer found a memory-safety defect, an accepted forgery or a way
to verify without a signature under a pinned root. What they found:

- The header walk of round 1 ran after the shallow decode, so the
  100,000-value budget did not bound the pre-crypto work (Fix-F1).
- Round 1's root-order fix still let the order of pinned anchors decide a
  verdict in two custom-anchor cases (Fix-F2).
- The walk checked fewer primitive rules than OpenSSL's `ANY` decoder, so
  the same invalid value was refused directly and accepted one SEQUENCE
  deeper (Fix-F3).
- The release build script did not pin the compiler (ABI-F1), an over-cap
  input was copied whole into linear memory before the core's cap applied
  (ABI-F2), and the C ABI read its inputs as C strings and answered in a
  document the wire schemas reject (ABI-F3, F4).

### 10.3 Decisions taken

From STATUS.md "Review (step 1.10)":

1. Lane A-fix2 takes the core items, lane A3 the ABI crate's items together
   with the C ABI step (MIGRATION 1.13).
2. Every wrapper lowers at most 3,145,729 bytes of any input, the largest
   cap plus one, before the copy into linear memory. Each cap is decided on
   the length alone, so the core's answer stays byte for byte the same. This
   closes ABI-F2 per host, in G1c.
3. The fixes that change a verdict get shared cases, and the divergences
   that remain are R20 rows.

### 10.4 The fix commits

Commits on `rust-core`: 39d15e4 (walk before shallow decode), 8baa580 (the
flood cost test), 8ab95db (one validation per candidate anchor), 128331d
(the walk refuses what OpenSSL's `ANY` decoder refuses), 8c98e9d (walk edge
tests, panic-safe counter), a5a9896 (17 shared cases). Merged by f36e76a.

| Id | Severity | Defect | Verdict | Disposition | Pinned by |
|---|---|---|---|---|---|
| Fix-F1 | fix before merge | The shallow decode ran before the walk and built a value per entry of the `certificates`, `crls` and `signerInfos` sets: 1.17 million `30 00` entries cost 0.6 to 0.95 s and about 114 MB before the member bound refused them. `receipt.rs` and THREAT-MODEL §3.7 described the opposite order | CONFIRMED | Fixed in 39d15e4: the walk runs first, so the node budget refuses the set after 100,000 values. The comments, both READMEs and §3.7 state that order. The 1,057-certificate flood now costs the walk first (Wasm 2.3 to 6.0 ms before, 9.7 to 16.5 ms after), bounded by the node budget | `a_million_tiny_set_entries_are_refused_by_the_node_budget_first`, `a_tiny_entry_flood_costs_what_junk_of_its_size_costs` in `envelope_bounds.rs`; the cost test in `hostile.rs` (8baa580) |
| Fix-F2 | fix before merge | One store held every anchor that issued something, so with two same-named pinned roots the order decided the verdict when the bag held a certificate from each tree, and an anchor named like the intermediate was taken as the leaf's issuer. Fails closed; custom anchors only, since Apple's three roots have distinct names | CONFIRMED | Fixed in 8ab95db: `X509_verify_cert` runs once per anchor that `X509_check_issued` pairs with the target or a vouched certificate, each time with a store of that anchor alone; the first passing path wins, and when none passes the problems come from the first run whose links hold, so the reason does not depend on order either. A chain that ends at an Apple root has one candidate and one run, as before | `a_certificate_from_a_same_named_roots_pki_in_the_bag_does_not_decide_the_path`, `an_anchor_named_as_the_intermediate_does_not_change_the_verdict` in `trust_pinning.rs`; two shared cases for a twin-issued bag certificate (either root first) and four for an anchor named as the intermediate (either order, receipt and transaction) |
| Fix-F3 | fix before merge | The walk checked eight primitive tags; OpenSSL's `ANY` decoder also refuses a short UTCTime or GeneralizedTime, a constructed BOOLEAN, INTEGER, NULL, OID or ENUMERATED, and a string of seven levels. The same value was refused as the payload's fourth field and accepted one SEQUENCE deeper, and R20's stated reason for the row was false | CONFIRMED | Fixed in 128331d, which also found two more of the same class while checking against `tasn_dec.c` (a primitive SEQUENCE or SET, an end-of-contents inside a definite length). The walk checks tags 16, 17, 23 and 24, refuses the five primitive-only types when constructed, counts string levels as `asn1_collect` does, and hands each outermost constructed string to `d2i_ASN1_TYPE`. R20's row now lists every rule | `what_openssl_refuses_on_its_own_is_refused_in_the_envelope_at_every_depth` in `envelope_bounds.rs`; cases `unreadable-fourth-field-sequence-holding-{a-short-utctime,a-short-generalizedtime,a-constructed-integer,a-primitive-sequence,an-end-of-contents}`, `reject-an-unsigned-value-sequence-holding-a-short-utctime`; `accept-fourth-field-sequence-holding-a-constructed-utctime` (Java refuses it, an R20 row) |
| Fix-N1 | note | Seven-level constructed strings are refused in more places than R20 recorded (version and later fields, the Xcode wrap, unsigned envelope values) | CONFIRMED | Documented: R20's row names every place. Wrap cases added in a5a9896 | `accept-double-wrap-rechunked-into-6-constructed-levels`, `unreadable-double-wrap-rechunked-into-7-constructed-levels`, `unreadable-fourth-field-sequence-holding-a-7-level-octet-string`, `reject-an-unsigned-value-sequence-holding-a-7-level-octet-string` |
| Fix-N2 | note | A seven-level payload value was reported as a foreign chunk; the verdict was right, the message wrong | CONFIRMED | Fixed in 128331d: the walk refuses the seventh level first and names it; the chunk error keeps its kind as a second line of defence | the F3 test above |
| Fix-N3 | note | `full_decodes_during` did not restore its counter after a panic, the class Rust-N8 fixed for `keys_used_during` | by reading | Fixed in 8c98e9d with a drop guard | `the_full_decode_counter_survives_a_panic_inside_it` |
| Fix-N4 | note | Nothing pinned the walk on indefinite lengths, a missing end-of-contents or a length one octet past its container. The walk was correct | CONFIRMED correct, untested | Fixed in 8c98e9d: tests at 24, 25 and 3,000 indefinite levels, an indefinite flood at the budget and one over, a missing end-of-contents, an end-of-contents in a definite length, a length one octet past | `indefinite_lengths_meet_the_same_bounds_and_must_end`, `a_length_one_octet_past_its_container_is_refused` |

### 10.5 The ABI crate

Commits on `rust-core`: 617e85f (C ABI byte calls, lints, committed header),
5b49152 (`build.sh`), 772dbbc (duplicate `roots`), 195a16d (README), 4a07b44
(strip), d16e6fb (ABI tests), b863252 (ARCHITECTURE). Merged as f6059ee.

| Id | Severity | Defect | Verdict | Disposition | Pinned by |
|---|---|---|---|---|---|
| ABI-F1 | fix before merge | `build.sh` does not pin rustc. CI and the release run it from the repository root, where rustup does not read `rust/rust-toolchain.toml`, so the released `aprv.wasm` came from the runner's default compiler and `tools/reproduce-wasm.sh` could not reproduce it | CONFIRMED | Fixed in 5b49152: `build.sh` reads the channel from that file, exports `RUSTUP_TOOLCHAIN` and stops unless `rustc --version` names it, which also holds for a toolchain on `PATH` without rustup | checked by hand with a rustc that is not 1.98.1 (recorded in the commit); no automated test |
| ABI-F2 | fix before merge | An over-cap input is copied whole into linear memory before the core answers `TOO_LARGE`, the memory is never returned, and an input of 2 GiB or more traps and reports `INTERNAL_ERROR` instead. A 256 MiB JWS grew an instance from 2 to 258 MiB, up to 8,000 times what the core ever reads | CONFIRMED | Closed per host in G1c: every wrapper lowers at most 3,145,729 bytes. The Java Endive engine already had it (c328219, merged in 6e44c84); each other host's pin, cap and re-run are STATUS.md's G1c entry, and this log does not record them as done. 195a16d documents the rule for hand-rolled hosts | `a_host_that_lowers_the_largest_cap_plus_one_gets_too_large` (d16e6fb) and the shared cap and cap-plus-one cases through the trap host; per-host tests come with G1c |
| ABI-F3 | fix before merge | The C ABI reads its inputs as C strings: a NUL truncates the input (a genuine receipt, a NUL and junk verified where `aprv.wasm` answers `MALFORMED`), and non-UTF-8 is a call error where the module answers a verdict. The harnesses skipped the decodeBase64 group that would have failed | CONFIRMED | Fixed in 617e85f: three `_bytes` calls take a pointer and a length and answer `aprv-wire`'s documents through the surface, byte for byte as `aprv.wasm` does. The C-string calls stay, documented with their limits. The Elixir example still drives them and is not built here | both harnesses run all 340 cases at that commit, the decodeBase64 groups included through the verify calls, e.g. `base64/reject-control-characters` |
| ABI-F4 | fix before merge | The step 1.14 gate and ARCHITECTURE §7.10 say the C ABI's JSON validates against the wire schemas; its failure document has no `verified` member and uses tokens outside the eight reasons, and its success answer is the bare payload | CONFIRMED | Fixed in 617e85f: the byte calls answer wire documents, and a call mistake carries no document | the ctypes harness writes the documents for `tools/validate-wire.mjs` |
| ABI-F5 | note | The guest trusts every range the host hands it, and the README promised traps that do not happen: a wrapping range answers `TOO_LARGE` as a value and the later `free` of a pointer it never allocated leaves the heap undefined; `random-get`'s answer pointer is not checked; `cabi_realloc` accepts any old pointer | CONFIRMED | Documented in 195a16d: what a hand-rolled host can rely on and what it cannot, and that such a host discards the instance. Not fixed in code: component runtimes check ranges and every wrapper here lowers through `cabi_realloc`, so the guest-side trap the review proposed as optional was not added | none (documentation) |
| ABI-F6 | note | `build.sh` leaves `aprv.wasm` and the component in the output directory when a contract check fails | CONFIRMED | Fixed in 5b49152: the module is built and checked in the work directory and copied out only after every check passes; earlier outputs are removed first | checked by hand with a toolchain whose OpenSSL embeds its install path (the output directory stays empty) |
| ABI-F7 | note | `init`'s configuration reader keeps the last of two `roots` members, so `{"roots":["AQ=="],"roots":[]}` selected the Apple roots | CONFIRMED | Fixed in 772dbbc: the reader sees every member through serde's map visitor and refuses `roots` named more than once, in either order | `the_configuration_names_roots_or_nothing` in `rust/bindings/wire` |
| ABI-F8 | note | The ABI tests and trap host do not cover `_initialize`, the over-cap copy, a wrong-length `random-get` answer, a non-UTF-8 JWS that reaches the UTF-8 check, or a vacuous `random-get` check | CONFIRMED (reading and running) | Partly fixed in d16e6fb: the Wasmtime ABI suite gains `_initialize` (optional, harmless after an export, traps the second time), the cap-plus-one lowering, and short and long `random-get` answers. Not fixed: the trap host is unchanged, so its 2-segment non-UTF-8 JWS, its `randomCalls === 0` pass and its missing `trim: -1` remain | `initialize_is_optional_once_and_harmless_after_an_export`, `a_host_that_lowers_the_largest_cap_plus_one_gets_too_large`, `a_random_get_answer_of_the_wrong_length_traps` |
| ABI-F9 | note | The wire schemas admit values the core cannot produce (a 19-digit `id` above `i64::MAX`, attribute keys above `u32`, an `epochMillis` not ending in `000`). No answer the core produced was rejected: 5,888 answers from the corpora validate | CONFIRMED (reading) | Not fixed: no commit touches the schemas, and the review offered tightening as optional ("or leave as documented") | none |
| ABI-F10 | note | Stale statements: the C ABI's `Cargo.toml` said `aprv_version()` reads `version.txt`; ARCHITECTURE §7 said a non-UTF-8 JWS answers `INVALID_JWS_FORMAT`; a comment said `json` is `NULL` only on allocation failure | CONFIRMED (reading) | Fixed in 617e85f (the two C ABI statements) and b863252 (ARCHITECTURE names the 0.7 reason) | none (documentation) |
| ABI-F11 | note | `build.sh` strips nothing: the shipped module carries a 258 KB name section, 8.6% of its size | CONFIRMED | Decided and done in 4a07b44: the `name` section is stripped. The stripped module passed `check-wasm.sh`, every shared case, the trap host's ABI tests and the hostile corpus byte for byte. What goes is Rust names in trap stack frames; the build stays reproducible | `tools/check-wasm.sh`, the trap host |

### 10.6 Other findings that went through the same fix

| Source | Defect | Disposition | Pinned by |
|---|---|---|---|
| Differential campaign against the 0.7 Java implementation (7,647 calls, [note](../evidence/2026-09-29-differential-campaign.md)) | A genuine receipt was refused as `UNTRUSTED_CHAIN` when the caller pinned two roots with one subject name and the bag held a stranger certificate from the other tree, the other root listed first. Found on a fuzz seed; the campaign otherwise found no verdict or payload difference on the corpora and no forgery | Fixed in 9bf238a, which touches the same function as Fix-F2's rule (8ab95db); both are in `rust-core` | `a_root_verifies_when_a_same_named_root_vouches_for_a_stranger_in_the_bag` and two shared cases after `receipt/verify-with-a-stranger-whose-key-is-unreadable` |
| Cost test in `hostile.rs` | The tiny-attribute cost test failed about one run in ten under shared load | 7b01ea9: each input is judged on its fastest of seven interleaved calls. The bound is unchanged and a margin of about 7% remains for CI to watch | `unsigned_content_of_tiny_attributes_is_refused_at_a_bounded_cost` |

### 10.7 Costs and parity after round 2

Native release builds for the first table, through `aprv.wasm` in V8 (second
call on a fresh instance) for the second. The reviewers' inputs were rebuilt
from their descriptions; the committed tests rebuild each shape.

| Input | Before | After |
|---|---|---|
| 1.17 million `30 00` entries in `certificates`, native | 605 to 711 ms, peak 20 to 134 MB, `TooManyCertificates` | 1.8 ms, flat, `TooManyNodes` |
| The same in `crls` or `signerInfos`, native | 571 to 957 ms | 1.7 to 1.8 ms |
| The `certificates` flood end to end through `verify_receipt`, 3 calls | 2.31 s against 14.8 ms for junk | 12.8 ms against 7.2 ms for junk |
| The same in `certificates`, Wasm | 339 ms, 94.2 MB | 11.3 ms, 7.5 MB |
| The same in `crls` or `signerInfos`, Wasm | 305 and 336 ms, 94.2 MB | 7.5 and 7.4 ms, 7.5 MB |
| 1,057 real certificates, Wasm | 2.3 to 6.0 ms | 9.7 to 16.5 ms (the walk now runs first) |
| A 256 MiB JWS through the ABI (ABI-F2) | answer in 429 ms, memory 2 to 258 MiB | bounded by the wrapper's 3,145,729-byte lowering; per-host figures are G1c's |

- The module rebuilt for round 2 (3,009,376 bytes) answered as its native
  twin on all 6,179 corpus rows and, against round 1's module, 6,134 rows
  identically and 45 in the message only, none in the verdict, all in the
  fuzz corpus. 42 mutants over the certificate or SignerInfo bound that also
  break something the walk checks now report the walk's message, and 3 with a
  string of seven levels now say so.
- Java answers 354 of the 357 cases after the fix lane's own run; the three
  it answered otherwise are R20 rows, and lane J-align's second round brought
  it to 357 of 357 (STATUS.md).
- After lane A3's merge the final module (name section stripped, 2,760,476
  bytes) passes `check-wasm.sh` and the trap host on 377 of 377 cases with no
  trap, and answers 6,134 rows as before and 45 in the message only (STATUS.md
  G1c). The workspace has 660 tests after round 2's fixes and 689 after the
  merge with A3's work.
- R20 (DECISIONS.md) gained two rows: a string of seven or more constructed
  levels one SEQUENCE deep, and a constructed UTCTime in a fourth field that
  Java refuses. Its rows for the seven-level string and the fourth field now
  list every place and rule of Fix-N1 and Fix-F3. One more Java divergence
  stays open for the differential campaign: a constructed string of a type other than OCTET or
  BIT STRING inside the envelope (an unsigned attribute value holding a
  constructed UTCTime).

### 10.8 Verified as sound

Checked at c0a6e15 by reviewer 4 (fix commits) or reviewer 5 (ABI crate).

**The header walk and the envelope order**

- `walk::header`: the `ASN1_get_object` call is memory-safe, OpenSSL 4.0.2
  reads at most `omax` octets, an error or `TOO_LONG` maps to `None`, and
  `head + content <= len` is checked again. Nothing leaks on the error queue
  [4].
- `Walker::value`: the node count comes before the header, so exactly the
  budget passes; depth counts constructed values of every class as 0.7 did;
  each value consumes at least two octets; an indefinite value is bounded by
  its parent's slice; recursion is at most 33 deep [4].
- Budget edges: 100,000 values pass and 100,001 are refused [4].
- `octet_string` and `MAX_STRING_NEST = 5`: six levels accepted and seven
  refused, as `asn1_collect` does in the 4.0.2 source [4].
- A mutation loop of 30,000 envelope mutants found no case where the full
  decode ran and an independent walker measured depth over 32, more than
  100,000 nodes or a size mismatch, no panic, and no case where `parse`
  accepted what `d2i_CMS_ContentInfo` refused. A payload loop of 50,000
  found no panic [4].
- The shallow grammar accepts every envelope the full CMS grammar does, so
  member counts equal what the full decode would build [4].
- `Headers::Short` matches 0.7's `asn1.rs` exactly, and the Xcode wrap has its
  own budget as in 0.7 [4].
- `decodes_as_any` and `d2i_whole` own and free every value and drain the
  error queue on refusal. The creation date is read once, and only after a
  SignerInfo names an embedded certificate [4].
- `store_anchors` used only anchor keys and was linear in anchors times
  untrusted certificates (superseded by Fix-F2's rule) [4].

**The module, its imports and its calls**

- Imports are exactly `aprv:verifier/host@1.0.0 random-get`. Exports are the
  four `@1.0.0` operations, their `cabi_post_` functions, `cabi_realloc`,
  `memory` and `_initialize` [5].
- A verify before `init`, a verify after a refused `init` and a second `init`
  after success trap; a refused `init` can be retried; `env` 2, 255 and
  2^32-1 trap before `init` is consulted [5].
- A `random-get` answer of the wrong length traps before any byte is read, a
  reentrant `init` from inside `random-get` traps, and ES256 asks the host
  once per instance [5].
- `wasi-none.c` defines every WASI function wasi-libc references and traps in
  all but two; the panic path ends in a trap; panic locations name only
  `/aprv/cargo/...` paths [5].
- Two builds from different work directories gave identical modules and
  components, so path remapping holds. The path check fired on a real leaked
  path [5].
- 2,000 calls each of init refusals, verified ES256 JWS, malformed receipts
  and sandbox endpoint answers left linear memory unchanged [5].
- The shared cases at the cap and cap plus one pass through the ABI: a
  receipt of 3,145,728 `A`s is `MALFORMED` in 59 ms, cap plus one
  `TOO_LARGE`; the endpoint and JWS likewise; 1.5 million levels of nesting
  at the cap answer 21002 in 3 ms [5].
- The corpora through the trap host on the reviewer's build: 22, 193, 811 and
  5,000 rows with no trap and no unexpected import; 338 of 338 cases;
  `abi-tests` with none failed [5].

**Wire and C ABI**

- The init-config schema's base64 pattern matches the reader exactly. Failure
  objects have exactly three members, strings escape correctly, and
  attribute types are `u32` in a `BTreeMap`, so keys are unique and ascending
  [5]. 3,858 `verify-receipt`, 2,029 `verify-signed-data` and one `init`
  answer validate against the schemas with Ajv [5].
- C ABI: every export is inside `catch_unwind`; null pointers are reported,
  not dereferenced; `anchors_of` refuses count and array disagreements; the
  free functions accept NULL; `AprvVerifier` is `Send` and `Sync` by its
  fields; the per-thread clock keeps concurrent calls' instants apart [5].

### 10.9 Not covered by round 2

- **The round-2 fixes themselves.** No reader other than their authors has
  seen lane A-fix2's and lane A3's commits, `c0a6e15..b863252`: the walk's
  new order and primitive rules, the per-anchor validation, the C ABI's byte
  calls, lints and header, the six fuzz targets, the `build.sh` changes, the
  duplicate-`roots` reader and the stripped module. A third round is planned
  for them.
- **The Wasm build under load.** Fix-F1's cost and memory in Wasm were not
  measured by reviewer 4, and the linear-memory retention was an inference.
  Lane A-fix2 measured them in V8 only.
- **Java on the residual rows.** Reviewer 4 had no Java run for Fix-F2's and
  Fix-F3's depth-dependent cases; lane A-fix2 ran Java on the 17 new cases.
- **Parts of the adapter read only where the reviewed code calls them:**
  `keys.rs`, `certificate.rs`, `sys.rs` and the `isolation.rs` changes of
  45c10a0. `tools/check-layering.mjs` rule 6 and `gen_fixtures.py` were not
  re-run by reviewer 4.
- **The Wasmtime ABI suite** (`rust/bindings/abi/tests`) was not built or run
  by reviewer 5, for disk and time; the trap host and Node probes cover the
  same rules on the core module. The component path was not exercised under
  Wasmtime by the review. The suite's later results are lane A3's.
- **Byte parity with lane A2's module.** Reviewer 5's module linked a scratch
  OpenSSL that embeds its install prefix, so `build.sh`'s path check failed on
  it, and a fresh-clone reproduction with the pinned toolchain was not
  rerun.
- **The C ABI's lints, exported-symbol allowlist and fuzz target** were absent
  at c0a6e15 (step 1.13, then pending). They landed in 617e85f and cc95875,
  after the review.
- **The Elixir NIF, the C++ and ctypes harnesses and the Python example**
  were read only where they bear on ABI-F3, and their conformance runs were
  not repeated. 0.7's C ABI was not built, so whether ABI-F3 is inherited is
  not verified.
- **Fuzzing.** Only the two in-process mutation loops ran during round 2.
  Lane A3 ran its six targets for 600 s each with no finding, and that
  campaign has no reader but its author either.
- **Per-host wrapper caps.** ABI-F2's closure is a G1c result per host and
  is not recorded here as complete.
