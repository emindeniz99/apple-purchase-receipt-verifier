# Review log: the OpenSSL core

Status: written 2026-09-29 for the owner's one read at the final pull
request. It closes MIGRATION.md step 1.10 for the core and records what
each review found, what was done about it, and what nobody looked at.

The three reviews were done by agents that did not write the code. Their
findings files are not in the repository; this log is their record.
Everything each finding did to the code is in git and in the evidence note
[core review fixes](../evidence/2026-09-29-core-review-fixes.md).

## 1. The short version

- Three reviews read every line of the OpenSSL adapter and the core's
  policy layer at commit d5c2838 and tried to break it with crafted input.
  They reported 34 findings: 2 blocking, 14 fix before merge, 18 notes.
- Nothing in memory safety, isolation or trust broke. No double free, no
  per-call leak, no panic path, valgrind clean. No input verified without a
  valid signature under a pinned root, and none could move the instant at
  which the chain is judged.
- What did break was the set of cheap checks before the full CMS decode.
  They covered less than 0.7's reader did: the certificate and SignerInfo
  bounds ran only on a well-formed `signedData`, the depth bound counted
  too little, the 100,000-node budget was gone, and some payload encodings
  changed verdict without a record. Three reviewers found the same gaps
  from three directions.
- Every blocking and fix-before-merge finding is fixed on the branch. Three
  notes are not fixed, each with a reason (section 6). The fixes are one
  `ASN1_get_object` header walk, 27 new shared cases and seven new rows in
  R20's divergence table.
- The fixes were checked by tests, the shared cases and the parity runs.
  No second review of the fix commits is recorded, so `walk.rs` and the
  payload changes have had no reader other than their author.

## 2. What was reviewed and how

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

| Review | Prefix | Blocking | Fix before merge | Notes | Total |
|---|---|---|---|---|---|
| Adapter, Rust side | `Rust-F`, `Rust-N` | 0 | 6 | 10 | 16 |
| Adapter, C templates | `C-F` | 1 | 2 | 5 | 8 |
| Core policy | `Policy-F` | 1 | 6 | 3 | 10 |
| **All** | | **2** | **14** | **18** | **34** |

Verdicts: 25 CONFIRMED, 3 PLAUSIBLE (Rust-N3, Rust-N7, Policy-F9) and 6
notes for which the review states no verdict (Rust-N4, N5, N6, N8, N9,
N10). The Rust review numbers its notes `N1` to `N10` and its other
findings `F1` to `F6`; the other two reviews number every finding `F1`
upward, whatever its severity.

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
and the per-level re-decode) was checked in its old form; the walk that
replaced it was not reviewed by anyone but its author.

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
  names `aprv-abi`, which lane A2 wrote after d5c2838, so no review saw it.
  The adapter reviewer did not look at `rust/ffi` or the symbol visibility of
  the static libcrypto; the policy reviewer did not look at the C ABI or the
  fuzz targets.
- **The other eight ports.** How Java and the seven other ports answer the
  depth and payload rows was compared only against the 0.7 Rust reader and
  the 0.7 API text. The fix lane ran Java on the 27 new cases only. The
  policy reviewer's Java comparisons used the host-java lane's jar as found.
- **The rest of the policy layer.** The endpoint's rendering, and datetime
  and JSON beyond their bounds, are unchanged since rust-core and were not
  re-read line by line. The policy reviewer read the adapter only where the
  policy depends on it.
- **The fixes themselves.** No reviewer other than the author read commits
  45c10a0, 2615d5d or 1aa7d98. Their evidence is the test suite (633 tests),
  clippy, `cargo deny`, `check-layering`, the shared cases and the parity
  runs.
- **Scratch material.** The reviewers' probe sources and generators stayed
  outside the repository, and the build directories were deleted to free
  disk.
