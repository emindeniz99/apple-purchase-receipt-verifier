# The header walk reduced to a counter, measured

**Question.** `rust/openssl/src/walk.rs` walks every header of the CMS
envelope and of each payload attribute SET before OpenSSL decodes them.
Its job that must stay is the denial-of-service bound: 32 constructed
levels, 100,000 values, nothing after the outermost value, and each
constructed string handed to OpenSSL's `ANY` decoder at its outermost
level so `ASN1_MAX_STRING_NEST` applies at any depth. Beyond that it
enforces grammar rules of its own. If OpenSSL's grammar is the grammar,
the walk becomes an iterative header counter (simplicity audit R16, item
G; the owner approved measuring it as a spike before any merge,
2026-10-05). What changes, and is any of it a refusal turned into `ok`?
The answer decides whether the walk is narrowed.

**Versions.** OpenSSL 4.0.2, built from source by `openssl-src`
400.0.1+4.0.2; source locations below are paths in that tarball. Rust
1.98.1, the test profile, on one Linux x86-64 container; the fuzz runs
used nightly 1.101.0 (2026-10-05) and cargo-fuzz 0.13.2. Run on
2026-10-06 on the branch `spike/core-walk-counter`, from main at 400acbd;
its commits are kept in the closed, unmerged [#294](https://github.com/emindeniz99/apple-purchase-receipt-verifier/pull/294).

**Method.** Each rule was read against the OpenSSL decode that follows the
walk. The rules were then removed in one commit, the counter
([`walk-counter.patch`](2026-10-06-core-walk-counter/walk-counter.patch)),
and the whole Rust suite run (`cargo test --locked` in `rust/`; the
shared cases are the 390 tests of `conformance`). A probe
([`walk-probe.rs`](2026-10-06-core-walk-counter/walk-probe.rs)) mints
inputs the shared cases do not cover, each valid but for one grammar
deviation: payloads signed under a minted P-256 PKI, unsigned parts of
the shared generated receipt, and a signer certificate the minted
intermediate signs. It prints the core's answer, how many full CMS
decodes ran, and whether `d2i_CMS_ContentInfo` alone takes the envelope.
It ran on three shapes: `kept` (main), `counter`, and `middle`, the
counter with two of the rules put back
([`walk-middle.patch`](2026-10-06-core-walk-counter/walk-middle.patch)).
The Java answers are the shared cases' expectations, which the Java suite
passes on main.

## What OpenSSL judges

`tasn_dec.c` and `asn1_lib.c` are in `crypto/asn1/`.

| Rule of the walk | OpenSSL 4.0.2 | Judged? |
|---|---|---|
| A primitive BOOLEAN, INTEGER, BIT STRING, NULL, OID, ENUMERATED, UTCTime, GeneralizedTime, UniversalString or BMPString must decode, and a SEQUENCE or SET must not be primitive (`CHECKED_TAGS`, handed to `d2i_ASN1_TYPE`) | At a template position and as an `ANY` value itself: `asn1_ex_c2i` (`tasn_dec.c:858`; NULL `:900`, BOOLEAN `:908`, INTEGER padding in `a_int.c:191-193`, BMP `:954`, Universal `:958`, GeneralizedTime `:962`, UTCTime `:966`) and `ASN1_R_TYPE_NOT_CONSTRUCTED` (`:796`). A SEQUENCE, SET or other-class value held as an `ANY` is kept in encoded form, unread (`:784-809`). The envelope holds such values in unsigned attributes (`SET OF ANY`, `crypto/x509/x_attrib.c:33`), AlgorithmIdentifier parameters (`crypto/asn1/x_algor.c:20`) and Name values (`ASN1_PRINTABLE`, `crypto/x509/x_name.c:48`, whose mask takes `B_ASN1_SEQUENCE`, `include/openssl/asn1.h.in:495-496`); the payload holds them in a receipt attribute's fields after the value | Only outside a kept SEQUENCE or SET. Inside one: the walk's alone |
| No constructed BOOLEAN, INTEGER, NULL, OID or ENUMERATED (`PRIMITIVE_ONLY_TAGS`) | `ASN1_R_TYPE_NOT_PRIMITIVE` (`tasn_dec.c:810-816`) at a template position and as an `ANY` value | Not inside a kept SEQUENCE; but the walk's own hand-off of each outermost constructed universal value reaches the same refusal there, so the list duplicates the hand-off |
| No end-of-contents inside a definite length | A template SEQUENCE (`ASN1_R_UNEXPECTED_EOC`, `tasn_dec.c:425-428`), a SET OF (`:667-670`) and a constructed string (`asn1_collect`, `:1102-1108`) refuse it. Inside a kept SEQUENCE, a definite length is skipped (`:806-808`) and `asn1_find_end` counts end-of-contents only to close indefinite lengths (`:1016-1064`) | Only outside a kept value |
| `Headers::Short` (payload): no tag in high-tag-number form, no length of more than four octets | `ASN1_get_object` reads the high-tag form for any tag number, 31 or not (`asn1_lib.c:61-76`), and a long-form length with leading zero octets up to `sizeof(long)` (`asn1_lib.c:131-140`) | No |
| `short_header` on an attribute's INTEGER or string value | As above | No |
| A constructed OCTET STRING value or Xcode wrap has only OCTET STRING chunks (`values_are_octet_strings`, `octet_string_exact`) | `asn1_collect` is called with tag -1 (`tasn_dec.c:820-826`, "just check for UNIVERSAL class and ignore the tag"); with a negative expected tag `asn1_check_tlen` checks neither tag nor class (`:1229-1240`) | No |
| Kept by every shape: depth, nodes, trailing bytes, readable headers, lengths within their container, the hand-off of the outermost constructed string | `ASN1_MAX_CONSTRUCTED_NEST` 30 (`tasn_dec.c:27`, `:221-223`) bounds template nesting only; a kept SEQUENCE is skipped by its length or by `asn1_find_end`, unbounded in depth and count. `ASN1_MAX_STRING_NEST` 5 (`:1080`, `:1122-1124`) bounds a string only where OpenSSL decodes it | The bounds are the walk's alone |

## Results

Answers are in `probe-output.txt`; the case table is `case-flips.tsv`.

### The counter

`counter` keeps only what the first paragraph lists. Production lines of
`rust/openssl/src`: 2455 on main, 2220 with the counter (−235): `walk.rs`
368 → 184 (235 → 125 lines of code), `payload.rs` 213 → 167, `cms.rs`
532 → 529, `item.rs` 92 → 90. `rust/src` does not change: payload errors
reach the core as detail strings, and none of it existed only to map the
removed ones. `cargo clippy --locked --all-targets -- -D warnings` and
`cargo fmt --check` are clean.

Failing with the counter: 10 of 390 shared cases, 4 unit tests in
`rust/src/receipt_payload.rs` (`a_value_or_a_wrap_with_a_chunk_that_is_not_an_octet_string_is_unreadable`,
`a_tag_in_high_tag_form_or_a_five_octet_length_is_not_read`,
`fields_after_the_value_are_valid_asn1_at_every_depth`,
`what_openssl_refuses_on_its_own_is_refused_one_sequence_deeper_too`) and
3 in `rust/tests/envelope_bounds.rs`
(`values_kept_whole_in_the_envelope_are_valid_asn1`,
`indefinite_lengths_meet_the_same_bounds_and_must_end`,
`what_openssl_refuses_on_its_own_is_refused_in_the_envelope_at_every_depth`).

**Refusals before the signature that verify.** Every one is an envelope
value OpenSSL keeps whole inside a SEQUENCE. `d2i_CMS_ContentInfo` alone
decodes each envelope:

| Input | kept | counter |
|---|---|---|
| `receipt/reject-an-unsigned-value-sequence-holding-a-short-utctime` (shared case, pinned) | `MALFORMED`, 0 full decodes | ok |
| Shared receipt, unsigned attribute value SEQUENCE holding a short UTCTime, a padded INTEGER, a BOOLEAN of two octets, an end-of-contents, or a primitive SEQUENCE (5 inputs) | `MALFORMED`, 0 full decodes | ok |
| Shared receipt, SignerInfo signatureAlgorithm parameters SEQUENCE holding a padded INTEGER | `MALFORMED`, 0 full decodes | ok |
| Minted signer certificate, signed by the minted intermediate under the pinned minted root, whose subject Name carries a value SEQUENCE holding a short UTCTime, a padded INTEGER, or an end-of-contents (3 inputs) | `MALFORMED`, 0 full decodes | ok |

The same deviations standing alone, not inside a SEQUENCE, stay
`MALFORMED` with the counter, because `d2i_CMS_ContentInfo` refuses them,
but only after the full decode has built every embedded certificate's key
(1 full decode where main had 0). An end-of-contents in a SignerInfo,
before its `sid` or after its signature, behaves the same way. The
signerInfos SET with an end-of-contents after its SignerInfo is still
refused with 0 full decodes.

**Answers after the signature that change** (the content verifies; Java
and 0.7 refuse it): all nine pinned, none `oneOf`.

| Shared case | kept (= Java) | counter |
|---|---|---|
| `receipt/unreadable-fourth-field-sequence-holding-a-padded-integer` | `UNREADABLE_PAYLOAD` | ok |
| `receipt/unreadable-fourth-field-sequence-holding-a-short-utctime` | `UNREADABLE_PAYLOAD` | ok |
| `receipt/unreadable-fourth-field-sequence-holding-a-short-generalizedtime` | `UNREADABLE_PAYLOAD` | ok |
| `receipt/unreadable-fourth-field-sequence-holding-a-primitive-sequence` | `UNREADABLE_PAYLOAD` | ok |
| `receipt/unreadable-fourth-field-sequence-holding-an-end-of-contents` | `UNREADABLE_PAYLOAD` | ok |
| `receipt/unreadable-attribute-type-in-high-tag-form` | `UNREADABLE_PAYLOAD` | ok, bundle id read |
| `receipt/app-item-id-in-high-tag-form-is-kept-raw` | ok, `app_item_id` null, raw `1F 02 01 05` kept | ok, `app_item_id` 5, no raw entry |
| `receipt/unreadable-attribute-value-with-a-utf8string-chunk` | `UNREADABLE_PAYLOAD` | ok, bundle id read |
| `receipt/unreadable-double-wrap-with-a-foreign-chunk` | `UNREADABLE_PAYLOAD` | ok, bundle id read |

In each, the payload template decode reads what the walk refused: the
fields after an attribute's value are a SEQUENCE OpenSSL keeps whole,
the high-tag `1F 02` is the INTEGER tag to `ASN1_get_object`, and
`asn1_collect` joins a UTF8String or INTEGER chunk as octets. The minted
payloads agree: an attribute type, an app item id value or the payload
SET itself in high-tag form, a five-octet length on the SET or the
bundle id, a UTF8String chunk in a value and an INTEGER chunk in the
wrap all read with the counter and are `UNREADABLE_PAYLOAD` (or kept raw)
on main.

`receipt/bundle-id-with-a-five-octet-length-is-kept-raw` passes in every
shape (only the raw octets are pinned), but with the counter the core
reads `com.example.app`, as Java already does.

**What does not change.** A constructed INTEGER or BOOLEAN inside a kept
SEQUENCE is still refused before the full decode, in the envelope, in a
minted Name value and in `receipt/unreadable-fourth-field-sequence-holding-a-constructed-integer`:
the hand-off of the outermost constructed string gives it to
`d2i_ASN1_TYPE`, which refuses it (`tasn_dec.c:814`). So
`PRIMITIVE_ONLY_TAGS` duplicated the hand-off. A seventh string level
stays refused at any depth, and so does an end-of-contents inside a
constructed OCTET STRING of definite length (`asn1_collect`).
`receipt/unreadable-fourth-field-boolean-of-two-octets` stays
`UNREADABLE_PAYLOAD` because OpenSSL decodes that field itself. A
SignerInfo version in high-tag form, and an eContent with a UTF8String
chunk, verify on main and with the counter: the envelope walk never had
those two rules.

### The middle shape

`middle` puts back the two envelope rules OpenSSL does not apply inside a
kept value: each primitive of a constrained type outside a string goes
to `d2i_ASN1_TYPE`, and an end-of-contents inside a definite length is
refused. The payload's header-form rule and chunk check stay gone, and
`PRIMITIVE_ONLY_TAGS` stays gone because the string hand-off covers it.
`walk.rs` is 205 lines, `payload.rs` 167; `rust/openssl/src` is 2241
(−214 against main).

Every envelope answer of the probe matches main, full-decode counts
included, and no refusal before the signature changes. Failing: 4 shared
cases, all pinned, all after the signature
(`receipt/unreadable-attribute-type-in-high-tag-form`,
`receipt/app-item-id-in-high-tag-form-is-kept-raw`,
`receipt/unreadable-attribute-value-with-a-utf8string-chunk`,
`receipt/unreadable-double-wrap-with-a-foreign-chunk`), and the two unit
tests that pin the same rules
(`a_value_or_a_wrap_with_a_chunk_that_is_not_an_octet_string_is_unreadable`,
`a_tag_in_high_tag_form_or_a_five_octet_length_is_not_read`).

## Fuzzing

The counter, the narrowest shape, under the repository's own targets
(`rust/fuzz`, release with debug assertions, AddressSanitizer on the Rust
code, the vendored OpenSSL uninstrumented), seeded as `rust/fuzz/run.sh`
seeds them, 600 seconds each:

| Target | Runs | Coverage at the end | Crashes, timeouts, OOMs |
|---|---|---|---|
| `verify-receipt` | 414,811 | 1,522 edges (1,386 after the seeds) | 0 |
| `verify-receipt-base64` | 1,376,197 | 1,412 edges (1,122 after the seeds) | 0 |

No panic, so no trap under the Wasm profile's `panic = "abort"`, and
`verify-receipt`'s invariants (never `INTERNAL_ERROR`; an accepted
receipt fails under an unrelated anchor set) held. Ten minutes per target is a smoke
run, not a campaign. The middle shape adds back code from main and was
not fuzzed on its own.

## Decision

**Recommendation: (b) keep the walk**, with (c) as the only narrowing
worth the owner's time.

- (a) The counter is blocked. It turns `MALFORMED` before the signature
  into `ok` on one pinned shared case and on nine minted envelopes, three
  of them inside a certificate signed under the pinned root. Its −235
  lines would also need nine pinned cases changed in Rust, Java and
  fixtures together, against what Java and 0.7 answer.
- (c) The middle shape keeps every envelope answer and saves 214 lines.
  What it costs is four pinned payload cases where OpenSSL reads a form
  0.7 and BouncyCastle refuse. Those cases would become port-defined in
  one PR (Rust, Java, `fixtures/cases.json`), with four R20 entries,
  undoing the owner's 2026-09-30 choice that the core keeps 0.7's header
  rules, the one that made the five-octet case port-defined. In return
  that case's bundle id would match Java's.
- (b) Keeping the walk changes no answer. The envelope rules cost only
  21 of the counter's 235 lines; most of what (c) saves is the payload's
  0.7 header and chunk rules, which is what its four flips trade. An
  iterative rewrite that keeps every rule was not measured.

**Where this stops holding.** OpenSSL 4.0.2 as the adapter calls it. A
later OpenSSL that decoded the inside of a kept SEQUENCE, or that refused
high-tag forms below 31 or foreign string chunks, would make the matching
rule a duplicate and change the first table. The probes ran on a 64-bit
native build only.
