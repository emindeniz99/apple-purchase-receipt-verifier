# The receipt payload through OpenSSL's ASN.1 decoder

Date: 2026-09-26. Code, scripts and raw results:
`2026-09-26-openssl-asn1-payload/`. Its `README.md` has the file table and
the commands.

This round follows the owner's decisions after round 3:

- **Q27.** No Java-matching prescans: Apple-compatible and fail closed.
  `cases.json` is the contract, and Java is only a reference. The
  `asn1.rs` prescan is gone.
- **Q29.** `rust/src/asn1.rs` is deleted. The receipt payload is read with
  OpenSSL's ASN.1 API instead: Apple's `ReceiptAttribute` SET, the nested
  in-app purchase SETs inside OCTET STRINGs, and BER as in the Xcode
  receipts.

It starts from round 3's CMS build without the prescan
(`2026-09-26-openssl-cms-everywhere.md`) and reuses the adapter, runners and
corpora of the earlier notes of the same day unchanged.

Labels: TESTED (ran here), DOCUMENTED (read in a source, header, manifest
or registry), EXPECTED (inferred, not run). Nothing in `rust/`,
`docs/rust-core/` or any other production path changed. `DECISIONS.md` is
untouched. No system package was installed or upgraded. The one addition to
`$SCRATCH` was the clippy component for rustc 1.98.1.

## Results, one line per task

1. **Inventory (DOCUMENTED).** On the CMS path, `asn1.rs` has one real
   job left: the payload (`receipt_payload.rs`). It also has one incidental
   use: `roots.rs` parses every trust anchor with `x509.rs`, and OpenSSL
   then parses it again. `x509.rs`, `cms.rs`, `crypto.rs`, `chain.rs` and
   the Rust paths in `receipt.rs` and `jws.rs` are not called on the CMS
   path. Deleting them breaks public API, `tests/common` and five test
   files, and three fuzz targets.
2. **API choice (DOCUMENTED, TESTED).** The pick is (a), declarative
   templates: 14 lines of C declarations and one `ASN1_item_d2i` call. The
   runner-up is (b), generic `SET OF ANY` / `SEQUENCE OF ANY`, which needs
   no C and uses less memory, but its grammar lives in Rust checks and it
   is looser (it accepts extra fields). (c): rust-openssl exposes nothing
   generic. (d): `ASN1_get_object` is rejected because it is hand TLV
   walking. Neither implemented walk does any tag or length arithmetic.
3. **Implementation and parity (TESTED).** Both walks built and ran, and
   `asn1.rs` is deleted from the spike tree. That tree builds; its 11 unit
   tests pass and clippy is clean. Both walks run the full 1,179 corpus
   natively and match round 3's CMS build on 1,179 of 1,179 rows. The
   5,000 mutants also match on 4,999; the one difference, fuzz/1972, is a
   refusal either way, with `INVALID_SIGNATURE` becoming `INVALID_CHAIN`.
   Route C templates match on 1,179 of 1,179 rows on 9 hosts (Node, Bun,
   Deno, wazero, Wasmtime, workerd, Chromium, Firefox, WebKit); payload-any
   matches on Node, workerd and Chromium. Java-equal is 1,028 of 1,048 for
   every run, the same as the baseline. `cases.json` through the C ABI
   passes 153 of 153 with 272 fields. The 43 receipt fixtures read the
   same with all three readers: the three Xcode receipts, g5, legacy (187
   in-app purchases) and the 2,300-purchase caps.
4. **Fuzzing (TESTED).** The repository's `verify-receipt` target ran on
   the no-asn1 tree under ASan for 2,700 s: 2,999,045 execs, coverage 6,457
   to 6,493, 936 new units, 0 findings. A differential target (old reader
   against new) ran alongside it: 5,634,104 execs, 0 crashes. Its
   differences fall into 9 classes, and no genuine or fixture payload
   falls into any of them.
5. **Rust crates (DOCUMENTED, one probe TESTED).** rasn and bcder read
   every BER spelling of the payloads. der 0.8.2 reads indefinite lengths
   but refuses chunked OCTET STRINGs and long-form lengths. asn1 (pyca) is
   DER only. None is a better choice than OpenSSL for this one job when
   the owner wants a single substrate.
6. **Size (TESTED).** The whole security path goes from 2,100 code lines,
   0 `unsafe` and 0 C to 2,207 lines, 93 `unsafe` keywords (402 lines
   inside `unsafe`) and 14 C lines. Most of that is the adapter from
   earlier rounds. The payload alone goes from 518 lines and 0 `unsafe` to
   374 lines, 12 `unsafe` and 14 C lines.

## 1. What `asn1.rs` is used for today (DOCUMENTED)

`asn1.rs` is a public module (`pub mod asn1`), and five production modules
build on it. On the CMS path every use but one has already moved to
OpenSSL:

| Module | What it reads with `asn1.rs` | On the round-3 CMS path | In the no-asn1 tree |
|---|---|---|---|
| `x509.rs` (public) | the whole certificate: TBS fields, validity, SPKI, extensions, OIDs (`encode_oid`, `decode_oid`) | not called: `aprv_security_openssl::Certificate` (`d2i_X509`) | deleted |
| `cms.rs` (public) | ContentInfo, SignedData, SignerInfo, signedAttrs, messageDigest, the SET re-tagging for the signature | not called: `CMS_ContentInfo` (`cms_path.rs`) | deleted |
| `crypto.rs` (public) | `RSAPublicKey` inside the SPKI, `ECDSA-Sig-Value` | not called: EVP through the adapter | deleted, with the `rsa`, `p256`, `p384`, `sha1`, `sha2` and `digest` dependencies |
| `chain.rs` (public) | nothing directly; it walks `x509::Certificate`s | not called: `X509_verify_cert` | deleted |
| `receipt.rs` | `names_the_signer`: serial and issuer of an embedded entry that is not a certificate | not called: `CMS_SignerInfo_cert_cmp` | the Rust path removed; the device hash uses the adapter's SHA-1 and `subtle` |
| `jws.rs` | nothing directly; the Rust `x5c` path uses `x509`, `chain`, `crypto` | not called: the substrate's `verify_jws` | the Rust path removed |
| `roots.rs` | `TrustAnchor` holds a parsed `x509::Certificate` | **still called**: every anchor is parsed by `asn1.rs` at construction, then re-parsed by OpenSSL from `.der()` | holds the DER after `d2i_X509` plus the adapter's readability check |
| `substrate.rs` (spike) | the prescan over the whole receipt | removed by Q27 | removed |
| `receipt_payload.rs` | **the payload**: the attribute SET, the Xcode double wrap, every attribute's INTEGER type and OCTET STRING value, the nested in-app SETs, each value's UTF8String, IA5String or INTEGER, and the pre-trust creation-date walk | **still called**: the only real use left | OpenSSL through the adapter (section 3) |

So the payload is the one job left, plus one incidental use: trust anchors
are still parsed by `x509.rs` at construction.

Deleting `asn1.rs` also removes public API. `pub mod asn1`, `x509`, `cms`,
`crypto` and `chain` go, and `TrustAnchor::certificate()` and
`From<x509::Certificate>` go with them. That is a breaking change for a 0.x
crate. It also breaks code in the repository that was not moved here:

- `tests/common/mod.rs` builds its fixtures with `asn1::tag` and
  `encode_oid`, so every integration test that includes it stops
  compiling;
- `tests/asn1.rs`, `tests/hostile.rs`, `tests/receipt_negative.rs`,
  `tests/trust_pinning.rs` and `tests/jws_negative.rs` use the deleted
  modules directly;
- the fuzz targets `parse-der`, `parse-certificate` and `parse-cms` fuzz
  the deleted modules.

The spike tree deletes the three fuzz targets. It does not rewrite the
tests: it runs the library's own unit tests and the C ABI conformance run
of all of `cases.json` instead (section 3).

## 2. Which OpenSSL API reads the payload best

The grammar being read is Apple's, as `receipt_payload.rs` reads it today:

```
Payload          ::= SET OF ReceiptAttribute   -- sometimes wrapped once more in an OCTET STRING (Xcode)
ReceiptAttribute ::= SEQUENCE { type INTEGER, version INTEGER, value OCTET STRING }
-- value holds a UTF8String, IA5String or INTEGER, or (type 17) another Payload
```

The four options, judged from OpenSSL 4.0.2's headers (`asn1.h`,
`asn1t.h`), its decoder (`crypto/asn1/tasn_dec.c`) and openssl 0.10.81's
source, and by building (a) and (b):

| Criterion | (a) templates + `ASN1_item_d2i` | (b) `ASN1_SET_ANY` / `ASN1_SEQUENCE_ANY` / `ASN1_ANY` via openssl-sys | (c) rust-openssl safe API | (d) `ASN1_get_object` |
|---|---|---|---|---|
| Tag or length arithmetic in our code | none: OpenSSL matches every tag and length against the declared grammar | none: OpenSSL decodes each element; Rust checks element *types* (`V_ASN1_SEQUENCE`, `V_ASN1_INTEGER`, `V_ASN1_OCTET_STRING`) and field count | n/a: no generic decoder | all of it: the caller advances the pointer, tracks constructed, indefinite and EOC. This is hand parsing |
| Grammar lives in | 14 declaration lines in `payload.c` | Rust checks in `payload_any.rs` | — | Rust |
| Depth bound | fixed by the grammar; template nesting is capped by `ASN1_MAX_CONSTRUCTED_NEST` (30) and constructed strings by `ASN1_MAX_STRING_NEST` (5) | the same caps. `SEQUENCE`, `SET` and non-universal values inside ANY stay raw, so they are not recursed into | — | ours to write |
| Memory at the 3 MiB payload cap (payload only, TESTED) | +58 MiB over a tiny payload: the whole tree is built at once | +20 MiB: the SET is held as one raw string per attribute, and each attribute's fields are decoded and freed in turn | — | — |
| BER indefinite lengths, constructed strings | yes (TESTED, section 3). The end of an indefinite ANY is found with a counter, not recursion | yes (TESTED) | — | ours to write |
| Ownership | one root, one `ASN1_item_free` (a `Drop` guard) frees the tree. Values are copied out before the guard drops | the same, per decoded item | — | — |
| `unsafe` in the payload code | 12 keywords, 12 lines | 11 keywords, 11 lines | — | — |
| C lines | 14 (declarations only, no logic) | 0 | 0 | 0 |
| Extra attribute fields (4th element) | refused (`SEQUENCE_LENGTH_MISMATCH`), like Apple's grammar | accepted, like `asn1.rs` | — | — |
| Route C wasm | unchanged: `payload.c` compiles with wasi-sdk next to OpenSSL; still only the two `aprv` imports (TESTED on 9 hosts) | unchanged (TESTED on Node, workerd, Chromium) | — | — |

Notes behind the table:

- **Why (a) needs C at all.** The template macros expand to static
  `ASN1_ITEM` tables that only a C compiler can produce. OpenSSL 4.0 also
  made `ASN1_STRING` opaque, so declaring a CHOICE of string types
  (`IMPLEMENT_ASN1_MSTRING`) fails outside libcrypto with "invalid
  application of sizeof to incomplete type". String values therefore use
  libcrypto's exported `DISPLAYTEXT_it` (UTF8String, IA5String,
  VisibleString, BMPString), and Rust keeps only UTF8String (12) and
  IA5String (22) by checking `ASN1_STRING_type`. The attribute's
  `version` is declared `ASN1_ANY`, because Apple's code ignores it and
  `asn1.rs` never type-checked it.
- **What (c) offers.** openssl 0.10.81 has `Asn1Integer`, `Asn1StringRef`
  and friends, but no `d2i` for a SET OF, a SEQUENCE OF or an ANY, and no
  way to declare an item. Both (a) and (b) therefore go through openssl-sys
  plus a few `extern` declarations for public libcrypto symbols it does
  not carry (`ASN1_item_d2i`, `ASN1_item_free`, `ASN1_INTEGER_get_int64`,
  the `*_it` item functions).
- **Why (d) is out.** `ASN1_get_object` returns a tag, a class and a
  length and leaves everything else to the caller: advancing, checking the
  length against the remaining input, the indefinite form (flag `0x21`),
  and matching EOCs. That is exactly the hand-written TLV walk `asn1.rs`
  already is, only in `unsafe` Rust.
- **Both implemented walks refuse trailing bytes** after the top-level
  item. `ASN1_item_d2i` does not check this itself; the shared
  `decode_exact` helper compares the advanced cursor with the input end.
- **Fail closed.** Every decode failure drains OpenSSL's error queue and
  maps to `INVALID_RECEIPT_FORMAT` in the core, the same kind as today.

**Pick: (a), templates.** It is the only option where the grammar itself
(three fields, their types, SET OF) is declared once and enforced by
OpenSSL, and it refuses attributes Apple's grammar does not allow. It costs
14 lines of C declarations and about 38 MiB more peak memory than (b) at the
3 MiB cap. The comparison is close, so (b) was built as well: it needs no C
and no `cc` build step, and uses less memory, but it keeps the grammar in
Rust type checks and accepts a fourth field. Both give identical results on
every corpus row, and the differences between them show up only in the
differential fuzzing (class S3, section 3).

## 3. The implementation, and what it returns

### What was built (TESTED)

- **Adapter** (`adapter/`, applied with `adapter-asn1.patch`). There is a
  new module `payload` with three functions:
  - `receipt_attributes(der)`: the attribute list. It first tries the
    Xcode double wrap (one OCTET STRING around the SET) and falls back to
    the bare SET.
  - `attribute_integer(der)`
  - `attribute_string(der)`

  An `Attribute` is its signed `type` and the joined content octets of
  its `value`. `build.rs` compiles `payload.c` with `cc` unless the
  feature `payload-any` is set. A second feature, `payload-diagnostics`,
  keeps OpenSSL's reason codes for the differential fuzzer; it is off in
  every build that was measured.
- **Core** (`patch/no-asn1.patch`). The patch deletes `asn1.rs`,
  `x509.rs`, `cms.rs`, `crypto.rs` and `chain.rs`, and makes these
  changes:
  - `receipt_payload.rs` keeps its whole attribute mapping, the in-app
    purchase recursion, the date rules and the pre-trust creation-date
    walk, but asks the adapter for attributes, integers and strings
    instead of walking TLVs.
  - `TrustAnchor` stores the DER after `Certificate::from_der` and the
    adapter's readability check.
  - The device hash uses the adapter's SHA-1 and `subtle::ConstantTimeEq`.
  - The `rsa`, `p256`, `p384`, `sha1`, `sha2` and `digest` dependencies
    are removed.
  - Building the core without the substrate is now a `compile_error!`.
- **Check.** `scripts/build.sh check-new` runs the library's unit tests
  (11 of 11) and `cargo clippy --lib -D warnings` for both walks:
  clean (`results/check-new.txt`). Nothing named `asn1` is left in
  `src/`. The ffi crate's copied `Cargo.lock` does not list `cc`, but the
  built libraries contain the `APRV_RECEIPT_PAYLOAD_it` symbols, so
  `payload.c` was compiled in.

### Parity with round 3's CMS build (TESTED)

Baseline: round 3's CMS build without the prescan, rebuilt here (`base`).
It matches round 3's own rows (`ossl402cms`) on 1,179 of 1,179 corpus rows
and 5,000 of 5,000 mutants.

| Build | Hosts | cases (153) | hostile (811) | algorithms (22) | substrate (193) | 5,000 mutants |
|---|---|---|---|---|---|---|
| `new` (templates), native C ABI | — | same | same | same | same | 4,999 same, 1 differs |
| `any` (payload-any), native C ABI | — | same | same | same | same | 4,999 same, 1 differs |
| `new-c` (templates), Route C | Node, Bun, Deno, wazero, Wasmtime, workerd, Chromium, Firefox, WebKit | same | same | same | same | not run |
| `any-c` (payload-any), Route C | Node, workerd, Chromium | same | same | same | same | not run |

No run trapped. Every Route C module imports only `aprv.clock_now_ms`
and `aprv.random_get`.

**The one difference, `fuzz/1972`.** Base refuses it with
`INVALID_SIGNATURE`; both new builds refuse it with `INVALID_CHAIN`
(`X509_V_ERR 10`, expired). The mutation shortened the `type` INTEGER of
the app-version attribute to zero content octets (`30 0d 02 00 03 02 01
01 04 05 …`), so the old `02 01 01` version now parses as a BIT STRING.
`asn1.rs` reads the empty INTEGER as 0 and keeps going. OpenSSL refuses it
(`ILLEGAL_ZERO_CONTENT`, class S1 below), which fails the whole payload.
So the new pre-trust walk finds no creation date, and the chain is judged
at the current time rather than the receipt's 2025-06-01. The chain has
expired by now, so it is refused before the signature (which the mutant
also broke) is checked. Both builds refuse the receipt; only the reason
changes.

**Other checks:**

- **`cases.json` through the C ABI** (`rust/ffi/tests/conformance.py`):
  153 passed, 272 expected fields checked, for base, new and any.
- **Java tallies:** Java-equal is 1,028 of 1,048 for every run, and the
  tallies are identical to base's per corpus. Round 3 with the prescan had
  1,030; the two rows are the ones the prescan existed for, and Q27
  dropped it.
- **Payload replay** (`results/payload-replay.txt`): each of the 43
  receipt fixture files is read by the old reader, templates and
  payload-any through the same core. The output covers the attribute
  map, the in-app list and the pre-trust date, and is identical on all 43.
  They include:
  - g5 (2 in-app purchases);
  - legacy (187);
  - `receipt-xcode-with-purchases`, `xcode-app-receipt-empty` and
    `xcode-app-receipt-with-transaction`;
  - the Node floor and the at-cap receipts (2,300 purchases, 3,130,492
    bytes);
  - every negative payload fixture.

  The Xcode receipts are BER in their CMS wrapping only; their payloads
  are DER.
- **BER spellings** (`results/ber-variants.txt`, `py/ber_variants.py`).
  The eight fixture payloads are re-spelled five ways:
  - indefinite lengths everywhere;
  - OCTET STRINGs chunked into constructed segments;
  - both of those together;
  - non-minimal long-form lengths;
  - chunked UTF8String values.

  The first four read identically with all three readers. For the chunked
  UTF8String, `asn1.rs` refuses (`ERR`) and both OpenSSL walks accept
  (class L4). On all 8 payloads they read the same decoded fields as from
  the DER original, and the same pre-trust date. The raw value bytes they
  keep (`*_bytes`, unknown attributes) are the chunked bytes, since that is
  what the input holds.

### Where the readers differ: the differential run (TESTED)

`fuzz/payload-diff.rs` runs the old reader (the repository's
`receipt_payload.rs` and `asn1.rs`, included with `#[path]`) and the new
one on the same raw payload in one ASan binary, and files every
disagreement:

- whether each reader accepts;
- the attribute map;
- the in-app list;
- the pre-trust date.

To classify a difference, the harness re-runs the culprit attribute alone
(a one-element SET) to find where the readers part.
`py/diff_classes.py` then replays that with an emulator of the old reader
to find where it stops, and matches the result against
`results/diff-classes.tsv`. The final replay covers 15,407 inputs (the
campaign corpus, the seeds and the filed differences) and yields 379
signatures for templates and 319 for payload-any. Every signature falls
into one of these classes:

| Class | New reader vs `asn1.rs` | X.690 | Templates: signatures / inputs | payload-any |
|---|---|---|---|---|
| L1 | accepts a `version` whose *contents* are malformed: the ANY is kept opaque and never parsed (Apple's code ignores the field) | — | 127 / 4,322 | 101 / 3,091 |
| L2 | accepts a tag number below 31 written in the long form | §8.1.2.2 requires the one-octet form | 14 / 563 | 15 / 587 |
| L3 | accepts a constructed OCTET STRING whose segment is another universal type (OpenSSL checks the segment's class, not its tag) | §8.7.3 requires OCTET STRING segments | 80 / 2,564 | 61 / 1,688 |
| L4 | accepts a constructed (chunked) UTF8String or IA5String value | allowed in BER | 3 / 150 | 3 / 150 |
| L5 | accepts a SET OF whose identifier has the constructed bit clear (`0x11`); the SET OF template passes no constructed check | §8.12.1 requires constructed | 17 / 397 | 16 / 352 |
| S1 | refuses an INTEGER with empty contents (`ILLEGAL_ZERO_CONTENT`) | §8.3.1 requires at least one octet | 11 / 372 | 11 / 383 |
| S2 | refuses a non-minimal INTEGER (`ILLEGAL_PADDING`) | §8.3.2 forbids it in BER too | 11 / 254 | 11 / 255 |
| S3 | refuses an attribute with more than three fields | Apple's grammar has three | 39 / 1,357 | none (accepted, as by `asn1.rs`) |
| S4 | refuses a `version` value that OpenSSL's ANY decoder rejects: BOOLEAN or NULL of the wrong length, a bad OID, a short time, and so on (payload-any: also in an extra field) | e.g. §8.2.1, §8.8.2 | 77 / 1,684 | 101 / 2,063 |

L means the new reader accepts what `asn1.rs` refused; S means it refuses
what `asn1.rs` accepted. `results/diff-classes.txt` lists every signature
with its shortest culprit in hex.

What the classes mean for the verifier:

- **No genuine or fixture payload hits any class.** The replay and BER
  runs above show this, and so does the 1,179-row parity.
- **The S classes are fail-closed.** In each of them OpenSSL refuses an
  encoding X.690 or Apple's grammar forbids, and `asn1.rs` was the lenient
  one.
- **L2, L3 and L5 are OpenSSL leniencies:** encodings X.690 forbids even
  in BER, which OpenSSL reads anyway. L1 is leniency by design (an ANY
  that is never looked at), and L4 is legal BER that `asn1.rs` did not
  support.
- **After trust, only Apple-signed bytes reach the reader.** The payload
  is read after the CMS signature verifies, so the L classes can change a
  verdict only for payloads Apple itself signed. Before trust, the reader
  runs only for the creation-date walk, where a difference moves the chain
  time between the receipt's date and now, as in `fuzz/1972`. Either
  choice is then checked by `X509_verify_cert` and the signature.
- **Making L1 to L5 fail closed (EXPECTED, not tried).** Re-encode the
  decoded tree with `ASN1_item_i2d` and compare it with the input. That
  would also refuse every BER spelling accepted today (indefinite
  lengths, chunked strings), which Q29 asks to keep. So it is listed here
  as an option, not a recommendation.

### Memory (TESTED)

`py/memory.py` builds four synthetic payloads and runs each through the
spike's `spike_payload` example, recording peak RSS:

- `tiny`;
- `flat-max`: 3 MiB of small attributes;
- `in-app-max`: 3 MiB inside one in-app SET;
- `deep-version`: 786,000 nested indefinite SEQUENCEs in one `version`.

`py/memory_cms.py` wraps the same payloads in a receipt and runs them
through the C ABI and Route C.

| Payload | `asn1.rs` | templates | payload-any |
|---|---|---|---|
| tiny, reader only | 33 MiB, OK | 33 MiB, OK | 33 MiB, OK |
| flat-max, reader only | 33 MiB, refused at its node budget | 92 MiB, OK | 54 MiB, OK |
| in-app-max, reader only | 33 MiB, refused at its node budget | 93 MiB, OK | 55 MiB, OK |
| deep-version, reader only | 33 MiB, refused | 33 MiB, OK in 0.02 s | 33 MiB, OK in 0.03 s |
| flat-max receipt, native C ABI | 47 MiB | 122 MiB | 84 MiB |
| flat-max receipt, Route C on Node (tiny: 67 MiB) | — | 145 MiB | 124 MiB |

The old reader caps the number of nodes; OpenSSL has no node cap. Memory
is bounded by the core's 3 MiB DER limit on its input instead, which gives
about 20 times the input for templates and 7 times for payload-any at the
cap. `deep-version` costs nothing, because an ANY that holds a SEQUENCE
is kept raw and its end is found with a counter. The synthetic receipts
have no signer, so they are all refused (`INVALID_RECEIPT_FORMAT`), but
only after the pre-trust date walk has read the payload.

### Route C size (TESTED)

| Module | raw | strip + gzip -9 |
|---|---|---|
| round 3 `cms-c.wasm` (CMS + `asn1.rs` payload) | 3,000,116 | 986,315 |
| `new-c.wasm` (templates) | 2,973,532 | 975,767 |
| `any-c.wasm` (payload-any) | 2,973,546 | 975,601 |

The native C ABI library shrinks from 8,619,736 to 8,532,952 bytes, because
the RustCrypto crates are gone.

### Not tested

- payload-any in Route C ran on three hosts (Node, workerd, Chromium), not
  nine.
- The differential run covers the payload reader alone. The whole receipt
  path is covered by `verify-receipt` (section 4) and by parity, not
  differentially.
- The 5,000 mutants ran natively only.
- The repository's integration tests that use the deleted modules were
  not rewritten (section 1).

## 4. Fuzzing the receipt path without `asn1.rs`

The setup (TESTED; `results/fuzz-campaign.txt` has the full detail):

- **Tree.** The no-asn1 tree on the CMS path, with the payload read
  through the templates and no prescan.
- **Toolchain.** OpenSSL 4.0.2 built with clang 18, ASan and
  `-fsanitize=fuzzer-no-link`. Rust is nightly 1.100.0 with cargo-fuzz
  0.13.2, because `-Zsanitizer` needs nightly; that is the one exception
  to rustc 1.98.1.
- **Flags.** `-max_total_time=2700 -timeout=10 -rss_limit_mb=2048
  -max_len=65536` and `ASAN_OPTIONS=detect_leaks=1`.
- **Load.** Both targets ran at once on a 4-core machine that was also
  running this round's builds, so exec/s is lower than in round 3.

| Target | Seeds | Execs | exec/s | Coverage (start to end) | New units | Peak RSS | Findings |
|---|---|---|---|---|---|---|---|
| `verify-receipt` (the repository's, unchanged) | 3,834 (round 3's corpus, the follow-up's, and the receipt seeds) | 2,999,045 | 1,110 | 6,457 to 6,493 (ft 21,361) | 936 | 618 MB | 0 |
| `payload-diff` (old reader against templates) | 601 payloads (every fixture's eContent, its BER spellings, the corpora's eContents) | 5,634,104 | 2,085 | 2,080 to 2,776 (ft 13,660) | 2,967 | 540 MB | 0 crashes; differences are in section 3 |

No crash, leak, timeout or OOM in either binary, and no artifact to
minimise.

Two caveats:

- The `verify-receipt` binary was built before a refactor of the
  adapter's refusal helper (`refused()`). With diagnostics off, its path
  is the same as the final source's.
- The `payload-diff` binary that ran was an earlier revision with the
  same comparison but coarser signatures. The class table in section 3
  comes from replaying all 15,407 inputs through the final harness, once
  for each walk.

Coverage grew only a little on `verify-receipt` (+36 edges). Round 3's
corpus already reached the CMS path, and the payload walk is now a few
OpenSSL calls rather than 265 lines of Rust.

## 5. Rust ASN.1 crates

The research only (DOCUMENTED, 2026-09-26) draws on:

- the crates.io API;
- each crate's published `.crate` source, counted by `scripts/crates.sh`;
- the repository head;
- rustsec.org.

On top of that, a small probe (TESTED, `probe/`) read the eight fixture
payloads and their BER spellings with der, rasn and bcder.
`results/crates.txt` and `results/crate-probe.txt` have the raw rows.

| Crate | Maintainer, notable users | BER indefinite length | `unsafe` in source | `forbid(unsafe_code)` | Downloads (all / 90 d) | Last release | Licence | Fuzzing / advisories |
|---|---|---|---|---|---|---|---|---|
| der 0.8.2 | RustCrypto; spki, pkcs8, x509-cert, ecdsa (340 dependents) | partly (TESTED): reads indefinite lengths, refuses chunked OCTET STRINGs ("not canonically encoded as DER") and long-form lengths | 4 | no | 474 M / 115 M | 2026-09-05 | Apache-2.0 OR MIT | fuzz targets for sibling crates (x509-cert, tls_codec), SECURITY.md, a cargo-audit config; no advisory |
| rasn 0.28.15 | librasn; rasn-pkix, rasn-cms, c2pa, apple-codesign (63) | yes (TESTED, every spelling) | 2 | no | 14 M / 2.6 M | 2026-09-25 | MIT OR Apache-2.0 | fuzzing directory; no advisory |
| asn1 0.24.1 | pyca (the Rust core of Python `cryptography`); rasn (18) | no: DER only (DOCUMENTED) | 0 | yes | 16 M / 3.7 M | 2026-03-21 | BSD-3-Clause | fuzz targets; no advisory |
| der-parser 10.0.0 | rusticata; x509-parser, webauthn-rs, webrtc-dtls (40) | yes, BER parser (DOCUMENTED, not probed) | 0 | yes | 167 M / 44 M | 2025-01-21 | MIT OR Apache-2.0 | fuzz targets; no advisory |
| asn1-rs 0.7.2 | rusticata; x509-parser, der-parser, c2pa, and `app-store-server-library` (a community App Store crate) (29) | yes, `FromBer` (DOCUMENTED, not probed) | 0 | yes | 163 M / 45 M | 2026-05-18 | MIT OR Apache-2.0 | CI only, no fuzz directory found; no advisory |
| bcder 0.7.7 | NLnet Labs; x509-certificate, cryptographic-message-syntax, apple-codesign (21) | yes (TESTED, every spelling) | 9 | no | 25 M / 4.3 M | 2026-06-08 | BSD-3-Clause | fuzz targets; RUSTSEC-2023-0062, a decoder panic on invalid input (patched in 0.7.3) |
| yasna 0.6.0 | qnighy; rcgen, webpki-roots, russh (73) | BER mode (DOCUMENTED, not probed) | 0 | yes | 107 M / 31 M | 2026-03-14 | MIT OR Apache-2.0 | fuzz targets; no advisory |
| simple_asn1 0.6.4 | jsonwebtoken (45) | no: DER only (DOCUMENTED) | 0 | no | 178 M / 42 M | 2026-02-12 | ISC | fuzz targets; RUSTSEC-2021-0125, a panic on an incorrect date (patched in 0.6.1) |
| picky-asn1 0.10.1 (+ picky-asn1-der 0.5.6) | Devolutions; picky, sspi, tss-esapi (15) | no: DER (serde) only (DOCUMENTED) | 2 (+0) | no | 8 M / 1.9 M | 2025-01-16 (der: 2026-04-21) | MIT OR Apache-2.0 | fuzzing in the picky repository; no advisory |

In the "BER indefinite length" column, "DOCUMENTED" means the crate's
documentation and source say so (the source-mention counts are in
`results/crates.txt`); only der, rasn and bcder were run.

**Probe.** All three crates read the eight DER payloads with the same
attribute lists: 11, 11, 14, 23, 208, 10, 9 and 10 attributes. On the 40
BER spellings (five per payload):

- rasn and bcder read all 40.
- der reads the indefinite and chunked-UTF8String spellings.
- der refuses the 8 chunked-OCTET-STRING spellings and the 8 long-form
  length spellings: 16 of 40.

**Is any crate a better choice than OpenSSL's API for this one job?** Not
while the owner wants a single mature substrate. After this round, OpenSSL
already decodes every other byte of the receipt: the CMS wrapper, the
certificates, the signature. Its ASN.1 decoder is also the one the round-3
and round-4 fuzz campaigns ran through. A Rust crate would bring back a
second ASN.1 parser for one SET OF SEQUENCE, with its own leniencies to
compare against OpenSSL's (section 3 shows how many such differences two
careful readers produce).

If a pure-Rust reader were ever wanted instead, for example to drop the
C file, rasn or bcder are the candidates: both read every BER spelling
here. bcder is what the Rust CMS and Apple code-signing crates
(cryptographic-message-syntax, apple-codesign) build on, and it has one
past advisory. der is
DER-first and refuses two of the BER spellings. asn1 (pyca) and
simple_asn1 are DER only.

## 6. Size of the security path, before and after

Counted by `scripts/loc.sh` (`py/loc.py`; `results/loc.txt`). "Code" is
non-blank, non-comment lines outside `#[cfg(test)]`. The "unsafe" column
counts `unsafe` keywords, and "lines in unsafe" counts code lines inside
`unsafe` blocks and functions (TESTED).

"Before" is today's repository: the pure-Rust security path (`asn1.rs`,
`x509.rs`, `cms.rs`, `crypto.rs`, `chain.rs`, `receipt_payload.rs`,
`receipt.rs`, `jws.rs`, `roots.rs`). "After" is the no-asn1 tree plus
the whole OpenSSL adapter (`lib.rs`, `cms_path.rs`, the payload files),
which is where the `unsafe` now lives.

| Scope | Code lines | `unsafe` keywords | Lines in `unsafe` | C lines |
|---|---|---|---|---|
| Whole security path, before (pure Rust, 9 files) | 2,100 | 0 | 0 | 0 |
| Whole security path, after, (a) templates | 2,207 | 93 | 402 | 14 |
| Whole security path, after, (b) payload-any | 2,227 | 92 | 401 | 0 |
| Payload only, before (`asn1.rs` + `receipt_payload.rs`) | 518 | 0 | 0 | 0 |
| Payload only, after (a) (`payload.rs`, `payload_templates.rs`, `payload.c`, `receipt_payload.rs`) | 374 | 12 | 12 | 14 |
| Payload only, after (b) (`payload.rs`, `payload_any.rs`, `receipt_payload.rs`) | 394 | 11 | 11 | 0 |

Most of the `unsafe` (81 keywords, 390 lines) is the adapter from the
earlier rounds (`lib.rs` and `cms_path.rs`): the certificate, CMS, EVP and
JWS paths. This round adds 12 `unsafe` keywords for the payload and
removes 1,067 lines of pure Rust:

- `asn1.rs`, 265 lines;
- `x509.rs`, 374;
- `cms.rs`, 148;
- `crypto.rs`, 198;
- `chain.rs`, 82.

Every `unsafe` block in the payload code carries a SAFETY comment, and no
pointer leaves the adapter.

For scale, not ours: OpenSSL 4.0.2's `crypto/asn1/*.c` is 15,964 lines
in 65 files, of which the template decoder `tasn_dec.c` is 1,270.
