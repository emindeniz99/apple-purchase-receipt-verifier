# The core review's fixes: one header walk, restored bounds, parity

Date: 2026-09-29. Branch `lane/core`, from 05b4ad9 (lane A2's module).

**Question.** Three reviews of the OpenSSL-backed core (adapter C
templates, adapter Rust, core policy) found bounds that the migration lost
or skipped, and payload rules that changed without a record. Do the fixes
restore 0.7's bounds at a bounded cost, which verdicts move, and does the
rebuilt `aprv.wasm` still answer as its native twin? It feeds the merge of
the rust-core branch and `docs/rust-core/DECISIONS.md` R20's divergence
table.

**Versions.** Rust 1.98.1, OpenSSL 4.0.2 (native and wasm32-wasip1
no-asm), wasi-sdk and wasm-tools from `tools/wasm-toolchain.sh` (lane D's
pins), wit-bindgen 0.62.0, Node v22.22.2 (trap host, V8), Wasmtime 49.0.1
(ABI tests), OpenJDK 21 for the Java suite, Python `cryptography` 50.0.1
for the fixture generator.

## What changed

One `ASN1_get_object` header walk (`rust/openssl/src/walk.rs`) runs over
the whole envelope before `d2i_CMS_ContentInfo`, and over the signed
payload before its template decode. It decodes no value: it counts every
constructed value of any class (depth 32, outermost 1) and every value
(100,000), follows indefinite lengths to their end-of-contents, and checks
the primitives OpenSSL keeps whole inside an `ANY` (BOOLEAN, INTEGER, BIT
STRING, NULL, OID, ENUMERATED, UniversalString, BMPString). For the payload
it also refuses the header forms 0.7 refused (high tag form, a length of
more than four octets). The envelope is first decoded shallowly
(`ContentInfo`, then `SignedData` with its members as raw `ANY`), so the
10-certificate, 4-SignerInfo and new 10-CRL bounds are counted before
anything is decoded in full; an envelope the shallow decode refuses is
refused there and never reaches the full decode (a counter behind
`__internal::cms_full_decodes_during` pins it). Failures are `MALFORMED`
over the envelope and `UNREADABLE_PAYLOAD` over the signed payload.

## Findings and disposition

C = adapter C review, Rust = adapter Rust review, Policy = core policy
review, N = the Rust review's notes. Costs "before" are the reviewers'
(native release build unless marked); "after" and the Wasm "before" are
this lane's, through `aprv.wasm` in V8 with the canonical ABI called by
hand, second call on a fresh instance (`results/review-inputs-wasm.txt`,
`out` = A2's module at 05b4ad9, `out2` = this lane's).

| Id | Finding | Disposition | Input | Before | After |
|---|---|---|---|---|---|
| C-F1, Policy-F3 | Member bounds skipped whenever the shallow decode fails (one trailing byte, no signerInfos) | Fixed: shallow decode and bounds before the full decode; the refusal returns before it | 1,834 to 5,440 certificates + 1 trailing byte; `nosigners` | 59 to 725 ms native, 1,008 to 1,109 ms Wasmtime; Wasm 105 to 1,178 ms | Wasm 18.8 to 28.2 ms, `MALFORMED`; zero full decodes (`envelope_bounds.rs`) |
| Rust-F2 | Same bound skipped for any content type but signedData | Fixed by the same shallow `ContentInfo` | `envelopedData` flood | 91 to 150 ms native; Wasm 126 to 1,033 ms | Wasm 20.2 to 21.3 ms |
| C-F2, Rust-F3, Policy-F2 | Depth counted only for SEQUENCE/SET inside SignerInfo values | Fixed: the walk counts every constructed value of the envelope | 40-deep nests behind context tags, in digestAlgorithms, in a crls `other` entry | verified (Wasm 1.3 to 1.7 ms) | `MALFORMED`, 0.1 ms; five shared cases |
| Rust-F4, Policy-F6 | No node budget before any cryptography | Fixed: 100,000 values over the envelope and each attribute SET | 1.17 M empty SEQUENCEs in an unsigned attribute | 0.61 to 0.9 s native, 138 to 144 MB RSS; Wasm 721 ms, 107 MB | `MALFORMED`, Wasm 10.2 ms, 14.5 MB |
| C-F6 | Pre-trust payload work unbounded | Fixed: the payload budget, and the creation date is read only once a signer certificate is found | unsigned content of 213,754 tiny attributes; deep-wide 4th field | 317 to 350 ms native, 115 to 143 MB; Wasm 287 to 352 ms, 58 to 123 MB | Wasm 40 to 45 ms, 19.2 MB (`INVALID_SIGNATURE`, unchanged) |
| Policy-F6 (Node lane) | `flat-max`: no embedded signer, 3 MiB of tiny attributes | Fixed: no signer certificate, no payload read | `wasm_cost.mjs hostile` | Node host 0.8 s, 73.9 MiB; Wasm 325 to 402 ms, memory 1.9 → 73.8 MiB | 16.5 to 26.1 ms, 1.9 → 16.1 MiB; same answer (`results/hostile-memory.txt`) |
| C-F5 | `crls` neither counted nor bounded | Fixed: at most 10 (`MALFORMED`); R20 row | genuine receipt + 39,121 CRLs | verified, 319 ms native, 53 MB; Wasm 435 ms | `MALFORMED`, Wasm 22.7 ms |
| C-F4, Rust-F1, Policy-F4 | eContent chunk check one level short of OpenSSL, wrong message | Fixed: `level > MAX_STRING_NEST`; six constructed levels verify, seven are OpenSSL's refusal (R20 row) | genuine receipt re-chunked | 6 levels `MALFORMED` "not an OCTET STRING" | 6 levels verify; 7 `MALFORMED` |
| C-F3, Rust-F6, Policy-F5 | Payload accepts foreign chunks, other header forms, invalid primitives | Fixed where 0.7's rule is cheap in the walk (foreign chunks, high tag form, long lengths, invalid primitives; `UNREADABLE_PAYLOAD` or kept raw as 0.7); the 7-level string recorded in R20 | minted signed payloads | verified with joined octets | 0.7's answers; 12 shared cases |
| C-F7, Rust-N10, Policy-F7 | THREAT-MODEL proofs cite deleted code | Fixed: `asn1.rs` cite, four fuzz targets, the re-encoding sentence, §3.3 steps 1 and 2 describe the code | reading | | |
| C-F8 | Unused exported item, missing prototypes, hand-mirrored layout | Fixed: `APRV_SIGNED_DATA_it` now used, `DECLARE_ASN1_ITEM` prototypes, `_Static_assert` and Rust `const` size/offset checks on both mirrors | reading | | |
| Rust-F5, Policy-F1 | Vendored openssl-sys committed without `build/` | Fixed by 947a5bb; a fresh `git clone` of `lane/core` builds (`results/fresh-clone-build.txt`) | clone | "couldn't read build/main.rs" | builds |
| Rust-N1 | `BIO_set_md` result ignored | Fixed: checked, fails closed | reading | | |
| Rust-N2 | `signer_digest_known` true for digests OpenSSL cannot run | Not fixed: the answer is `INVALID_SIGNATURE` either way (md4, mdc2, whirlpool, shake128 inputs, Wasm 1.0 to 2.8 ms); only the message would change, across corpus rows | reviewer inputs | | unchanged |
| Rust-N3 | Verify callback drops a problem it cannot record | Fixed: the callback fails the verification then | reading | | |
| Rust-N4 | `verify_path` precondition undocumented | Fixed: documented | reading | | |
| Rust-N5 | `OPENSSL_init_crypto` result ignored | Not fixed: the call fails only once OpenSSL is unusable, and init is untouched in this lane | reading | | |
| Rust-N6 | notAfter-second waiver dead on OpenSSL 4 | Comment says so; kept as a guard should a later OpenSSL change back, with the millisecond tests pinning the boundary | reading | | |
| Rust-N7 | Isolation limits unnamed | Named in `rust/openssl/README.md` | reading | | |
| Rust-N8 | `keys_used_during` not panic-safe | Fixed: a drop guard restores the recorder | reading | | |
| Rust-N9 | `has_extension` accepts names | Documented: callers pass dotted OIDs only | reading | | |
| Policy-F8 | Millisecond validity boundary untested | Fixed: tests on both sides of the boundary for a JWS and a dateless receipt | | | |
| Policy-F9 | Keyless-target path accepts issuers `X509_verify_cert` would not | Not fixed: the target on that path is refused afterwards whichever issuer it has (`INVALID_CERTIFICATE` for a receipt signer, a failed ES256 for a JWS leaf), so only the reason could change and nothing verifies | | | |
| Policy-F10 | README overstated critical-extension processing | Fixed: "accepted", not "processed" | | | |
| Swift host | Root choice among same-subject pinned roots depended on order | Fixed: among anchors sharing a subject, only those that issued the chain are stored; four shared cases, both orders. Apple's three roots have distinct subjects, so production chains never met it | minted root pair | second root `UNTRUSTED_CHAIN` | verifies in either order |
| Swift host | Even RSA modulus in the signer | Case added: `UNTRUSTED_CHAIN`; Java agrees | receipt byte 1121 zeroed | | |
| Go host | A raw call whose argument range runs past linear memory answers a value | Documented refusal in `rust/bindings/abi/README.md`: caps and early base64 failures decide before the first byte outside memory; any read outside it traps | reading | | |
| Go host | init 13 to 27 ms | Not touched: this lane changed no init code (roots parsing, `OPENSSL_init_crypto`) | | | |

## Shared cases added

27 cases in `fixtures/cases.json`, fixtures under
`fixtures/generated-0.7/core-review-*.der`, generated by
`gen_fixtures.py`. The core answers all 27; Java answers 23 the same way.
The four where Java differs are R20 rows:

| Case | Core | Java |
|---|---|---|
| `receipt/reject-econtent-rechunked-into-7-constructed-levels` | `MALFORMED` | verifies |
| `receipt/unreadable-attribute-value-rechunked-into-7-constructed-levels` | `UNREADABLE_PAYLOAD` | verifies |
| `receipt/reject-eleven-embedded-crls` | `MALFORMED` | verifies |
| `receipt/bundle-id-with-a-five-octet-length-is-kept-raw` | `bundle_id` null, raw bytes kept | reads `com.example.app` |

Verify (`ok`): `accept-econtent-rechunked-into-6-constructed-levels`,
`accept-digest-algorithm-parameters-nested-32-deep`,
`accept-ten-embedded-crls`,
`accept-signed-content-nested-32-deep-in-context-tags`,
`accept-attribute-value-as-a-constructed-octet-string`,
`bundle-id-as-a-constructed-utf8string-is-kept-raw`,
`app-item-id-in-high-tag-form-is-kept-raw`,
`accept-attribute-value-rechunked-into-6-constructed-levels`, and the four
`verify-under-the-{first,second}-of-two-roots-sharing-a-subject` (receipt
and transaction). `MALFORMED`:
`reject-digest-algorithm-parameters-nested-33-deep`,
`reject-an-envelope-nested-33-deep-in-context-tags`,
`reject-a-crls-entry-nested-33-deep`,
`reject-an-embedded-certificate-with-parameters-nested-33-deep`.
`UNREADABLE_PAYLOAD`: `unreadable-signed-content-nested-33-deep-in-context-tags`,
`unreadable-attribute-value-with-a-utf8string-chunk`,
`unreadable-double-wrap-with-a-foreign-chunk`,
`unreadable-attribute-type-in-high-tag-form`,
`unreadable-fourth-field-boolean-of-two-octets`,
`unreadable-fourth-field-sequence-holding-a-padded-integer`.
`UNTRUSTED_CHAIN`: `reject-signer-with-an-even-rsa-modulus`.

Inputs of 200 KB or more (floods, the node budget) are not shared cases:
`rust/tests/envelope_bounds.rs`, `rust/tests/hostile.rs` and the unit tests
in `rust/src/receipt_payload.rs` build each reviewer shape in code and pin
the refusal, the boundary value that still verifies, and that no full
decode ran.

## The rebuilt module

`rust/bindings/abi/build.sh` into `$SCRATCH/out2`:

| File | Bytes | SHA-256 | A2 (05b4ad9) |
|---|---|---|---|
| `aprv.wasm` | 3,009,278 | `9c0a581c5a0b6e4e7f7ba66675f07ec00096fa95772ae27ad86d6049a1a0f263` | 3,005,922, `4cbe2b02…` |
| `aprv.component.wasm` | 3,011,720 | `11798a292c8b092dfcacc62dff29661c5555642515a113b432d4123b0bd87504` | 3,008,364, `8f758c0b…` |
| `aprv.wit` | unchanged | | |

- `tools/check-wasm.sh`: 5/5 ok, one import (`results/check-wasm.txt`,
  `results/imports.txt`).
- Trap host `cases`: 338/338, 0 traps; the same with `_initialize` never
  called (`results/cases-trap-host.txt`, `results/no-initialize.txt`);
  every answer validates against the wire schemas
  (`results/cases-schemas.txt`).
- Trap host `abi-tests`: 0 failed, linear memory 2,097,152 bytes before and
  after 2,000 calls (`results/abi-tests-node.txt`). Wasmtime ABI tests: 11
  passed (`results/abi-tests-wasmtime.txt`).
- Parity (`2026-09-29-aprv-wasm-parity/scripts/parity.sh`): the module
  answers as its native twin on all 6,179 rows of the five corpora, 0 traps
  (`results/parity.txt`).
- Against A2's module rows (`against_a2.py`, `results/against-a2.txt`):
  6,085 identical, 93 differ in the message only, 1 in the verdict:
  `fuzz/4378/substrate/flood/unsigned-attribute-values-10000` was
  `INVALID_CERTIFICATE_PURPOSE` and is `MALFORMED` again, as in 0.7 (which
  refused its length encoding). The 93 messages: 78 "not a CMS ContentInfo"
  and 4 "a SignerInfo value is not ASN.1 nested at most 32 deep" and 3
  "bytes follow" now "nested deeper than 32 constructed values"; 6 "not a
  CMS ContentInfo" now "bytes follow"; one each between "not a CMS
  SignedData", "bytes follow" and "not a CMS ContentInfo".
- `cargo test --locked --workspace`: 633 passed, 0 failed; clippy with
  `-D warnings` clean; `cargo deny check bans licenses sources` ok
  (`results/deny.txt`); `tools/check-layering.mjs` ok with the new rule 6
  (`results/check-layering.txt`) and its tests 11/11.

## Where this stops holding

- Wasm timings are V8 in one Node process on a shared machine, one input
  per fresh instance; they compare the two modules, not hosts. Interpreter
  hosts (Wasmi, Endive) are several times slower in absolute terms.
- The reviewer inputs were rebuilt from the reviewers' scripts, which stay
  outside the repository; the committed tests rebuild each shape.
- `docs/rust-core/THREAT-MODEL.md` §5's "145 MiB for a hostile 3 MiB receipt
  of tiny attributes" predates this change; the unsigned and signerless
  forms now peak near 18 MiB of linear memory. A signed payload still reaches the
  full payload decode (R21), which this lane did not measure.

## Round 2: the second review of these fixes

A second review read the fix commits above at c0a6e15 and found three
things to fix before merge and four notes. Branch `lane/core-fix2`, from
rust-core at c8c3b28. Same versions as above; the module was built with
lane D's toolchain install (`tools/wasm-toolchain.sh`, installed by an
earlier revision of that script), Java is OpenJDK 21 with Maven 3.9.11.

### Dispositions

F = fix before merge, N = note.

| Id | Finding | Disposition | Commit |
|---|---|---|---|
| F1 | The shallow decode ran before the walk, and `SET OF ANY` built a value per entry of `certificates`, `crls` and `signerInfos`: 1.17 million `30 00` entries cost 0.6 to 0.95 s and about 114 MB before the member bound refused the count | Fixed: the walk runs first, so the node budget refuses the set after 100,000 values. `receipt.rs`, `cms.rs`, both READMEs and THREAT-MODEL §3.7 state that order | 39d15e4 |
| F1, test | With the walk first, the 1,057-certificate flood is walked in full (about 41,000 values, 20,000 primitives checked), which in a debug build costs one to two times its base64 decode; the timing test judged against junk and failed one run in three | The control is now the same flood with one trailing byte, which the walk reads in full and then refuses. The flood and a shallow-refused variant must cost at most 1.5 times that plus ten genuine verifications. The full decode alone costs about 45 ms; with the member bound disabled the test fails (446 ms against a 193 ms walk) | 8baa580 |
| F2 | One store held every anchor that issued something, so the order of two same-named roots decided the verdict when the bag held a certificate from each; an anchor named as the intermediate was taken as the leaf's issuer | Fixed: `X509_verify_cert` runs once per anchor that `X509_check_issued` pairs with the target or a vouched certificate, with a store of that anchor alone; the first passing path wins. When none passes, the problems come from the first run whose links hold, so the reason does not depend on the order either | 8ab95db |
| F3 | The walk checked eight primitive tags; OpenSSL's `ANY` decoder also refuses short UTCTime and GeneralizedTime, constructed BOOLEAN, INTEGER, NULL, OID and ENUMERATED, and strings of seven levels, so those were refused directly and accepted one SEQUENCE deeper | Fixed, and two more of the same class found while checking the fix against OpenSSL 4.0.2's `tasn_dec.c`: a primitive SEQUENCE or SET, and an end-of-contents inside a definite length. The walk checks tags 16, 17, 23 and 24 too, refuses the five primitive-only types when constructed, counts string levels as `asn1_collect` does, and hands each outermost constructed string to `d2i_ASN1_TYPE` for its joined octets | 128331d |
| N1 | Seven-level strings are refused in more places than R20 said | R20's row names every place: the value, the version, later fields, the Xcode wrap, unsigned envelope values. Wrap cases added | R20 with this note; cases a5a9896 |
| N2 | A seven-level payload value was reported as a foreign chunk | The walk now refuses the seventh level first and names it ("constructed string nested deeper than OpenSSL decodes"); `values_are_octet_strings` keeps the chunk error's kind as a second line of defence | 128331d |
| N3 | `full_decodes_during` did not restore its counter on a panic | Fixed with a drop guard, tested by a panicking count nested in another | 8c98e9d |
| N4 | Nothing pinned the walk on indefinite lengths | Tests: indefinite nesting at 24, 25 and 3,000 levels, an indefinite flood at the node budget and one over, a missing end-of-contents, an end-of-contents in a definite length, a length one octet past its container | 8c98e9d |

Apple's three roots have distinct subject names and none carries an
intermediate's name, so F2 changes nothing for a chain that ends at one of
them: exactly one anchor is a candidate and one run happens, as before.

### Costs

Native, release build, `SignedData::parse` alone unless marked (the
reviewer's probes, rerun on this branch; they stay outside the repository,
and `rust/tests/envelope_bounds.rs` rebuilds each shape):

| Input | Before (reviewer) | After |
|---|---|---|
| 1.17 M `30 00` in `certificates` | 605 to 711 ms, VmHWM 20 → 134 MB, `TooManyCertificates` | 1.8 ms, VmHWM flat, `TooManyNodes` |
| the same in `crls` / `signerInfos` | 571 to 957 ms | 1.7 to 1.8 ms |
| certificates flood, end to end through `verify_receipt`, 3 calls | 2.31 s against 14.8 ms for junk | 12.8 ms against 7.2 ms for junk |
| 1,057 real certificates, end to end, one call | not measured | 7.8 ms (genuine 0.68 ms, junk 1.2 ms, walk alone 5.6 ms) |

Through `aprv.wasm` in V8, second call on a fresh instance
(`flood_inputs.py`, `wasm_cost.mjs files`; `results/round2-flood-wasm.txt`,
`results/round2-genuine-wasm.txt`). Before is the G1b module (lane A-fix's,
`9c0a581c…`), after this branch's:

| Input | Before | After |
|---|---|---|
| 1.17 M `30 00` in `certificates` | 339 ms, linear memory 94.2 MB | 11.3 ms, 7.5 MB |
| the same in `crls` / `signerInfos` | 305 / 336 ms, 94.2 MB | 7.5 / 7.4 ms, 7.5 MB |
| junk of the same size | 6.0 ms, 7.5 MB | 4.6 ms, 7.5 MB |
| 1,057 real certificates | 2.3 to 6.0 ms, 6.2 MB | 9.7 to 16.5 ms, 6.2 MB |
| the shared receipt | 2.3 to 4.7 ms | 2.3 to 4.9 ms |

The 1,057-certificate flood costs more than before: the walk now runs
before the count refuses it. That cost is bounded by the node budget, as
any envelope's walk is.

### Shared cases added

17 cases in `fixtures/cases.json`, fixtures
`fixtures/generated-0.7/core-review-r2-*.der`, from
`gen_fixtures_round2.py`, which reuses `gen_fixtures.py`'s writer and keys
and leaves the round-1 fixtures as they are. The core answers all 17.
Against the G1b module 13 answer otherwise, which shows each pins a fix.

| Case | Core | G1b | Java |
|---|---|---|---|
| `receipt/verify-under-the-{second,first}-of-two-same-named-roots-with-the-other-roots-certificate-in-the-bag` | ok | `UNTRUSTED_CHAIN` second, ok first | ok |
| `receipt/verify-beside-an-anchor-named-as-the-intermediate-its-root-{second,first}` | ok | `UNTRUSTED_CHAIN` | ok |
| `transaction/verify-beside-an-anchor-named-as-the-intermediate-its-root-{second,first}` | ok | `UNTRUSTED_CHAIN` | ok |
| `receipt/unreadable-fourth-field-sequence-holding-{a-short-utctime,a-short-generalizedtime,a-constructed-integer,a-primitive-sequence,an-end-of-contents}` | `UNREADABLE_PAYLOAD` | ok | `UNREADABLE_PAYLOAD` |
| `receipt/unreadable-fourth-field-sequence-holding-a-7-level-octet-string` | `UNREADABLE_PAYLOAD` | ok | ok |
| `receipt/accept-fourth-field-sequence-holding-a-constructed-utctime` | ok | ok | `UNREADABLE_PAYLOAD` |
| `receipt/reject-an-unsigned-value-sequence-holding-a-short-utctime` | `MALFORMED` | ok | `MALFORMED` |
| `receipt/reject-an-unsigned-value-sequence-holding-a-7-level-octet-string` | `MALFORMED` | ok | ok |
| `receipt/accept-double-wrap-rechunked-into-6-constructed-levels` | ok | ok | ok |
| `receipt/unreadable-double-wrap-rechunked-into-7-constructed-levels` | `UNREADABLE_PAYLOAD` | `UNREADABLE_PAYLOAD` | `UNREADABLE_PAYLOAD` |

The look-alike roots in the receipt cases have RSA keys, since the shared
receipt's chain is RSA: OpenSSL pairs a certificate with a would-be issuer
only when the issuer's key type fits the signature algorithm, and P-256
look-alikes left G1b verifying. Java (`mvn -B -T 1 -f java
-Dtest=ConformanceCasesTest test`, `results/round2-java.txt`) passes 354 of
357; the three it answers otherwise are rows in DECISIONS.md R20.

### The rebuilt module

`rust/bindings/abi/build.sh`:

| File | Bytes | SHA-256 |
|---|---|---|
| `aprv.wasm` | 3,009,376 | `8be03ece7055b8e689b4538324e00f0ffd4d23cdce0e93c127799572bce5c142` |
| `aprv.component.wasm` | 3,011,818 | `95a1226eea0344801c8f728ee6c29f73959bd2d54525ea89e6f0a649a2476d36` |
| `aprv.wit` | 692 | `2ba9315ef2db5c3533efed5af67b9854b40009aa2d05e73f054d967e9ec810fa` (unchanged) |

- `tools/check-wasm.sh`: ok, one import (`results/round2-check-wasm.txt`).
- Trap host `cases`: 355 of 355, 0 traps (`results/round2-cases-trap-host.txt`).
- Trap host `abi-tests`: 0 failed, linear memory 2,097,152 bytes before
  and after 2,000 calls (`results/round2-abi-tests-node.txt`).
- Parity (`2026-09-29-aprv-wasm-parity/scripts/parity.sh`): identical to
  its native twin on all 6,179 rows of the five corpora, 0 traps, and every
  answer validates against the wire schemas (`results/round2-parity.txt`).
  The script exits 1 on its A1-row comparison, as it did for round 1: those
  rows predate both rounds.
- Against G1b's rows (`against_a2.py`, `results/round2-against-g1b.txt`):
  6,134 identical, 45 differ in the message only, none in the verdict, all
  in the fuzz corpus. 42 mutants with more than ten certificates or four
  SignerInfos that also break something the walk checks now report the
  walk's "not a CMS ContentInfo" instead of the count, because the walk runs
  first; 3 mutants holding a string of seven or more levels now say so
  instead of "not a CMS ContentInfo".
- `cargo test --locked --workspace`: 660 passed, 0 failed; clippy with
  `-D warnings` clean; `cargo fmt --check` clean with 1.98.1's rustfmt;
  `cargo deny check bans licenses sources` ok (`results/round2-deny.txt`);
  `tools/check-layering.mjs` ok and its tests 11 of 11
  (`results/round2-check-layering.txt`).

### Where this stops holding

- `hostile.rs`'s `unsigned_content_of_tiny_attributes_is_refused_at_a_bounded_cost`
  failed in some full-suite runs on this shared machine. Its costs are the
  same before and after this round (debug, minimum of 20 calls: 72.8 and
  72.2 ms for the embedded-signer input against 50.4 and 48.7 ms for the
  flat control, a bound of 1.5 times the control plus ten genuine calls),
  so its margin is about 10%; this round did not change it.
- The Wasmtime ABI tests (`rust/bindings/abi/tests`) were not run.
- Timings are one shared machine under load; they compare inputs and
  modules, not hosts.

## Round 3: the third review

A third review read the round-2 fix commits and lane A3's core-facing
changes at b863252 and found two things to fix before merge and seven
notes, and revisited four notes of round 2 on the ABI crate. Branch
`lane/core-fix3`, from rust-core at 60b2091. Same versions as round 2,
plus Rust 1.85.0 (the crates' floor) and nightly cargo 1.100.0
(2026-09-25) for two CI findings, ShellCheck 0.11.0 and cbindgen 0.29.0.
Three findings from the first run of the wired CI workflows joined this
round's brief.

### Dispositions

F = fix before merge, N = note, ABI = round 2's notes on the ABI crate,
CI = the first CI run.

| Id | Finding | Disposition | Commit |
|---|---|---|---|
| F1 | OpenSSL's issuer lookup over the untrusted certificates takes the first name match and never backtracks, so with custom anchors that carry no key identifiers a same-named intermediate placed first in the unsigned bag (from a second pinned root, or a sibling under the same root) made a genuine receipt `UNTRUSTED_CHAIN` | Fixed: before the per-anchor runs, the bag is narrowed to the certificates that signed the target or a certificate already linked, by issuer name and signature, at most n × (n + 1) name comparisons for the n certificates the cap allows. The first version paired with `X509_check_issued`, which also judges the issuer's `keyUsage`; seven corpus rows then lost their "not a CA" message, so the link is the name and the signature alone, as OpenSSL's lookup pairs them. Apple's roots are unaffected: their certificates carry key identifiers, so `X509_check_issued` refuses a look-alike on its own | 1d44bc5, 9b42d0c |
| F2 | The walk judged each primitive chunk inside a constructed string as a value of its own; OpenSSL joins chunks unchecked, so a certificate whose signature `BIT STRING` was split in two verified or was `MALFORMED` by the signature's first octet | Fixed: no chunk check inside a constructed string; the nesting cap and the check of the whole string at its outermost level stay. R20's row on the walk's rules says so, and a new R20 row records Java's answer | 6c81533 |
| F3 | The tiny-attribute cost test judged against junk, which costs only its base64; it failed in release, and twice on the 1.85.0 CI leg | Fixed: judged against the flat value of the same size with the same signer; twice its cost without a signer, three times with one (below) | e67b3be |
| F4 | The node budget admits an attribute of about 100,000 OBJECT IDENTIFIERs that verifies and costs over a hundred times a genuine call natively | Documented: the cost table below and THREAT-MODEL §5 (docs/rust-core). No tighter bound was tried | this note |
| F5 | `build.sh` left an earlier run's module in place when a check before its cleanup failed | Fixed: the four outputs are removed right after the argument check | 0632948 |
| F6 | `build.sh` checked the `rustc` on PATH while cargo honours `RUSTC`, `CARGO_BUILD_RUSTC` and wrappers | Fixed: the compiler cargo would pick is the one checked and is handed to cargo by path; every wrapper variable is refused and cleared. `tools/test/build-sh.test.mjs` holds the pin and the cleanup (ABI-F1, ABI-F6) in under a second, without a build, and fails on the previous script | 0632948, 1110fe9 |
| F7 | Endive's name-section prefixer is a no-op on the stripped module; the 2026-09-26 note's "profiling works" was stale | The prefixer line is gone from `java-wasm/pom.xml`; `java-wasm/README.md` and the abi README say frames carry the function index; the Endive note has a dated correction | a1dd695, 33438da |
| F8 | `anchors_of` in the C ABI built a slice from an unchecked caller length | Fixed: each anchor through `borrow_bytes` (`INVALID_ARGUMENT` over `PTRDIFF_MAX`), and the anchor count checked the same way; the header is unchanged (`check-header.sh`) | 5b1eabe |
| F9 | `asan-openssl.sh` stopped at the first failing target; `differential.sh` took the first jar in `java/target` | Fixed: the five targets run one by one and the script names every failure; the jar is named by `version.txt` | 25ddc5f, 63e1432 |
| ABI-F5 | The guest trusted every list range | Fixed: each export, and the `random-get` answer, traps on a range past the end of linear memory before a byte is read or the list freed; a Wasmtime test calls both verify exports with ranges at the end of memory and one that wraps | 077ec85 |
| ABI-F8 | Two trap-host checks did not test what they named | Fixed as proposed: a three-segment JWS for the not-UTF-8 check, and the short `random-get` check now requires a call | d5bc38a |
| ABI-F9 | The wire schemas admitted what the core cannot write | Tightened: attribute keys are decimal u32, receipt instants a multiple of 1,000 ms; every case answer and every corpus answer validates (below) | f80143e |
| CI | `rust (beta)`: `exported_symbols.rs` looked for the cdylib beside the test binary, which cargo's build-dir layout moves | Fixed: the test searches the profile directory below cargo's `CACHEDIR.TAG` and takes the newest copy; passes on 1.98.1 (debug and release) and on nightly 1.100, where the old lookup fails | 79737ed |
| CI | `rust (1.85.0)`: the tiny-attribute cost test failed twice | F3's fix; five of five on 1.85.0 in debug | e67b3be |
| CI | `rust-wasm-checks`: ShellCheck SC2010 in `differential.sh` | F9's fix; ShellCheck clean on every script touched and on the CI job's set | 63e1432 |

### Costs

F3, the tiny-attribute cost test, fastest of seven interleaved calls,
five runs each (the test's own inputs, printed by a scratch copy of the
test):

| Build | Genuine | Flat, no signer | Tiny, no signer | Flat, signer | Tiny, signer |
|---|---|---|---|---|---|
| 1.98.1 debug | 0.86 to 0.90 ms | 38.2 to 42.8 ms | 37.3 to 39.3 ms | 45.4 to 46.7 ms | 71.4 to 76.2 ms |
| 1.98.1 release | 0.58 to 0.64 ms | 10.8 to 15.8 ms | 9.9 to 15.5 ms | 17.7 to 28.6 ms | 27.8 to 42.2 ms |
| 1.85.0 debug | 0.90 to 0.99 ms | 35.8 to 49.4 ms | 36.1 to 55.0 ms | 43.2 to 61.2 ms | 74.4 to 103.7 ms |

Without a signer the ratio is near 1 in every build, so that bound is
twice the flat input. Under a signer the tiny input also walks the
payload up to the node budget, which the flat value does not: 1.6 times
the flat input on 1.98.1 and up to 2.0 on 1.85.0 in debug, so that bound
is three times. Twice would have left 1.85.0 debug about 8% of margin.
The regression both bounds guard, the payload read in full before a
signer is found, cost about 30 times the flat input. The full `hostile`
suite passed five of five in each of the three builds.

F4, the node budget's ceiling (`node_budget_inputs.py`): the shared
receipt with one unsigned attribute of OBJECT IDENTIFIERs up to 100,000
values in the envelope, and one value over. Native is a release build
through `verify_der`, best and worst of five, from a scratch probe; Wasm
is `wasm_cost.mjs files` on this round's module, second call on a fresh
instance, three runs (`results/round3-node-budget-wasm.txt`). The machine
was shared and loaded: compare the rows, not the absolute figures.

| Input | Size | Answer | Native | `aprv.wasm` in V8 | Linear memory |
|---|---|---|---|---|---|
| the shared receipt | 3,380 B | verifies | 0.45 ms | 7.3 to 9.9 ms | 1.9 MiB |
| 99,830 OIDs `06 01 2a` | 303 KB | verifies | 60 to 67 ms | 62 to 87 ms | 4.8 MiB |
| 99,830 OIDs of 20 octets | 2.2 MB | verifies | 126 to 149 ms | 101 to 128 ms | 16.9 MiB |
| 99,831 OIDs `06 01 2a` | 303 KB | `MALFORMED`, over the budget | 20 to 26 ms | 30 to 48 ms | 2.6 MiB |

The walk hands every OBJECT IDENTIFIER to OpenSSL (`d2i_ASN1_TYPE`), and
the full CMS decode then builds each again, so an input at the budget
costs about three times one just over it, which the walk refuses before
the decode. This is the most one anonymous request costs under the
budget, as far as this round measured: 130 to 330 times a genuine call
natively and 10 to 17 times through `aprv.wasm` in V8 here
(the reviewer measured 112 to 268 ms against 2.6 ms). Interpreter hosts
pay several times more. The review's alternative, counting a checked
primitive's content length against the budget, was not tried: the brief
asked for a bound change only with evidence that it keeps every shared
case, and none was gathered.

### Shared cases added

Seven cases in `fixtures/cases.json`, fixtures
`fixtures/generated-0.7/core-review-r3-*.der`, from
`gen_fixtures_round3.py`, which reuses the round-1 generator's writer and
its minted P-256 PKI (no key identifiers). All seven verify. The G1c
module answers four otherwise, which shows each group pins a fix; the
other three are their order twins.

| Case | Core | G1c | Java |
|---|---|---|---|
| `receipt/verify-with-another-roots-same-named-intermediate-before-the-real-one-own-root-{first,second}` | ok | `UNTRUSTED_CHAIN` | ok |
| `receipt/verify-with-another-roots-same-named-intermediate-after-the-real-one-own-root-{first,second}` | ok | ok | ok |
| `receipt/verify-with-a-same-named-sibling-intermediate-before-the-real-one` | ok | `UNTRUSTED_CHAIN` | ok |
| `receipt/verify-with-a-same-named-sibling-intermediate-after-the-real-one` | ok | ok | ok |
| `receipt/accept-a-certificate-whose-signature-bit-string-is-in-two-chunks` | ok | `MALFORMED` | `MALFORMED` |

Java (`mvn -B -T 1 -f java -Dtest=ConformanceCasesTest test`,
`results/round3-java.txt`) passes 385 of 386: it answers the two-chunk
signature `MALFORMED` ("receipt has trailing or unparseable bytes").
DECISIONS.md R20 records the row; aligning Java is left to a J-align
lane, since this lane does not edit `java/`.

### The rebuilt module

`rust/bindings/abi/build.sh` with lane D's toolchain install:

| File | Bytes | SHA-256 |
|---|---|---|
| `aprv.wasm` | 2,764,700 | `4e9d2d85c7c1f9b6dbcabbd49c51783e2efd4832ac17994be732b63a98cdc9dd` |
| `aprv.component.wasm` | 2,767,142 | `ccccbfb53b2d4643a3da3a58c30d355d503edfd69850ada6ebb2a3c3fa001fd2` |
| `aprv.wit` | 692 | `2ba9315ef2db5c3533efed5af67b9854b40009aa2d05e73f054d967e9ec810fa` (unchanged) |

- `tools/check-wasm.sh`: ok, one import (`results/round3-check-wasm.txt`).
- Trap host `cases`: 384 of 384, 0 traps
  (`results/round3-cases-trap-host.txt`); `abi-tests`: 0 failed, linear
  memory 2,097,152 bytes before and after 2,000 calls
  (`results/round3-abi-tests-node.txt`).
- Wasmtime ABI tests (`rust/bindings/abi/tests`): 14 passed, the new
  range test among them; on the G1c module that test fails, the first
  range answered with a value (`results/round3-abi-tests-wasmtime.txt`).
- Every answer to the shared cases (68 init, 369 receipt, 289 JWS) and
  every corpus answer (3,922 receipt, 2,085 JWS, 1 init) validates against
  the tightened schemas (`results/round3-schemas.txt`).
- Against G1c's rows on the five corpora, the same pinned calls
  (`$SCRATCH/g1c/same.py`, `results/round3-against-g1c.txt`): 6,173
  identical, 6 differ in the message only, none in the verdict, 0 traps.
  All six are fuzz mutants of a chain whose intermediate is not a CA and
  whose mutation also broke that intermediate's signature over the signer
  (checked with `cryptography`: the signature fails). OpenSSL used to build
  the path through it and report "an intermediate is not a CA" first; the
  narrowed bag no longer offers a certificate that signed nothing on the
  path, so they report "chain does not reach a pinned root". That is F1's
  shape. With the first, `keyUsage`-judging pairing, the unmutated
  `substrate/pkix/receipt/intermediate-keyusage-without-certsign` changed
  the same way; with the signature-only link it answers as before.
- `cargo test --locked --workspace`: 700 passed, 0 failed, in debug and
  in release; clippy `-D warnings` clean for the workspace and for
  `aprv-abi` on `wasm32-wasip1`; `cargo fmt --check` clean with 1.98.1's
  rustfmt; `cargo deny check bans licenses sources` ok
  (`results/round3-deny.txt`); `node tools/lint-cases.mjs` ok, 384 cases;
  `node tools/check-layering.mjs` ok (6 rules, 26 core packages);
  `npm --prefix tools test` 31 of 31 with `APRV_WASM` set (three
  `private-receipt-check` tests need the module); `rust/ffi/check-header.sh` current.

### Where this stops holding

- The fuzz campaign (`asan-openssl.sh`) was not run: no ASan OpenSSL build
  here. Its new loop was run with a stand-in `run.sh` that fails two
  targets: all five ran and both failures were named.
- `tools/differential.sh` was not run end to end.
- The guard on the `random-get` answer's range has no test: the Wasmtime
  host answers from `cabi_realloc`, and no host here places the answer
  elsewhere.
- F4's native figures come from a scratch probe that timed the committed
  generator's inputs; the probe is not committed.
- Timings are one shared machine under load.
