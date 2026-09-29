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
