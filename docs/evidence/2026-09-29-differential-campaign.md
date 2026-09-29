# The differential campaign: the core against the 0.7 Java implementation

MIGRATION.md step 1.8, DECISIONS.md R20 and R33. The Rust core, as the
real `aprv.wasm`, and the 0.7 Java implementation (`java/`) answered the
same 7,647 calls: the 360 shared cases, the substrate bake-off's five
corpora (1,179 rows and 5,000 mutants) and every port's fuzz seeds. Each
difference was sorted into a group that says why it exists; the groups
are the rows below, for R20.

**Result.** No forgery and no acceptance of anything unsigned. The
campaign found one core bug, now fixed with a test and two shared cases:
the core refused a genuine receipt when a second trusted root with the
same name vouched for a stranger certificate in the bag (§3). Every other
difference is a refusal the two implementations reach at different
stages, or one of the twelve case rows R20 already records. On the five
corpora the core and Java never differ in verdict or payload: every
difference there is a `reason` row (two refusals).

## 1. What ran

- **Core:** `aprv.wasm` built by `rust/bindings/abi/build.sh` on
  lane/core after the fix in §3 (sha256 `95117782…2049a`), through
  `tools/wasm-trap-host.mjs calls` on Node 22.22.2. The module was then
  stripped of its name section (review round 2, F11); the stripped module
  (`d06de141…70d5`) answered the 811 hostile rows byte for byte as this
  one, and all 360 cases.
- **Java:** the 0.7 Java implementation at the same commit, on Java 21,
  through `tools/differential/Differential.java`.
- **Comparison:** `tools/differential/compare.mjs` (classes in
  `tools/differential/README.md`). `same` and `message-only` pass;
  `java-no-call` passes (input bytes that are not UTF-8 have no Java
  spelling, since its API takes `String`s); `reason`, `payload`, `verdict`
  and `fault` fail unless recorded.
- **Calls** (`scripts/run.sh` end to end):
  - the cases: `tools/differential/cases-calls.mjs` over
    `fixtures/cases.json`, 661 calls from 360 cases;
  - the five corpora as round 13's call files, every unpinned clock
    pinned to 2026-09-29T00:00:00Z: `algorithms` 22, `cases` 153 (the
    0.7-era case corpus), `substrate` 193, `hostile` 811, `fuzz` 5,000;
  - the ports' fuzz seeds (`scripts/seeds-calls.mjs`), 808 calls: the
    endpoint-json seeds of rust, node, python, swift, php and dotnet,
    dotnet's JSON-reader seeds, Go's inline seeds, and the fixture
    directories Jazzer, atheris, ruzzy, the Swift and .NET fuzzers, PHP
    and cargo-fuzz seed from. Each receipt and JWS runs twice: under
    Apple's roots, and under every trust-anchor fixture of the cases, so
    a seed reaches the chain and the signature and not only the envelope.
- **Groups:** `scripts/classify.py` sorts every failing row by the two
  answers' reasons and messages and writes the corpus rows' recorded file
  (`results/recorded-corpus.json`); a row that fits no group fails it.
  With `--old` it also reads the pre-migration Rust core's rows (the
  OpenSSL core parity note's) and counts, per group, how many the 0.7
  core answered as the core does now.

## 2. Counts

Second pass, with the recorded files (`results/*.report.txt`):

| Calls | Rows | same | message-only | java-no-call | reason | verdict | payload | fault |
|---|---|---|---|---|---|---|---|---|
| cases (`fixtures/cases.json`) | 661 | 191 | 458 | 0 | 3 | 8 | 1 | 0 |
| algorithms | 22 | 22 | 0 | 0 | 0 | 0 | 0 | 0 |
| cases (0.7 corpus) | 153 | 105 | 44 | 0 | 4 | 0 | 0 | 0 |
| substrate | 193 | 95 | 97 | 0 | 1 | 0 | 0 | 0 |
| hostile | 811 | 208 | 465 | 129 | 9 | 0 | 0 | 0 |
| fuzz | 5,000 | 635 | 4,092 | 175 | 98 | 0 | 0 | 0 |
| seeds | 808 | 222 | 558 | 0 | 19 | 8 | 1 | 0 |

No traps, no `INTERNAL_ERROR`, no exception out of the Java library. The
twelve case rows are the ones `tools/differential/recorded.json` already
held; the seeds' verdict and payload rows are the same fixtures under the
trust-anchor configuration. Every run passes with the recorded files
(`EXIT 0`). One row reads `STALE`: `receipt/reject-signer-on-an-unimplemented-curve`
is a `reason` row in the 0.7 case corpus (Apple's roots) and `same` in
today's case, which names the test roots; the two share an id.

## 3. The bug the seeds found

Under the trust-anchor configuration (every test root trusted),
`fixtures/generated-0.7/review-receipt-stranger-unreadable-key.der`
verified in Java in either root order, and the core answered
`UNTRUSTED_CHAIN` when the other tree's root came first. Two trusted
roots share a subject name; the receipt's intermediate is issued by one,
and the unsigned bag carries a stranger issued by the other. OpenSSL's
issuer lookup takes the first store certificate whose name matches, and
does not try the next when that one's signature fails, so the root order
decided the verdict. The review fixes of the same day kept only
same-named roots that issued something in the bag, which leaves both
here.

The fix (`rust/openssl/src/path.rs`) builds one store per combination of
same-named anchors that issued something in the bag (at most 64), keeps
only the bag certificates each store vouches for, and takes the first
store that verifies. `rust/tests/trust_pinning.rs`
`a_root_verifies_when_a_same_named_root_vouches_for_a_stranger_in_the_bag`
fails without it; the two shared cases after
`receipt/verify-with-a-stranger-whose-key-is-unreadable` pin it for every
host. Apple's three roots have distinct names, so a production receipt
under the default roots could not reach it.

## 4. The rows, for R20

"0.7" is the pre-migration Rust core; Java is the 0.7 Java
implementation; the case column names a shared case, or the group in
`results/recorded-corpus.json` for corpus-only rows. Counts are corpus
rows (fuzz, hostile, substrate, 0.7 cases, seeds).

| Input | 0.7 | Java | Core | Why the core answers so | Case |
|---|---|---|---|---|---|
| An envelope OpenSSL's ContentInfo template refuses anywhere (indefinite-length attributes, garbage in the CRLs field, a mutated certificate set): 31 rows | 8 as the core, 15 `UNTRUSTED_CHAIN`, 7 a purpose or certificate reason, 1 seed not run | a chain or certificate reason | `MALFORMED` | OpenSSL decodes the whole ContentInfo before any check (R21); BouncyCastle reads only what it needs. Fails closed | `envelope-decode-stage` |
| An envelope BouncyCastle cannot read to the end, which OpenSSL reads (absent digest parameters, 10,000 unsigned attribute values, a signer on an unimplemented curve): 26 rows | 24 as the core | `MALFORMED` "trailing or unparseable bytes" | the chain, purpose or certificate reason the next check finds | Both refuse; Java's reader refuses first | `bouncycastle-refuses-first` |
| An x5c certificate OpenSSL's X.509 decoder refuses and the JDK reads: 22 rows | 15 as the core | the chain or signature reason | `INVALID_CERTIFICATE` "x5c entry is not a valid certificate" | Both refuse; the decoders differ on what a certificate is | `x5c-openssl-refuses-first` |
| An x5c certificate the JDK refuses and OpenSSL reads: 15 rows | 13 as the core | `INVALID_CERTIFICATE` "x5c[n] does not decode" | the chain or signature reason | Both refuse, as above the other way round | `x5c-jdk-refuses-first` |
| The SignerInfo's own certificate is one a strict reader refuses (version 11, an extension twice, a corrupt extension): 25 rows | the 13 corpus rows as the core; 12 seeds not run | `MALFORMED` "an embedded certificate is not a valid certificate" | `INVALID_CERTIFICATE` "receipt signer certificate does not decode" | Already R20's case rows; the cases allow both | `receipt/reject-signer-certificate-version-11` and two more (`signer-certificate-refusal-stage`) |
| A signer on an unimplemented curve under Apple's roots: 5 rows | all as the core | `INVALID_CERTIFICATE` | `INVALID_CERTIFICATE_PURPOSE` (the intermediate's WWDR marker) | The core checks the chain's markers before it reads the signer's key; either refusal is right, and the case under the test roots agrees | `check-order-marker-before-key` |
| One hostile receipt with an unknown digest OID in a place Java's CMS code does not expect: 1 row | as the core | `MALFORMED` "unexpected java.lang.IllegalArgumentException" | `INVALID_SIGNATURE` "unsupported digest algorithm" | Java's catch-all; the core names the defect | `java-catch-all` |
| A genuinely signed envelope that is not valid DER elsewhere (certificates field twice, extensions twice, malformed signed attributes in a second SignerInfo): 8 seed rows | not run | ok (trust anchors) | `MALFORMED` / `INVALID_CERTIFICATE` | Already R20's case rows (`tolerant-envelope-decoding`) | `receipt/certificates-field-twice-does-not-crash` and three more |
| A self-signed twin of the signer's identity ahead of the leaf: 1 seed row | not run | `UNTRUSTED_CHAIN` | ok | Already R20's case row; neither uses the twin's key | `receipt/genuine-signer-behind-a-copy-of-its-identity-does-not-crash` |
| The four core-review inputs the Java lane aligns: 6 seed rows | not run | ok | as R20's core-review rows | Already in R20 | `receipt/reject-econtent-rechunked-into-7-constructed-levels` and three more |

Rows the Java API cannot express (`java-no-call`, 304): 129 hostile and
175 fuzz calls whose input bytes are not UTF-8. A root that is not a
certificate is refused by both before any call (the core's `init`
answers `{"ok":false}`, Java's `CertificateFactory` throws), which the
comparison counts as `same`.

## 5. What CI runs

`tools/differential.sh <aprv.wasm> <out-dir> [calls.jsonl...]` is the
nightly `java-differential` job's entry point (R33): with no call files it
runs the shared cases and fails on any row `tools/differential/recorded.json`
does not record. The corpora and the seeds need their call files (the
corpora are the spike's, not in the repository; `scripts/seeds-calls.mjs`
makes the seeds' from the repository) and `RECORDED=results/recorded-corpus.json`.
`TRAP_HOST` names `tools/wasm-trap-host.mjs` when it is not beside the
script.

## 6. Limits

- One Java version (21) and one host (the Node trap host). The hosts'
  own suites hold every other host to the core's answers.
- The seed calls run each seed as found; the fuzzers' mutations of them
  are the fuzz corpus, not rerun here.
- The 0.7 core's answers exist for the five corpora only; the seed rows
  have none (`not run`).
