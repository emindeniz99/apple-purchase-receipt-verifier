# Fuzz seeds under the 0.6 and the 0.7 fixture receipt root (2026-10-03)

**Question.** #232 seeded the Java and PHP receipt fuzz targets from
`fixtures/generated-0.7/`, but both harnesses still added the 0.6 fixture
root, `fixtures/generated/receipt-root.der`, to Apple's three roots. How
many seeds verify under that set, and how many under the same set with
`fixtures/generated-0.7/receipt-root.der` instead? A seed that never
verifies never runs the target's anchor-set invariant. This feeds the
switch of both harnesses to the 0.7 root.

**Versions.** Base commit `a699ec0`. Java: the `java/` library at 0.7.0,
BouncyCastle 1.86, OpenJDK 21.0.10. Core: the module Go commits
(`go/internal/wasm/aprv.wasm`, 2,764,700 bytes, sha256
`4e9d2d85c7c1f9b6dbcabbd49c51783e2efd4832ac17994be732b63a98cdc9dd`, built
after core review round 3), run by `tools/private-receipt-check.mjs` from
commit `e9cff0e` on Node 22.22.2. Scripts and commands are in
`2026-10-03-fuzz-seed-anchor/`.

## Results

Verified seeds, out of the DER files in each directory, read at full size:

| seeds | Java, 0.6 root | Java, 0.7 root | core, 0.6 root | core, 0.7 root |
|---|---|---|---|---|
| `fixtures/generated-0.7/*.der` (191) | 0 | 17 | 0 | 11 |
| `fixtures/generated/*.der` (55) | 0 | 0 | 0 | 0 |

The Java counts are from `CountSeeds.java`, the core counts from
`count-core.sh`. Under the 0.6 root, six `fixtures/generated` receipts stop
at `INVALID_CERTIFICATE_PURPOSE` (no WWDR marker); under the 0.7 root they
stop at `UNTRUSTED_CHAIN`. Neither root verifies one, so the harnesses
replace the 0.6 root rather than keep both.

`CountSeeds.java` also ran the `receipt-base64` target's seeds: 2 of 17
`fixtures/generated/receipt-b64/*` and 2 of the 3 receipts in
`fixtures/public-receipts/` verify under either root, all Apple-signed.

The 17 and the 11 differ by eight files, all limit fixtures whose cases
in `fixtures/cases.json` accept either verdict (`oneOf: ok, MALFORMED`).
Java verifies seven the core refuses as `MALFORMED`: the `-33` nesting
fixtures (certificate parameters, CRL, digest algorithms, unsigned
context tags), `econtent-7-levels`, `eleven-crls` and
`r2-unsigned-sequence-7-level-octet-string`. The core verifies
`r3-certificate-signature-in-two-chunks`, which Java refuses.

Every verified DER seed is under 5 KB, so the 64 KiB seed limit PHP's
`run.sh` now applies to `verify-receipt`, and the `-max_len=65536`
truncation Jazzer applies, drop none of them. One verified base64 seed is
not: `fixtures/public-receipts/receipt-sandbox-legacy.b64` is 105,472
bytes, so Jazzer loads it cut to 65,536 and refuses it, and inside the
`receipt-base64` target one public receipt verifies, not two.

## Where this stops holding

- The PHP harness itself did not run: it reaches the core through
  `aprv-server`, which CI builds from the tree and this measurement did
  not. The core count is the committed module's, not one built from
  `a699ec0`. The core commits between them (`e9cff0e..a699ec0` in
  `rust/src`) touch base64, PEM roots, JSON and dates, not the CMS or
  chain checks. The date change (`663e5c8`, `4cde968`) is the one that
  could move a verdict: the receipt's creation date sets the instant the
  chain is checked at. The verdicts are expected to hold; the next release
  refreshes the module and the script can be rerun against it with a
  different `rev`.
- Both counters check the chain at the receipt's own creation date
  (attribute 12) and read the clock only when that date is missing, so an
  expiring fixture certificate does not move the counts.
