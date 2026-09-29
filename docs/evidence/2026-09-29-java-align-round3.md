# Java against the round-3 case and the Phase 7 proposals

**Question.** Two things. First, should Java be aligned with the core on
`receipt/accept-a-certificate-whose-signature-bit-string-is-in-two-chunks`?
Second, how does Java answer lane P7-code's 76 proposed cases,
seven of which differ from the deleted 0.7 port test
([proposal note](2026-09-29-phase7-proposed-cases.md) on `lane/phase7-code`,
commit 4b73900)? This feeds DECISIONS.md R20 and the orchestrator's choice
of which proposals become shared cases.

**Versions, 2026-09-29.**
- The core is the G1d module: `aprv.wasm`, 2,764,700 bytes, SHA-256
  `4e9d2d85c7c1f9b6dbcabbd49c51783e2efd4832ac17994be732b63a98cdc9dd`,
  built at rust-core b0a7f3d. It ran through `tools/wasm-trap-host.mjs`
  on Node v22.22.2.
- Java is `java/` at `lane/java-align` after the round-3 merge
  (BouncyCastle 1.86, OpenJDK 21). It ran through
  `tools/differential/Differential.java` and was compared with
  `tools/differential/compare.mjs` against `recorded.json`.
- Inputs were minted by the proposal's `probe.py` under Python 3.11 with
  `cryptography` 50.0.1.

Code: [`2026-09-29-java-align-round3/`](2026-09-29-java-align-round3/).

## The two-chunk signature BIT STRING

The case's certificate spells its signature as `23 82 01 07`, followed by
the chunk `03 01 00` and the chunk `03 82 01 00 96 e4 81 ...`. The second
chunk is the signature octets with no initial octet of its own.

X.690 8.6.4 encodes each segment of a constructed BIT STRING as a
bitstring encoding of its own, which starts with an unused-bits octet. By
that rule the second segment claims 0x96 = 150 unused bits, so the value is
not valid BER. OpenSSL's `asn1_collect` instead concatenates the chunks'
raw contents and reads the first octet of the result as the unused-bits
count. That reading gives back the original signature.

The same certificate in three spellings (`bitstring_variants.py`,
`results/bitstring.report.txt`):

| Spelling | Core | Java |
|---|---|---|
| The case: `03 01 00`, then the signature without an initial octet | ok | `MALFORMED` |
| X.690: `03 01 00`, then `03 L 00 sig` | `UNTRUSTED_CHAIN` | ok |
| One segment: `03 L 00 sig` inside `23` | ok | ok |

The two readings disagree on every constructed BIT STRING with more than
one non-empty segment. Aligning Java with the case would make it refuse
the valid spelling and accept the invalid one. So Java keeps `MALFORMED`,
and R20 records why. The row the core gets wrong is the X.690 one, where
a correctly signed chain is refused. Apple does not chunk signatures, so
no Apple-signed verdict changes.

## The Phase 7 proposals

82 rows: the 4 controls, the 76 proposals, and 2 rows the note had probed
by hand (`results/proposals.report.txt`). Result: 40 are the same, 38
differ in the message only, 2 differ in the reason and 2 in the verdict.
All four controls are the same on both sides.

The seven findings of the proposal note:

| # | Proposal | Core (G1d) | Java | R20 |
|---|---|---|---|---|
| 1 | `receipt/reject-an-unparseable-stranger-{first,middle,last}` | `MALFORMED` | `MALFORMED` | agree |
| 2 | `receipt/verify-a-signer-whose-issuer-name-is-reencoded` | ok | ok | agree |
| 3 | `receipt/relabelled-signature-algorithm-still-verifies` | `INVALID_SIGNATURE` | `INVALID_SIGNATURE` | agree; the existing `oneOf` case could narrow to `INVALID_SIGNATURE` |
| 4a | `receipt/verify-with-a-signing-time-in-month-13` | ok | `MALFORMED` | not recorded: BouncyCastle refuses the UTCTime while it parses the envelope |
| 4b | `receipt/verify-with-an-unknown-signed-attribute-holding-invalid-utf8` | ok | `INVALID_SIGNATURE` | recorded (the non-DER signed-attributes row); see below |
| 5 | `transaction/reject-a-signed-date-of-{nan,infinity}` | `UNREADABLE_PAYLOAD` | `UNREADABLE_PAYLOAD` | agree |
| 6 | `receipt/in-app-attribute-type-above-int32-max-keeps-the-purchase-raw` | ok, purchase raw | ok, same payload | agree |
| 7 | `receipt/hand-fractional-creation-date-at-not-after` (`12:00:00.000Z` against a signer that expires at 12:00:00) | `INVALID_CERTIFICATE` | `INVALID_CERTIFICATE` | agree: neither reads the fractional date |

4b is not about UTF-8. The probe appends the extra attribute after the
three standard ones, so the signed attributes SET is not in DER order.
BouncyCastle re-encodes the SET in DER order before it checks the digest,
and the signature no longer matches. With the same attribute placed first
(`receipt/hand-invalid-utf8-signed-attribute-in-der-order`), both sides
verify. If the proposal becomes a case, putting the attribute first pins
what it names.

Two more rows differ in the reason. Neither is among the seven, and
neither is recorded:
- `receipt/reject-a-signer-valid-from-month-13`: `INVALID_CERTIFICATE` in
  the core, `MALFORMED` in Java. The cause is the same UTCTime parse as 4a.
- `signed-data/reject-an-rsa-leaf-under-es256`: `INVALID_SIGNATURE` in the
  core, `INVALID_CERTIFICATE` ("x5c[0] does not decode") in Java. The
  probe's leaf reuses a made-up 16,384-bit modulus.

## Where this stops holding

- The core's answers are G1d's. The proposal note's own column is G1c's;
  the two agree on all 76 proposals and the 4 controls.
- The ECDSA signatures in the minted inputs are randomised, so a rerun
  produces different bytes but the same answers.
- Only the case's certificate position (the first in the bag) was
  rechunked.
