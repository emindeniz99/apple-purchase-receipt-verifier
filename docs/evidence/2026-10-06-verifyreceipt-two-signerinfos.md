# Apple's verifyReceipt refuses a receipt with two SignerInfos

**Question.** A receipt may carry more than one SignerInfo. Both
implementations try them in order and the first that verifies decides, but
the Java implementation stops at a SignerInfo BouncyCastle cannot build a
verifier for, so a bogus SignerInfo placed ahead of Apple's makes Java answer
`MALFORMED` where the core answers ok (final Java review, 2026-10-06). What
does Apple's own verifyReceipt answer for two SignerInfos? The answer decides
whether the two implementations keep trying several, or accept exactly one.

**Date and versions.** 2026-10-06, `sandbox.itunes.apple.com` and
`buy.itunes.apple.com`; the core is the `aprv.wasm` pinned in `go/` at main
1ecb907, run through the Go package; the Java implementation at the same
commit with BouncyCastle 1.86.

**Method.** The two genuine sandbox receipts in `fixtures/public-receipts/`
(`receipt-sandbox-g5`, `receipt-sandbox-legacy`; each carries one
SignerInfo). Each variant keeps every byte Apple wrote and changes only the
signerInfos SET and the three length headers around it
([`splice.py`](2026-10-06-verifyreceipt-two-signerinfos/splice.py), which
checks that rebuilding the SET with the one genuine SignerInfo reproduces the
original bytes exactly). A bogus SignerInfo is the genuine one with its
digest algorithm set to `1.2.3.4`; a bad-signature one has the last bit of
its signature flipped. Every variant went to both endpoints, twice, with the
same answers. Only `status` was kept; even a sandbox answer carries the
receipt's purchase records.

Reading the status: 21004 (sandbox: the shared secret does not match) and
21007 (a sandbox receipt sent to production) both mean Apple decoded and
accepted the receipt and stopped at a later step; 21002 is Apple's refusal.
Apple answered 21002, not 21003, even for a broken signature or payload, so
here 21002 means "refused" and does not say why.

## Results

`results/apple.txt`, `results/core.txt`, `results/java.txt`; both receipts
gave identical rows.

| Variant | Apple | Core | Java |
|---|---|---|---|
| c0: the original | 21004 / 21007 | ok | ok |
| c2: one payload octet flipped | 21002 | `INVALID_SIGNATURE` | `INVALID_SIGNATURE` |
| c3: one signature bit flipped | 21002 | `INVALID_SIGNATURE` | `INVALID_SIGNATURE` |
| c4: the bogus SignerInfo alone | 21002 | `INVALID_SIGNATURE` | `MALFORMED` |
| c5: the certificates SET in DER order | 21002 | ok | ok |
| v1: bogus, then genuine | 21002 | ok | `MALFORMED` |
| v2: genuine, then bogus | 21002 | ok | ok |
| v3: genuine twice | 21002 | ok | ok |
| v4: bad signature, then genuine | 21002 | ok | ok |
| v5: genuine, then bad signature | 21002 | ok | ok |

- **Apple refuses every receipt that carries two SignerInfos**, in either
  order, even the genuine one twice. It never tries a second SignerInfo.
- **Apple also refuses its own receipt with the certificates reordered**
  (c5): the set's contents, the signature and the payload are untouched.
  Both implementations accept it; they find the signer by its identity, not
  its position. That is the Apple-signed-content-in-other-packaging class,
  where accepting is allowed (DECISIONS.md R20), and nothing changes here.
- The first attempt rebuilt the envelope with BouncyCastle, which sorts the
  certificates SET; Apple refused even the one-SignerInfo control, so that
  run measured c5 ten times over (`results/apple-bouncycastle-reencoded.txt`).

## Decision (owner, Q65, 2026-10-06)

Both implementations keep trying up to four SignerInfos, and the first that
verifies decides. Apple's one-SignerInfo rule is unpublished and could change
(a second signature in another algorithm is the case RFC 4853 was written
for), and a verifier that tracked it would refuse a genuine receipt the day it
did. RFC 5652 §5.1 allows any number of signers, and RFC 4853 says that one
signature that verifies is a success and that an implementation "MUST
gracefully handle unimplemented signature algorithms". The security floor is
unchanged: the SignerInfo that decides is verified over the content that is
returned, under a chain to a pinned root.

So the Java implementation now treats a SignerInfo BouncyCastle cannot verify
as one that does not verify, and tries the next. It reads every SignerInfo's
signed and unsigned attributes first, so a SignerInfo that is malformed is
still `MALFORMED` whatever its position, as in the core. On the variants above
Java now answers as the core does on every row
(`results/java-after-fix.txt`). The core needed no change. Three shared cases
built from the G5 receipt the same way (`tools/generate-signer-info-fixtures.mjs`)
pin the agreement.

The rejected alternative, accept exactly one SignerInfo in both
implementations, is kept as `one-signer-info.patch`: 35 fewer lines, and five
shared cases would have changed their verdict.

## Where this stops holding

Two receipts, one family of SignerInfo changes, one day. Apple may treat a
second SignerInfo that it signed itself differently; no such receipt exists to
test. The endpoint is deprecated, and StoreKit 2's JWS has one signature by
construction.
