# Walkthrough trace of a genuine receipt

**Question.** What does each step of the Java legacy-receipt path see on a
genuine Apple receipt? The answer is the worked example in
[java/WALKTHROUGH.md](../../java/WALKTHROUGH.md) §6.3, which a review team
reads before taking `java/` to production.

**Date and versions.** 2026-10-06. The Java implementation on `main` at
`993cb5f`, BouncyCastle 1.86, jackson-core 2.22.3, OpenJDK 21.0.10.

**Method.** [`Trace.java`](2026-10-06-walkthrough-trace/Trace.java) runs
the steps of `ReceiptCore.verifySignature` one at a time on the vendored
sandbox receipts in `fixtures/public-receipts/`, then calls
`Verifier.verifyReceipt` on the same input. It also runs the chain check a
second time at the clock instead of the receipt's creation date. The
folder's [README](2026-10-06-walkthrough-trace/README.md) has the commands.

## Results

From the console output of the two runs:

| Step | `receipt-sandbox-g5` | `receipt-sandbox-legacy` |
|---|---|---|
| Base64, decoded | 7,556 chars, 5,665 bytes | 105,472 chars, 79,104 bytes |
| eContent | 1,344 bytes | 74,884 bytes |
| SignerInfo | 1; sid = issuer and serial; SHA-256; rsaEncryption; no signedAttrs | 1; sid = issuer and serial; SHA-1; rsaEncryption; no signedAttrs |
| Creation date (attribute 12) | 2025-12-26T18:39:47Z | 2020-05-06T18:28:49Z |
| Bag | leaf (notAfter 2026-08-23T14:50:02Z), WWDR G5 (2030-12-10), Apple Root CA copy (2035-02-09) | leaf and WWDR (both notAfter 2023-02-07T21:48:47Z), Apple Root CA copy |
| `sid` matches | 1, the leaf | 1, the leaf |
| Top-down acceptance order | WWDR G5, root copy, then leaf | WWDR, root copy, then leaf |
| PKIX path at the creation date | leaf, WWDR G5 (2 below the anchor) | leaf, WWDR (2 below the anchor) |
| Same chain at the clock (2026-10-06) | `INVALID_CERTIFICATE` | `INVALID_CERTIFICATE` |
| Markers, CMS signature | present, valid | present, valid |
| Payload | `ProductionSandbox`, `SANDBOX`, 2 in-app purchases | `ProductionSandbox`, `SANDBOX`, 187 in-app purchases |
| Unmodelled top-level types kept raw | 6, 7, 8, 9, 10, 11, 13, 14, 20, 25 | the same |
| `verifyReceipt` | verified | verified |

The g5 leaf expired on 2026-08-23, so since that day the g5 receipt
verifies only because validity is judged at its creation date; at the
clock its chain is `INVALID_CERTIFICATE`. The legacy chain has been in the
same state since 2023-02-07.

**Where it stops holding.** These two receipts, BouncyCastle 1.86 and the
code at `993cb5f`. The clock-instant row depends on the day the trace runs:
before 2026-08-23 the g5 chain passed at the clock too.
