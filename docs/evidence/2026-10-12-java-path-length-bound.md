# Java's post-build path-length check, reached

**Question.** `ReceiptCore.validateChain` refuses a built path longer
than six certificates after `CertPathBuilder` returns it, and no test
reached that check (vendor review F2, 2026-10-11). Is it dead, or does
some genuinely signed receipt reach it? The owner chose to test it and
keep it (Q103 a); if no shape reached it, the check would have been
reported instead.

**Versions.** BouncyCastle 1.86 (the pin and floor), OpenJDK 21.0.10,
Go 1.24.7 with wazero 1.12.0 over the committed
`go/internal/wasm/aprv.wasm` (SHA-256 `0aa53e8e…c45b`, pinned in
1abad35c, which contains the current `rust/src/path.rs`; the core
commits after it only touch clippy lints and the OpenSSL 4.0.3 build).
Run on 2026-10-12 on `test/java-chain-length-bound`, from main at
4d86e13e. The BouncyCastle line numbers below are from the 1.86 sources
jar on Maven Central, the OpenSSL ones from openssl-src 400.0.2+4.0.3;
the pinned module may predate the move to 4.0.3 (bdefa05e), and the
function cited is read, not instrumented.

## Why the walk does not bound the built path

Two bounds sit in front of the check:

- The top-down walk accepts a certificate in round *r* when its issuer
  name equals the subject of a certificate accepted in round *r*−1 and
  that certificate's key verifies it (`AppleTrust.signedByAny`), for
  six rounds.
- BouncyCastle's builder refuses to extend a path when
  `tbvPath.size() - 1 > maxPathLength`
  (`PKIXCertPathBuilderSpi.java:163-169`). It counts every certificate,
  self-issued or not, and with `setMaxPathLength(5)` it still returns
  paths of seven. It tries candidate issuers out of a `HashSet`
  (`:236-263`), matched by subject name only
  (`CertPathValidatorUtilities.findIssuerCerts`, `:1221-1271`), and
  moves to the next candidate when a path fails validation.

When every certificate has its own key, round count equals depth, so
the walk stops at six and the builder never sees seven. Two certificates
with the same subject and key at different depths break that: the walk
accepts the certificates below them one round after the shallower copy,
and the builder may route through the deeper one.

## Results

`probe-output.txt` holds the second run. The first run, an earlier
draft of the same probe before the message change, gave the old
message: `self-6`
4 refused of 20, `self-7` 6, `cross-valid-5` 10, `cross-expired-5` 20,
`cross-expired-4` 0.

| Shape (20 receipts each, two runs) | Java refused | Core refused |
|---|---|---|
| `self-6`: one CA name and key, under the root, then five same-key self-issued renewals | 5 of 40 | 0 of 40 |
| `self-7`: six renewals | 8 of 40 | 0 of 40 |
| `cross-valid-5`: the CA under the root, and again below five other CAs | 18 of 40 | 0 of 40 |
| `cross-expired-5`: the same, with the copy under the root expired | 40 of 40 | 40 of 40 |
| `cross-expired-4`: four other CAs, a six-certificate path | 0 of 40 | 0 of 40 |

Every refusal is `UNTRUSTED_CHAIN` with the length message: Java's
post-build check, the core's `chain exceeds the maximum length`. The
`rerun` probe gave each of the 100 receipts of the second run Java's
first answer again, three times each in a new JVM: the answer is fixed
by the receipt's bytes, through the certificates' hash codes, and moves
between receipts of one shape.

- **The check is live and load-bearing.** `cross-expired-5` reaches it
  every time: the builder backtracks off the expired copy and returns
  the seven-certificate path through the current one. With the check
  disabled, that receipt verifies (`ReceiptVerificationTest.
  boundsThePathTheBuilderReturnsNotOnlyTheWalk` fails with "nothing was
  thrown"). That test now pins it.
- **The review's shape reaches it by chance only.** Same-key
  self-issued renewals put every renewal in round 2, but a short path
  through the copy under the root always exists, and Java refuses only
  when the builder's `HashSet` order takes a renewal first.
- **Java and the core disagree on `self-*` and `cross-valid-5`.** The
  core hands OpenSSL the walk's certificates in round order, and
  OpenSSL takes the first issuer valid at the instant
  (`get0_best_issuer_sk`, `x509_vfy.c:414-450`), with no backtracking.
  That is the copy under the root, so the core always builds the short
  path and verifies. Java refuses some of those receipts. Where the long
  route is the only valid one (`cross-expired-5`), both refuse.

## Where this stops holding

- BouncyCastle 1.86. A builder that bounds the path itself, or that
  tries issuers in a fixed order, changes every Java column but
  `cross-expired`.
- No receipt Apple signs has either shape: Apple's chains are leaf,
  WWDR intermediate, root. The disagreement refuses a receipt with a
  valid short path; it accepts nothing unsigned. R20 records it
  (row of 2026-10-12).
- `cross-expired-5` gives the same verdict in both implementations, so
  it could become a shared case. None was added.

## Outcome (2026-10-12, Q108 a)

The owner chose to delete the post-build check, on the condition that
deleting it opens no hole. It was deleted the same day. The test above
became `acceptsAnyPathTheBuilderValidatesWhateverItsLength` (the
seven-certificate `cross-expired-5` shape now verifies), and
`refusesTheSevenCertificatePathWhenOneLinkIsBroken` pins the same shape
with one defect on the long route.

Why the check carried no security weight. Every certificate on a path
the builder returns, whatever its length, has passed these checks:

- The walk accepted it only once a pinned root, or a certificate
  accepted in the round before, verified its signature. Only those
  certificates reach the builder, so the path is made of certificates
  signed under keys a pinned root vouches for.
- BouncyCastle's PKIX validator verifies every signature on the path
  again, from the anchor down, and checks each certificate's validity
  at the instant, the CA rules (`basicConstraints`, `pathLenConstraint`,
  `keyUsage`) and every critical extension other than the two
  `AppleTrust.HANDLED_CRITICAL_EXTENSIONS` marks processed.
- `requireMarkers` still asks Apple's signing marker on the signer and
  the WWDR marker on the certificate above it, and the CMS signature is
  still checked with the signer's key.

An extra link therefore needs a certificate issued under a key the
pinned roots vouch for, valid at the instant and allowed to issue. An
attacker without one of Apple's CA keys cannot make one; an attacker
with one can already sign a short path. The deleted check refused only
a length, and a length alone gave nothing.

The defect probe (`CrossDefectProbeTest`, `probe-output.txt`) shows
the long route still refused when one link is wrong: a CA signed by a
key no root vouches for (40 of 40 refused), a CA that is not a CA (40
of 40), the deep copy expired at the instant (40 of 40). Each is refused
by the walk or by PKIX; the forged link and the expired copy always
answer `INVALID_CERTIFICATE`, from the expired short copy that is all
that is left. The not-a-CA answer is `UNTRUSTED_CHAIN` or
`INVALID_CERTIFICATE` by `HashSet` order, never ok.

Cost is unchanged: the check ran after the build. The builder's
`setMaxPathLength(5)` still refuses an eighth certificate, the walk
still runs six rounds, and a receipt embeds at most 10 certificates.

The check also made the verdict follow BouncyCastle's `HashSet` order
on the `self-*` and `cross-valid-5` shapes. After the deletion the
third run of the shapes probe answers ok for all 100 receipts, and
again for each of them in a new JVM.

Java and the core now agree on every shape here but `cross-expired-5`,
which Java accepts and the core refuses ("chain exceeds the maximum
length"). The owner accepted that difference: Java is judged on its
own. R20 records it (row of 2026-10-12, updated).
