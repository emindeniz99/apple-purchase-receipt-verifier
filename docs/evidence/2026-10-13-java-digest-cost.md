# Java: what the SignerInfo's digest algorithm costs

Date: 2026-10-13. Measures what the digest a SignerInfo declares costs the
Java implementation, for owner decision Q134 a (refuse the slow digests
before digesting) and the figures in DECISIONS.md R20, java/README.md and
THREAT-MODEL.md §3.7. Sources and commands:
[`2026-10-13-java-digest-cost/`](2026-10-13-java-digest-cost/).

## Question

A SignerInfo's digestAlgorithm is not signed, so the sender picks it.
BouncyCastle digests the whole encapsulated content with it, once per
SignerInfo and up to the cap of four, before it compares the
messageDigest attribute or checks a signature. Nothing about it needs a
key: the SignerInfos only have to name a certificate that chains to a
pinned root, and Apple's receipt-signing leaf is in every receipt. How
much does the slowest digest BouncyCastle implements cost at the receipt
cap, and which digests are slow enough to refuse?

## Setup

- OpenJDK 21.0.10 (Ubuntu build), OpenJDK 8u504 and 11.0.32 (JRE), default
  collectors, 4 vCPU. bcprov, bcutil and bcpkix 1.86.
- The library at `main` `da79ce4d` for the figures before the denylist,
  and the `fix/java-digest-denylist` branch for those after.
- The ratios: every OID-shaped string in the provider's entries (the
  test takes those in its MessageDigest entries, the same 37), offered
  to the digest calculator provider `JcaSimpleSignerInfoVerifierBuilder`
  builds (`JcaDigestCalculatorProviderBuilder` on BouncyCastle's
  provider). 37 resolve. Each is timed over the same random bytes,
  interleaved with the others, and its best warm time is divided by
  SHA-256's from the same run. The parameterised SHAKE256-with-length OID
  (2.16.840.1.101.3.4.2.18) resolves only with a length and runs the
  SHAKE256 engine, which is among the fastest.
- The call: `DigestLeverProbe` builds a receipt at the 3 MiB base64 cap
  (3,145,708 characters) whose four SignerInfos name the test PKI's
  genuine leaf, declare the digest under test and are signed by an
  unrelated key, and times `verifyReceipt` under the test PKI's root.

## Results

### Ratios to SHA-256

`results/sweep.txt`: `DigestSweep` three times per JDK in each of six
settings (buffer 256 KiB to 2 MiB, two to six warm rounds, five to eight
measured), 54 runs. Lowest and highest ratio seen:

| Digest | OID | JDK 8 | JDK 11 | JDK 21 |
|---|---|---:|---:|---:|
| GOST R 34.11-94 | 1.2.643.2.2.9 | 17.5–21.5 | 17.8–24.9 | 18.4–22.4 |
| MD2 | 1.2.840.113549.2.2 | 16.8–17.8 | 15.7–17.8 | 15.8–16.8 |
| Whirlpool | 1.0.10118.3.0.55 | 7.7–9.2 | 7.3–8.9 | 7.3–8.1 |
| DSTU 7564-384, -512 | 1.2.804.2.1.1.1.1.2.2.2, .3 | 5.0–5.5 | 4.0–4.7 | 3.7–4.3 |
| GOST R 34.11-2012 (Streebog) 256, 512 | 1.2.643.7.1.1.2.2, .3 | 4.5–5.2 | 4.4–5.0 | 4.8–5.3 |
| DSTU 7564-256 | 1.2.804.2.1.1.1.1.2.2.1 | 4.0–4.3 | 3.1–3.8 | 2.9–3.4 |
| RIPEMD-160 | 1.3.36.3.2.1 | 2.4–2.6 | 2.0–2.3 | 2.2–2.5 |
| the other 28 (SHA-1, SHA-2, SHA-3, SHAKE, BLAKE2, BLAKE3, SM3, MD4, MD5, RIPEMD-128/256) | | at most 1.5 | at most 1.2 | at most 1.3 |

`results/test-tables.txt` is `DigestDenylistCostTest`'s own table, 20
rounds of 512 KiB inside the Maven suite, once per JDK; it agrees (DSTU
7564-256 at 4.29, 3.60 and 3.10, RIPEMD-160 at 2.54, 2.10 and 2.37).

The slow digests form a cluster: the eight above RIPEMD-160 are 2.9 times
SHA-256 or more on every JDK, and everything else is 2.6 times or less.
`results/survey-jdk21.txt`, the first survey over
8 MiB with one implementation per class and one warm-up run, puts the
same three on top but reads some fast digests high (BLAKE2b-256 3.5
there, about 0.6 in the sweep), so the sweep's interleaved rounds
replaced it.

These ratios are the digest alone. A figure of 3.3 for Streebog, cited
before this note, divided an 8 MiB digest by a whole SHA-256 call at the
cap; on the digest alone Streebog is 4.4 to 5.3 times SHA-256.

### The band the test asserts

`DigestDenylistCostTest` asserts two edges, not one cut: every refused
digest costs more than 2.4 times SHA-256, and every other one less than
3.2 times. A digest measured between the edges passes whether it is
refused or not, so one near the boundary cannot flip the test from run
to run; only a digest that leaves the band on the wrong side fails it.
Each edge sits at least a fifth away from the nearest measurement: the
fastest refused digest, DSTU 7564-256, was 2.94 at its lowest (JDK 21),
22% above 2.4, and the slowest allowed one, RIPEMD-160, was 2.58 at its
highest (JDK 8), 24% below 3.2. The edges first proposed, 2.5 and 3.0,
left 18% and 16% on those two JDKs. A digest whose JIT compilation lags
reads slow for a few rounds, so the test keeps each digest's best time
and continues for up to 20 rounds until the table agrees.

### One call at the cap

`results/lever-before.txt`, four SignerInfos, before the denylist. Every
call ended `INVALID_SIGNATURE`, "CMS signature does not match the signer
certificate's key": the digest ran over the whole content four times and
matched, and only the signature failed.

| Digest | JDK 21 cold | JDK 8 cold | JDK 21 warm | JDK 8 warm |
|---|---:|---:|---:|---:|
| GOST R 34.11-94 | 1,270–1,474 ms | 1,637–1,846 ms | 1,187 ms | 1,179 ms |
| MD2 | 1,175–1,250 ms | 1,300–1,369 ms | 1,081 ms | 1,193 ms |
| SHA-256 | 152–204 ms | 184–250 ms | 82 ms | 94 ms |

`results/lever-three-refused.txt` is the same probe with only GOST R
34.11-94, MD2 and Whirlpool refused, the step before the whole cluster
was: Streebog then cost 331–388 ms warm and up to 613 ms cold at the
cap, and DSTU 7564-384 and -512 267–439 ms warm and up to 554 ms cold.

`results/lever-after.txt`, with all eight refused. They end at "CMS
verifier refused the signer info: digest <OID> is refused" before
anything is digested; RIPEMD-160, now the slowest digest accepted, is
digested and ends where SHA-256 does.

| Digest | JDK 21 cold | JDK 8 cold | JDK 21 warm | JDK 8 warm |
|---|---:|---:|---:|---:|
| the eight refused | 78–137 ms | 93–150 ms | 21–28 ms | 23–34 ms |
| RIPEMD-160 | 262–442 ms | 315–425 ms | 174 ms | 207 ms |
| SHA-256 | 176–254 ms | 194–226 ms | 86 ms | 93 ms |

A refused SignerInfo now costs less than a SHA-256 one, since nothing is
digested. The slowest digest accepted costs about twice a SHA-256 call at
the cap, 0.17 to 0.21 s warm and up to 0.44 s cold, where GOST R
34.11-94 cost about 1.2 s warm and up to 1.8 s cold.

## Verdict

Refuse the slow cluster by OID before the digest runs (owner, Q134 a):
GOST R 34.11-94, MD2, Whirlpool, GOST R 34.11-2012 256 and 512, and DSTU
7564 256, 384 and 512, none a hash Apple signs receipts with. The verdict
is the one a digest BouncyCastle does not implement gets:
`INVALID_SIGNATURE`, and the next SignerInfo is tried (RFC 4853). A
denylist rather than an allowlist, so a fast digest added later is
accepted without a code change.

The Rust core refuses all eight because none is present in it. The core
loads no provider: no `OSSL_PROVIDER_load` appears in `rust/openssl` or
`rust/src` (`rust/tests/trust_pinning.rs` forbids `OSSL_PROVIDER` in its
source), and `rust/openssl/src/lib.rs` initialises OpenSSL with
`OPENSSL_INIT_NO_LOAD_CONFIG`, so no configuration file can load one. Only
OpenSSL's default provider is present. MD2 and Whirlpool live in the
legacy provider since OpenSSL 3.0, and GOST R 34.11-94, Streebog and DSTU
7564 are not in OpenSSL at all. `results/verdicts.txt` shows the verdicts
agree: the genuine G5 receipt with its one SignerInfo's digestAlgorithm
set to each of the eight is `INVALID_SIGNATURE` in the core and in Java.
The MD2 receipt is the shared case
`receipt/reject-a-signer-info-in-a-refused-digest`.

## Where this stops holding

- One machine; the ratios move by up to a third between runs and JDKs,
  which is why the test asserts a band with a dead zone rather than a
  single cut.
- bcprov 1.86. A BouncyCastle that adds a digest, or changes how fast one
  runs, changes the table; `DigestDenylistCostTest` fails when one leaves
  the band on the wrong side.
- The cost is per byte of content, so the cap bounds it; four SignerInfos
  is the cap on those.
