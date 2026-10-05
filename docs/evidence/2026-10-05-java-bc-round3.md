# Java port, review round 3: what BouncyCastle accepts that the core refuses

**Question.** After two review rounds and the L1 to L7 fixes, does the
Java implementation still accept an input the core refuses, change a
verdict under a host's JVM settings, or let an exception escape? The
answer feeds R20 (four new rows) and the `java/README.md` platform
caveats, and it told the JDK vendor matrix
([2026-10-05-java-jdk-vendors](2026-10-05-java-jdk-vendors.md)) what to
look for.

**Method.** The code is `java/` at 8ff4085 (library 0.8.1, BouncyCastle
1.86), run on OpenJDK 21.0.10 on one 4 vCPU Linux x86_64 machine. The
core's verdict for the same bytes comes from `corediff`, a Go program
(Go 1.25.0, wazero 1.12.0) over the committed `go/internal/wasm/aprv.wasm`
(0.8.1).
Every input is a public sandbox fixture under `fixtures/` or a
re-signing of one under a key the probe generates; no production
receipt. The probes and the harness are in
[`2026-10-05-java-bc-round3/`](2026-10-05-java-bc-round3/), with the
commands that reproduce each number. The baseline, `mvn -f java/pom.xml
test`, was green: 599 tests, all 388 cases.

## Results

### Accepted by Java, refused by the core (J1 to J4)

None of the four is in a signed field, and Apple produces none of them,
so none changes an Apple-signed input's verdict or accepts anything
unsigned. The owner recorded them in R20 on 2026-10-05 rather than add
code to either implementation.

| # | Input | Java | Core | Probe, output line |
|---|---|---|---|---|
| J1 | Genuine receipt, outer `ContentInfo.contentType` set to `id-data` or `1.2.3.4` | ok | `MALFORMED` | `Probe1Envelope`: `m1-outer-oid-data: ok`, `m1b-outer-oid-bogus: ok` |
| J2 | An `x5c` entry, any of the three, followed by a zero byte, by garbage, by 5,000 bytes or by a second certificate; a root slot holding leaf and root; the leaf as PEM text; the leaf inside a PKCS#7 certs-only bundle (header re-signed each time) | ok | `INVALID_CERTIFICATE` | `Probe14Trail`: `t1` to `t7` ok; `Probe15Pem`: `u1-leaf-as-pem: ok`, `u2-leaf-as-pkcs7-certs-only: ok` |
| J3 | Leaf whose AuthorityKeyIdentifier differs from the intermediate's SubjectKeyIdentifier, names and signature valid | ok | `UNTRUSTED_CHAIN` | `Probe18Profile`: `p3-inter-has-skid-leaf-akid-other: ok` |
| J4 | ES256 with a secp256k1 or brainpoolP256r1 leaf (64-byte signature) | ok | `INVALID_SIGNATURE` | `Probe17Curve`: `curve-secp256k1 (sig 64 bytes): ok`, `curve-brainpoolP256r1: ok`; the P-384 leaf is `INVALID_SIGNATURE` in both |

### JVM settings that reach a verdict (J5, J6)

| # | Finding | Measurement |
|---|---|---|
| J5 | BouncyCastle draws from the JVM's default `SecureRandom` when it first decodes an RSA public key (`RSAKeyParameters.validate`, Miller-Rabin through `CryptoServicesRegistrar.getSecureRandom()`). With a first-listed provider whose `SecureRandom` throws: `Verifier.create` throws (`failed to recover public key`) with the runtime probe on; with `runtimeProbe(false)` a genuine receipt answers `UNTRUSTED_CHAIN` (`signer certificate is not issued under a pinned Apple root`), not `INTERNAL_ERROR`, because `signedByAny` swallows the `RuntimeException` | `Probe9BadRng`. `Probe8Rng`: the draw happens on a miss in BouncyCastle's static `BigIntegers.Cache`, which keeps 8 moduli, so warm calls draw 0 bytes |
| J6 | Legal input nested below BouncyCastle's bound of 64 overflows a small thread stack: a SignerInfo `digestAlgorithm` nested 55 deep escapes as `StackOverflowError` at 152 KB and parses at 160 KB. A genuine receipt, a JWS and an endpoint call complete at 64 KB. The default 1 MB stack has about six times the margin | `Probe6Stack`: `stack=152k ... ESCAPED java.lang.StackOverflowError`, `stack=160k ... ok`; `Probe7MinStack` |

### Nothing found

- **Fuzz against the core.** `Probe3Fuzz`: 6,000 mutations of the public
  receipts; 51 "Java ok, core `MALFORMED`", all at the outer OID or the
  `digestAlgorithms` tag, the two unsigned envelope fields of J1's R20
  row. `Probe10JwsFuzz`: 8,000 header and payload
  edits, re-signed. No exception escaped; every other mismatch is a
  recorded R20 class (lone surrogate escape, unknown digest OID, the
  `allow_non-der_tbscert` re-encode).
- **Concurrency.** `Probe13Conc`: 24 threads for 15 s over mixed genuine
  and hostile input, 12,028 genuine calls all ok, nothing thrown.
- **Global state.** `Probe2Global`: `Security` providers and properties,
  system properties, default `Locale` and `TimeZone` unchanged after
  `create`, both verify methods and the endpoint.
- **Dates.** `Probe12Tz`: 42,000 endpoint dates from signed receipts,
  years 0000 to 9999, rendered as the core renders them.
- **Locale, charset, time zone.** `locales.sh`: tr-TR, th-TH-TH, ja-JP-JP
  with `file.encoding=ISO-8859-1`, ar-SA with `Pacific/Kiritimati`: the
  conformance, endpoint and decoder tests pass unchanged.
- **Security configuration.** `sec1.props` disables SHA1, SHA256, RSA, EC
  for certpath; `sec2.props` reorders the providers: verdicts unchanged.
- **Stricter than the core, which fails closed.** `Probe18Profile` p5: a
  `policyConstraints` with `requireExplicitPolicy=0` on the intermediate
  is `UNTRUSTED_CHAIN` in Java and ok in the core. Both refuse a v3
  intermediate without BasicConstraints. Both accept a leaf with EKU
  serverAuth, keyUsage keyCertSign only, or CA:true with pathlen 0, an
  intermediate with a code-signing EKU, and a root whose notAfter is
  before the chain instant (`Probe16Anchor`).
- **Trust and binding.** Keys are decoded only after a pinned root
  vouches for the certificate; the signer is bound by SID to an embedded
  certificate in `authenticated`; both Apple marker OIDs are required;
  the chain is checked before the signature. The signed-attribute
  relabelling forgery is blocked because an `Attribute` needs an OID
  first element while receipt attributes start with an INTEGER
  (`Probe4Attr`). The JWS `alg` check, `x5c` count, base64url rule and
  signing input match the core (`Probe11Esc`).

## Where this stops holding

- One JDK (OpenJDK 21.0.10, HotSpot). The vendor matrix runs the suite
  elsewhere but not these probes; OpenJ9 frame sizes (J6) and other
  vendors' default `SecureRandom` (J5) were not measured.
- `corediff` runs the committed Go module, which can lag `rust/src`
  between releases; at 0.8.1 they agree.
- The receipt path was not probed for J3; only the JWS path was.
- `X500Principal.equals` (JDK) and BouncyCastle's `X500Name` both
  canonicalise names; only this JDK's behaviour was seen.
