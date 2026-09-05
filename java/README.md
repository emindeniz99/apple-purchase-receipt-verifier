# apple-purchase-receipt-verifier (Java)

Verify Apple in-app purchases locally — no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS transactions and legacy PKCS#7 app receipts against pinned Apple
root certificates.

```xml
<dependency>
  <groupId>io.github.emindeniz99</groupId>
  <artifactId>apple-purchase-receipt-verifier</artifactId>
  <version>0.3.0</version> <!-- check the Maven Central badge in the project README for the current one -->
</dependency>
```

```java
import io.github.emindeniz99.applepurchasereceiptverifier.AppleRootCerts;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;

// Legacy PKCS#7 app receipt
ReceiptVerifier receipts = new ReceiptVerifier(AppleRootCerts.receiptRoots(), "com.example.app");
AppReceipt receipt = receipts.verify(receiptBase64);
System.out.println(receipt.receiptType() + " " + receipt.inAppPurchases().size());

// StoreKit 2 signed transaction
JwsVerifier transactions = new JwsVerifier(
        AppleRootCerts.jwsRoots(), "com.example.app", EnumSet.of(Environment.PRODUCTION, Environment.SANDBOX));
TransactionPayload transaction = transactions.verifyTransaction(jws);
System.out.println(transaction.productId() + " " + transaction.expiresDate());
```

Java **8** is the compiled target (`maven.compiler.release=8`), built and
tested with any modern JDK. Every entry point throws the checked
`VerificationException`, never an unchecked one.

## The three JWS entry points

```java
Set<X509Certificate> roots = AppleRootCerts.jwsRoots();
JwsVerifier verifier = new JwsVerifier(
        roots,
        "com.example.app",
        EnumSet.of(Environment.PRODUCTION, Environment.SANDBOX),
        1_234_567_890L,   // appAppleId — required to accept a PRODUCTION AppTransaction
        300_000L);        // maxSignedAge, milliseconds — null disables the rule

TransactionPayload transaction = verifier.verifyTransaction(jws);      // JWSTransactionDecodedPayload
AppTransactionPayload app = verifier.verifyAppTransaction(jws);        // AppTransaction
Map<String, Object> claims = verifier.verifyRaw(jws);                  // renewal info, notifications
```

`verifyRaw` checks the chain and the signature, and enforces no *identity*
claim: the caller checks bundle id, environment and app Apple id in the
returned map itself. It is not claim-free, though — it runs the same signed
path as `verifyTransaction`, so a configured `maxSignedAge` applies to it
too and a payload older than that is `STALE_PAYLOAD` rather than a returned
map.

Include `Environment.SANDBOX` in `acceptedEnvironments` on any endpoint App
Review can reach: App Review runs production builds against sandbox.

`JwsVerifier` has three constructors, each the previous one plus optional
trailing parameters (`appAppleId`, `maxSignedAge`, then `clock`); passing
`null` for a trailing parameter has the same effect as omitting it.

**Date claims on `TransactionPayload` and `AppTransactionPayload` are
`Long` epoch-millisecond fields** — `signedDate`, `purchaseDate`,
`expiresDate`, `revocationDate`, `receiptCreationDate` — exactly as Apple
ships them. That is contractual across every port of this library: converting
them to a `java.time` type would lose the raw claim and put this port out of
step with the other eight. Receipt *attribute* dates are the opposite case
and are exposed as `Instant`.

Every claim, modelled or not, is reachable through `verifyRaw`.
`TransactionPayload.isActiveAt(Date now)` answers the entitlement question
from the signed claims alone: not revoked, and for a subscription not
expired. A refund or a renewal after signing is invisible to it.

## Legacy PKCS#7 app receipts

`ReceiptVerifier.verify` is overloaded on the input type, so both transport
forms are reachable with and without the device GUID:

```java
ReceiptVerifier verifier = new ReceiptVerifier(AppleRootCerts.receiptRoots(), "com.example.app");

verifier.verify(receiptDer);                       // byte[]
verifier.verify(receiptBase64);                     // String
verifier.verify(receiptDer, deviceGuid);            // byte[], byte[]
verifier.verify(receiptBase64, deviceGuid);         // String, byte[]
```

`verify(String)` decodes exactly what Apple's `receipt-data` accepts: RFC
4648 Base64, the standard (`+`/`/`) or base64url (`-`/`_`) alphabet — never
both in the same string — padding present or omitted, and `CR`/`LF`/space/tab
anywhere. A character neither alphabet defines, anything but whitespace after
padding starts, or a `=` count other than zero or the exact count the data
length requires is `INVALID_RECEIPT_FORMAT` before any bytes reach the CMS
parser — see `ReceiptBase64` in `receipt/ReceiptBase64.java`.

Passing `deviceGuid` additionally enforces the device binding:
`SHA1(guid ‖ opaqueValue ‖ bundleIdBytes)` must equal attribute 5, compared in
constant time via `MessageDigest.isEqual`. The check is optional because a
server does not always have the client's `identifierForVendor`.

Attribute types the library does not model are exposed verbatim on
`AppReceipt.unknownAttributes()` / `InAppPurchase.unknownAttributes()`,
keyed by type, to the raw verified-but-undecoded value bytes — so a field
Apple adds later stays reachable without a library update.

`ReceiptVerifier.verifyReceiptCore(byte[] receiptDer, Set<X509Certificate>
trustedRoots)` is the static primitive the verifier and the endpoint are both
built on: chain and signature only, **without** the bundle-id check. It is
public because the alternative is a wildcard bundle id inside a security
library. A caller that unlocks a product on the strength of it, without
comparing `receipt.bundleId()`, will accept a genuine, correctly signed
receipt from a different app.

## The `verifyReceipt`-compatible endpoint

```java
VerifyReceiptEndpoint endpoint = new VerifyReceiptEndpoint(
        AppleRootCerts.receiptRoots(), Environment.PRODUCTION);

Map<String, Object> response = endpoint.verifyReceipt(requestBody);   // Map in, Map out
String json = endpoint.verifyReceiptJson(rawRequestBody);             // String in, String out
```

Neither method throws: the Apple status code is a field of the body, for
every input, including one that is not JSON (`verifyReceiptJson` answers
`{"status":21002}` for that case). The statuses it can produce are
`STATUS_OK` (`0`), `STATUS_MALFORMED` (`21002`), `STATUS_NOT_AUTHENTICATED`
(`21003`), `STATUS_SANDBOX_RECEIPT_ON_PRODUCTION` (`21007`),
`STATUS_PRODUCTION_RECEIPT_ON_SANDBOX` (`21008`) and `STATUS_INTERNAL`
(`21009`) — and no others, because the rest describe conditions that only
exist on Apple's servers. Local 21007/21008 routing fails closed: only
receipt types `Production` and `ProductionVPP` count as production.

Like Apple's endpoint, this does **not** check the bundle id — compare
`receipt.get("bundle_id")` yourself. `password` and
`exclude-old-transactions` are accepted for wire compatibility and never
read. See [COMPARISON.md](../COMPARISON.md) for the field-by-field fidelity
account.

The two-argument `VerifyReceiptEndpoint(Set, boolean)` constructor is
deprecated in favor of the `Environment` overload — a `boolean` cannot say
at a call site which of Production or Sandbox it means.

## The error vocabulary

Every failure is a checked `VerificationException` carrying one of eleven
`VerificationException.Reason` values, and nothing else — no logging, no
metrics, no callbacks. The message is `Reason + ": " + detail`; match on
`reason()`, never parse it.

```java
try {
    TransactionPayload transaction = verifier.verifyTransaction(jws);
} catch (VerificationException e) {
    switch (e.reason()) {
        case WRONG_ENVIRONMENT:
            retryAgainstSandbox();
            break;
        case INVALID_CHAIN:
        case INVALID_SIGNATURE:
            alertSecurity();
            break;
        default:
            reject(e.reason());
    }
}
```

| `Reason` | Raised when |
|---|---|
| `INVALID_JWS_FORMAT` | not three dot-separated segments, a segment that is not a base64url-encoded JSON *object*, `alg != ES256`, or an `x5c` that is not exactly three entries |
| `INVALID_CERTIFICATE` | an `x5c` entry does not decode to a parseable certificate. The base64 goes through `Base64.getMimeDecoder()`, which skips characters outside the alphabet, so a stray `!` inside an entry is dropped rather than refused — what is left has to fail to parse for this verdict |
| `INVALID_CERTIFICATE_PURPOSE` | the leaf or intermediate lacks its Apple marker OID, or the receipt signer lacks its own |
| `INVALID_CHAIN` | the path does not reach a pinned anchor, a certificate was not valid at the signing instant, or a receipt embeds more than ten certificates or a chain longer than six |
| `INVALID_SIGNATURE` | the ES256 or CMS signature check failed, or the signer key is not RSA |
| `WRONG_BUNDLE_ID` | the verified payload or receipt names another bundle |
| `WRONG_ENVIRONMENT` | the environment is outside the accepted set |
| `WRONG_APP_APPLE_ID` | a Production `AppTransaction` does not name the configured app Apple id |
| `INVALID_RECEIPT_FORMAT` | the PKCS#7/CMS blob does not parse, has trailing bytes, has no signer info, or an attribute is malformed |
| `DEVICE_HASH_MISMATCH` | the device hash does not match attribute 5, or the receipt lacks the attributes the check needs |
| `STALE_PAYLOAD` | the payload was signed longer ago than `maxSignedAge` |

The vocabulary is **closed** by the cross-port contract: a twelfth reason
would be a change to the shared vector file and to every port at once.

**Misconfiguration is a different failure mode.** Empty or null trust
anchors, a null bundle id, an empty accepted-environment set, and an
endpoint environment other than `PRODUCTION` or `SANDBOX` all throw
`IllegalArgumentException` from the constructor. A programming mistake must
not be catchable as a verification verdict.

## Trust anchors

`AppleRootCerts.jwsRoots()` and `.receiptRoots()` both return all three
published Apple roots (Apple Inc. Root CA, Apple Root CA - G2, Apple Root
CA - G3) as a `Set<X509Certificate>`, loaded from `.cer` resources bundled
in the jar. Apple deliberately documents the JWS chain as ending in "an
Apple root certificate" rather than naming one, so narrowing either set
would fail closed, silently, the day Apple re-anchored a path.

Trust reaches this library through exactly the `trustedRoots` constructor
argument, never through the JDK's own `cacerts` or a `TrustManagerFactory`
default. `TrustStoreIsolationTest` (below) is what proves that, rather than
only documenting it.

## Environment routing and staleness

`acceptedEnvironments` on `JwsVerifier` is a `Set<Environment>` checked
against the payload's `environment` (or `receiptType`, for an
`AppTransaction`) claim; a value outside it is `WRONG_ENVIRONMENT`.
`VerifyReceiptEndpoint`'s single `Environment` drives the 21007/21008 status
routing the same way the other ports do.

`maxSignedAge` (milliseconds) is optional; a payload signed longer ago than
that is `STALE_PAYLOAD`. A payload that states no signing date at all has no
age to be stale by, so the rule never fires for it.

## The clock

`JwsVerifier`'s six-argument constructor and `VerifyReceiptEndpoint`'s
three-argument constructor both take an optional `java.time.Clock`; `null`
(the default of every shorter constructor) means `Clock.systemUTC()`. It is
read in exactly two places:

1. the `STALE_PAYLOAD` comparison in `JwsVerifier`;
2. the `request_date` / `_ms` / `_pst` triple in `VerifyReceiptEndpoint`.

**Certificate validity is never judged by the injected clock.** It is judged
at the payload's own `signedDate` / `receiptCreationDate`, or at the
receipt's attribute-12 creation date; where the input states no date of its
own, the fallback reads `System.currentTimeMillis()` directly — not the
injected clock — so a caller injecting a clock to test staleness, or to work
around skew, cannot thereby accept an expired chain or expire a live one.

`ReceiptVerifier` therefore takes **no clock at all**: it would have no
consumer, and an option with no consumer is an invitation to wire it into
the one place it must never reach.

## Resource bounds

Two bounds are internal to `ReceiptVerifier` and are not constructor
arguments — Java relies on BouncyCastle's CMS/ASN.1 reader rather than a
hand-rolled one, so there is no depth or node-count knob to expose:

- **At most ten embedded certificates** (`MAXIMUM_EMBEDDED_CERTIFICATES`),
  enforced before any of them is decoded. Genuine receipts carry one to
  three.
- **A chain of at most six certificates**, anchor excluded
  (`MAX_PATH_LENGTH`), the same number every other port in this repository
  uses. `PKIXBuilderParameters.setMaxPathLength` counts intermediates rather
  than certificates and exempts self-issued ones from that count (RFC 5280
  §6.1.4), so the built path is measured again afterward against the
  six-certificate bound directly.

Unlike the PHP and Rust ports, this library does not expose a configurable
ceiling on decoded receipt size or ASN.1 node count; callers who need one
should bound the input before it reaches `verify`.

## Testing

```bash
mvn test                                                  # default JDK
mvn test -Pjdk8-runtime -Djdk8.jvm=/path/to/jdk8/bin/java # the suite on a real Java 8 JVM
mvn spotless:check                                        # format/lint (not bound to any lifecycle phase)
```

`ConformanceCasesTest` runs every case in `fixtures/cases.json`, the
normative cross-language vector file every port of this library answers.

`TrustStoreIsolationTest`
(`src/test/java/.../TrustStoreIsolationTest.java`) asserts the trust-pinning
rule three ways: **environmentally**, by starting a child JVM whose
`-Djavax.net.ssl.trustStore` genuinely makes the JDK's own default trust
manager trust the fixture roots, and showing this library still refuses the
matching receipt and JWS under the bundled Apple anchors (and that this
machine's real `cacerts`, handed to the library as its whole anchor set,
refuses a genuine Apple receipt the bundled roots accept); **structurally**,
by scanning every file under `src/main/java` for any spelling that could
reach a trust store, a socket, or a subprocess; and **positively**, by
installing a JCA provider that shadows the JDK's PKIX path builder and
validator and capturing the exact anchor set that reaches it.

Beyond conformance and trust isolation, the suite covers hostile and
malformed input (`HostileJwsFixtures`, `HostileReceiptInputTest`), the
resource bounds above (`ReceiptVerifierTest`), a generated fake Apple PKI
(`TestPki`), and public genuine Apple receipts (`PublicReceiptsTest`).

`java/fuzz/` holds five [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer)
targets — the receipt path, its base64 entry point, the JWS path, the
endpoint JSON body, and the three package-private readers reached by
reflection — seeded from the shared fixtures and run by CI for a fixed
budget on every push. `java/fuzz/README.md` lists them and the invariant
each asserts beyond "only `VerificationException` escapes".

`jvm-interop/` (unpublished) proves the published jar is usable from Kotlin
and Scala 3 as well as Java — see [its
README](../jvm-interop/README.md) for what it found, including that Kotlin
categorically refuses named-argument syntax against any Java-declared
constructor, which is a Kotlin/Java-interop rule and not a fixable property
of this jar's compiled metadata.

## Port-specific: `x5c[2]` is parsed here, and only here

`x5c[2]`, the JWS header's third certificate, is never trusted anywhere in
this library: it is never compared to an anchor and the chain terminates at
the pinned root regardless of what it contains. Node, Python and Swift never
even decode it. `decodeChain` in `JwsVerifier` decodes all three `x5c`
entries as certificates before the leaf and intermediate are looked at, so a
`x5c[2]` that is not a parseable certificate is `INVALID_CERTIFICATE` in
Java, where it reaches the ES256 signature check unremarked in the other
four ports. No verdict about a well-formed JWS moves — see
[rust/README.md](../rust/README.md#a-verified-blob-is-not-an-identifier) for
the full cross-port account. This is a recorded, deliberate divergence with
no shared conformance vector yet (see [ROADMAP.md](../ROADMAP.md)), not a
bug to fix unilaterally in either direction.

## Why offline

Signature verification cannot fail because a vendor endpoint is down, so a
purchase can be honoured immediately and reconciled against the App Store
Server API afterwards. Refunds and revocations still need that
reconciliation pass — a signature proves what Apple signed, not what
happened since.

This is one of nine implementations (Java, Node, Python, Swift, Go, Ruby,
Rust, PHP, .NET) that share a single fixture suite, including Apple's own
official test fixtures, and are required to agree byte for byte. See the
[project README](../README.md) for the full picture and
[COMPARISON.md](../COMPARISON.md) for how it differs from Apple's official
libraries.

## Licence

MIT — see [LICENSE](./LICENSE).
