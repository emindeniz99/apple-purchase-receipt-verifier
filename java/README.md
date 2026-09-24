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
tested with any modern JDK.

Every verification entry point reports a rejected input as the checked
`VerificationException` and nothing else, including on input built to exhaust
memory: the size bounds under [Resource bounds](#resource-bounds) are what
make that true rather than aspirational. Two failures are deliberately
unchecked, because neither is a verdict about a payload: misconfiguration
(`IllegalArgumentException` from a constructor, see [The error
vocabulary](#the-error-vocabulary)) and bundled trust anchors that do not
match their pinned fingerprints (`IllegalStateException` from
`AppleRootCerts`, see [Trust anchors](#trust-anchors)).

The version is `0.x` on Maven Central, so the API may still change between
minor versions.

## Dependencies and conflicts

Two runtime dependencies, both compile-scope and both transitively pulled in
by Maven:

| Dependency | Jars it puts on the classpath | Size |
|---|---|---|
| `org.bouncycastle:bcpkix-jdk18on` | `bcpkix` 1.3 MB, `bcprov` 7.2 MB, `bcutil` 0.8 MB | 9.4 MB |
| `com.fasterxml.jackson.core:jackson-databind` | `jackson-databind` 1.7 MB, `jackson-core` 0.6 MB, `jackson-annotations` 0.1 MB | 2.4 MB |

Sizes are the jars at the versions the pom declared when they were measured
(BouncyCastle 1.86, Jackson 2.22.2; `bcprov` lost three megabytes between
1.85 and 1.86, so re-measure after a bump rather than trust this table).
BouncyCastle is most of what depending on this library costs, and `bcprov`
is most of BouncyCastle.

Every Central deployment carries a CycloneDX 1.6 SBOM listing exactly these
six jars, attached as the `cyclonedx` classifier
(`apple-purchase-receipt-verifier-<version>-cyclonedx.json`) and signed like
the jars, and the build is reproducible: `project.build.outputTimestamp` is
pinned in the pom, so two builds of one commit are byte-identical.

The pom declares a third, `org.jspecify:jspecify`, as `optional`: it is
annotations only, nothing reads them at run time, and an optional dependency
is not transitive, so it reaches neither your classpath nor the table above
(see [Kotlin and null-safety](#kotlin-and-null-safety)).

**BouncyCastle line collision.** The `jdk18on` artifacts share every package
name with the older `bcprov-jdk15on` and `bcprov-jdk15to18` lines but have
different artifact ids, so Maven does not deduplicate them: a classpath that
carries two of them resolves each BouncyCastle class from whichever jar comes
first, which is a property of jar ordering rather than of any version
declaration. Check before deploying:

```bash
mvn dependency:tree | grep -E 'bcprov-(jdk15on|jdk15to18)'
```

Nothing printed means the classpath carries one line. If another dependency
brings an older line, exclude it there rather than downgrading this library:
the `jdk15on` jars are no longer released.

**Jackson floor: 2.16.** `JwsVerifier` and `VerifyReceiptEndpoint` state
`StreamReadConstraints` on their mappers instead of relying on Jackson's
defaults, because a JWS header is parsed before any signature check
(see [Resource bounds](#resource-bounds)). `StreamReadConstraints` arrived in
Jackson 2.15 and `maxDocumentLength` in 2.16, so on an older Jackson 2 the
verifier fails at construction rather than running with guards it believes it
set.

Spring Boot 4.0.x pins Jackson 2 at 2.21.x through its BOM, which is above
that floor, and Jackson 3 (`tools.jackson`) sits alongside Jackson 2 under a
different package root, so an application on both is not a conflict. Verified
with a Spring Boot 4.0.8 application in `samples/spring-boot-smoke`.

## The three JWS entry points

```java
Set<X509Certificate> roots = AppleRootCerts.jwsRoots();
JwsVerifier verifier = new JwsVerifier(
        roots,
        "com.example.app",
        EnumSet.of(Environment.PRODUCTION, Environment.SANDBOX),
        1_234_567_890L);  // appAppleId, required to accept a PRODUCTION AppTransaction

TransactionPayload transaction = verifier.verifyTransaction(jws);      // JWSTransactionDecodedPayload
AppTransactionPayload app = verifier.verifyAppTransaction(jws);        // AppTransaction
Map<String, Object> claims = verifier.verifyRaw(jws);                  // renewal info, notifications
```

`verifyRaw` checks the chain and the signature, and enforces no *identity*
claim: the caller checks bundle id, environment and app Apple id in the
returned map itself.

Include `Environment.SANDBOX` in `acceptedEnvironments` on any endpoint App
Review can reach: App Review runs production builds against sandbox.

Accepting SANDBOX has a cost. TestFlight builds, including ones installed
from a public link, buy in sandbox too, and a sandbox purchase is free. So
record the environment with every grant (`payload.environment()`, or
`receipt.receiptType()` for a legacy receipt) and scope sandbox grants: give
them a short lifetime, keep them off production accounts, or limit them to
App Review's test accounts. The samples under [Integrating](#integrating-from-verified-payload-to-entitlement)
pass the environment to the grant for this reason. A sandbox purchase that
reaches a production entitlement unscoped is a free subscription for anyone
with the TestFlight link.

`JwsVerifier` has two constructors, the second the first plus the optional
trailing `appAppleId`; passing `null` for it has the same effect as omitting
it.

**Date claims on `TransactionPayload` and `AppTransactionPayload` are
`Long` epoch-millisecond fields** — `signedDate`, `purchaseDate`,
`expiresDate`, `revocationDate`, `receiptCreationDate` — exactly as Apple
ships them. That is contractual across every port of this library: converting
them to a `java.time` type would lose the raw claim and put this port out of
step with the other eight. Receipt *attribute* dates are the opposite case
and are exposed as `Instant`.

Every claim, modelled or not, is reachable through `verifyRaw`.

**Entitlement is your rule.** There is no "is active" helper, as in Apple's
own libraries; read the signed fields:

```java
long now = System.currentTimeMillis();
boolean entitled = payload.revocationDate() == null
        && (payload.expiresDate() == null || payload.expiresDate() > now);
```

That is only what the payload said when it was signed. A billing grace
period (it lives in the renewal info), an upgrade (`isUpgraded`) and a refund
after signing are yours to handle; App Store Server Notifications V2 or the
App Store Server API give the live status. `isActiveAt(Date)` is gone.

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

A null receipt is a verdict (`INVALID_RECEIPT_FORMAT`), not a
`NullPointerException`, but a literal `null` needs a cast to pick an
overload: `verify((String) null)`. A typed variable that happens to be null
resolves on its own.

`verify(String)` decodes exactly what Apple's verifyReceipt accepts as
`receipt-data` (measured 2026-09-23, see
[`docs/evidence/2026-09-23-verifyreceipt-base64.md`](../docs/evidence/2026-09-23-verifyreceipt-base64.md)):
standard base64 (`+`/`/`) with the canonical `=` padding and nothing else.
Whitespace anywhere, the base64url alphabet, omitted or extra padding,
anything after the padding and an empty string are `INVALID_RECEIPT_FORMAT`
before any bytes reach the CMS parser. Unused low bits in the last data
character are accepted, as Apple accepts them. See `ReceiptBase64` in
`receipt/ReceiptBase64.java`.

Passing `deviceGuid` additionally enforces the device binding:
`SHA1(guid ‖ opaqueValue ‖ bundleIdBytes)` must equal attribute 5, compared in
constant time via `MessageDigest.isEqual`. The check is optional because a
server does not always have the client's device GUID — the raw bytes of
`identifierForVendor` on iOS, iPadOS, tvOS and watchOS, including an iOS
app running on an Apple silicon Mac, or the primary network interface's
MAC address from `copy_mac_address` on macOS and Mac Catalyst.

`ReceiptVerifier` accepts a receipt from every environment: it takes no
environment and never raises `WRONG_ENVIRONMENT`. Read
`receipt.receiptType()` yourself. Only `Production` and `ProductionVPP` are
production; `ProductionSandbox` is a sandbox or TestFlight purchase.

Attribute types the library does not model are exposed verbatim on
`AppReceipt.unknownAttributes()` / `InAppPurchase.unknownAttributes()`,
keyed by type, to the raw verified-but-undecoded value bytes — so a field
Apple adds later stays reachable without a library update.
[RECEIPT-FIELDS.md](../RECEIPT-FIELDS.md) names every attribute type the
genuine fixture receipts carry, says which ones Apple documents and which are
community-established, and maps each modelled one to its accessor.

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

VerifyReceiptResult result = endpoint.verifyReceiptResult(requestBody);  // Map, or the raw JSON String
Map<String, Object> response = result.toResponse();                      // Apple's body as a Map
String json = result.toJson();                                           // Apple's body as JSON

String json2 = endpoint.verifyReceiptJson(rawRequestBody);  // same as verifyReceiptResult(raw).toJson()
VerifyReceiptResult bare = endpoint.verifyReceiptData(base64Receipt);   // receipt-data alone, no envelope
```

No endpoint method throws: the Apple status code is a field of the body, for
every input, including one that is not JSON (`{"status":21002}`). The
statuses it can produce are `STATUS_OK` (`0`), `STATUS_MALFORMED` (`21002`),
`STATUS_NOT_AUTHENTICATED` (`21003`), `STATUS_SANDBOX_RECEIPT_ON_PRODUCTION`
(`21007`), `STATUS_PRODUCTION_RECEIPT_ON_SANDBOX` (`21008`) and
`STATUS_INTERNAL` (`21009`), and no others, because the rest describe
conditions that only exist on Apple's servers. Local 21007/21008 routing
fails closed: only receipt types `Production` and `ProductionVPP` count as
production.

A `VerifyReceiptResult` is one verification. `status()` is the answer for
the endpoint's own environment; `receipt()` is the verified `AppReceipt`
whenever the receipt bytes verified, 21007 and 21008 included;
`failureReason()` says why there is no receipt, and exactly one of the two
is non-null. `isVerified()` is `true` exactly when `receipt()` is non-null,
which includes 21007 and 21008: the receipt verified, only its environment
differs from this endpoint's own. That makes `isVerified()` **not** the same
check as `status() == 0` — `status() == 0` is "does this endpoint's own
environment accept the receipt", `isVerified()` is "did the receipt verify at
all". The response is rendered only when `toResponse()` or `toJson()`
is called. The result is immutable and thread-safe, and only the endpoint can
create one.

**Retrying in the other environment costs no second verification.**
`toResponse(Environment)` and `toJson(Environment)` render what an endpoint
of that environment would answer, recomputing the status from the receipt's
own type each time:

| receipt | on `PRODUCTION` | on `SANDBOX` |
|---|---|---|
| `Production`, `ProductionVPP` | 0 | 21008 |
| any other type, or none | 21007 | 0 |
| failed verification | its own status | its own status |

```java
VerifyReceiptResult result = production.verifyReceiptResult(requestBody);
String json = result.status() == VerifyReceiptEndpoint.STATUS_SANDBOX_RECEIPT_ON_PRODUCTION
        ? result.toJson(Environment.SANDBOX)
        : result.toJson();
```

A sandbox receipt never renders as a production 0, whichever endpoint
verified it. 21007 and 21008 bodies carry the status alone, as Apple's do.

Re-rendering a 21007 as sandbox is what keeps App Review working, and it is
also what gives every TestFlight tester's free purchase a status 0. Record
`result.receipt().receiptType()` with the grant and scope sandbox grants, as
[The three JWS entry points](#the-three-jws-entry-points) describes.

**Failure reasons.** `failureReason()` is a `VerificationException.Reason`:

| `failureReason()` | status | when |
|---|---|---|
| `REQUEST_TOO_LARGE` | 21002 | the raw body is over `MAX_REQUEST_BYTES` (3,145,728 UTF-8 bytes); Apple answers HTTP 413 here, see [Resource bounds](#resource-bounds) |
| `MALFORMED_REQUEST` | 21002 | the body is not JSON, not a JSON object or nests deeper than 64, or `receipt-data` is missing, empty or not a string |
| `INVALID_RECEIPT_FORMAT` | 21002 | `receipt-data` is not base64, is over `MAX_RECEIPT_BYTES`, or its CMS envelope does not parse |
| `INVALID_CHAIN`, `INVALID_SIGNATURE`, other certificate reasons | 21003 | the receipt did not authenticate |
| `INTERNAL_ERROR` | 21009 | not the client's fault: the receipt authenticated but its signed content cannot be read (`failureCause()` is the parser's exception), or an unexpected runtime exception (`failureCause()` holds it). Alert and retry or escalate; do not deny the user |

**`request_date`.** Every method has an overload taking an `Instant`, which
becomes `request_date` in place of the endpoint's clock; without one the
clock is read once, when the call is made, and `requestDate()` returns it.
That instant reaches `request_date` and nothing else. Certificate validity
never sees it (see [The clock](#the-clock)).

Like Apple's endpoint, this does **not** check the bundle id: compare
`result.receipt().bundleId()` (or `receipt.bundle_id` in the body)
yourself before granting anything, or use `ReceiptVerifier`, which checks it
for you. `password` and `exclude-old-transactions` are accepted for wire
compatibility and never read. See [COMPARISON.md](../COMPARISON.md) for the
field-by-field fidelity account.

`verifyReceiptResult(null)` does not compile, because both the `Map` and the
`String` overload match; cast the `null` to the one you mean.

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
| `INVALID_JWS_FORMAT` | not three dot-separated segments, a segment that is not a base64url-encoded JSON *object*, `alg != ES256`, an `x5c` that is not exactly three entries, or a JWS over `MAX_JWS_BYTES` or nested past the reader limit |
| `INVALID_CERTIFICATE` | an `x5c` entry does not decode to a parseable certificate. The base64 goes through `Base64.getDecoder()` behind a length check, because RFC 7515 §4.1.6 makes an entry standard base64: a character outside that alphabet (a stray `!`, a space or line break, a base64url `-` or `_`) or omitted or extra `=` padding is refused, not skipped, so such an entry gets this verdict before any certificate is parsed. Also raised when the receipt's signer certificate does not decode, or its key or signature cannot be read |
| `INVALID_CERTIFICATE_PURPOSE` | the leaf or intermediate lacks its Apple marker OID, or the receipt signer lacks its own |
| `INVALID_CHAIN` | the path does not reach a pinned anchor, a certificate was not valid at the signing instant, or a receipt embeds more than ten certificates or a chain longer than six |
| `INVALID_SIGNATURE` | the ES256 or CMS signature check failed, or the signer key is not RSA |
| `WRONG_BUNDLE_ID` | the verified payload or receipt names another bundle |
| `WRONG_ENVIRONMENT` | the environment is outside the accepted set |
| `WRONG_APP_APPLE_ID` | a Production `AppTransaction` does not name the configured app Apple id |
| `INVALID_RECEIPT_FORMAT` | the PKCS#7/CMS blob does not parse, has trailing bytes, has no signer info, embeds a certificate other than the signer that cannot be read (the certificate bag is not signed, so that is a defect of the receipt), or the receipt is over `MAX_RECEIPT_BYTES` |
| `DEVICE_HASH_MISMATCH` | the device hash does not match attribute 5, or the receipt lacks the attributes the check needs |
| `INTERNAL_ERROR` | the receipt's chain and signature verified, but its payload does not parse; `getCause()` is the parser's exception. Not the client's fault: alert and retry or escalate, do not deny |

**Order of the receipt checks.** CMS parse → the creation date alone
(attribute 12; nothing else in the payload is decoded yet) → chain at that
date, or at the system clock when the date is missing, empty, unreadable or
stated twice → receipt-signing marker OID → CMS signature → full payload
parse → bundle id → device hash. Nothing is trusted before the chain and
the signature, so reading the date never rejects. The chain comes first so
the attacker's own key is never run before it is trusted. A payload that
fails the full parse was signed by a trusted signer, so it is
`INTERNAL_ERROR`, not `INVALID_RECEIPT_FORMAT`.

The vocabulary is **closed** by the cross-port contract: a twelfth reason
would be a change to the shared vector file and to every port at once.
`Reason` also carries `MALFORMED_REQUEST` and `REQUEST_TOO_LARGE`, but only
as [`VerifyReceiptResult.failureReason()`](#the-verifyreceipt-compatible-endpoint)
values: no `VerificationException` is ever thrown with either, so a `switch`
over a caught exception's `reason()` never sees them. `INTERNAL_ERROR` keeps
the position it had when it was endpoint-only, so no ordinal moved.

**Misconfiguration is a different failure mode.** Empty or null trust
anchors, a null bundle id, an empty accepted-environment set, and an
endpoint environment other than `PRODUCTION` or `SANDBOX` all throw
`IllegalArgumentException` from the constructor. A programming mistake must
not be catchable as a verification verdict.

**Tampered trust anchors are a third.** `AppleRootCerts` throws
`IllegalStateException` when a bundled root is missing or does not match its
pinned SHA-256 (see [Trust anchors](#trust-anchors)). That is a statement
about the deployment, not about any payload, so it is not a `Reason` either.

## Integrating: from verified payload to entitlement

The backend flow these calls sit inside is written out once in the
[project README](../README.md#integrating-from-verified-payload-to-entitlement):
verify offline, deny on any failure, check the refund and expiry fields,
refresh a payload past the freshness window, guard against replay on the
transaction id, then grant with the environment recorded. That section also
carries the policy table saying what each reason means and which ones are
worth an alert. Here are its two branches in this port's API. `Grants` and
`Entitlements` stand for your own storage and entitlement code.

A StoreKit 2 signed transaction:

```java
import io.github.emindeniz99.applepurchasereceiptverifier.AppleRootCerts;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.TransactionPayload;
import java.util.EnumSet;
import java.util.logging.Logger;

public class Redeem {
    private static final Logger LOG = Logger.getLogger(Redeem.class.getName());
    private static final long FRESHNESS_MILLIS = 300_000L;

    public interface Grants {
        /**
         * Records userId as the owner of transactionId unless a grant for it
         * (or, for a subscription, for originalTransactionId) already exists.
         * Returns the existing owner, or null when this call recorded it.
         */
        String recordIfAbsent(String transactionId, String originalTransactionId, String userId,
                Environment environment);
    }

    public interface Entitlements {
        /** Idempotent per transactionId. expiresAtMillis is null for a purchase that does not expire. */
        void grant(String userId, String transactionId, String productId, Long expiresAtMillis,
                Environment environment);
    }

    // SANDBOX is App Review, and also every TestFlight build: see "The three JWS entry points".
    private final JwsVerifier verifier = new JwsVerifier(
            AppleRootCerts.jwsRoots(),
            "com.example.app",
            EnumSet.of(Environment.PRODUCTION, Environment.SANDBOX));
    private final Grants grants;
    private final Entitlements entitlements;

    public Redeem(Grants grants, Entitlements entitlements) {
        this.grants = grants;
        this.entitlements = entitlements;
    }

    public String redeemTransaction(String userId, String jws) {
        TransactionPayload payload;
        try {
            payload = verifier.verifyTransaction(jws);                  // step 2
        } catch (VerificationException e) {
            LOG.warning("purchase rejected: " + e.reason());
            return "denied";
        }
        long now = System.currentTimeMillis();
        // Accepted by the verifier, so PRODUCTION or SANDBOX; recorded with the grant.
        Environment environment = Environment.fromValue(payload.environment());

        if (payload.revocationDate() != null) {                         // step 3
            return "denied";                                            // refunded or revoked
        }
        Long expires = payload.expiresDate();
        if (expires != null && expires <= now) {
            return "denied";                                            // the term had ended
        }

        // step 4, your call: past the window, ask the client for a fresh
        // jwsRepresentation, or fetch one from the App Store Server API and
        // verify that instead
        Long signed = payload.signedDate();
        if (signed == null || now - signed > FRESHNESS_MILLIS) {
            return "refresh";
        }

        String id = payload.transactionId();                            // step 5
        String owner = grants.recordIfAbsent(id, payload.originalTransactionId(), userId, environment);
        if (owner != null && !owner.equals(userId)) {
            return "denied";                                            // replayed by another user
        }

        entitlements.grant(userId, id, payload.productId(), expires, environment);   // step 6
        return "granted";
    }
}
```

The legacy PKCS#7 app receipt is the same policy on the other input, the one
StoreKit 1 apps and older SDKs still send. A receipt is not one purchase: it
lists every purchase the app has not finished consuming, and for a
subscription every renewal, in no guaranteed order, with the expired and
refunded ones still present. So the sample picks rather than stopping at the
first matching entry: it skips entries with a `cancellationDate`, takes the
renewal with the latest `expiresDate`, and grants only if that is still in
the future. Entries without an `expiresDate` (consumables, non-consumables)
are granted one by one, by transaction id.

```java
import io.github.emindeniz99.applepurchasereceiptverifier.AppleRootCerts;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.InAppPurchase;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

public class RedeemReceipt {
    private static final Logger LOG = Logger.getLogger(RedeemReceipt.class.getName());
    private static final Duration WINDOW = Duration.ofMinutes(5);

    public interface Grants {
        /** As in Redeem: the existing owner, or null when this call recorded userId. */
        String recordIfAbsent(String transactionId, String originalTransactionId, String userId,
                Environment environment);
    }

    public interface Entitlements {
        /** Idempotent per transactionId. expiresAt is null for a purchase that does not expire. */
        void grant(String userId, String transactionId, String productId, Instant expiresAt,
                Environment environment);
    }

    private final ReceiptVerifier receipts =
            new ReceiptVerifier(AppleRootCerts.receiptRoots(), "com.example.app");
    private final Grants grants;
    private final Entitlements entitlements;

    public RedeemReceipt(Grants grants, Entitlements entitlements) {
        this.grants = grants;
        this.entitlements = entitlements;
    }

    public String redeemReceipt(String userId, String receiptData, String productId) {
        AppReceipt receipt;
        try {
            receipt = receipts.verify(receiptData);                     // step 2
        } catch (VerificationException e) {
            LOG.warning("receipt rejected: " + e.reason());
            return "denied";
        }
        Instant now = Instant.now();
        // ReceiptVerifier accepts every environment. ProductionSandbox is
        // App Review or TestFlight; record it and scope the grant.
        String type = receipt.receiptType();
        Environment environment = "Production".equals(type) || "ProductionVPP".equals(type)
                ? Environment.PRODUCTION
                : Environment.SANDBOX;

        InAppPurchase latest = null;                  // auto-renewable: latest term
        List<InAppPurchase> oneTime = new ArrayList<InAppPurchase>();
        for (InAppPurchase purchase : receipt.inAppPurchases()) {       // step 3
            if (!productId.equals(purchase.productId()) || purchase.cancellationDate() != null) {
                continue;                             // another product, or refunded as of signing
            }
            if (purchase.expiresDate() == null) {
                oneTime.add(purchase);                // consumable or non-consumable
            } else if (latest == null || purchase.expiresDate().isAfter(latest.expiresDate())) {
                latest = purchase;
            }
        }
        if (latest != null && !latest.expiresDate().isAfter(now)) {
            return "denied";                          // the latest term had ended when Apple signed
        }
        if (latest == null && oneTime.isEmpty()) {
            return "denied";
        }

        // step 4: the same caller-side check, on the creation date. Past the
        // window, ask the client to refresh its receipt, or call the App
        // Store Server API by transactionId and verify the JWS back.
        if (receipt.creationDate() == null
                || Duration.between(receipt.creationDate(), now).compareTo(WINDOW) > 0) {
            return "refresh";
        }

        List<InAppPurchase> toGrant = latest != null ? Collections.singletonList(latest) : oneTime;
        boolean granted = false;
        for (InAppPurchase purchase : toGrant) {                        // step 5
            String owner = grants.recordIfAbsent(
                    purchase.transactionId(), purchase.originalTransactionId(), userId, environment);
            if (owner != null && !owner.equals(userId)) {
                continue;                             // replayed by another user
            }
            entitlements.grant(userId, purchase.transactionId(), productId,  // step 6
                    purchase.expiresDate(), environment);
            granted = true;
        }
        return granted ? "granted" : "denied";
    }
}
```

For a subscription group, run the selection over every product in the group
and keep the latest term. A non-renewing subscription carries no
`expiresDate`, so it lands with the one-time purchases and its term is yours
to compute from `purchaseDate()`.

## App Store Server Notifications V2

Refunds, revocations, renewals and expiries after the grant arrive as App
Store Server Notifications V2. The notification is a JWS with no dedicated
model, so it goes through `verifyRaw`, which checks the chain and the
signature and no claim at all. The app identity (`bundleId`, `appAppleId`,
`environment`) is not at the top level: it sits under `data`, beside the
nested `signedTransactionInfo` and `signedRenewalInfo`, which are JWS in
their own right and need their own verification.

Apple retries a notification it did not get a 200 for, for days, so the
same `notificationUUID` arrives more than once: dedupe on it, and do not
apply a five-minute freshness window here. Numbers in a `verifyRaw` map are
`Integer` or `Long` depending on their size, so read them as
`((Number) value).longValue()`.

```java
import io.github.emindeniz99.applepurchasereceiptverifier.AppleRootCerts;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.TransactionPayload;
import java.util.EnumSet;
import java.util.Map;
import java.util.logging.Logger;

public class Notifications {
    private static final Logger LOG = Logger.getLogger(Notifications.class.getName());
    private static final String BUNDLE_ID = "com.example.app";
    private static final long APP_APPLE_ID = 1_234_567_890L;

    public interface Seen {
        boolean contains(String notificationUuid);
        void add(String notificationUuid);
    }

    public interface Entitlements {
        /** REFUND, REVOKE: take the purchase back. */
        void revoke(TransactionPayload transaction, Environment environment);

        /** Everything else with a transaction: DID_RENEW, EXPIRED, DID_CHANGE_RENEWAL_STATUS, ... */
        void update(String notificationType, TransactionPayload transaction,
                Long gracePeriodExpiresDate, Environment environment);
    }

    private final JwsVerifier verifier = new JwsVerifier(
            AppleRootCerts.jwsRoots(), BUNDLE_ID, EnumSet.of(Environment.PRODUCTION, Environment.SANDBOX));
    private final Seen seen;
    private final Entitlements entitlements;

    public Notifications(Seen seen, Entitlements entitlements) {
        this.seen = seen;
        this.entitlements = entitlements;
    }

    /** signedPayload from the POST body {"signedPayload": "..."}; returns the HTTP status for Apple. */
    public int handle(String signedPayload) {
        try {
            Map<String, Object> notification = verifier.verifyRaw(signedPayload);
            Object uuid = notification.get("notificationUUID");
            if (!(uuid instanceof String)) {
                return 400;
            }
            if (seen.contains((String) uuid)) {
                return 200;                           // a retry of one already handled
            }
            Object data = notification.get("data");
            if (!(data instanceof Map)) {
                seen.add((String) uuid);              // a summary notification: no app data to act on
                return 200;
            }
            Map<?, ?> d = (Map<?, ?>) data;

            // verifyRaw checked no claim: check the app identity here.
            if (!BUNDLE_ID.equals(d.get("bundleId"))) {
                return 400;
            }
            Object env = d.get("environment");
            Environment environment = env instanceof String ? Environment.fromValue((String) env) : null;
            if (environment != Environment.PRODUCTION && environment != Environment.SANDBOX) {
                return 400;
            }
            Object appAppleId = d.get("appAppleId");   // absent in sandbox
            if (environment == Environment.PRODUCTION
                    && !(appAppleId instanceof Number && ((Number) appAppleId).longValue() == APP_APPLE_ID)) {
                return 400;
            }

            // The nested JWS are verified on their own. verifyTransaction checks
            // bundle id and environment; renewal info goes through verifyRaw.
            Object signedTransaction = d.get("signedTransactionInfo");
            if (signedTransaction instanceof String) {
                TransactionPayload transaction = verifier.verifyTransaction((String) signedTransaction);
                String type = String.valueOf(notification.get("notificationType"));
                if ("REFUND".equals(type) || "REVOKE".equals(type)) {
                    entitlements.revoke(transaction, environment);
                } else {
                    Long graceUntil = null;
                    Object signedRenewal = d.get("signedRenewalInfo");
                    if (signedRenewal instanceof String) {
                        Map<String, Object> renewal = verifier.verifyRaw((String) signedRenewal);
                        if (!environment.value().equals(renewal.get("environment"))) {
                            return 400;
                        }
                        Object grace = renewal.get("gracePeriodExpiresDate");
                        graceUntil = grace == null ? null : ((Number) grace).longValue();
                    }
                    entitlements.update(type, transaction, graceUntil, environment);
                }
            }
            seen.add((String) uuid);                  // only after the work is done
            return 200;
        } catch (VerificationException e) {
            LOG.warning("notification rejected: " + e.reason());
            // INTERNAL_ERROR is not Apple's fault or an attack: answer 500 and page,
            // and Apple's retries give you days to ship a fix.
            return e.reason() == Reason.INTERNAL_ERROR ? 500 : 400;
        }
    }
}
```

Two deliveries of one notification can race past `seen.contains`, so
`revoke` and `update` must be idempotent themselves; `seen` only saves the
repeated work.

## Kotlin and null-safety

Every public package carries JSpecify's `@NullMarked`, so each type in the
API is non-null unless it says otherwise, and Kotlin types the boundary as
`String` / `String?` instead of the platform `String!` it has to guess at.

What is `@Nullable`: every claim accessor on `TransactionPayload` and
`AppTransactionPayload` and every attribute accessor on `AppReceipt` and
`InAppPurchase`, because Apple sends only the claims and attributes that
apply and an absent one reads as `null`; `Environment.fromValue` for an
unrecognised claim; the optional constructor parameter `appAppleId` and the
endpoint's `clock`; the `deviceGuid` that switches the device-hash
check on; the values of the map `verifyRaw` returns and of the one
`verifyReceiptResult` accepts, since a JSON `null` stays one on both sides; and the
receipt or JWS a `verify` overload is handed, which is reported as
`INVALID_RECEIPT_FORMAT` / `INVALID_JWS_FORMAT` rather than as a
`NullPointerException` a caller cannot catch beside the others.

`org.jspecify:jspecify` is an `optional` dependency: nothing reads the
annotations at run time and they are not inherited transitively, so a
consumer pays nothing for them. Declare the same artifact yourself to run
NullAway or the Checker Framework over your own code. `jvm-interop`'s
`KotlinInteropTest` compiles under `-Xjspecify-annotations=strict`, which
makes a nullness mismatch there a compile error rather than a warning.

## Trust anchors

`AppleRootCerts.jwsRoots()` and `.receiptRoots()` both return all three
published Apple roots (Apple Inc. Root CA, Apple Root CA - G2, Apple Root
CA - G3) as a `Set<X509Certificate>`, loaded from `.cer` resources bundled
in the jar. Apple deliberately documents the JWS chain as ending in "an
Apple root certificate" rather than naming one, so narrowing either set
would fail closed, silently, the day Apple re-anchored a path.

**The anchors are fingerprint-pinned, and are loaded from this library's own
package.** Each of the three certificates is checked against the SHA-256 of
the root it must be, and a mismatch, a missing resource, or anything other
than three distinct roots throws `IllegalStateException` from both accessors:
they fail closed rather than return an anchor set that is not Apple's. Both
halves matter. A classpath resource lookup is first-match, so before the
resources moved under
`io/github/emindeniz99/applepurchasereceiptverifier/certs/`, any earlier jar
or shaded uber-jar carrying a `certs/` tree replaced the trust anchors with
no error and no log line, and a receipt Apple never signed verified.

Trust reaches this library through exactly the `trustedRoots` constructor
argument, never through the JDK's own `cacerts` or a `TrustManagerFactory`
default. `TrustStoreIsolationTest` (below) is what proves that, rather than
only documenting it.

**Root expiry and rotation.** The bundled roots expire on these dates, read
from the certificate files in [`certs/`](../certs):

| Root | Expires (UTC) | Anchors today |
|---|---|---|
| Apple Inc. Root CA | 2035-02-09 | legacy receipts |
| Apple Root CA - G2 | 2039-04-30 | neither path today |
| Apple Root CA - G3 | 2039-04-30 | JWS |

Certificate validity is judged at the payload's signing instant, not at
verification time, so a payload signed before a root expires keeps
verifying after it. A payload signed after Apple moves to a new root needs
that root in the anchor set, and the anchors are bundled and pinned, so a
new Apple root means a library upgrade (or passing your own anchor set to
the constructors). The repository's weekly `apple-root-watch` workflow
compares the pinned roots with Apple's PKI page and fails when Apple changes
a root or publishes a new one, which is the signal for that release.

**Certificate revocation is not checked**: no OCSP, no CRL
(`setRevocationEnabled(false)` on both PKIX parameter objects). Offline
verification is the point, and Apple handles a compromised signing
certificate by rotating it. See
[THREAT-MODEL.md](../THREAT-MODEL.md) section 4 for the rationale, and use
the App Store Server API for refunds, revocations and subscription state,
none of which a signature can express.

### One platform caveat worth knowing

The Java port verifies chains and signatures with its own pinned
BouncyCastle, so `jdk.certpath.disabledAlgorithms` and the JVM provider list
do not affect it. Every cryptographic lookup names a private
`BouncyCastleProvider` instance that is never registered with `Security`:
certificate parsing, chain building and validation (`PKIX`), the CMS and
ES256 signature checks, and every digest, the device-hash SHA-1 included.
The host's provider order, its `java.security` file and the JVM version do
not change a verdict.

Why: the genuine legacy Apple receipt chain is SHA-1 end to end (the leaf and
the WWDR intermediate are both `sha1WithRSAEncryption`). The JDK's own PKIX
code obeys `jdk.certpath.disabledAlgorithms`, and RHEL and Fedora system
crypto policies and many hardened enterprise `java.security` files disable
SHA-1 there outright. Built with the JDK's PKIX code, every genuine legacy
receipt failed on such a host as `INVALID_CHAIN`, as if it were forged.
BouncyCastle's PKIX code does not read that property.

The trade-off is deliberate: an administrator cannot restrict this library
through `java.security` either. What it accepts is fixed by the library and
the roots the caller passes, and it is the same on every JVM.

The `java-hardened-policy` and `java-distroless` CI jobs run the full
conformance suite under this policy and require every case to pass,
`receipt/verify-genuine-legacy-sha1-chain` included:

```
jdk.certpath.disabledAlgorithms=MD2, MD5, SHA1, RSA keySize < 1024
```

`HostPolicyTest` checks the same in a child JVM on every build, after showing
that the JDK's own PKIX code refuses the chain under that policy. Ruby, PHP
and Go still depend on their runtime's policy for this chain.

## Environment routing and freshness

`acceptedEnvironments` on `JwsVerifier` is a `Set<Environment>` checked
against the payload's `environment` (or `receiptType`, for an
`AppTransaction`) claim; a value outside it is `WRONG_ENVIRONMENT`.
`VerifyReceiptEndpoint`'s single `Environment` drives the 21007/21008 status
routing the same way the other ports do.

`ReceiptVerifier` has no environment setting: it accepts a receipt of every
`receipt_type` and never raises `WRONG_ENVIRONMENT`. Read
`receipt.receiptType()` and decide, as the
[`RedeemReceipt`](#integrating-from-verified-payload-to-entitlement) sample
does. Whether you accept sandbox at all, and how you scope it (TestFlight
buys in sandbox for free), is the same decision on both paths; see
[The three JWS entry points](#the-three-jws-entry-points).

**Freshness is your call.** No payload is rejected for its age, as in Apple's
own App Store Server Libraries: `signedDate` only decides the instant the
chain is judged at. The right limit depends on the endpoint (Apple retries a
server notification for days, and a device may present an old but genuine
payload), so apply one yourself where it fits:
`boolean tooOld = payload.signedDate() == null || System.currentTimeMillis() - payload.signedDate() > 300_000L;`

## The clock

`VerifyReceiptEndpoint`'s three-argument constructor takes an optional
`java.time.Clock`; `null` (the default of the shorter constructor) means
`Clock.systemUTC()`. It is read in exactly one place: the `request_date` /
`_ms` / `_pst` triple.

**Certificate validity is never judged by the injected clock.** It is judged
at the payload's own `signedDate` / `receiptCreationDate`, or at the
receipt's attribute-12 creation date; where the input states no date of its
own, the fallback reads the system clock directly, not the injected clock, so
a caller injecting a clock to pin `request_date`, or to work around skew,
cannot thereby accept an expired chain or expire a live one.

`JwsVerifier` and `ReceiptVerifier` therefore take **no clock at all**: it would have no
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

Three more bound the input itself, checked at every public entry point before
anything is decoded. They are Apple's limits, fixed constants in every port
of this library, not constructor parameters. Measured on 2026-09-23 against
both of Apple's verifyReceipt endpoints (production and sandbox), a request
body of 3,145,728 bytes is answered normally and one of 3,145,729 bytes gets
HTTP 413. Apple counts UTF-8 bytes, not characters: 3,145,729 bytes of `é`,
only 1,572,874 characters, also got 413. `fixtures/cases.json` holds every
port to these numbers from both sides.

- **`VerifyReceiptEndpoint.MAX_REQUEST_BYTES` (3 MiB, 3,145,728 bytes)**,
  applied to the raw body at `verifyReceiptJson` and
  `verifyReceiptResult(String)`. A larger body answers `{"status":21002}`
  with `failureReason()` `REQUEST_TOO_LARGE`, before any parsing.
- **`ReceiptVerifier.MAX_RECEIPT_BYTES` (3 MiB, 3,145,728 bytes)**, applied
  to the transport string at `verify(String)` and at the endpoint's
  `receipt-data`, and to the DER at every entry point that takes bytes,
  `verifyReceiptCore` included. No receipt Apple accepts can be larger than
  the request that carries it. Over the limit is `INVALID_RECEIPT_FORMAT`.
- **`JwsVerifier.MAX_JWS_BYTES` (256 KiB)**, applied to the compact JWS before
  it is split. Every JWS in the shared corpus, Apple's own mock notification
  data included, is under 2.5 KB. Over the limit is `INVALID_JWS_FORMAT`.

Strings are measured in UTF-8 bytes without being encoded. A Java `String`
holds UTF-16 units, so the check takes two shortcuts before it looks at a
character: more units than the limit is over it, and three times the units
within the limit is within it. Only a string between the two is walked, and
the walk stops at the first byte past the limit. A lone surrogate counts as
three bytes.

Without these bounds a 64 MB input under `-Xmx256m` left `verify` as an
`OutOfMemoryError`, which is neither catchable as a verdict nor reportable as
one.

**Answering 413 like Apple.** `REQUEST_TOO_LARGE` exists so an HTTP layer can
send the status Apple sends. The body is Apple's 21002 either way:

```java
VerifyReceiptResult result = endpoint.verifyReceiptResult(rawRequestBody);
int httpStatus = result.failureReason() == Reason.REQUEST_TOO_LARGE ? 413 : 200;
return ResponseEntity.status(httpStatus).body(result.toJson());
```

A framework that caps request bodies itself has to allow at least 3 MiB, or
it refuses bodies Apple would answer.

**JSON reader limits.** Both mappers state `StreamReadConstraints` explicitly:
nesting depth 64, and string and document lengths matching the bounds above.
A JWS header is attacker-controlled and is parsed before any signature check,
and the depth guard behind that parse is a Jackson default, which a host BOM
pinning an older Jackson 2 removes without a word. Hence the 2.16 floor under
[Dependencies and conflicts](#dependencies-and-conflicts).

## Thread safety

`JwsVerifier`, `ReceiptVerifier` and `VerifyReceiptEndpoint` are immutable
once constructed and are meant to be shared: build one of each at startup and
hand it to every request, as a singleton Spring bean or its equivalent. Each
holds only final fields, copies the anchor set at construction and never
hands that copy out, keeps its per-call state in locals, and shares nothing
else beyond a configured Jackson `ObjectMapper`, which Jackson documents as
safe to use from many threads once it is configured.

The objects they return are immutable too. `TransactionPayload` and
`AppTransactionPayload` take their claims through a constructor rather than
having Jackson write them into non-final fields afterwards, which is what
makes a verified payload safe to publish to another thread. `AppReceipt` and
`InAppPurchase` have final fields, and `AppReceipt` copies every array it
exposes, so one reader cannot rewrite a verified attribute under another.

`ConcurrencyTest` is what holds this rather than the paragraph above: sixteen
threads, fifty iterations each, through `verify(String)`,
`verifyReceiptResult(Map)`, `verifyReceiptJson(String)` and `verifyTransaction`,
each answer compared to the answer a single thread gets.

## Testing

```bash
mvn test                                                  # default JDK
mvn test -Pjdk8-runtime -Djdk8.jvm=/path/to/jdk8/bin/java # the suite on a real Java 8 JVM
mvn spotless:check                                        # format/lint (not bound to any lifecycle phase)
```

`ConformanceCasesTest` runs every case in `fixtures/cases.json`, the
normative cross-language vector file every port of this library answers.

`AppleRootCertsTest` pins the three bundled roots to their fingerprints and
plants a directory of impostor `.cer` files ahead of the library on a class
loader, showing the anchor load fails closed instead of returning them.
`InputSizeBoundsTest` holds the bounds above, each over-limit input built so
that it verifies or is refused differently without them.
`ConcurrencyTest` runs the shared-instance claim across sixteen threads.

`TrustStoreIsolationTest`
(`src/test/java/.../TrustStoreIsolationTest.java`) asserts the trust-pinning
rule three ways: **environmentally**, by starting a child JVM whose
`-Djavax.net.ssl.trustStore` genuinely makes the JDK's own default trust
manager trust the fixture roots, and showing this library still refuses the
matching receipt and JWS under the bundled Apple anchors (and that this
machine's real `cacerts`, handed to the library as its whole anchor set,
refuses a genuine Apple receipt the bundled roots accept); **structurally**,
by scanning every file under `src/main/java` for any spelling that could
reach a trust store, a socket, or a subprocess, and for any JCA lookup that
does not name the library's own BouncyCastle instance; and **positively**, by
installing a JCA provider ahead of all others that shadows every engine the
verifiers use, and showing it is never asked for one while the verdict
follows the caller's roots alone.

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

## `x5c[2]` is parsed, never trusted

`x5c[2]`, the JWS header's third certificate, is never trusted anywhere in
this library: it is never compared to an anchor and the chain terminates at
the pinned root regardless of what it contains. `decodeChain` in
`JwsVerifier` still decodes all three `x5c` entries as certificates before
the leaf and intermediate are looked at, so an `x5c[2]` that is not a
parseable certificate is `INVALID_CERTIFICATE`. This port used to be the
only one that did this; every port does now, and the shared vector
`transaction/reject-x5c-root-that-is-not-a-certificate` holds all nine to
it. No verdict about a well-formed JWS moves. See
[rust/README.md](../rust/README.md#what-the-checks-are-and-in-what-order)
for the cross-port account.

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
