# apple-purchase-receipt-verifier (Java)

Verify Apple in-app purchases locally — no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS transactions and legacy PKCS#7 app receipts against pinned Apple
root certificates.

```xml
<dependency>
  <groupId>io.github.emindeniz99</groupId>
  <artifactId>apple-purchase-receipt-verifier</artifactId>
  <version>0.5.1</version> <!-- x-release-please-version -->
</dependency>
```

Versions before 0.4.0 must not be used: their trust anchors can be replaced
from the classpath (see [Trust anchors](#trust-anchors)). Coming from 0.5,
read [Upgrading from 0.5](#upgrading-from-05) first.

Replacing a `verifyReceipt` call? Read these in order:
[Differences from Apple's verifyReceipt](#differences-from-apples-verifyreceipt-read-before-migrating),
[Migrating from verifyReceipt](#migrating-from-verifyreceipt),
[Serving it from Spring](#serving-it-from-spring) and
[Operations](#operations).

```java
import io.github.emindeniz99.applepurchasereceiptverifier.AppleRootCerts;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.TransactionPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import java.util.EnumSet;

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
`AppleRootCerts`, see [Trust anchors](#trust-anchors)). An `Error` is not
covered by any of this: a `LinkageError` from a BouncyCastle or Jackson
version clash on the classpath (see [Dependencies and
conflicts](#dependencies-and-conflicts)) or an `OutOfMemoryError` escapes as
itself.

The version is `0.x` on Maven Central, so the API may still change between
minor versions; [Stability](#stability) says which parts are fixed.

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
set. Below 2.15 the class `StreamReadConstraints` is missing, and on 2.15 the
method `maxDocumentLength` is, so the failure is a `LinkageError`
(`NoClassDefFoundError` or `NoSuchMethodError`): `JwsVerifier`'s constructor
throws it, and `VerifyReceiptEndpoint` fails to initialize as a class.

Spring Boot 4.0.x pins Jackson 2 at 2.21.x through its BOM, which is above
that floor, and Jackson 3 (`tools.jackson`) sits alongside Jackson 2 under a
different package root, so an application on both is not a conflict. Verified
with a Spring Boot 4.0.8 application in `samples/spring-boot-smoke`.

**Spring Boot 2.7 and 3.0 to 3.2 manage Jackson below the floor** (2.13 to
2.15), and their BOM wins over this library's declared version. Set the
`jackson-bom.version` property to a Jackson 2 release of 2.16 or later (this
library is built and tested against 2.22.2), then run your own tests, since
the override moves Jackson for the whole application:

```xml
<properties>
  <jackson-bom.version>2.22.2</jackson-bom.version>
</properties>
```

In Gradle with the Spring dependency-management plugin, the same property is
`ext['jackson-bom.version'] = '2.22.2'`. Check what actually resolved with
`mvn dependency:tree -Dincludes=com.fasterxml.jackson.core`.

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
App Store Server API give the live status. `isActiveAt(Date)` is gone (see
[Upgrading from 0.5](#upgrading-from-05)).

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

`identifierForVendor` usually reaches a server as its UUID string. The GUID
is its 16 raw bytes, most significant first, not the string's UTF-8 and not
hex:

```java
import java.nio.ByteBuffer;
import java.util.UUID;

UUID idfv = UUID.fromString(identifierForVendor);   // "E621E1F8-C36C-495A-93FC-0C247A3E6E5F"
byte[] deviceGuid = ByteBuffer.allocate(16)
        .putLong(idfv.getMostSignificantBits())
        .putLong(idfv.getLeastSignificantBits())
        .array();
AppReceipt receipt = verifier.verify(receiptBase64, deviceGuid);
```

`VerifyReceiptEndpoint` takes no GUID, as Apple's endpoint took none, so it
cannot check the device hash. A caller that needs the binding calls
`ReceiptVerifier.verify(receiptBase64, deviceGuid)` instead.

The app version (attribute 3, `appVersion()`) is decoded and never
compared: Apple's on-device step 4 has no server-side equivalent the
library could enforce, so comparing it is your policy if you want one. See
[RECEIPT-FIELDS.md](../RECEIPT-FIELDS.md#step-4-stated-plainly).

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

### Differences from Apple's verifyReceipt (read before migrating)

In one line: for one-time purchases (consumables, non-consumables) this is a
complete replacement; for auto-renewable subscriptions it gives only the
state as of the moment Apple signed the receipt.

| Apple's endpoint | This endpoint | What to do instead |
|---|---|---|
| `latest_receipt_info`, `latest_receipt`: renewals after the receipt was signed | Never produced | App Store Server API Get Transaction History (by any transaction id of the customer) or Get All Subscription Statuses, and Server Notifications V2 (`DID_RENEW`, `EXPIRED`, `DID_FAIL_TO_RENEW`) |
| `pending_renewal_info` (`auto_renew_status`, `expiration_intent`, grace period) | Never produced | Get All Subscription Statuses, or `signedRenewalInfo` in a notification, verified with `verifyRaw` (see [Server Notifications V2](#app-store-server-notifications-v2)) |
| A refund after signing | Not visible: a receipt signed before the refund verifies forever, and `cancellation_date` is set only if the refund predates the signature | Server Notifications V2 `REFUND` and `REVOKE`, or Get Transaction History; revoke by transaction id |
| `password` (shared secret), `exclude-old-transactions` | Accepted and never read; 21004 is never returned | Nothing to verify locally. The App Store Server API authenticates with an In-App Purchase API key (a signed JWT), not the shared secret |
| Rejections: Apple answered 21002 for every rejection measured (2026-09-22, see [COMPARISON.md](../COMPARISON.md#status-codes)) | 21002 for input that never becomes a receipt, 21003 for a receipt that fails to authenticate | Update alerting: 21003 is new to you, and its rate is the fraud signal. See [Operations](#operations) |
| 21005, 21100 to 21199, `is_retryable` | Never produced: there is no remote server to be unavailable | Remove retry logic keyed on them. 21009 is not retryable either (see `INTERNAL_ERROR` below) |
| `in_app_ownership_type`, `cancellation_reason`, `promotional_offer_id` | Not produced: no receipt carries `in_app_ownership_type`, and Apple documents no ASN.1 type for the other two | The App Store Server API's signed transaction: `inAppOwnershipType()`, `revocationReason()`, `offerIdentifier()` on `TransactionPayload`. Attribute 1721, the community-reported promotional offer id, is reachable raw via `InAppPurchase.unknownAttributes()` if a receipt carries it |
| No bundle-id check | No bundle-id check | Compare `result.receipt().bundleId()` yourself, or use `ReceiptVerifier` |
| Key order | Matches Apple's for the leading `receipt` keys, not everywhere (Apple puts `original_application_version` just before `in_app`) | Parse the JSON; never compare response bodies as strings |

[COMPARISON.md](../COMPARISON.md) is the field-by-field account behind this
table.

No endpoint method throws a `RuntimeException` or a checked exception: the
Apple status code is a field of the body, for every input, including one
that is not JSON (`{"status":21002}`). An `Error` still escapes as itself:
an `OutOfMemoryError`, or a `LinkageError` from a BouncyCastle or Jackson
clash on the classpath, such as `bcprov-jdk15on` beside `bcprov-jdk18on`
(see [Dependencies and conflicts](#dependencies-and-conflicts)). The
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
// endpoint: new VerifyReceiptEndpoint(AppleRootCerts.receiptRoots(), Environment.PRODUCTION)
VerifyReceiptResult result = endpoint.verifyReceiptResult(requestBody);
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
| `INTERNAL_ERROR` | 21009 | not the client's fault: the receipt authenticated but its signed content cannot be read (`failureCause()` is the parser's exception), the runtime lacks an algorithm the check needs, or an unexpected runtime exception (`failureCause()` holds it). Deterministic: the same bytes give the same answer again. Do not retry; see [`INTERNAL_ERROR` is deterministic](#internal_error-is-deterministic) |

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

## Migrating from verifyReceipt

### Checklist

- **Bundle id.** Neither Apple's endpoint nor this one checks it. If your
  code never compared `receipt.bundle_id`, add the check now:
  `result.receipt().bundleId()`, or use `ReceiptVerifier`, which checks it.
- **Subscription state.** Anything you read from `latest_receipt_info` or
  `pending_renewal_info` needs a new source: App Store Server Notifications
  V2 for changes as they happen, the App Store Server API (Get All
  Subscription Statuses, Get Transaction History) for the current state. See
  the [differences table](#differences-from-apples-verifyreceipt-read-before-migrating).
- **Alert mapping.** 21003 appears where Apple sent 21002; 21005 and 21100
  to 21199 disappear; 21009 means a library or runtime problem. The
  [status table](#what-each-status-means-for-you) says what each one
  should trigger.
- **Body size at every layer.** Apple accepts a body of up to 3 MiB
  (3,145,728 bytes). Every layer in front of the endpoint must accept that
  much or it refuses receipts Apple would have answered: the load balancer,
  the reverse proxy (nginx's `client_max_body_size` defaults to 1 MB), the
  servlet container and the framework (Spring WebFlux's in-memory codec
  limit defaults to 256 KB). See [Serving it from Spring](#serving-it-from-spring).
- **21007 handling.** The old "call production, retry sandbox on 21007"
  still works but verifies the receipt twice. Render the result for sandbox
  instead, with `result.toJson(Environment.SANDBOX)`, and record that the
  grant came from sandbox.
- **Device GUID.** If you checked the device hash, the endpoint cannot:
  call `ReceiptVerifier.verify(receiptBase64, deviceGuid)` (see
  [Legacy PKCS#7 app receipts](#legacy-pkcs7-app-receipts)).
- **Shared secret.** Nothing reads it any more. Keep it only for as long as
  you still call Apple.

### Shadow mode

Run both for a while before switching, off the request path so the user
never waits for the second call:

1. Capture `Instant at = Instant.now()`, send the body to Apple as today,
   and call `endpoint.verifyReceiptResult(body, at)` with the same body on
   an endpoint of the same environment (`PRODUCTION` beside
   `buy.itunes.apple.com`).
2. Compare `status`. Expected differences: Apple's 21002 where this
   endpoint answers 21003 (an authentication failure), and 21005 or 211xx
   from Apple, which this endpoint never produces.
3. When both answer 0, compare the two `receipt` objects as parsed JSON,
   not as strings, because key order differs. First remove `request_date`,
   `request_date_ms` and `request_date_pst` from both, and remove the fields
   only Apple produces (`in_app_ownership_type` in every `in_app` entry, and
   any other field the differences table lists). Match `in_app` entries by
   `transaction_id`; their order is not guaranteed.
4. Ignore `latest_receipt_info`, `latest_receipt` and
   `pending_renewal_info` at the top level: they are gone for good. Before
   switching, confirm nothing downstream reads them.
5. Count mismatches by field and log the transaction ids involved, not the
   receipt. Switch when only the expected differences remain.

## Serving it from Spring

Bind the body as a `String`, not a `Map`. The `String` overload measures the
body against `MAX_REQUEST_BYTES` before parsing and parses it with the
library's own nesting guard; a `Map` has already been parsed by the
framework's mapper, with neither.

```java
import io.github.emindeniz99.applepurchasereceiptverifier.AppleRootCerts;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.VerifyReceiptEndpoint;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.VerifyReceiptResult;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class VerifyReceiptController {
    // One instance for every request: it is immutable and thread-safe.
    private final VerifyReceiptEndpoint endpoint =
            new VerifyReceiptEndpoint(AppleRootCerts.receiptRoots(), Environment.PRODUCTION);

    // consumes = "*/*": clients of Apple's endpoint send any content type.
    @PostMapping(path = "/verifyReceipt", consumes = "*/*")
    public ResponseEntity<String> verify(@RequestBody String body) {
        VerifyReceiptResult result = endpoint.verifyReceiptResult(body);
        // Apple answers HTTP 413 above 3 MiB; the body is its 21002 either way.
        int httpStatus = result.failureReason() == Reason.REQUEST_TOO_LARGE ? 413 : 200;
        return ResponseEntity.status(httpStatus)
                .contentType(MediaType.APPLICATION_JSON)
                .body(result.toJson());
    }
}
```

This is Apple's endpoint and nothing more. The code that grants entitlements
still checks `bundle_id`, reads `receipt_type` and applies the rules under
[Integrating](#integrating-from-verified-payload-to-entitlement).

Size limits on the way in:

- **Spring WebFlux** buffers a `@RequestBody String` under
  `spring.codec.max-in-memory-size`, 256 KB by default. Receipts with a long
  purchase history are larger (the 187-purchase fixture is about 105 KB of
  base64, and a receipt can reach 3 MiB), so set it to `3MB`.
- **Spring MVC on Tomcat** has no cap on a `@RequestBody String`: Tomcat's
  `maxPostSize` (`server.tomcat.max-http-form-post-size`) applies to form
  bodies only. The library refuses anything over 3 MiB, but only after the
  container has read all of it into memory, so put the cap in front, at the
  proxy or load balancer.
- **The proxy** must allow at least 3 MiB: nginx `client_max_body_size 3m;`
  is exactly Apple's limit.

## Operations

### What each status means for you

| status | `failureReason()` | Action |
|---|---|---|
| 0 | none | Grant, after your own bundle-id check and entitlement rules |
| 21007 | none (the receipt verified) | A sandbox receipt on a production endpoint. For App Review, render it for sandbox from the same result (`result.toJson(Environment.SANDBOX)`); do not verify again. Record the grant as sandbox |
| 21008 | none (the receipt verified) | A production receipt on a sandbox endpoint. Render it for `PRODUCTION` from the same result, or deny |
| 21002 | `MALFORMED_REQUEST`, `REQUEST_TOO_LARGE`, `INVALID_RECEIPT_FORMAT` | Deny. No alert: this is a client or transport defect. `REQUEST_TOO_LARGE` maps to HTTP 413 |
| 21003 | `INVALID_CHAIN`, `INVALID_SIGNATURE`, `INVALID_CERTIFICATE`, `INVALID_CERTIFICATE_PURPOSE` | Deny. Alert on the rate, not on each one: a steady trickle is normal, a spike is someone probing |
| 21009 | `INTERNAL_ERROR` | Page. The library could not read what Apple signed, or failed inside; see [below](#internal_error-is-deterministic) |

For the JWS path, the per-reason table in the
[project README](../README.md#what-to-do-per-reason) is the same policy.

### `INTERNAL_ERROR` is deterministic

`INTERNAL_ERROR` comes from a typed-claim mismatch in a JWS the signature
check accepted (Apple signed a claim with a type this library's model does
not expect), from receipt content that authenticated but does not parse,
from a runtime lacking an algorithm the check needs, or from an unexpected
exception inside the endpoint. For a given library version and runtime,
the same bytes give the same answer every time, so retrying the library
achieves nothing.

- Do not hot-retry.
- Log `failureCause()` (endpoint) or `getCause()` (a caught
  `VerificationException`) with the library version, and alert.
- Settle the purchase through the App Store Server API by transaction id.
  For a JWS, `verifyRaw` on the same string still returns the claims,
  because it applies no typed model, so `transactionId` is readable there;
  for a receipt, use a transaction id you already hold for the account or
  ask the client for one.
- Grant provisionally only if the business accepts that risk. Denying
  outright is wrong too: Apple signed these bytes.

### What to log

Per call: `status()`, `failureReason()`, the receipt's `receipt_type` and
`bundle_id`, the transaction ids you granted, and the library version.
For every failed verification also log `failureCause().getMessage()`: it
holds the `VerificationException` behind the status, so a 21003 says
whether the chain did not reach a pinned root, a certificate had expired or
the signature did not match. It is null only when the request itself was
refused before any verification (`MALFORMED_REQUEST`, `REQUEST_TOO_LARGE`,
or `receipt-data` over the size cap), never appears in the JSON, and quotes
input only after replacing control characters. Never log the full receipt or JWS: it carries
the user's purchase history and can be replayed.

### Metrics

The library has no logging, metrics or callbacks, on purpose; count in your
own code. A counter tagged with `failureReason()` (`OK` when it is null) and
the status covers the alerts above:

```java
String reason = result.failureReason() == null ? "OK" : result.failureReason().name();
// e.g. Micrometer: registry.counter("receipt.verify", "reason", reason, "status", String.valueOf(result.status())).increment();
```

### Idempotency

Key grants on `transaction_id`, not on the receipt bytes: a legacy receipt
is BER, so one signed receipt has several byte spellings. Store
`original_transaction_id` beside it for subscriptions. A retry by the same
user for a transaction already granted to them should answer "granted"
again without granting twice; the same transaction presented by another
user is a replay and is denied. The samples under
[Integrating](#integrating-from-verified-payload-to-entitlement) do this.

### Capacity

Measured on a 4 vCPU cloud VM with JDK 21, one call at a time:

| Call | Time per call | Allocated per call |
|---|---:|---:|
| `JwsVerifier.verifyTransaction` | about 850 to 890 µs | about 620 KB |
| Receipt verification, g5 fixture (2 purchases) | about 685 µs | about 427 KB |
| Receipt verification, legacy fixture (187 purchases) | about 3.9 ms | about 4.7 MB |
| A receipt near the 3 MiB limit | | 60 to 75 MB |

[`java-bench/README.md`](../java-bench/README.md) has the JMH baseline
behind the receipt numbers, per step, and how to re-run it; plan with the
higher of its figures and these.

CPU is rarely the limit: five million verifications a day is under 60 a
second on average, a small fraction of one core. Memory is. Every
concurrent call can hold tens of megabytes when the receipt is large, and
Tomcat's default of 200 request threads times 75 MB is 15 GB. Limit the body
size at the HTTP layer and limit how many verifications run at once (a
`Semaphore` around the call, or a bounded executor), sized so that the
limit times 75 MB fits in the heap.

### Health check

Construct the verifiers at startup, not on first request, so a broken
classpath or tampered trust anchors (`IllegalStateException` from
`AppleRootCerts`, a `LinkageError` from a Jackson clash) stop the deploy
instead of the first purchase.

The jar ships no receipt to test with. Keep one genuine sandbox receipt of
your own app (from a sandbox or TestFlight purchase with a test account),
and verify it at startup and periodically through the same endpoint
instance: on a `PRODUCTION` endpoint it must answer 21007 with your bundle
id in `result.receipt().bundleId()`. It keeps verifying after its
certificates expire, because validity is judged at the receipt's creation
date. Beyond that, alert on spikes in the per-reason counters above.

## The error vocabulary

Every failure is a checked `VerificationException` carrying one of eleven
`VerificationException.Reason` values, and nothing else — no logging, no
metrics, no callbacks. The message is `Reason + ": " + detail`; match on
`reason()`, never parse it.

```java
interface Outcomes {                        // your code
    void deny(VerificationException.Reason reason);
    void denyAndAlert(VerificationException.Reason reason);
    void escalate(VerificationException e);  // log getCause() with the library version, page
}

TransactionPayload transaction;
try {
    transaction = verifier.verifyTransaction(jws);
} catch (VerificationException e) {
    switch (e.reason()) {
        case INVALID_CHAIN:
        case INVALID_SIGNATURE:
        case INVALID_CERTIFICATE_PURPOSE:
        case WRONG_BUNDLE_ID:
        case WRONG_APP_APPLE_ID:
            outcomes.denyAndAlert(e.reason());
            break;
        case INTERNAL_ERROR:
            outcomes.escalate(e);            // deterministic: do not retry
            break;
        default:                             // WRONG_ENVIRONMENT included: deny, never retry elsewhere
            outcomes.deny(e.reason());
    }
    return;
}
```

`WRONG_ENVIRONMENT` from a `JwsVerifier` means the payload's environment is
outside the set you configured, which is a policy decision already made:
deny it. There is no other environment to retry in, since the verifier is
offline. (`ReceiptVerifier` never raises it; see
[Environment routing and freshness](#environment-routing-and-freshness).)

| `Reason` | Raised when |
|---|---|
| `INVALID_JWS_FORMAT` | not three dot-separated segments, a segment that is not a base64url-encoded JSON *object*, `alg != ES256`, an `x5c` that is not exactly three entries, or a JWS over `MAX_JWS_BYTES` or nested past the reader limit |
| `INVALID_CERTIFICATE` | an `x5c` entry does not decode to a parseable certificate. The base64 goes through `Base64.getDecoder()` behind a length check, because RFC 7515 §4.1.6 makes an entry standard base64: a character outside that alphabet (a stray `!`, a space or line break, a base64url `-` or `_`) or omitted or extra `=` padding is refused, not skipped, so such an entry gets this verdict before any certificate is parsed. Also raised when the receipt's signer certificate does not decode, or its key or signature cannot be read |
| `INVALID_CERTIFICATE_PURPOSE` | the leaf or intermediate lacks its Apple marker OID, or the receipt signer lacks its own |
| `INVALID_CHAIN` | the path does not reach a pinned anchor, a certificate was not valid at the signing instant, or a receipt embeds more than ten certificates or a chain longer than six |
| `INVALID_SIGNATURE` | the ES256 or CMS signature check failed, or the signer key is not RSA |
| `WRONG_BUNDLE_ID` | the verified payload or receipt names another bundle |
| `WRONG_ENVIRONMENT` | `JwsVerifier` only: the payload's environment is outside the accepted set. `ReceiptVerifier` accepts every environment and never raises it |
| `WRONG_APP_APPLE_ID` | a Production `AppTransaction` does not name the configured app Apple id |
| `INVALID_RECEIPT_FORMAT` | the PKCS#7/CMS blob does not parse, has trailing bytes, has no signer info, embeds a certificate other than the signer that cannot be read (the certificate bag is not signed, so that is a defect of the receipt), or the receipt is over `MAX_RECEIPT_BYTES` |
| `DEVICE_HASH_MISMATCH` | the device hash does not match attribute 5, or the receipt lacks the attributes the check needs |
| `INTERNAL_ERROR` | the chain and signature verified, but what was signed cannot be read: a receipt payload that does not parse, or a JWS claim whose type does not match this library's model (`verifyTransaction`, `verifyAppTransaction`); `getCause()` is the parser's exception. Also raised when the runtime lacks an algorithm the check needs. Not the client's fault, and deterministic: do not retry, see [`INTERNAL_ERROR` is deterministic](#internal_error-is-deterministic) |

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
over a caught exception's `reason()` never sees them. Store a reason by
`name()`, never by `ordinal()`: 0.6 removed `STALE_PAYLOAD` and added three
values, so an ordinal stored under 0.5 names a different reason now.

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

That classpath replacement is the defect fixed in 0.4.0 (commit `54f72eb`,
"pin the bundled Apple roots by fingerprint"), which is why versions before
0.4.0 must not be used.

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

[Serving it from Spring](#serving-it-from-spring) has a complete controller
that does this. A framework that caps request bodies itself has to allow at
least 3 MiB, or it refuses bodies Apple would answer.

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
hands that copy out, and keeps its per-call state in locals.

What they do share is read-only once class initialization has finished:

- configured Jackson `ObjectMapper`s (one per `JwsVerifier`, and static ones
  behind the endpoint and the typed claim reader), which Jackson documents
  as safe to use from many threads once configured;
- the one private `BouncyCastleProvider` instance every cryptographic lookup
  names, and the root set `AppleRootCerts` loads once;
- one static `JcaSignerInfoVerifierBuilder` in `ReceiptVerifier`, reused for
  every receipt's CMS signature check. Sharing it relies on BouncyCastle
  internals (its `build` writes no state), which were checked for 1.86, the
  version the pom declares, and a comment in the source asks for the check
  to be repeated on every BouncyCastle upgrade. If you override the BouncyCastle version, through a BOM or
  `dependencyManagement`, that check is yours: read `build` in the version
  you resolve, or run a concurrent load against it like `ConcurrencyTest`.

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

The tests read the repository's `fixtures/` directory, which sits next to
`java/`. If you vendor the Java port, copy `java/` and `fixtures/` together;
if `fixtures/` lives elsewhere, point the tests at it with
`mvn test -Daprv.fixtures.dir=/path/to/fixtures`.

`AppleRootCertsTest` pins the three bundled roots to their fingerprints and
plants a directory of impostor `.cer` files ahead of the library on a class
loader, showing the anchor load fails closed instead of returning them.
`InputSizeBoundsTest` holds the bounds above, each over-limit input built so
that it verifies or is refused differently without them.
`ConcurrencyTest` runs the shared-instance claim across sixteen threads, and
releases 128 threads at once on freshly built verifiers to cover the first
calls.

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

## Upgrading from 0.5

0.6 removes API. What to change:

- **`VerificationException.Reason.STALE_PAYLOAD` is gone.** No payload is
  rejected for its age any more; apply your own window on `signedDate`
  (see [Environment routing and freshness](#environment-routing-and-freshness)).
- **`JwsVerifier`'s five- and six-argument constructors are gone**, the ones
  taking `maxSignedAge` and a `Clock`. Use
  `new JwsVerifier(roots, bundleId, acceptedEnvironments, appAppleId)`, or
  the three-argument form without `appAppleId`.
- **`TransactionPayload.isActiveAt(Date)` is gone.** Its exact equivalent:

  ```java
  long t = now.getTime();
  boolean active = (payload.revocationDate() == null || t < payload.revocationDate())
          && (payload.expiresDate() == null || t < payload.expiresDate());
  ```

  The check under [Entitlement is your rule](#the-three-jws-entry-points)
  is stricter: it treats any `revocationDate` as not entitled.
- **`VerifyReceiptEndpoint(Set, boolean production)` and its `Clock`
  variant are gone.** Pass `Environment.PRODUCTION` or
  `Environment.SANDBOX`.
- **`VerifyReceiptEndpoint.verifyReceipt(Map)` is gone.** Use
  `verifyReceiptResult(Map).toResponse()`, or keep the `VerifyReceiptResult`
  for its `failureReason()` and the re-render without a second verification.
  `verifyReceiptJson(String)` is unchanged.
- **`Reason` has three new values**, `MALFORMED_REQUEST`, `INTERNAL_ERROR`
  and `REQUEST_TOO_LARGE`, and the ordinals moved: a `switch` needs a
  `default`, and reasons you store must be stored by name.
- **`INTERNAL_ERROR` is now thrown** by `verifyTransaction`,
  `verifyAppTransaction` and the receipt verifiers, where Apple signed
  something this library cannot read. Handle it apart from the deny reasons
  (see [`INTERNAL_ERROR` is deterministic](#internal_error-is-deterministic)).
- **The size bounds are Apple's now.** `MAX_REQUEST_BYTES` went from 1 MiB
  to 3 MiB and `MAX_RECEIPT_BYTES` from 2 MiB to 3 MiB, so raise any HTTP
  limit you set to match the old values.
- **All cryptography runs on the library's private BouncyCastle provider.**
  `jdk.certpath.disabledAlgorithms` and the JVM provider list no longer
  affect a verdict (see [One platform caveat worth knowing](#one-platform-caveat-worth-knowing)).

## Stability

The version is `0.x`, and 0.6 shows the Java API can still change between
minor versions. What is held fixed, and by what:

- **The endpoint's wire output.** Statuses, fields, value types and date
  formatting are pinned by the endpoint cases in
  [`fixtures/cases.json`](../fixtures/cases.json), which every port must
  pass. Key order is not part of that contract.
- **The `Reason` set.** It is closed by the cross-port contract: adding or
  removing a reason is a change to the shared vector file and to all nine
  ports at once, and is called out as a breaking change.
- **The size bounds and the date claim types** (`Long` epoch milliseconds
  on the JWS models), both fixed across ports.

What may change in a minor version: constructors and method names (as this
release shows), exception message text (match on `reason()`, never parse
the message), everything in the `internal` package, and performance.

## Licence

MIT — see [LICENSE](./LICENSE).
