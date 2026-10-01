# apple-purchase-receipt-verifier (Java)

Verify Apple in-app purchases locally: no calls to Apple's servers. Checks a
StoreKit 2 signed JWS or a legacy PKCS#7 app receipt against pinned Apple root
certificates and hands back what Apple signed.

This is a verifier, not business logic. It answers one question: did Apple
sign this data? If so, it returns the data, unfiltered by bundle id,
environment or product. Every policy decision, bundle id, environment,
product id, device binding, refunds, idempotency, is yours; see
[What to check after verification](#what-to-check-after-verification).

```xml
<dependency>
  <groupId>io.github.emindeniz99</groupId>
  <artifactId>apple-purchase-receipt-verifier</artifactId>
  <version>0.7.0</version> <!-- x-release-please-version -->
</dependency>
```

Java **8** is the compiled target (`maven.compiler.release=8`), built and
tested with any modern JDK.

Depend on this artifact or on `apple-purchase-receipt-verifier-wasm` (the
same API on the shared Rust core), never both: they have the same class
names. `Verifier.create` throws `IllegalStateException` when it finds both
on the classpath.

**On Spring Boot**, Boot's BOM decides your Jackson version, not this
library. The floor is jackson-core 2.16 (see
[Dependency floors](#vendoring)). Spring Boot 3.0 to 3.2 manage an older
jackson-core, 2.14 or 2.15, and there `Verifier.create` throws
`IllegalStateException`. On Boot 3.x, set Boot's `jackson-bom.version`
property to 2.16.2 or newer. It moves every Jackson artifact together.
Maven:

```xml
<properties>
  <jackson-bom.version>2.16.2</jackson-bom.version>
</properties>
```

Gradle:

```groovy
ext['jackson-bom.version'] = '2.16.2'
```

Every Boot line in open-source support, 4.0 and 4.1, already manages a
newer Jackson 2 and needs nothing.

Coming from 0.6? Read [Upgrading from 0.6](#upgrading-from-06): the API is
smaller and every method name has changed.

## Quick start

```java
import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.Failure;
import io.github.emindeniz99.applepurchasereceiptverifier.JsonPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationResult;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;

// Build once, at startup, and share it: Verifier is immutable and thread-safe.
Verifier verifier = Verifier.create(Config.defaults());

// A legacy PKCS#7 app receipt, as StoreKit hands it to the app.
VerificationResult<ReceiptPayload> receiptResult = verifier.verifyReceipt(receiptBase64);
if (receiptResult.verified()) {
    ReceiptPayload receipt = receiptResult.payload();
    System.out.println(receipt.bundleId() + " " + receipt.inApp().size());
} else {
    Failure failure = receiptResult.failure();
    System.out.println(failure.reason() + ": " + failure.message());
}

// A StoreKit 2 signed transaction, renewal info, app transaction or notification.
VerificationResult<JsonPayload> jwsResult = verifier.verifySignedData(jws);
if (jwsResult.verified()) {
    String json = jwsResult.payload().json();       // parse it yourself, see below
}

// The deprecated verifyReceipt HTTP contract, answered locally.
String responseJson = verifier.verifyReceiptEndpoint(Environment.PRODUCTION, requestJson);
```

**No method throws for any input.** A `null` or empty `base64` / `jws` /
`requestJson` is input and fails as `Reason.MALFORMED`, the same as a garbled
one. An unexpected runtime exception inside the library is reported by where
it happened: before a signature has verified it is `Reason.MALFORMED` (input
nobody vouched for must not be able to raise the internal-error alarm at
will), while the signed receipt content is decoded `Reason.UNREADABLE_PAYLOAD`,
and anywhere else `Reason.INTERNAL_ERROR`. Only a JVM error such as
`OutOfMemoryError` escapes.
The one exception: a `null` `Environment` or `Config` is a programming
mistake, not something a receipt can cause, and throws
`NullPointerException`.

**A custom clock**, for tests or for pinning `request_date`:

```java
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

Config config = Config.builder()
        .clock(Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC))
        .build();
Verifier verifier = Verifier.create(config);
```

`Config.defaults()` uses Apple's three bundled, pinned roots and
`Clock.systemUTC()`. The clock is read once per call, before the input is
looked at, and used for two things: the chain-validity instant when the
receipt or JWS states no signing date, and `request_date` in the endpoint
response. It never
decides whether a certificate is expired when the input states a date; see
[Trust anchors](#trust-anchors).

`Verifier.create` and `Config.defaults()` fail at startup, not per call:
`Config.defaults()` throws `IllegalStateException` if the bundled roots do
not parse, and `Verifier.create`
throws `IllegalArgumentException` for an empty root set, since a verifier
with no roots would answer `UNTRUSTED_CHAIN` to everything and nobody would
notice until production. `Verifier.create` also builds the bounded Jackson
readers, touches the BouncyCastle provider and a bcpkix class, and probes
the crypto runtime (see [Running in production](#running-in-production)),
so a jackson-core below 2.16 or a missing BouncyCastle jar throws
`IllegalStateException` there rather than on the first call.

## Which method to call

| You have | Call |
|---|---|
| A legacy PKCS#7 app receipt (`receipt-data`, as StoreKit hands it to the app) | `verifyReceipt(base64)` |
| A StoreKit 2 signed transaction, renewal info, app transaction, or App Store Server Notification | `verifySignedData(jws)` |
| A `verifyReceipt`-style HTTP request body (`{"receipt-data": "..."}`) that your own server needs to answer | `verifyReceiptEndpoint(environment, requestJson)` |

`verifyReceiptEndpoint` runs `verifyReceipt` underneath and renders the
result in Apple's wire format; call it only when you are reproducing that
HTTP contract. Everything else should call `verifyReceipt` or
`verifySignedData` directly and read the typed payload.

## What to check after verification

The library checks only that Apple signed the bytes. A `verified()` result is
not by itself a reason to grant anything: check, in your own code, every
time:

| Check | How |
|---|---|
| Bundle id | `receipt.bundleId()` (or, in a JWS payload, the `bundleId` claim in `json()`) equals your app's id |
| Environment | `Environment.fromReceiptType(receipt.receiptType())` for a receipt, or the JWS `environment` claim for a JWS. Decide whether to accept `SANDBOX` at all, and scope what you grant from it: TestFlight, including public-link installs, buys in sandbox for free, and App Review runs production builds against sandbox |
| Product id | The purchase or transaction names a product you actually sell |
| Idempotency | Key grants on the transaction id (`transactionId` claim, or `InAppPurchase.transactionId()`), not on the receipt or JWS bytes: a legacy receipt is BER, so one signed receipt has more than one byte spelling, and Apple retries a notification for days, so the same `notificationUUID` arrives more than once. A retry by the same user for a transaction already granted to them should answer "granted" again without granting twice; the same transaction from another user is a replay and is denied |

Nothing here is optional. `verifyReceipt` and `verifySignedData` take no
bundle id, environment or product parameter, so skipping one of these checks
means accepting a genuine, correctly signed receipt or transaction from a
different app, environment or product.

## The device-hash example

A receipt's device binding (attribute 5) is `SHA-1(deviceId ‖ opaqueValue ‖
bundleIdBytes)`, over the exact octets the receipt carries. `opaqueValue()`,
`bundleIdBytes()` and `sha1Hash()` return those octets so you can compute and
compare it yourself; the library takes no device id parameter and does not
check it for you.

`deviceId` is the raw 16 bytes of `identifierForVendor`, most significant
first, not its UUID string and not hex:

```java
import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

static boolean deviceHashMatches(ReceiptPayload receipt, String identifierForVendor)
        throws NoSuchAlgorithmException {
    UUID idfv = UUID.fromString(identifierForVendor);   // "E621E1F8-C36C-495A-93FC-0C247A3E6E5F"
    byte[] deviceId = ByteBuffer.allocate(16)
            .putLong(idfv.getMostSignificantBits())
            .putLong(idfv.getLeastSignificantBits())
            .array();

    byte[] opaqueValue = receipt.opaqueValue();
    byte[] bundleIdBytes = receipt.bundleIdBytes();
    byte[] sha1Hash = receipt.sha1Hash();
    if (opaqueValue == null || bundleIdBytes == null || sha1Hash == null) {
        return false;                                   // the receipt lacks an attribute the check needs
    }
    MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
    sha1.update(deviceId);
    sha1.update(opaqueValue);
    sha1.update(bundleIdBytes);
    return MessageDigest.isEqual(sha1.digest(), sha1Hash);   // constant-time compare
}
```

The check is optional because a server does not always have the client's
device id: on iOS, iPadOS, tvOS and watchOS (including an iOS app running on
an Apple silicon Mac) it is `identifierForVendor`; on macOS and Mac Catalyst
it is the primary network interface's MAC address from `copy_mac_address`.

## Decoding a receipt

`ReceiptPayload` and `InAppPurchase` decode every attribute the library
models, plus `unknownAttributes()` for everything it does not. The rules,
the same for both:

- A missing attribute decodes to `null`. The library invents no values.
- Dates are epoch milliseconds, UTC, with an `Ms` suffix. Receipts carry
  whole seconds, so the value always ends in `000`. An **empty** date string
  means "not set" and decodes to `null` with nothing kept raw. A
  **non-empty** date string that does not parse also decodes to `null`, but
  its raw bytes are kept in `unknownAttributes`.
- The trial and intro-offer flags are `Boolean`: `0` is `false`, any other
  value is `true`.
- A known attribute that appears more than once: the **first** occurrence in
  receipt order wins, for the typed field and (for attribute 12) for the
  chain-validity date. Every later copy is kept raw.
- Nothing Apple signed is lost. `unknownAttributes()` (an in-app purchase's
  own, for an in-app attribute) holds the raw value octets of an attribute
  type the library does not model, the second and later copies of a known
  attribute, and a known attribute whose value does not parse (whose typed
  field is then `null`), keyed by attribute type, in receipt order. A fresh
  defensive copy on every call.
- 64-bit ids (`appItemId`, `downloadId`, `versionExternalIdentifier`,
  `webOrderLineItemId`) are `Long`, not `int`: genuine receipts carry
  18-digit `downloadId` values.

`ReceiptPayload.toJson()` renders the payload as JSON for logging and
storage, written by jackson-core's generator. Every one of the nine ports of
this library produces the same JSON value, not the same bytes: key order,
whitespace and escaping style are free. The 64-bit ids above are JSON
strings (dates stay numbers: epoch milliseconds do not exceed 2^53 until
roughly the year 287,000), bytes are padded standard base64, a missing value
is `null` rather than an omitted key, and `unknown_attributes` is an object
keyed by the decimal attribute type. Parse it and compare values, never the
string.

## App Store Server Notifications V2

A notification is a JWS with no dedicated model, so it goes through
`verifySignedData` like any other. Its payload nests two more JWS inside
`data`: `signedTransactionInfo` and `signedRenewalInfo`, each its own signed
claim set that needs its own verification. Apple POSTs
`{"signedPayload": "<JWS>"}`.

A `TEST` notification (sent when you request one from App Store Connect)
carries **neither** nested field: `data` is a summary with no transaction to
act on.

```java
import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.JsonPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationResult;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;

import com.apple.itunes.storekit.model.Data;
import com.apple.itunes.storekit.model.JWSRenewalInfoDecodedPayload;
import com.apple.itunes.storekit.model.JWSTransactionDecodedPayload;
import com.apple.itunes.storekit.model.ResponseBodyV2DecodedPayload;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

public class Notifications {
    private final Verifier verifier = Verifier.create(Config.defaults());
    private final ObjectMapper mapper = new ObjectMapper();

    /** signedPayload from the POST body; returns the HTTP status to answer Apple with. */
    public int handle(String signedPayload) {
        VerificationResult<JsonPayload> outer = verifier.verifySignedData(signedPayload);
        if (!outer.verified()) {
            // INTERNAL_ERROR is not Apple's fault or an attack: page, and
            // Apple's retries give you days to ship a fix. Anything else: deny.
            return outer.failure().reason() == Reason.INTERNAL_ERROR ? 500 : 400;
        }
        ResponseBodyV2DecodedPayload notification;
        try {
            notification = mapper.readValue(outer.payload().json(), ResponseBodyV2DecodedPayload.class);
        } catch (IOException e) {
            return 400;   // Apple signed it, but this app's model can't read it
        }
        // Dedupe on notificationUUID: Apple retries an unacknowledged
        // notification for days, so the same one arrives more than once.
        if (seen(notification.getNotificationUUID())) {
            return 200;
        }
        Data data = notification.getData();
        if (data == null) {
            markSeen(notification.getNotificationUUID());
            return 200;   // a summary notification, or a TEST notification: nothing nested to verify
        }
        if (!"com.example.app".equals(data.getBundleId())) {
            return 400;   // verifySignedData checked no claim: check identity yourself
        }

        if (data.getSignedTransactionInfo() != null) {
            VerificationResult<JsonPayload> tx = verifier.verifySignedData(data.getSignedTransactionInfo());
            if (!tx.verified()) {
                return 400;
            }
            try {
                JWSTransactionDecodedPayload transaction =
                        mapper.readValue(tx.payload().json(), JWSTransactionDecodedPayload.class);
                applyTransaction(notification.getRawNotificationType(), transaction);
            } catch (IOException e) {
                return 400;
            }
        }
        if (data.getSignedRenewalInfo() != null) {
            VerificationResult<JsonPayload> renewal = verifier.verifySignedData(data.getSignedRenewalInfo());
            if (!renewal.verified()) {
                return 400;
            }
            try {
                JWSRenewalInfoDecodedPayload info =
                        mapper.readValue(renewal.payload().json(), JWSRenewalInfoDecodedPayload.class);
                applyRenewalInfo(info);
            } catch (IOException e) {
                return 400;
            }
        }
        markSeen(notification.getNotificationUUID());   // only after the work is done
        return 200;
    }

    private void applyTransaction(String notificationType, JWSTransactionDecodedPayload transaction) { /* your code */ }
    private void applyRenewalInfo(JWSRenewalInfoDecodedPayload info) { /* your code */ }
    private boolean seen(String notificationUuid) { return false; /* your storage */ }
    private void markSeen(String notificationUuid) { /* your storage */ }
}
```

Two deliveries of one notification can race past the `seen` check, so
whatever `applyTransaction` and `applyRenewalInfo` do must be idempotent
themselves; the dedupe store only saves the repeated work.

## Deserialising a JWS payload into a typed model

`JsonPayload.json()` is the verified payload exactly as Apple signed it: a
plain `String`, not a parsed object. The library ships no typed JWS models
and no parse helper, on purpose, so it never lags a claim Apple adds.
[Apple's own `app-store-server-library`](https://github.com/apple/app-store-server-library-java)
publishes and maintains those model classes
(`com.apple.itunes.storekit.model.JWSTransactionDecodedPayload`,
`JWSRenewalInfoDecodedPayload`, `AppTransaction`, and the notification models
used above); parse `json()` into them with a plain Jackson `ObjectMapper`:

```java
import com.apple.itunes.storekit.model.JWSTransactionDecodedPayload;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

ObjectMapper mapper = new ObjectMapper();

VerificationResult<JsonPayload> result = verifier.verifySignedData(jws);
if (result.verified()) {
    try {
        JWSTransactionDecodedPayload transaction =
                mapper.readValue(result.payload().json(), JWSTransactionDecodedPayload.class);
        System.out.println(transaction.getProductId() + " " + transaction.getExpiresDate());
    } catch (JsonProcessingException e) {
        // Apple signed it, but this app's model can't read it: alert, don't retry.
    }
}
```

Apple's model classes ship every date claim (`signedDate`, `purchaseDate`,
`expiresDate`, `revocationDate`) as `Long` epoch milliseconds, exactly as
signed; there is no "is active" helper, so read `revocationDate()` and
`expiresDate()` against your own clock.

Two things to weigh before adding it: **Apple's library brings
`jackson-databind` 2 with it**, which this library deliberately does not
depend on any more (see [Upgrading from 0.6](#upgrading-from-06)); that
dependency is your choice, not this library's. And **Apple's library needs
Java 11**, above this library's Java 8 floor, so it is only an option where
your own consumer already runs 11 or later. Where it is not, or in the other
eight ports of this library, where Apple has no equivalent, declare your own
struct or class for the claims you read and deserialise into that instead.

## The verifyReceipt-compatible endpoint

```java
String responseJson = verifier.verifyReceiptEndpoint(Environment.PRODUCTION, requestJson);
```

Input is a `verifyReceipt` request body, `{"receipt-data": "...", ...}`.
Output is the response JSON Apple's endpoint for that environment would
return, as a `String`, for every input, never a thrown exception. Apple's
own `password` and `exclude-old-transactions` fields are read and ignored,
as in 0.6.
Duplicate member names are last-wins: where this request body repeats
`receipt-data`, a JWS header repeats `alg` or `x5c`, or a JWS payload
repeats `signedDate`, the last occurrence is the value used.

`environment` picks which of Apple's two URLs this call imitates and drives
the 21007/21008 routing below; `request_date` in the response comes from the
`Config` clock, read at most once per call. `web_order_line_item_id` is omitted from
an in-app purchase entry when attribute 1711 is `0`, as Apple omits it for
consumables.

Status, from the verification outcome, the same table in every port of this
library:

| Outcome | Status |
|---|---|
| Verified, receipt's environment matches this endpoint's | 0 |
| Verified, a sandbox receipt answered by a `PRODUCTION` endpoint | 21007 |
| Verified, a production receipt answered by a `SANDBOX` endpoint | 21008 |
| `Reason.MALFORMED`, `Reason.TOO_LARGE` | 21002 |
| `Reason.INVALID_SIGNATURE`, `Reason.UNTRUSTED_CHAIN`, `Reason.INVALID_CERTIFICATE`, `Reason.INVALID_CERTIFICATE_PURPOSE` | 21003 |
| `Reason.UNREADABLE_PAYLOAD`, `Reason.INTERNAL_ERROR` | 21009 |

A receipt whose `receipt_type` is missing or unknown counts as
non-production: 21007 on `PRODUCTION`, status 0 on `SANDBOX`.

This endpoint never returns Apple's 21005 or the 21100-21199 range: those
mean Apple's own servers failed, and there is no remote server here to fail.
**21009 is deterministic for the same input: alert on it, do not retry.**
`AppleStatus` names every status code Apple documents, with its Javadoc
saying which ones this endpoint can actually return, so you do not have to
write `21007` by hand.

There is no separate method to re-render a result for the other
environment without a second verification, unlike 0.6's
`VerifyReceiptResult.toJson(Environment)`: call `verifyReceiptEndpoint`
again with the other `Environment`, or call `verifyReceipt` once yourself
and decide with `Environment.fromReceiptType`.

## The error vocabulary

`VerificationResult<T>` never throws for a rejected input; it carries either
the payload or a `Failure`:

```java
VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(base64);
if (!result.verified()) {
    Failure failure = result.failure();
    switch (failure.reason()) {
        case INTERNAL_ERROR:
        case UNREADABLE_PAYLOAD:
            page(failure);                  // deterministic: do not retry
            break;
        default:
            deny(failure.reason());
    }
}
```

`Failure.message()` is safe to log as is (it never quotes the input's bytes,
so there is nothing in it to neutralise; a message may state a date or a
count the input declared) but is not meant to be parsed; match
on `reason()`, never on the message text, and store a reason by `name()`,
never by `ordinal()`.

| `Reason` | Meaning |
|---|---|
| `MALFORMED` | The base64, ASN.1, CMS or JWS structure is broken, or a structural bound was exceeded (JSON nesting past 64, ASN.1 nesting past BouncyCastle's bound, more than 10 embedded certificates, more than 4 SignerInfos). Decided before any signature check |
| `TOO_LARGE` | Over a fixed size cap: 3,145,728 UTF-8 bytes for a receipt or an endpoint request body, 262,144 for a JWS. Decided before anything is decoded |
| `INVALID_SIGNATURE` | The signature does not match the signed content |
| `UNTRUSTED_CHAIN` | The certificate chain does not reach a pinned root, or has more than six certificates below the anchor |
| `INVALID_CERTIFICATE` | A certificate the check depends on does not decode, or is expired or not yet valid at the signing instant |
| `INVALID_CERTIFICATE_PURPOSE` | A certificate that chains to a pinned root but is the wrong kind: the leaf lacks Apple's signing marker OID, or the intermediate lacks Apple's WWDR marker OID. This is what keeps a genuine developer certificate, which chains to the same roots, from signing a receipt or JWS |
| `UNREADABLE_PAYLOAD` | The signature and chain verified, so the payload bytes are Apple's, but they do not parse. `Failure.cause()` carries the parser's exception. Deterministic: alert, do not retry |
| `INTERNAL_ERROR` | The library itself failed before it could decide, for example a runtime missing an algorithm the check needs. `Failure.cause()` carries the exception. Deterministic: alert, do not retry |

The set is closed by the cross-port contract: adding or removing a `Reason`
is a change to the shared fixture file and to all nine ports at once, and is
a breaking change.

## Trust anchors

`Config.defaults()` trusts all three published Apple roots (Apple Inc. Root
CA, Apple Root CA - G2, Apple Root CA - G3), compiled into `AppleRootCerts`
as base64 constants, so no resource on the classpath can stand in for them.
Apple documents the JWS chain as ending in "an Apple root certificate"
rather than naming one, so narrowing the set would fail closed, silently,
the day Apple re-anchored a path. `AppleRootCertsTest` pins the three to
Apple's published SHA-256 fingerprints and to the repository's `certs/`.

Certificate validity is judged at the payload's own signing instant (a
receipt's creation date, or a JWS's `signedDate`), not at verification time,
so a payload signed before a root expires keeps verifying after it:

| Root | Expires (UTC) | Anchors today |
|---|---|---|
| Apple Inc. Root CA | 2035-02-09 | legacy receipts |
| Apple Root CA - G2 | 2039-04-30 | neither path today |
| Apple Root CA - G3 | 2039-04-30 | JWS |

A payload signed after Apple moves to a new root needs that root in the
anchor set: bump this library, or pass your own set through
`Config.builder().roots(...)`.

Revocation is not checked: no OCSP, no CRL. Offline verification is the
point; Apple handles a compromised signing certificate by rotating it, and
`INVALID_CERTIFICATE` is where a future revocation check would report a
revoked certificate. See [THREAT-MODEL.md](../THREAT-MODEL.md) section 4,
and use the App Store Server API for refunds, revocations and subscription
state, none of which a signature can express.

### One platform caveat: BouncyCastle, not the JDK's PKIX

Every cryptographic lookup in this library, certificate parsing, chain
building and validation, the CMS and ES256 signature checks, and every
digest, names a private `BouncyCastleProvider` instance that is never
registered with `Security`. `jdk.certpath.disabledAlgorithms` and the host's
provider order never change a verdict.

Why it matters: the genuine legacy Apple receipt chain is SHA-1 end to end
(the leaf and the WWDR intermediate are both `sha1WithRSAEncryption`). RHEL
and Fedora system crypto policies, and many hardened enterprise
`java.security` files, disable SHA-1 outright through
`jdk.certpath.disabledAlgorithms`. Built against the JDK's own PKIX code,
every genuine legacy receipt fails on such a host as `UNTRUSTED_CHAIN`, as
if it were forged. BouncyCastle's PKIX code does not read that property, so
this library keeps verifying real receipts under a policy like:

```
jdk.certpath.disabledAlgorithms=MD2, MD5, SHA1, RSA keySize < 1024
```

The trade-off is deliberate: an administrator cannot restrict what this
library accepts through `java.security` either. What it accepts is fixed by
the library and the roots the caller passes, the same on every JVM, with
one exception: the ASN.1 nesting bound is BouncyCastle's own, which
`java.security` or a system property can move (see [Resource
bounds](#resource-bounds)).

## Resource bounds

Fixed constants, not configurable, except the ASN.1 nesting bound (below
the table). The three size caps are checked before anything is decoded;
the others as the structure they bound is read:

| Bound | Value | `Reason` |
|---|---|---|
| Receipt base64, UTF-8 bytes | 3,145,728 | `TOO_LARGE` |
| Endpoint request body, UTF-8 bytes | 3,145,728 | `TOO_LARGE` (status 21002) |
| JWS, UTF-8 bytes | 262,144 | `TOO_LARGE` |
| JSON nesting depth, the outer object included | 64 | `MALFORMED` (JWS header, request body); a JWS payload is carried to the signature: `UNREADABLE_PAYLOAD` if it verifies |
| JSON member name, characters | 50,000 | as nesting depth |
| JSON number, characters | 1,000 | as nesting depth |
| ASN.1 nesting, constructed values | BouncyCastle's, 64 by default | `MALFORMED` (receipt envelope), `UNREADABLE_PAYLOAD` (signed receipt content), `INVALID_CERTIFICATE` (an `x5c` entry) |
| Certificates embedded in a receipt | 10 | `MALFORMED` |
| Chain length, certificates below the anchor | 6 | `UNTRUSTED_CHAIN` |
| SignerInfos in a receipt | 4 | `MALFORMED` |

The ASN.1 nesting bound is BouncyCastle's
`org.bouncycastle.asn1.max_cons_depth`, 64 unless the host sets it. It is
read each time BouncyCastle opens an ASN.1 stream, from `java.security`
first and then from the system property of that name. Its count depends
on the shape by one: 65 nested SETs parse
when the innermost is empty and are refused when it holds a value. The
Rust core, which every other package runs, keeps its own bound of 32, so
the shared cases nested 33 deep allow both answers (DECISIONS.md R20). A
genuine Apple receipt nests 9 deep: a host that sets the property below
9 refuses every genuine receipt as `MALFORMED`.

Apple's own endpoint answers a request body of exactly 3,145,728 bytes and
sends HTTP 413 for 3,145,729 (measured 2026-09-23 against both of Apple's
verifyReceipt URLs; counted in UTF-8 bytes, not characters). Any HTTP layer
in front of `verifyReceiptEndpoint`, load balancer, reverse proxy, servlet
container, must accept at least that much, or it refuses receipts Apple
would have answered.

## Running in production

A checklist for a service that puts this library behind an HTTP endpoint.
Figures marked approximate were measured on OpenJDK 21, one thread,
BouncyCastle 1.86; expect yours to differ by machine.

**Self-test at startup, then keep it running as a canary.** Verify a
known-good Apple-signed receipt and a known-good Apple-signed JWS at startup,
and fail readiness unless both are `verified()`. Repeat every minute. The
two receipts `receipt-sandbox-legacy.b64` and `receipt-sandbox-g5.b64` under
[`fixtures/public-receipts/`](../fixtures/public-receipts/) chain to the real
Apple roots and keep verifying, because validity is judged at their own
signing date. The repository has no JWS signed by a real Apple root (the
vendored Apple JWS fixtures are signed by a test CA), so keep one from your
own sandbox, such as a transaction you bought there. Why: a runtime that
cannot construct a crypto engine answers `INTERNAL_ERROR`, but an unchecked
exception BouncyCastle throws while parsing is reported as a verdict on the
input (`MALFORMED` before the signature, `UNREADABLE_PAYLOAD` after it). That
is by design, so hostile input cannot page you. It also means a broken host
and an attack wave look alike in the counters. A known-good input that must
verify is what tells them apart.

**Let `Verifier.create` fail a broken runtime at deployment.** By default
`Verifier.create` asks the library's BouncyCastle provider for the SHA-256
digest, the ES256 signature, the X.509 certificate factory, the PKIX path
validator and builder and the Collection cert store, and checks the signature
of each of the three bundled Apple roots, the SHA-1 one included. It needs no
receipt or JWS. It checks the bundled roots, not the roots in your `Config`,
so a deployment with custom roots whose runtime lacks their signature
algorithm still answers `INTERNAL_ERROR` on the first call. If any
step fails, as on a stripped JRE, a
FIPS-mode JDK that refuses the provider or a corrupt jar, it throws
`IllegalStateException`, so the deploy fails instead of the first request
answering `INTERNAL_ERROR`. `Config.builder().runtimeProbe(false)` turns the
probe off. The only use we can name is a test setup that stands in a double
for the crypto provider; with the probe off, a broken runtime shows up as
`INTERNAL_ERROR` on the first call instead. The probe does not replace the
self-test above: it proves the engines exist, not that a real receipt parses.

**Bound body size and concurrency at the edge.** Reject bodies above
3 MiB (3,145,728 bytes, the library's cap; see
[Resource bounds](#resource-bounds)), or lower if your product never sees
large receipts. Put a `Semaphore` (or a bounded executor) of about twice the
core count around the verify call. Why: memory, not CPU, is the limit. A
1 MB genuine receipt costs about 30 ms and about 30 MB of allocation per
call, a cap-sized one about 70 ms and 75 MB (approximate), so 100 such calls
at once exhaust a normal heap. Hostile input is cheap to reject, a 1 MB
forgery about 5 ms, because nothing expensive runs before the chain is
trusted.

**Warm up before taking traffic.** Build the `Verifier` at startup, not
lazily on the first request. `Verifier.create` takes about 450 ms cold, the
first receipt about 150 ms and the first JWS about 75 ms (approximate), and
calls settle only after about 1,000 to 2,000 of them, when the JIT has
compiled the hot paths. At 10 requests a second that is minutes of slower
answers after every deploy, so verify a known receipt and JWS that many
times before the instance reports ready.

**Export metrics and alert on the right ones.** Count results per `Reason`,
and keep a latency histogram and an input-size histogram. Page on
`INTERNAL_ERROR` and `UNREADABLE_PAYLOAD` (both status 21009 from the
endpoint): each is deterministic and points at the host, the library or a
change in Apple's format, not at the client. Alert, without paging, on a shift in the ratio of
`MALFORMED` (21002) and of 21003: that is either a client bug or someone
probing.

**Enforce the dependency set in the service build.** BouncyCastle
`bcpkix`, `bcprov` and `bcutil` at one version, and no duplicate
`org.bouncycastle` classes: a `jdk15on` jar and a `jdk18on` jar on one
classpath make `verifyReceipt` fail with a `LinkageError`, which the
never-throws contract does not cover. `jackson-core` 2.16 or newer. Make
the build fail on a violation rather than relying on review. See
[Vendoring](#vendoring) for why each floor exists.

**Write down the residual risk.** Revocation is not checked, and the
validity instant is the payload's own date. A leaked historical Apple leaf
key would therefore verify a payload back-dated into that key's validity
window. Apple's own libraries behave the same. Watch this repository's
weekly [`apple-root-watch`](../.github/workflows/apple-root-watch.yml)
workflow, which fails when Apple's published roots change, and own the root
set in service config through `Config.builder().roots(...)` so a new root is
a config change, not a dependency bump.

**Prefer Java 17 or 21.** Java 8 is supported, but there
`Provider.getService` is synchronized, and every call makes several lookups
on the library's private BouncyCastle provider, so concurrent calls
serialise on it.

The worst-case CPU for one call is measured in the next section.

## Measured worst-case CPU

Measured on 2026-09-27 with `java-bench`'s `WorstCaseBenchmark`, which times
every shared case in `fixtures/cases.json` that carries a time budget:
oversized untrusted keys, a cross-signed certificate mesh, and the encoding
oddities inside certificates. OpenJDK 21.0.10, JMH 1.37, one thread, on a
shared 4-vCPU KVM guest (Intel Xeon Processor @ 2.10GHz). The JIT is warm:
each case runs once and is checked, then five 1-second warm-up iterations,
then five 1-second measured iterations in one fork. The genuine receipt
comes from `ReceiptBenchmark` (the same settings, two forks).

| Call | Mean | Slowest iteration |
|---|---:|---:|
| Slowest hostile case: `receipt/verify-genuine-padded-with-oversized-strangers` (a valid receipt carrying oversized certificates it does not need) | 2.4 ms | 2.7 ms |
| Next: `receipt/reject-untrusted-oversized-intermediates` | 1.2 ms | 1.4 ms |
| Slowest hostile JWS: `signed-data/intermediate-with-an-indefinite-certificate-length-does-not-crash` | 1.1 ms | 1.1 ms |
| Every other budgeted case | under 1.1 ms | under 1.2 ms |
| For scale: `verifyReceipt` on the genuine 187-purchase legacy receipt | 3.1 ms | 3.4 ms |
| For scale: `verifyReceiptEndpoint` on the same receipt | 4.0 ms | 4.4 ms |

No hostile input in the shared suite costs more than an ordinary large
receipt: the cost of a call follows the size of the input, which the caps in
[Resource bounds](#resource-bounds) limit, not the structure an attacker
chooses. These are warm-JVM figures; see
[Running in production](#running-in-production) for the cold start. The
machine was shared with other work, so treat them as an order of magnitude.
For numbers on your own hardware, build as in
[java-bench/README.md](../java-bench/README.md), then run

```bash
java -cp java-bench/target/benchmarks.jar \
    io.github.emindeniz99.applepurchasereceiptverifier.bench.WorstCaseBenchmark
java -jar java-bench/target/benchmarks.jar 'ReceiptBenchmark.(verifyReceipt|endpointJson)$' \
    -p fixture=receipt-sandbox-legacy
```

## Testing with synthetic receipts

Your own logic and wiring tests need none of this: mock `Verifier` and build
a `ReceiptPayload` by hand, or replay a sandbox receipt from your own app
(see [What to check after verification](#what-to-check-after-verification)).

For an end-to-end test, one that signs its own fake receipt or JWS and feeds
it through a real `Verifier`, add the `tests` test-jar classifier this
library publishes alongside the main jar. It ships `TestPki`, the same
synthetic-PKI signer this library's own suite uses, and needs BouncyCastle
at test scope to build and sign certificates with:

```xml
<dependency>
  <groupId>io.github.emindeniz99</groupId>
  <artifactId>apple-purchase-receipt-verifier</artifactId>
  <version>0.7.0</version> <!-- x-release-please-version -->
  <classifier>tests</classifier>
  <type>test-jar</type>
  <scope>test</scope>
</dependency>
<dependency>
  <groupId>org.bouncycastle</groupId>
  <artifactId>bcpkix-jdk18on</artifactId>
  <version>1.86</version>
  <scope>test</scope>
</dependency>
```

`TestPki` is a public class in
`io.github.emindeniz99.applepurchasereceiptverifier`; import it from any
package. Only the members below are public; the rest is this library's own
fixture machinery:

| Member | Builds |
|---|---|
| `TestPki.receipt()` | A fresh root/intermediate/leaf chain carrying Apple's marker OIDs, for CMS receipts |
| `TestPki.jws()` | The same, for a StoreKit 2 JWS |
| `TestPki.receiptPayload(bundleId, appVersion, opaque, sha1Hash, creationDate, inAppSets)` | A receipt attribute SET |
| `TestPki.inAppPurchase(quantity, productId, transactionId, originalTransactionId, purchaseDate, expiresDate)` | One in-app purchase attribute SET, for `inAppSets` above |
| `TestPki.claims(key, value, ...)` | An insertion-ordered claims map, for `signJws` |
| `pki.signReceipt(payload)` | CMS-signs a receipt payload with this chain |
| `pki.signJws(claims)` | Signs claims as a compact ES256 JWS with this chain in `x5c` |
| `pki.root` | The chain's trust anchor, to pin with `Config.builder().roots(...)` |

```java
package io.github.emindeniz99.applepurchasereceiptverifier;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;

// The receipt's own creation date pins the chain-validity instant, so the
// fixed clock below just has to be an instant TestPki.receipt()'s one-year
// chain actually covers: "now" always is.
Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);

TestPki pki = TestPki.receipt();
byte[] payload = TestPki.receiptPayload(
        "com.example.app",
        "1.0",
        new byte[] {1, 2, 3, 4},   // opaqueValue
        new byte[] {5, 6, 7, 8},   // sha1Hash
        now.toString(),
        Collections.<byte[]>emptyList());
String receiptBase64 = Base64.getEncoder().encodeToString(pki.signReceipt(payload));

Config config = Config.builder()
        .roots(Collections.singleton(pki.root))
        .clock(Clock.fixed(now, ZoneOffset.UTC))
        .build();
Verifier verifier = Verifier.create(config);

VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(receiptBase64);
// result.verified() is true; result.payload().bundleId() is "com.example.app"
```

This example is compile-checked against the built classes in
`ReadmeSyntheticReceiptExampleTest`, in `src/test/java`.

## Debugging a receipt by hand

See ["Debugging a receipt by hand"](../README.md#debugging-a-receipt-by-hand)
in the project README for opening a receipt with `openssl` outside this
library.

## Upgrading from 0.6

0.6's three verifier classes, one checked exception and every policy
parameter (bundle id, environment, device GUID, app Apple id) are gone. 0.7
answers one question, did Apple sign this, so parameters that used to
express a policy decision have no replacement: read the corresponding field
from the verified payload and decide yourself (see
[What to check after verification](#what-to-check-after-verification)).

### Entry points

| 0.6 | 0.7 |
|---|---|
| `receipt.ReceiptVerifier(roots, bundleId)`, `.verify(byte[]\|String[, deviceGuid])` | `Verifier.create(config).verifyReceipt(base64)`. No bundle id at construction, no bundle-id check, no device GUID parameter; do both yourself (checklist above, [device-hash example](#the-device-hash-example)) |
| `receipt.ReceiptVerifier.verifyReceiptCore(byte[], roots)` (static) | No direct replacement. `verifyReceipt(base64)` already does chain, signature and decode with no bundle-id check; if you hold raw DER, base64-encode it first |
| `jws.JwsVerifier(roots, bundleId, acceptedEnvironments[, appAppleId])`, `.verifyTransaction`, `.verifyAppTransaction`, `.verifyRaw` | `Verifier.create(config).verifySignedData(jws)` for all four JWS shapes. No bundle id, accepted-environment set or app Apple id at construction; check `bundleId`, `environment` and `appAppleId` in the returned `json()` yourself |
| `receipt.VerifyReceiptEndpoint(roots, Environment[, Clock])`, `.verifyReceiptResult(String\|Map[, Instant])`, `.verifyReceiptJson(String[, Instant])`, `.verifyReceiptData(String[, Instant])` | `Verifier.create(config).verifyReceiptEndpoint(environment, requestJson)`. One method, one input shape (the JSON request body); the clock comes from `Config`, not a per-call `Instant` |
| `AppleRootCerts.jwsRoots()`, `.receiptRoots()` (public) | Gone as public API; `Config.defaults()` uses the same bundled, pinned roots. `Config.builder().roots(...)` for a custom set |

### Results and errors

| 0.6 | 0.7 |
|---|---|
| `receipt.AppReceipt` | `ReceiptPayload`. Same attributes; dates are now `Long` epoch milliseconds everywhere (0.6 exposed receipt dates as `Instant`, JWS claim dates as `Long`; 0.7 is `Long` on both, see [Decoding a receipt](#decoding-a-receipt)) |
| `jws.TransactionPayload`, `jws.AppTransactionPayload` (typed claim classes) | Gone. `JsonPayload.json()` is the raw signed payload; deserialise it yourself, see [Deserialising a JWS payload into a typed model](#deserialising-a-jws-payload-into-a-typed-model) |
| `receipt.VerifyReceiptResult` (`status()`, `receipt()`, `failureReason()`, `toResponse()`, `toJson()`, `toJson(Environment)`) | Gone. `verifyReceiptEndpoint` returns the rendered JSON `String` directly; there is no cost-free re-render for the other environment, call it again |
| `VerificationException` (checked), `.reason()`, `.getCause()` | Gone. `VerificationResult<T>.verified()` / `.payload()` / `.failure()`; `Failure.reason()` / `.message()` / `.cause()`. No method throws for a rejected input |
| `VerificationException.Reason` (eleven values) | `Reason` (eight values). See the mapping below |
| `VerifyReceiptEndpoint.STATUS_*` constants | `AppleStatus` constants, with the full set Apple documents (not just the ones this library returns) |
| `Environment.PRODUCTION`, `.SANDBOX`, `.XCODE`, `.LOCAL_TESTING`; `.fromValue(String)` | `Environment.PRODUCTION`, `.SANDBOX` only. `XCODE` and `LOCAL_TESTING` only ever named a JWS `environment` string; such a payload is never Apple-signed and always failed the chain check regardless of what `acceptedEnvironments` allowed. `fromValue` splits into `Environment.fromReceiptType(String)` (a receipt's `receipt_type`) and `Environment.fromJwsEnvironment(String)` (a JWS `environment` claim) |

### `Reason` mapping

| 0.6 `VerificationException.Reason` | 0.7 `Reason` |
|---|---|
| `INVALID_CHAIN` | `UNTRUSTED_CHAIN`, except a certificate outside its validity window, which is now `INVALID_CERTIFICATE` |
| `INVALID_RECEIPT_FORMAT`, `INVALID_JWS_FORMAT`, `MALFORMED_REQUEST` | `MALFORMED` |
| `REQUEST_TOO_LARGE` | `TOO_LARGE` |
| `INVALID_CERTIFICATE`, `INVALID_CERTIFICATE_PURPOSE`, `INVALID_SIGNATURE` | Same names, unchanged |
| `INTERNAL_ERROR` | `INTERNAL_ERROR` when the library or runtime itself failed; `UNREADABLE_PAYLOAD` when the chain and signature verified but the payload does not parse (this reason did not distinguish the two cases in 0.6) |
| `WRONG_BUNDLE_ID`, `WRONG_ENVIRONMENT`, `WRONG_APP_APPLE_ID`, `DEVICE_HASH_MISMATCH` | Gone. These were policy checks the library made for you; it verifies and returns the data now, so check these fields yourself (see the checklist above) |

## Vendoring

The library is one package with no generated code, so copying
`src/main/java` into another build works. What a
vendored copy has to carry with it:

**Dependency floors.** `jackson-core` 2.16 or later: the JSON readers set
`StreamReadConstraints` (`maxDocumentLength` and `maxNameLength` are 2.16
API), and below it `Verifier.create` throws `IllegalStateException`.
BouncyCastle `bcprov` and `bcpkix` 1.86, the version the code was checked
against.

**What to re-check on a BouncyCastle upgrade.** The code relies on a few
BouncyCastle behaviours that are not API contracts. Thread safety is not
one of them: apart from the provider instance, every BouncyCastle object is
built per call, including the CMS verifier builder, the PKIX validator and
path builder (it keeps per-build counters), the `CertificateFactory` (it
keeps stream state between calls) and every `Signature`.

- BouncyCastle bounds the nesting of every constructed value, definite or
  indefinite length, at 64 by default (`org.bouncycastle.asn1.max_cons_depth`),
  and throws an `IOException` past it. That bound is the library's only
  ASN.1 nesting bound, for the envelope, the payload, each x5c entry and
  every value BouncyCastle decodes inside them (an extension value inside
  a certificate, for example), so it must still exist, and still throw an
  `IOException`, after an upgrade.
- The signature BIT STRING of a certificate is decoded lazily, so the
  decoders read it once on purpose (`JwsCore.decodeChain`,
  `ReceiptCertificates.decode`).
- `IA5String` does not check that its bytes are seven-bit, so
  `ReceiptDecoder.decodeString` does.

**The trust anchors are compiled in.** The three roots are base64
constants in `AppleRootCerts`. To add a root Apple publishes, add its
`.cer` to the repository's `certs/`, add its base64 as a constant and to
the `parse(...)` call, and add the fingerprint Apple lists on its PKI page
(check it with `sha256sum` on the DER file) to `AppleRootCertsTest`, which
pins the set against both.

**The tests need the shared fixtures.** They read `fixtures/` next to
`java/`, or the directory `-Daprv.fixtures.dir=...` names. The subset they
use is `cases.json`, `generated/`, `generated-0.7/`, `limits/`,
`public-receipts/` and `apple-official/`; `cases.schema.json` is not
read. Two tests also read the build itself: `VerifierApiTest` compares
`Version.CURRENT` with `pom.xml`, and `TrustStoreIsolationTest` scans
`src/main/java`.

**Generators are tests that write nothing by default.**
`FixtureGeneratorTest` and the classes named `*Fixture` or `*Fixtures`
(other than `TestFixtures`) regenerate files under `fixtures/`, and only
with `-Dfixtures.generate=true`. Keep them compiled: `TestPki`,
`SyntheticReceipts` and `InputSizeBoundsTest` share helpers with several of
them.

## Stability

The version is `0.x`: the API can still change between minor versions.
Fixed by the cross-port fixture contract regardless: the endpoint's wire
output (statuses, fields, value types, date formatting; key order is not
part of the contract), the `Reason` set, the size bounds, and `Long` epoch
milliseconds for every date. Everything else, method names, exception-free
error handling, and performance, may change in a minor version.

## Licence

MIT, see [LICENSE](./LICENSE).
