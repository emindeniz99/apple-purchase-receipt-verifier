# Integrating: from verified payload to entitlement

The full flow from a verified payload to a granted purchase. The
[README](./README.md#using-the-result) has the short version and the
[table of what to do per failure reason](./README.md#what-to-do-per-reason).

Verification proves Apple signed the bytes. It does not prove the presenter
owns them, and it says nothing about what happened after the signature. The
flow below is the shape this library is meant to sit inside. Each package's
README carries the same steps written in its own API.

There are two branches because clients send two things, and both are
first-class here. StoreKit 2 apps send a signed JWS transaction. StoreKit 1
apps and older SDKs still send the base64 PKCS#7 app receipt, the blob that
used to be POSTed to Apple's now-deprecated `verifyReceipt` endpoint, and
`verifyReceiptEndpoint` is the drop-in replacement for that call: the same
request body, the same response body, the same status codes, answered offline
against pinned roots.

## Branch A: StoreKit 2 signed transaction

```text
0. AT STARTUP
   verifier = Verifier.create(Config.defaults())   // Apple's pinned roots;
                                                   // immutable, share it

1. RECEIVE
   POST /purchases { jws }          the client's jwsRepresentation

2. VERIFY, OFFLINE, THEN CHECK IT IS YOURS
   result = verifier.verifySignedData(jws)
   on failure:
       log(result.failure.reason)   // README's reason table says what next
       deny                         // nothing partial is returned
   payload = parse(result.payload.json)   // Apple's model classes, or your
                                          // own struct: the library checks
                                          // no claim
   if payload.bundleId is not "com.example.app":
       deny
   environment = Environment.fromJwsEnvironment(payload.environment)
   if environment is not PRODUCTION or SANDBOX:
       deny                         // App Review runs production builds
                                    // against Sandbox, and so does every
                                    // TestFlight build: accept Sandbox where
                                    // App Review can reach, and record it
                                    // with the grant (step 6)

3. REVOKED OR EXPIRED?
   if payload.revocationDate is set:
       deny                         // refunded or revoked as of signing time
   if payload.expiresDate is set and not in the future:
       deny                         // the subscription term had ended

4. FRESH ENOUGH? YOUR CALL
   // the library does not judge age; where a window fits this endpoint,
   // compare it against the payload's own signing time
   if now - payload.signedDate > FRESHNESS_WINDOW:     // e.g. 5 minutes
       signed  = appStoreServerApi.getTransactionInfo(payload.transactionId)
       back to step 2 with the re-signed JWS            // same verifier

5. REPLAY GUARD
   owner = store.recordGrantIfAbsent(payload.transactionId,
                                     payload.originalTransactionId,  // subscriptions
                                     userId, environment)
   if owner is another user:
       deny                         // this purchase already unlocked something
   // the same user again is a retry: answer as before, grant nothing twice

6. GRANT
   grant(userId, payload.productId, payload.expiresDate, environment)
   // scope Sandbox grants: TestFlight purchases, public links included,
   // are free
```

## Branch B: legacy PKCS#7 app receipt

```text
1. RECEIVE
   POST /purchases { receiptData }  the base64 app receipt

2. VERIFY, OFFLINE, THEN CHECK IT IS YOURS
   result = verifier.verifyReceipt(receiptData)       // the same verifier
   on failure:
       log(result.failure.reason)
       deny
   receipt = result.payload
   if receipt.bundleId is not "com.example.app":
       deny                         // the library checks no bundle id
   environment = Environment.fromReceiptType(receipt.receiptType)
   if environment is not PRODUCTION or SANDBOX:
       deny                         // Xcode and unknown receipt types
   // Or hand the request body straight to verifyReceiptEndpoint and read
   // `status`: 0, 21002, 21003, 21007, 21008, 21009. Like Apple's endpoint
   // it does not check the bundle id, so compare bundle_id yourself.

3. REFUNDED OR EXPIRED?
   // a receipt lists every renewal of a subscription, expired and refunded
   // ones included, in no guaranteed order: select, do not take the first
   entries = receipt.inApp for the product you are unlocking,
             without the ones whose cancellationDateMs is set
   if any entry has an expiresDateMs:         // auto-renewable subscription
       purchase = the entry with the latest expiresDateMs
       if purchase.expiresDateMs is not in the future:
           deny                     // the latest term had ended when signed
   else:                                      // consumable, non-consumable
       each remaining entry is one purchase, granted by its transactionId
   if nothing is left:
       deny

4. FRESH, OR REFRESH
   // a receipt is a snapshot of the same kind: Apple re-signs it whenever the
   // app refreshes it, and a refunded purchase carries cancellation_date
   if now - receipt.receiptCreationDateMs > FRESHNESS_WINDOW:
       ask the client to refresh its receipt and re-send, or
       signed = appStoreServerApi.getTransactionInfo(purchase.transactionId)
       decide from verifier.verifySignedData(signed) instead, as in branch A
   // the same caller-side check as branch A, against the receipt's own
   // creation date

5. REPLAY GUARD
   owner = store.recordGrantIfAbsent(purchase.transactionId,
                                     purchase.originalTransactionId,
                                     userId, environment)
   if owner is another user:
       deny

6. GRANT
   grant(userId, purchase.productId, purchase.expiresDateMs, environment)
```

## Both branches

**Refunds and cancellations after step 6** arrive as App Store Server
Notifications V2, which are Apple-signed JWS this library verifies on either
branch:

```text
POST /apple/notifications { signedPayload }
    n = parse(verifier.verifySignedData(signedPayload).payload.json)
                                                 // deny on failure
    if n.notificationUUID was handled before:
        answer 200                               // Apple retries for days
    data = n.data                                // absent on summary types
    check data.bundleId, data.environment, and data.appAppleId in
        Production: they live under data, not at the top level
    tx = parse(verifier.verifySignedData(data.signedTransactionInfo).payload.json)
    renewal = parse(verifier.verifySignedData(data.signedRenewalInfo).payload.json)
                                                 // if present
    on REFUND or REVOKE: revoke(tx.transactionId)
    record n.notificationUUID, answer 200
```

The nested `signedTransactionInfo` and `signedRenewalInfo` are JWS of their
own and need their own verification. No freshness window applies here:
Apple retries an unanswered notification for days.
[java/README.md](java/README.md#app-store-server-notifications-v2) has a
complete handler.

**Why a fresh payload needs no network call.** Apple re-signs a transaction
every time the app fetches it, and a refunded transaction carries
`revocationDate` (JWS) or a cancellation date (receipt) from then on. So a
payload signed seconds ago, with neither field set, is Apple's current answer
about that purchase, and step 3 is the whole check. Five minutes is a
reasonable default for the window where one fits, but the library enforces
none on either path: compare `signedDate` (JWS) or the receipt's creation date
yourself. The right limit depends on the endpoint. Apple retries a server
notification for days, and a device may present an old but genuine payload,
so an age limit is a business decision rather than a verification step.
Apple's own App Store Server Libraries make the same choice: they read
`signedDate` only as the instant the chain is judged at.

**Step 4 is the only place either branch talks to Apple, and it is optional.**
Get Transaction Info by `transactionId`, or the subscription status endpoint,
answers with a freshly signed JWS, which goes through the same verifier before
anything is decided from it. A client that can re-fetch a current
`jwsRepresentation`, or refresh its app receipt, removes the step entirely:
answer a stale payload by asking for a fresh one.

**Dedupe on the transaction id, not on the bytes.** A legacy receipt is BER,
so one correctly signed receipt has several byte spellings; the id is the
identifier (PLAN.md D4). For a subscription keep `originalTransactionId`
beside it, since that is what ties renewals to one purchase.
