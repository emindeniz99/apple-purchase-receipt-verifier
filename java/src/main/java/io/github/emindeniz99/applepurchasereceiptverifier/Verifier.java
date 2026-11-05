package io.github.emindeniz99.applepurchasereceiptverifier;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import org.jspecify.annotations.Nullable;

/**
 * Verifies Apple-signed purchase data offline, against pinned Apple roots,
 * and answers one question: did Apple sign this data? If so it returns the
 * data. Bundle id, environment, product, device binding, refunds and
 * idempotency are the caller's decisions; nothing here checks them.
 *
 * <p>Immutable and thread-safe: build one at startup with
 * {@link #create(Config)} and share it. An interface, so a caller can
 * substitute its own.</p>
 *
 * <p><strong>No method throws for any input.</strong> A {@code null} or empty
 * input string fails as {@link Reason#MALFORMED}. An unexpected runtime
 * exception inside the library is reported by where it happened. In
 * {@link #verifyReceipt} or {@link #verifySignedData}, before the signature
 * has verified, it refuses the input with the reason of the step that
 * threw: {@link Reason#UNTRUSTED_CHAIN} while the chain is walked, built
 * or validated, {@link Reason#INVALID_CERTIFICATE} for an {@code x5c} entry or
 * a certificate's key that does not decode, {@link Reason#INVALID_SIGNATURE}
 * in a receipt's CMS signature check, and {@link Reason#MALFORMED}
 * anywhere else, parsing and screening among them; never
 * {@link Reason#INTERNAL_ERROR}. While the signed content is read, it is
 * {@link Reason#UNREADABLE_PAYLOAD}; anywhere else (a clock that throws,
 * for example), {@link Reason#INTERNAL_ERROR}. Only JVM errors such
 * as {@link OutOfMemoryError} escape, besides the
 * {@link NullPointerException} a {@code null} {@link Config} or
 * {@link Environment}, a programming error, throws.</p>
 */
public interface Verifier {

    /**
     * A verifier over {@code config}'s roots and clock.
     *
     * <p>The runtime probe ({@link Config.Builder#runtimeProbe(boolean)})
     * asks the BouncyCastle provider for the digest, ES256, X.509, PKIX and
     * Collection cert store engines and checks each bundled Apple root's own
     * signature. It checks the bundled roots, not the roots in
     * {@code config}, so with custom roots a runtime that lacks their
     * signature algorithm passes the probe and then answers
     * {@link Reason#UNTRUSTED_CHAIN} to every input that reaches the chain
     * check: no signature by such a root verifies, so nothing chains to
     * it.</p>
     *
     * @throws NullPointerException     if {@code config} is null
     * @throws IllegalArgumentException if {@code config} has no roots, since
     *                                  such a verifier would reject everything,
     *                                  or if its revocation settings are
     *                                  refused (see
     *                                  {@link Config.Builder#revocationLists},
     *                                  {@link Config.Builder#revocationIssuers}
     *                                  and {@link Config.Builder#distrust});
     *                                  the message names the first problem
     *                                  and its index
     * @throws IllegalStateException    if this runtime cannot run the
     *                                  library. Each of these throws:
     *                                  <ul>
     *                                  <li>jackson-core is below 2.16;</li>
     *                                  <li>bcprov is below 1.86, or
     *                                  BouncyCastle fails to initialise,
     *                                  as without its bcutil or bcpkix
     *                                  jar;</li>
     *                                  <li>{@code org.bouncycastle.asn1.max_cons_depth}
     *                                  is set below 9, which refuses every
     *                                  genuine receipt;</li>
     *                                  <li>the time-zone database lacks
     *                                  America/Los_Angeles (the endpoint
     *                                  stand-in renders Pacific-time
     *                                  dates);</li>
     *                                  <li>the runtime probe is on (see
     *                                  {@link Config#runtimeProbe()}) and this
     *                                  runtime cannot verify Apple
     *                                  signatures.</li>
     *                                  </ul>
     */
    static Verifier create(Config config) {
        return new DefaultVerifier(config);
    }

    /**
     * Verifies a legacy PKCS#7 app receipt given as standard, padded base64
     * (the {@code receipt-data} a client sends), and decodes it.
     *
     * <p>Checks, in order: the size cap, strict base64, the CMS envelope, the
     * chain from a SignerInfo's certificate to a pinned root with its
     * validity (at the receipt's creation date, the clock when it states
     * none), Apple's marker OIDs on the signer and on the intermediate that
     * issued it, and the CMS signature. Up to four SignerInfos are tried in
     * order: the first that verifies decides, and when none does the first
     * one's failure is the verdict. More than four is {@code MALFORMED}. A
     * SignerInfo of a shape Apple never issues is left out before any is
     * tried, so "first" means first among those kept, and each one is tried
     * with every embedded certificate its SignerId names, in the same
     * way.</p>
     */
    VerificationResult<ReceiptPayload> verifyReceipt(@Nullable String base64);

    /**
     * Verifies a compact ES256 JWS from the App Store (a transaction, renewal
     * info, app transaction or App Store Server Notification) and returns its
     * payload unchanged. A notification's nested {@code signedTransactionInfo}
     * and {@code signedRenewalInfo} are JWS of their own: pass each one here
     * again.
     *
     * <p>Checks, in order: the size cap, three strict base64url segments, a
     * header whose {@code alg} is {@code ES256} and whose {@code x5c} holds
     * exactly three certificates, the chain from the leaf through the
     * intermediate to a pinned root with its validity, Apple's marker OIDs on
     * the leaf and on the intermediate, the ES256 signature, and last that
     * the payload is a JSON object. {@code x5c[2]} is decoded but not used:
     * the pinned root stands in for it.</p>
     *
     * <p>The certificates' validity is judged at the payload's own
     * {@code signedDate}, else its {@code receiptCreationDate} (an app
     * transaction carries one), else the clock. The payload is read for that
     * date before it is trusted, which only moves the validity window: the
     * chain and the signature are still required. So a payload signed before
     * an Apple certificate expired keeps verifying after it. A payload that
     * does not read is {@link Reason#UNREADABLE_PAYLOAD}, never
     * {@link Reason#MALFORMED}, since Apple signed it.</p>
     */
    VerificationResult<JsonPayload> verifySignedData(@Nullable String jws);

    /**
     * Answers a verifyReceipt request body ({@code {"receipt-data": "..."}})
     * with the response JSON Apple's endpoint in {@code environment} would
     * return. See {@link AppleStatus} for the status codes it can return.
     *
     * @throws NullPointerException if {@code environment} is null
     */
    String verifyReceiptEndpoint(Environment environment, @Nullable String requestJson);

    /**
     * Where the revocation lists this verifier can use are published, to
     * download and pass to {@link Config.Builder#revocationLists}: the list
     * URL of each built-in issuer that chains to the configured roots, then
     * the http and https cRLDistributionPoints of the added issuers,
     * without duplicates, in that order. With the default roots:
     * {@code http://crl.apple.com/root.crl},
     * {@code http://crl.apple.com/applerootcag3.crl},
     * {@code http://crl.apple.com/wwdrg5.crl} and
     * {@code http://crl.apple.com/wwdrg6.crl}. An added issuer's own list
     * URL is not known here (Apple names it only on the certificates that
     * issuer signs); fetch it as well. Unmodifiable.
     *
     * <p>The default, for a caller's own implementation, is empty.</p>
     */
    default List<String> revocationUrls() {
        return Collections.emptyList();
    }

    /**
     * The earliest {@code nextUpdate} among the lists held for the issuers
     * this verifier expects lists from (the built-in issuers that chain to
     * the configured roots, and the added issuers), or null when any of
     * them has no list held (none passed, or the one passed was ignored).
     * Null means live revocation is not fully in force; an instant in the
     * past means a list is stale. Neither fails a call: alert on both, and
     * build a new verifier with fresh lists.
     *
     * <p>The default, for a caller's own implementation, is null.</p>
     */
    default @Nullable Instant revocationValidUntil() {
        return null;
    }
}
