package io.github.emindeniz99.applepurchasereceiptverifier;

import org.jspecify.annotations.Nullable;

/**
 * Verifies Apple-signed purchase data offline, against pinned Apple roots,
 * and answers one question: did Apple sign this data? If so it returns the
 * data. Bundle id, environment, product, device binding, refunds and
 * idempotency are the caller's decisions; nothing here checks them.
 *
 * <p>Immutable and thread-safe: build one at startup with
 * {@link #create(Config)} and share it. An interface so callers can mock it
 * in their own tests.</p>
 *
 * <p><strong>No method throws for any input.</strong> A {@code null} or empty
 * input string fails as {@link Reason#MALFORMED}. An unexpected runtime
 * exception inside the library is reported by where it happened: before a
 * signature has verified as {@link Reason#MALFORMED}, while the signed
 * receipt content is decoded as {@link Reason#UNREADABLE_PAYLOAD}, and
 * anywhere else as {@link Reason#INTERNAL_ERROR}. Only JVM errors such as
 * {@link OutOfMemoryError} escape. The one exception: a
 * {@code null} {@link Environment} is a programming error and throws
 * {@link NullPointerException}.</p>
 */
public interface Verifier {

    /**
     * A verifier over {@code config}'s roots and clock.
     *
     * @throws NullPointerException     if {@code config} is null
     * @throws IllegalArgumentException if {@code config} has no roots, since
     *                                  such a verifier would reject everything
     * @throws IllegalStateException    if a dependency does not load: a
     *                                  jackson-core below 2.16, a
     *                                  BouncyCastle that fails to initialise,
     *                                  or a time-zone database without
     *                                  America/Los_Angeles (the endpoint
     *                                  stand-in renders Pacific-time dates);
     *                                  or, unless
     *                                  {@link Config#runtimeProbe()} is off,
     *                                  if this runtime cannot verify Apple
     *                                  signatures
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
     * issued it, and the CMS signature. A receipt with several SignerInfos
     * verifies when at least one of them does.</p>
     */
    VerificationResult<ReceiptPayload> verifyReceipt(@Nullable String base64);

    /**
     * Verifies a compact ES256 JWS from the App Store (a transaction, renewal
     * info, app transaction or App Store Server Notification) and returns its
     * payload unchanged. A notification's nested {@code signedTransactionInfo}
     * and {@code signedRenewalInfo} are JWS of their own: pass each one here
     * again.
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
}
