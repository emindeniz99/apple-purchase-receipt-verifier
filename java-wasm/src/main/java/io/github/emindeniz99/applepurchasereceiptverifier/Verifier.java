package io.github.emindeniz99.applepurchasereceiptverifier;

import org.jspecify.annotations.Nullable;

/**
 * Verifies Apple-signed purchase data offline, against pinned Apple roots,
 * and answers one question: did Apple sign this data? If so it returns the
 * data. Bundle id, environment, product, device binding, refunds and
 * idempotency are the caller's decisions; nothing here checks them.
 *
 * <p>In this artifact every decision is made by the shared Rust core,
 * {@code aprv.wasm}, run by an {@link Engine}; this interface only moves the
 * input in and the answer out. The API is the main artifact's.</p>
 *
 * <p>Immutable and thread-safe: build one at startup with
 * {@link #create(Config)} and share it. It keeps a small pool of module
 * instances, one per concurrent call. An interface so callers can mock it
 * in their own tests.</p>
 *
 * <p><strong>No method throws for any input.</strong> A {@code null} or empty
 * input string fails as {@link Reason#MALFORMED}. A trap in the verifier
 * module, a runtime failure, an answer this library cannot read and a clock
 * that throws are {@link Reason#INTERNAL_ERROR} (21009 from the endpoint),
 * with the exception in {@link Failure#cause()}; the module instance
 * involved is discarded. Only JVM errors such as {@link OutOfMemoryError}
 * escape. The one exception: a {@code null} {@link Environment} is a
 * programming error and throws {@link NullPointerException}.</p>
 */
public interface Verifier {

    /**
     * A verifier over {@code config}'s roots and clock, on the engine for
     * this JVM: {@link Engine#endive()} on Java 11 and later, the server
     * engine ({@link Engine#server(ServerSource...)} with its default
     * sources) on Java 8. The choice depends on the JVM version alone.
     *
     * @throws NullPointerException          if {@code config} is null
     * @throws IllegalArgumentException      if {@code config} has no roots,
     *                                       since such a verifier would reject
     *                                       everything; or, unless
     *                                       {@link Config#runtimeProbe()} is
     *                                       off, if the verifier module refuses
     *                                       one of them
     * @throws IllegalStateException         if this artifact and the main
     *                                       {@code apple-purchase-receipt-verifier}
     *                                       artifact are both on the classpath;
     *                                       or, unless the probe is off, if the
     *                                       engine cannot run the verifier
     *                                       module here (for the server
     *                                       engine: no source worked, with
     *                                       each source's reason)
     */
    static Verifier create(Config config) {
        return create(config, Engine.forThisJvm());
    }

    /**
     * A verifier over {@code config}'s roots and clock, run by
     * {@code engine}.
     *
     * @throws NullPointerException          if {@code config} or
     *                                       {@code engine} is null
     * @throws IllegalArgumentException      as {@link #create(Config)}
     * @throws IllegalStateException         as {@link #create(Config)}, and
     *                                       when {@code engine} is
     *                                       {@link Engine#endive()} on a JVM
     *                                       older than Java 11
     */
    static Verifier create(Config config, Engine engine) {
        return Engine.createVerifier(config, engine);
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
