package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Arrays;
import java.util.Base64;

/**
 * Test shorthand over the public {@link Verifier}.
 *
 * <p>{@link #unwrap} turns a failed {@link VerificationResult} back into the
 * package's {@link VerificationException}, carrying the failure's reason,
 * message and cause. That keeps the security suites written against 0.6 in
 * their {@code assertThrows(...); assertEquals(Reason.X, e.reason())} shape,
 * so each migrated assertion still says exactly what it said before; only
 * the call it wraps changed. The public contract that nothing throws is
 * pinned separately, in {@code VerifierApiTest}.</p>
 */
final class Checks {

    private Checks() {}

    static Verifier verifier(X509Certificate... roots) {
        return Verifier.create(Config.builder().roots(Arrays.asList(roots)).build());
    }

    static Verifier verifier(TestPki pki) {
        return verifier(pki.root);
    }

    static Verifier verifier(Clock clock, X509Certificate... roots) {
        return Verifier.create(
                Config.builder().roots(Arrays.asList(roots)).clock(clock).build());
    }

    /** {@code verifier.verifyReceipt} over the base64 of {@code der}, unwrapped. */
    static ReceiptPayload receipt(Verifier verifier, byte[] der) throws VerificationException {
        return unwrap(verifier.verifyReceipt(Base64.getEncoder().encodeToString(der)));
    }

    static ReceiptPayload receipt(Verifier verifier, String base64) throws VerificationException {
        return unwrap(verifier.verifyReceipt(base64));
    }

    static JsonPayload signedData(Verifier verifier, String jws) throws VerificationException {
        return unwrap(verifier.verifySignedData(jws));
    }

    /** The payload of a verified result, or the failure thrown back as a {@link VerificationException}. */
    static <T> T unwrap(VerificationResult<T> result) throws VerificationException {
        T payload = result.payload();
        if (payload != null) {
            if (result.failure() != null) {
                throw new AssertionError("a verified result also carries a failure");
            }
            return payload;
        }
        Failure failure = result.failure();
        if (failure == null) {
            throw new AssertionError("a result carries neither a payload nor a failure");
        }
        throw new VerificationException(failure.reason(), failure.message(), failure.cause());
    }
}
