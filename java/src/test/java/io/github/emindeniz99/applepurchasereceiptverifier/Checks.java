package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Arrays;
import java.util.Base64;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;

/**
 * Test shorthand over the public {@link Verifier}, and the helpers several
 * tests share.
 *
 * <p>{@link #unwrap} turns a failed {@link VerificationResult} back into the
 * package's {@link VerificationException}, carrying the failure's reason,
 * message and cause, so a test can state a refusal as
 * {@code assertThrows(...); assertEquals(Reason.X, e.reason())}. The public
 * contract that nothing throws is pinned separately, in
 * {@code VerifierApiTest}.</p>
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

    /** {@code count} copies of {@code c}: Java 8, the artifact's floor, has no {@code String.repeat}. */
    static String repeat(char c, int count) {
        char[] chars = new char[count];
        Arrays.fill(chars, c);
        return new String(chars);
    }

    /** {@code innermost} inside {@code depth} objects, each its one member {@code "a"}. */
    static String nested(int depth, String innermost) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            out.append("{\"a\":");
        }
        out.append(innermost);
        for (int i = 0; i < depth; i++) {
            out.append('}');
        }
        return out.toString();
    }

    /** One receipt attribute whose value is the DER of {@code value}. */
    static ASN1Encodable integerAttribute(int type, long value) throws Exception {
        return TestPki.attribute(type, new ASN1Integer(value).getEncoded());
    }
}
