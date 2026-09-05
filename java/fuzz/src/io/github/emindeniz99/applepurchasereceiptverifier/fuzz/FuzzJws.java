package io.github.emindeniz99.applepurchasereceiptverifier.fuzz;

import io.github.emindeniz99.applepurchasereceiptverifier.jws.AppTransactionPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.TransactionPayload;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * All three StoreKit 2 entry points on one compact JWS string: the strict
 * base64url reader, the Jackson header and payload parse, the x5c certificate
 * decode, the marker-OID checks, the PKIX chain build and the ES256 signature
 * check — plus the two typed payload bindings on top of them.
 *
 * <p>The trusted root is the fixture JWS root, so the generated {@code .jws}
 * fixtures verify and mutations explore past the chain check rather than
 * bouncing off it.
 */
public final class FuzzJws {

    private FuzzJws() {}

    public static void fuzzerTestOneInput(byte[] data) {
        String jws = new String(data, StandardCharsets.ISO_8859_1);

        TransactionPayload transaction =
                Harness.attempt("verifyTransaction", () -> Harness.JWS_VERIFIER.verifyTransaction(jws));
        if (transaction != null) {
            Harness.touch(transaction);
        }
        AppTransactionPayload appTransaction =
                Harness.attempt("verifyAppTransaction", () -> Harness.JWS_VERIFIER.verifyAppTransaction(jws));
        if (appTransaction != null) {
            Harness.touch(appTransaction);
        }

        Map<String, Object> claims = Harness.attempt("verifyRaw", () -> Harness.JWS_VERIFIER.verifyRaw(jws));
        if (claims == null) {
            return;
        }
        Harness.touch(claims);

        // ANCHOR-SET INVARIANT. verifyRaw is the one of the three that checks
        // no claim at all, so an acceptance here is a pure cryptographic
        // verdict — and it must not survive swapping the trust anchors for
        // Apple's production JWS roots, which signed nothing in this
        // repository.
        Map<String, Object> underApple =
                Harness.attempt("verifyRaw(Apple JWS roots)", () -> Harness.APPLE_JWS_VERIFIER.verifyRaw(jws));
        if (underApple != null) {
            throw new AssertionError(
                    "a JWS accepted under the fixture JWS root was also accepted under Apple's production JWS roots");
        }
    }
}
