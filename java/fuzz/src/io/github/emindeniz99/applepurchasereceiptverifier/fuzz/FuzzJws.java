package io.github.emindeniz99.applepurchasereceiptverifier.fuzz;

import io.github.emindeniz99.applepurchasereceiptverifier.JsonPayload;
import java.nio.charset.StandardCharsets;

/**
 * {@code Verifier.verifySignedData} on one compact JWS string: the strict
 * base64url reader, the streaming header and payload reads, the x5c
 * certificate decode, the marker-OID checks, the PKIX chain validation and
 * the ES256 signature check.
 *
 * <p>The trusted root is the fixture JWS root, so the generated {@code .jws}
 * fixtures verify and mutations explore past the chain check rather than
 * bouncing off it.
 */
public final class FuzzJws {

    private FuzzJws() {}

    public static void fuzzerTestOneInput(byte[] data) {
        String jws = new String(data, StandardCharsets.ISO_8859_1);

        JsonPayload payload = Harness.attempt("verifySignedData", () -> Harness.JWS.verifySignedData(jws));
        if (payload == null) {
            return;
        }
        Harness.touch(payload);

        // ANCHOR-SET INVARIANT. verifySignedData checks no claim at all, so an
        // acceptance is a pure cryptographic verdict, and it must not survive
        // swapping the trust anchors for Apple's production roots, which
        // signed nothing in this repository.
        JsonPayload underApple =
                Harness.attempt("verifySignedData(Apple roots)", () -> Harness.APPLE.verifySignedData(jws));
        if (underApple != null) {
            throw new AssertionError(
                    "a JWS accepted under the fixture JWS root was also accepted under Apple's production roots");
        }
    }
}
