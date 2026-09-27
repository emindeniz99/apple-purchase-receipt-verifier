import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.Failure;
import io.github.emindeniz99.applepurchasereceiptverifier.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationResult;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

/**
 * Smoke-tests the jar as published to Maven Central. Everything it touches —
 * the verifier, the result types, the bundled root certificates — comes from
 * the resolved artifact, so a jar missing its resources fails here rather than
 * in a user's build.
 */
public final class Smoke {
    public static void main(String[] args) throws Exception {
        String receiptB64 = Files.readString(Path.of("receipt-sandbox-g5.b64"), StandardCharsets.US_ASCII).trim();

        // Config.defaults() throws if the bundled roots are missing or fail
        // their pinned fingerprints; the count catches a jar that lost one.
        Config config = Config.defaults();
        if (config.roots().size() != 3) {
            throw new AssertionError("expected three bundled Apple roots, got " + config.roots().size());
        }
        Verifier verifier = Verifier.create(config);

        // A real Apple-signed receipt against the real pinned root: exercises
        // the packaged certs, the DER reader, the chain build and the signature.
        VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(receiptB64);
        ReceiptPayload receipt = result.payload();
        if (receipt == null) {
            throw new AssertionError("verification failed: " + result.failure());
        }
        if (!"ProductionSandbox".equals(receipt.receiptType())) {
            throw new AssertionError("receiptType was " + receipt.receiptType());
        }
        if (!"dev.bonzer.weeka.app".equals(receipt.bundleId())) {
            throw new AssertionError("bundleId was " + receipt.bundleId());
        }

        // And the negative direction, so a verifier that accepted everything
        // would fail here too: the same receipt with one bit flipped in its
        // signature, the byte 128 from the end of the DER (BENCHMARKS.md).
        byte[] der = Base64.getDecoder().decode(receiptB64);
        der[der.length - 128] ^= 0x01;
        Failure failure = verifier.verifyReceipt(Base64.getEncoder().encodeToString(der)).failure();
        if (failure == null || failure.reason() != Reason.INVALID_SIGNATURE) {
            throw new AssertionError("a tampered signature was not rejected as INVALID_SIGNATURE: "
                    + (failure == null ? "verified" : failure.reason()));
        }

        System.out.printf("maven: published jar verified a genuine Apple receipt (%s, %d purchases)"
                + " and rejected a tampered signature%n", receipt.bundleId(), receipt.inApp().size());
    }
}
