package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import org.junit.jupiter.api.Test;

/**
 * Compile-checks the "Testing with synthetic receipts" example in
 * java/README.md against the public {@link TestPki} surface: if this stops
 * compiling or passing, the README example is wrong. Uses only the members
 * a test-jar consumer has (see the table in that README section), never
 * {@code TestPki}'s package-private fixture machinery.
 */
class ReadmeSyntheticReceiptExampleTest {

    @Test
    void verifiesASyntheticReceipt() throws Exception {
        // The receipt's own creation date pins the chain-validity instant, so
        // the fixed clock below just has to be an instant TestPki.receipt()'s
        // one-year chain actually covers: "now" always is.
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);

        TestPki pki = TestPki.receipt();
        byte[] payload = TestPki.receiptPayload(
                "com.example.app",
                "1.0",
                new byte[] {1, 2, 3, 4},
                new byte[] {5, 6, 7, 8},
                now.toString(),
                Collections.<byte[]>emptyList());
        String receiptBase64 = Base64.getEncoder().encodeToString(pki.signReceipt(payload));

        Config config = Config.builder()
                .roots(Collections.singleton(pki.root))
                .clock(Clock.fixed(now, ZoneOffset.UTC))
                .build();
        Verifier verifier = Verifier.create(config);

        VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(receiptBase64);
        assertTrue(result.verified());
        assertEquals("com.example.app", result.payload().bundleId());
    }
}
