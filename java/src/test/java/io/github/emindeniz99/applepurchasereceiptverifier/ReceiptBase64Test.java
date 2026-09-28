package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.cert.TrustAnchor;
import java.util.Collections;
import org.junit.jupiter.api.Test;

/**
 * The spellings {@link StrictBase64#decode} must accept and refuse are the
 * decodeBase64 groups of {@code fixtures/cases.json}, which
 * {@code ConformanceCasesTest} runs against it and against the x5c decoder.
 * What stays here is the one input a JSON vector cannot hold: {@code null},
 * which the receipt entry point refuses before it reaches the decoder.
 */
class ReceiptBase64Test {

    @Test
    void nullIsInvalidReceiptFormat() {
        VerificationException thrown = assertThrows(
                VerificationException.class,
                () -> ReceiptCore.verify(null, Collections.<TrustAnchor>emptySet(), System.currentTimeMillis()));
        assertEquals(Reason.MALFORMED, thrown.reason());
    }
}
