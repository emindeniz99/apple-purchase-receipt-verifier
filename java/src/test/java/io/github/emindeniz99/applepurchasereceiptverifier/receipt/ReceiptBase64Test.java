package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import org.junit.jupiter.api.Test;

/**
 * The spellings {@link ReceiptBase64#decode} must accept and refuse are the
 * decodeBase64 groups of {@code fixtures/cases.json}, which
 * {@code ConformanceCasesTest} runs against it and against the x5c decoder.
 * What stays here is the one input a JSON vector cannot hold: {@code null}.
 */
class ReceiptBase64Test {

    @Test
    void nullIsInvalidReceiptFormat() {
        VerificationException thrown = assertThrows(VerificationException.class, () -> ReceiptBase64.decode(null));
        assertEquals(Reason.INVALID_RECEIPT_FORMAT, thrown.reason());
    }
}
