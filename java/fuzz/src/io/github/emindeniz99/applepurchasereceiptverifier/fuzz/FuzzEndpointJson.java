package io.github.emindeniz99.applepurchasereceiptverifier.fuzz;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;

/**
 * {@code VerifyReceiptEndpoint.verifyReceiptJson} on a raw request body — the
 * bytes an HTTP framework would hand straight through.
 *
 * <p>Its javadoc says "never throws" and its response shape is Apple's, so the
 * invariant here is stronger than the other targets': not "only a
 * {@code VerificationException} escapes" but "nothing escapes at all, and the
 * answer is always a JSON object carrying a numeric {@code status}". A body
 * that produced a bare stack trace, a null, or a response Jackson cannot read
 * back would each end the run.
 */
public final class FuzzEndpointJson {

    private FuzzEndpointJson() {}

    public static void fuzzerTestOneInput(byte[] data) {
        String body = new String(data, StandardCharsets.UTF_8);

        String response;
        try {
            response = Harness.ENDPOINT.verifyReceiptJson(body);
        } catch (Throwable t) {
            throw Harness.leaked("verifyReceiptJson", t);
        }
        if (response == null) {
            throw new AssertionError("verifyReceiptJson returned null");
        }

        JsonNode answer;
        try {
            answer = Harness.MAPPER.readTree(response);
        } catch (Exception e) {
            throw new AssertionError("verifyReceiptJson answered something that is not JSON: " + response, e);
        }
        if (answer == null || !answer.isObject()) {
            throw new AssertionError("verifyReceiptJson answered a non-object: " + response);
        }
        JsonNode status = answer.get("status");
        if (status == null || !status.isNumber()) {
            throw new AssertionError("verifyReceiptJson answered without a numeric status: " + response);
        }
    }
}
