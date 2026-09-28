package io.github.emindeniz99.applepurchasereceiptverifier.fuzz;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import java.nio.charset.StandardCharsets;

/**
 * {@code Verifier.verifyReceiptEndpoint} on a raw request body, the bytes an
 * HTTP framework would hand straight through.
 *
 * <p>Its javadoc says it never throws and its response shape is Apple's, so
 * the invariant here is: nothing escapes at all, and the answer is always a
 * JSON object whose first member is a numeric {@code status}, never 21009.
 * That status means an unexpected runtime exception inside the pipeline, or
 * content a trusted signer signed that the library cannot read; a fuzzer
 * cannot forge a trusted signature, so for fuzz input it can only be the
 * first, and that is a bug. The response is read back with jackson-core, the
 * one Jackson artifact on the library's runtime classpath.
 */
public final class FuzzEndpointJson {

    private FuzzEndpointJson() {}

    private static final JsonFactory JSON = new JsonFactory();

    public static void fuzzerTestOneInput(byte[] data) {
        String body = new String(data, StandardCharsets.UTF_8);
        for (Environment environment : Environment.values()) {
            String response;
            try {
                response = Harness.RECEIPTS.verifyReceiptEndpoint(environment, body);
            } catch (Throwable t) {
                throw Harness.leaked("verifyReceiptEndpoint", t);
            }
            if (response == null) {
                throw new AssertionError("verifyReceiptEndpoint returned null");
            }
            int status = status(response);
            if (status == 21009) {
                throw new AssertionError("verifyReceiptEndpoint answered 21009 for fuzz input: " + response);
            }
        }
    }

    /** The leading {@code status} of a response that must be one complete JSON object. */
    private static int status(String response) {
        try (JsonParser parser = JSON.createParser(response)) {
            if (parser.nextToken() != JsonToken.START_OBJECT
                    || parser.nextToken() != JsonToken.FIELD_NAME
                    || !"status".equals(parser.currentName())
                    || parser.nextToken() != JsonToken.VALUE_NUMBER_INT) {
                throw new AssertionError("the answer does not start with a numeric status: " + response);
            }
            int status = parser.getIntValue();
            parser.skipChildren();
            JsonToken token;
            while ((token = parser.nextToken()) != JsonToken.END_OBJECT) {
                if (token == null) {
                    throw new AssertionError("the answer ends inside its object: " + response);
                }
                parser.nextToken();
                parser.skipChildren();
            }
            if (parser.nextToken() != null) {
                throw new AssertionError("the answer carries something after its object: " + response);
            }
            return status;
        } catch (java.io.IOException e) {
            throw new AssertionError("the answer is not JSON: " + response, e);
        }
    }
}
