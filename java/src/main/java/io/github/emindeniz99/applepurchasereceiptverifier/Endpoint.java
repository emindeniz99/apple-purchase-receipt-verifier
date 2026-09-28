package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.io.IOException;
import java.security.cert.TrustAnchor;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * {@link Verifier#verifyReceiptEndpoint}: Apple's verifyReceipt request and
 * response, verified offline. The status table is docs/design/0.7-api.md's.
 */
final class Endpoint {

    /** Apple's own limit, in UTF-8 bytes (it answers HTTP 413 above it); this answers 21002. */
    static final int MAX_REQUEST_BYTES = 3145728;

    static final JsonFactory JSON = BoundedJson.factory(MAX_REQUEST_BYTES);

    private Endpoint() {}

    static String respond(
            Environment environment, @Nullable String requestJson, Set<TrustAnchor> trustAnchors, long now) {
        int status;
        ReceiptPayload receipt = null;
        try {
            receipt = ReceiptCore.verify(receiptData(requestJson), trustAnchors, now);
            status = status(environment, receipt);
        } catch (VerificationException e) {
            status = status(e.reason());
        } catch (RuntimeException e) {
            status = AppleStatus.INTERNAL_DATA_ACCESS_ERROR;
        }
        return EndpointResponse.render(status, environment, receipt, now);
    }

    static int status(Reason reason) {
        switch (reason) {
            case MALFORMED:
            case TOO_LARGE:
                return AppleStatus.MALFORMED_RECEIPT_DATA;
            case INVALID_SIGNATURE:
            case UNTRUSTED_CHAIN:
            case INVALID_CERTIFICATE:
            case INVALID_CERTIFICATE_PURPOSE:
                return AppleStatus.RECEIPT_NOT_AUTHENTICATED;
            default:
                return AppleStatus.INTERNAL_DATA_ACCESS_ERROR;
        }
    }

    private static int status(Environment environment, ReceiptPayload receipt) {
        boolean productionReceipt = Environment.fromReceiptType(receipt.receiptType()) == Environment.PRODUCTION;
        if (environment == Environment.PRODUCTION && !productionReceipt) {
            return AppleStatus.SANDBOX_RECEIPT_ON_PRODUCTION;
        }
        if (environment == Environment.SANDBOX && productionReceipt) {
            return AppleStatus.PRODUCTION_RECEIPT_ON_SANDBOX;
        }
        return AppleStatus.OK;
    }

    /**
     * The {@code receipt-data} string of a request body: TOO_LARGE over the
     * cap, MALFORMED when the body is not a JSON object or
     * {@code receipt-data} is missing or not a string. The whole object is
     * read and the last {@code receipt-data} wins; nothing after it is read.
     */
    static String receiptData(@Nullable String requestJson) throws VerificationException {
        if (requestJson == null) {
            throw new VerificationException(Reason.MALFORMED, "request body is empty");
        }
        if (Utf8Length.exceeds(requestJson, MAX_REQUEST_BYTES)) {
            throw new VerificationException(
                    Reason.TOO_LARGE, "request body exceeds the maximum of " + MAX_REQUEST_BYTES + " bytes");
        }
        String receiptData = null;
        // One char array: Jackson reads a long String in chunks, and a long value in them slowly.
        try (JsonParser parser = JSON.createParser(requestJson.toCharArray())) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                throw new VerificationException(Reason.MALFORMED, "request body is not a JSON object");
            }
            while (parser.nextToken() == JsonToken.FIELD_NAME) {
                String name = parser.currentName();
                JsonToken value = parser.nextToken();
                if ("receipt-data".equals(name)) {
                    receiptData = value == JsonToken.VALUE_STRING ? parser.getText() : null;
                }
                parser.skipChildren();
            }
        } catch (IOException | RuntimeException e) {
            // What the parser throws unchecked is still a body it could not
            // read: MALFORMED, never the 21009 an unexpected exception gets.
            throw new VerificationException(Reason.MALFORMED, "request body is not valid JSON", e);
        }
        if (receiptData == null) {
            throw new VerificationException(Reason.MALFORMED, "receipt-data is missing or not a string");
        }
        return receiptData;
    }
}
