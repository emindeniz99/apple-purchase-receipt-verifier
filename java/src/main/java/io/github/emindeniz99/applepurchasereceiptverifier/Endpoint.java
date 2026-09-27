package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import java.io.IOException;
import java.security.cert.TrustAnchor;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * {@link Verifier#verifyReceiptEndpoint}: a local stand-in for Apple's
 * deprecated verifyReceipt endpoint. Same request body, same response body,
 * same status codes, but verified offline against the pinned roots instead of
 * by calling Apple. Fields that exist only in Apple's server-side database,
 * such as {@code latest_receipt_info} and {@code pending_renewal_info}, are
 * not produced. Like Apple's endpoint, it checks no bundle id: the caller
 * compares {@code receipt.bundle_id}.
 *
 * <p>Status from the verification outcome, the same table in every port:
 * verified answers 0, or 21007 for a receipt that is not a production receipt
 * on {@link Environment#PRODUCTION} and 21008 for a production receipt on
 * {@link Environment#SANDBOX}; {@link Reason#MALFORMED} and
 * {@link Reason#TOO_LARGE} answer 21002; the chain, certificate and signature
 * reasons answer 21003; {@link Reason#UNREADABLE_PAYLOAD} and
 * {@link Reason#INTERNAL_ERROR} answer 21009. A receipt whose
 * {@code receipt_type} is missing or unknown counts as non-production.</p>
 */
final class Endpoint {

    /**
     * Ceiling on the request body, in UTF-8 bytes: 3 MiB, Apple's own limit.
     * Both of Apple's verifyReceipt endpoints answer a body of 3,145,728
     * bytes and send HTTP 413 for 3,145,729; this answers 21002 instead,
     * decided before any parsing. The body is measured without being
     * encoded, so a {@code String} of any size costs no copy to refuse.
     */
    static final int MAX_REQUEST_BYTES = 3145728;

    // Nothing inside the body can be larger than the body, and a body within
    // MAX_REQUEST_BYTES bytes is within it in characters too, so both length
    // bounds (counted in characters for String input) are MAX_REQUEST_BYTES.
    private static final JsonFactory JSON = BoundedJson.factory(MAX_REQUEST_BYTES);

    private Endpoint() {}

    static String respond(
            Environment environment, @Nullable String requestJson, Set<TrustAnchor> trustAnchors, CallClock clock) {
        int status;
        ReceiptPayload receipt = null;
        long requestDateMillis = 0;
        try {
            receipt = ReceiptCore.verify(receiptData(requestJson), trustAnchors, clock);
            status = status(environment, receipt);
            if (status == AppleStatus.OK) {
                requestDateMillis = clock.millis();
            }
        } catch (VerificationException e) {
            status = status(e.reason());
        } catch (RuntimeException e) {
            status = AppleStatus.INTERNAL_DATA_ACCESS_ERROR;
        }
        return EndpointResponse.render(status, environment, receipt, requestDateMillis);
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
     * The {@code receipt-data} string of a request body. A body over
     * {@link #MAX_REQUEST_BYTES} is TOO_LARGE; a body that is not a JSON
     * object (unparseable, empty, {@code null}, an array, a scalar) or nests
     * deeper than 64, and a {@code receipt-data} that is missing or not a
     * string, are MALFORMED. Apple has no status for "that wasn't JSON";
     * 21002 is the closest, and it is what a JSON object without usable
     * {@code receipt-data} gets anyway.
     *
     * <p>The whole object is read, so a body that breaks after
     * {@code receipt-data} is still refused, and the last
     * {@code receipt-data} wins, as it would in a map. Anything after the
     * object is not read. {@code password} and
     * {@code exclude-old-transactions} are read and ignored.</p>
     *
     * <p>The parser reads the body from one char array. Given a
     * {@code String} longer than 32,768 characters, Jackson wraps it in a
     * StringReader and reads it in chunks, and a string value longer than a
     * chunk goes through its slow character-at-a-time path;
     * {@code receipt-data} is such a value for any receipt with more than a
     * handful of purchases, and reading it that way took longer than
     * decoding it.</p>
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
        boolean isString = false;
        try (JsonParser parser = JSON.createParser(requestJson.toCharArray())) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                throw new VerificationException(Reason.MALFORMED, "request body is not a JSON object");
            }
            while (parser.nextToken() == JsonToken.FIELD_NAME) {
                String name = parser.currentName();
                JsonToken value = parser.nextToken();
                if ("receipt-data".equals(name)) {
                    isString = value == JsonToken.VALUE_STRING;
                    receiptData = isString ? parser.getText() : null;
                }
                parser.skipChildren();
            }
        } catch (IOException | RuntimeException e) {
            // What the parser throws unchecked is still a body it could not
            // read: MALFORMED, never the 21009 an unexpected exception gets.
            throw new VerificationException(Reason.MALFORMED, "request body is not valid JSON", e);
        }
        if (!isString || receiptData == null) {
            throw new VerificationException(Reason.MALFORMED, "receipt-data is missing or not a string");
        }
        return receiptData;
    }
}
