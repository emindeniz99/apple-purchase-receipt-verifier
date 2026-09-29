package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadFeature;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Reads the module's answers (aprv-wire, ARCHITECTURE.md §4) into the API's
 * types. This is decoding, not verification: the module has decided, and
 * this class only moves its values into Java objects. Anything that does not
 * follow the wire format exactly (a missing or unknown key, a wrong type, a
 * reason this library does not know, trailing text) is a {@link GuestFailure},
 * never a verdict.
 *
 * <ul>
 *   <li>{@code init}: {@code {"ok":true}} or {@code {"ok":false,"message":"..."}}.</li>
 *   <li>{@code verify-receipt}: {@code {"verified":true,"payload":<ReceiptPayload>}},
 *       the payload in 0.7's "Our JSON" (docs/design/0.7-api.md).</li>
 *   <li>{@code verify-signed-data}: {@code {"verified":true,"payload":"<the signed JSON>"}}.</li>
 *   <li>Either failure: {@code {"verified":false,"reason":"<Reason>","message":"..."}}.</li>
 *   <li>{@code verify-receipt-endpoint}: Apple's response JSON, passed through.</li>
 * </ul>
 *
 * <p>Messages name the key that broke the format and never quote a value,
 * since values come from the input.</p>
 */
final class Wire {

    private Wire() {}

    /** Stands for a JSON {@code null} inside the parsed tree. */
    private static final Object NULL = new Object();

    private static final JsonFactory JSON = JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .build();

    /**
     * @throws InitRefused  when the module answered {@code {"ok":false}}
     * @throws GuestFailure when the answer is not an {@code init} answer
     */
    static void initAnswer(String answer) {
        Map<String, Object> object = object(parse(answer), "init answer");
        Object ok = object.get("ok");
        if (Boolean.TRUE.equals(ok) && object.size() == 1) {
            return;
        }
        if (Boolean.FALSE.equals(ok) && object.size() == 2 && object.get("message") instanceof String) {
            throw new InitRefused((String) object.get("message"));
        }
        throw malformed("init answer");
    }

    static VerificationResult<ReceiptPayload> receiptAnswer(String answer) {
        Map<String, Object> object = object(parse(answer), "verify-receipt answer");
        if (verified(object, "verify-receipt answer")) {
            return VerificationResult.of(receipt(object(object.get("payload"), "payload")));
        }
        return VerificationResult.failed(failure(object, "verify-receipt answer"));
    }

    static VerificationResult<JsonPayload> signedDataAnswer(String answer) {
        Map<String, Object> object = object(parse(answer), "verify-signed-data answer");
        if (verified(object, "verify-signed-data answer")) {
            Object payload = object.get("payload");
            if (!(payload instanceof String)) {
                throw malformed("payload");
            }
            return VerificationResult.of(new JsonPayload((String) payload));
        }
        return VerificationResult.failed(failure(object, "verify-signed-data answer"));
    }

    /** Apple's response JSON, unchanged; only an empty answer is refused. */
    static String endpointAnswer(String answer) {
        if (answer.isEmpty()) {
            throw malformed("verify-receipt-endpoint answer");
        }
        return answer;
    }

    // ------------------------------------------------------------ the envelope

    /** True for {"verified":true,"payload":...}; false for a well-formed failure. */
    private static boolean verified(Map<String, Object> object, String what) {
        Object verified = object.get("verified");
        if (Boolean.TRUE.equals(verified)) {
            keys(object, what, "verified", "payload");
            return true;
        }
        if (Boolean.FALSE.equals(verified)) {
            keys(object, what, "verified", "reason", "message");
            return false;
        }
        throw malformed(what + " \"verified\"");
    }

    private static Failure failure(Map<String, Object> object, String what) {
        Object reason = object.get("reason");
        Object message = object.get("message");
        if (!(reason instanceof String) || !(message instanceof String)) {
            throw malformed(what);
        }
        for (Reason known : Reason.values()) {
            if (known.name().equals(reason)) {
                return new Failure(known, (String) message, null);
            }
        }
        throw malformed(what + " \"reason\" (not one of the 0.7 reasons)");
    }

    // ------------------------------------------------------------ the receipt

    private static final String[] RECEIPT_KEYS = {
        "receipt_type",
        "app_item_id",
        "bundle_id",
        "bundle_id_bytes",
        "application_version",
        "opaque_value",
        "sha1_hash",
        "receipt_creation_date_ms",
        "download_id",
        "version_external_identifier",
        "in_app",
        "original_purchase_date_ms",
        "original_application_version",
        "expiration_date_ms",
        "unknown_attributes"
    };

    private static final String[] PURCHASE_KEYS = {
        "quantity",
        "product_id",
        "transaction_id",
        "purchase_date_ms",
        "original_transaction_id",
        "original_purchase_date_ms",
        "expires_date_ms",
        "web_order_line_item_id",
        "cancellation_date_ms",
        "is_trial_period",
        "is_in_intro_offer_period",
        "unknown_attributes"
    };

    private static ReceiptPayload receipt(Map<String, Object> m) {
        keys(m, "payload", RECEIPT_KEYS);
        Object purchases = m.get("in_app");
        if (!(purchases instanceof List)) {
            throw malformed("payload \"in_app\"");
        }
        List<InAppPurchase> inApp = new ArrayList<>();
        for (Object purchase : (List<?>) purchases) {
            inApp.add(purchase(object(purchase, "in_app element")));
        }
        return new ReceiptPayload(
                string(m, "receipt_type"),
                id(m, "app_item_id"),
                string(m, "bundle_id"),
                bytes(m, "bundle_id_bytes"),
                string(m, "application_version"),
                bytes(m, "opaque_value"),
                bytes(m, "sha1_hash"),
                number(m, "receipt_creation_date_ms"),
                id(m, "download_id"),
                id(m, "version_external_identifier"),
                inApp,
                number(m, "original_purchase_date_ms"),
                string(m, "original_application_version"),
                number(m, "expiration_date_ms"),
                attributes(m));
    }

    private static InAppPurchase purchase(Map<String, Object> m) {
        keys(m, "in_app element", PURCHASE_KEYS);
        return new InAppPurchase(
                number(m, "quantity"),
                string(m, "product_id"),
                string(m, "transaction_id"),
                number(m, "purchase_date_ms"),
                string(m, "original_transaction_id"),
                number(m, "original_purchase_date_ms"),
                number(m, "expires_date_ms"),
                id(m, "web_order_line_item_id"),
                number(m, "cancellation_date_ms"),
                bool(m, "is_trial_period"),
                bool(m, "is_in_intro_offer_period"),
                attributes(m));
    }

    /** {@code {"13": ["<base64>", ...]}}: decimal types, values in receipt order. */
    private static Map<Integer, List<byte[]>> attributes(Map<String, Object> m) {
        Map<String, Object> object = object(m.get("unknown_attributes"), "\"unknown_attributes\"");
        Map<Integer, List<byte[]>> attributes = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : object.entrySet()) {
            int type;
            try {
                type = Integer.parseInt(entry.getKey());
            } catch (NumberFormatException e) {
                throw malformed("\"unknown_attributes\" key");
            }
            if (!Integer.toString(type).equals(entry.getKey()) || !(entry.getValue() instanceof List)) {
                throw malformed("\"unknown_attributes\" entry");
            }
            List<byte[]> values = new ArrayList<>();
            for (Object value : (List<?>) entry.getValue()) {
                if (!(value instanceof String)) {
                    throw malformed("\"unknown_attributes\" value");
                }
                values.add(base64((String) value, "\"unknown_attributes\" value"));
            }
            attributes.put(type, values);
        }
        return attributes;
    }

    // ------------------------------------------------------------ one value

    private static @Nullable String string(Map<String, Object> m, String key) {
        Object value = m.get(key);
        if (value == NULL) {
            return null;
        }
        if (!(value instanceof String)) {
            throw malformed("\"" + key + "\"");
        }
        return (String) value;
    }

    /** A 64-bit id, which the wire writes as a decimal string. */
    private static @Nullable Long id(Map<String, Object> m, String key) {
        String text = string(m, key);
        if (text == null) {
            return null;
        }
        try {
            long id = Long.parseLong(text);
            if (!Long.toString(id).equals(text)) {
                throw malformed("\"" + key + "\"");
            }
            return id;
        } catch (NumberFormatException e) {
            throw malformed("\"" + key + "\"");
        }
    }

    /** A JSON integer that fits a long: dates in epoch milliseconds, the quantity. */
    private static @Nullable Long number(Map<String, Object> m, String key) {
        Object value = m.get(key);
        if (value == NULL) {
            return null;
        }
        if (!(value instanceof Long)) {
            throw malformed("\"" + key + "\"");
        }
        return (Long) value;
    }

    private static @Nullable Boolean bool(Map<String, Object> m, String key) {
        Object value = m.get(key);
        if (value == NULL) {
            return null;
        }
        if (!(value instanceof Boolean)) {
            throw malformed("\"" + key + "\"");
        }
        return (Boolean) value;
    }

    private static byte @Nullable [] bytes(Map<String, Object> m, String key) {
        String text = string(m, key);
        return text == null ? null : base64(text, "\"" + key + "\"");
    }

    /** Padded standard base64, as the wire writes bytes. */
    private static byte[] base64(String text, String what) {
        if (text.length() % 4 != 0) {
            throw malformed(what);
        }
        try {
            return Base64.getDecoder().decode(text);
        } catch (IllegalArgumentException e) {
            throw malformed(what);
        }
    }

    /** Exactly {@code expected}, no more and no fewer: the wire writes a missing value as null. */
    private static void keys(Map<String, Object> object, String what, String... expected) {
        if (object.size() != expected.length) {
            throw malformed(what + " (keys)");
        }
        for (String key : expected) {
            if (!object.containsKey(key)) {
                throw malformed(what + " (no \"" + key + "\")");
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(@Nullable Object value, String what) {
        if (!(value instanceof Map)) {
            throw malformed(what);
        }
        return (Map<String, Object>) value;
    }

    private static GuestFailure malformed(String what) {
        return new GuestFailure("the verifier module's answer does not follow the wire format: " + what);
    }

    // ------------------------------------------------------------ JSON

    /** One JSON value and nothing after it, as maps, lists, strings, longs, booleans and {@link #NULL}. */
    private static Object parse(String text) {
        try (JsonParser parser = JSON.createParser(text)) {
            JsonToken first = parser.nextToken();
            if (first == null) {
                throw malformed("empty answer");
            }
            Object value = value(parser, first);
            if (parser.nextToken() != null) {
                throw malformed("text after the answer");
            }
            return value;
        } catch (IOException e) {
            throw new GuestFailure(
                    "the verifier module's answer is not JSON: " + e.getClass().getName(), e);
        }
    }

    private static Object value(JsonParser parser, @Nullable JsonToken token) throws IOException {
        if (token == null) {
            throw malformed("the answer ends early");
        }
        switch (token) {
            case START_OBJECT: {
                Map<String, Object> object = new LinkedHashMap<>();
                while (parser.nextToken() == JsonToken.FIELD_NAME) {
                    String name = parser.currentName();
                    object.put(name, value(parser, parser.nextToken()));
                }
                return Collections.unmodifiableMap(object);
            }
            case START_ARRAY: {
                List<Object> array = new ArrayList<>();
                JsonToken next;
                while ((next = parser.nextToken()) != JsonToken.END_ARRAY) {
                    array.add(value(parser, next));
                }
                return Collections.unmodifiableList(array);
            }
            case VALUE_STRING:
                return parser.getText();
            case VALUE_NUMBER_INT: {
                Number number = parser.getNumberValue();
                if (number instanceof BigInteger) {
                    throw malformed("a number beyond 64 bits");
                }
                return number.longValue();
            }
            case VALUE_TRUE:
                return Boolean.TRUE;
            case VALUE_FALSE:
                return Boolean.FALSE;
            case VALUE_NULL:
                return NULL;
            default:
                // A fraction or an exponent: the wire writes neither.
                throw malformed("a " + token + " token");
        }
    }
}
