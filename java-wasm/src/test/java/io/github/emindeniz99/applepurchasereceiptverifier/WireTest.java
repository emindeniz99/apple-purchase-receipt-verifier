package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The decoding of the module's answers (aprv-wire), without the module: the
 * receipt payloads fixtures/cases.json pins as {@code toJson} values are
 * wrapped the way the module writes them, decoded, and must come back as the
 * same value. Anything off the wire format is a {@link GuestFailure}, never
 * a verdict.
 */
class WireTest {

    @Test
    void everyPinnedReceiptPayloadRoundTripsThroughTheDecoder() throws Exception {
        int checked = 0;
        for (JsonNode kase : Cases.document().get("cases")) {
            JsonNode expected = kase.get("expected");
            if (!expected.has("toJson")) {
                continue;
            }
            String payload = expected.get("toJson").asText();
            JsonNode environment = expected.get("environment");
            VerificationResult<ReceiptPayload> result = Wire.receiptAnswer(
                    "{\"verified\":true,\"payload\":" + payload + ",\"environment\":" + environment + "}");
            ReceiptPayload decoded = result.payload();
            assertTrue(decoded != null, kase.get("id").asText());
            assertEquals(
                    Cases.MAPPER.readTree(payload),
                    Cases.MAPPER.readTree(decoded.toJson()),
                    kase.get("id").asText());
            assertEquals(
                    environment.isNull() ? null : environment.asText(),
                    decoded.environment() == null ? null : decoded.environment().value(),
                    kase.get("id").asText());
            checked++;
        }
        assertTrue(checked > 0, "no case pins a toJson value");
    }

    @Test
    void aSignedPayloadIsTheStringTheModuleReturned() {
        String signed = "{\"b\":1, \"a\":\"\\u00e9\"}";
        VerificationResult<JsonPayload> result = Wire.signedDataAnswer(
                "{\"verified\":true,\"payload\":" + quote(signed) + ",\"environment\":\"Sandbox\"}");
        assertEquals(signed, result.payload().json());
        assertEquals(Environment.SANDBOX, result.payload().environment());
        assertEquals(
                Environment.PRODUCTION,
                Wire.signedDataAnswer("{\"verified\":true,\"payload\":\"{}\",\"environment\":\"Production\"}")
                        .payload()
                        .environment());
        assertNull(Wire.signedDataAnswer("{\"verified\":true,\"payload\":\"{}\",\"environment\":null}")
                .payload()
                .environment());
    }

    /**
     * The environment is the module's answer, refused like a missing payload
     * when it is absent or not one of Apple's two spellings or null: a module
     * that does not state it is older than this library.
     */
    @Test
    void aVerifiedAnswerWithoutAnEnvironmentIsAModuleFailure() {
        for (String environment : new String[] {
            "",
            ",\"environment\":\"sandbox\"",
            ",\"environment\":\"Xcode\"",
            ",\"environment\":1",
            ",\"environment\":\"Sandbox\",\"environment\":null"
        }) {
            String answer = "{\"verified\":true,\"payload\":\"{}\"" + environment + "}";
            assertThrows(GuestFailure.class, () -> Wire.signedDataAnswer(answer), answer);
        }
    }

    @Test
    void failuresCarryTheReasonAndMessageAndNoCause() {
        for (Reason reason : Reason.values()) {
            String answer = "{\"verified\":false,\"reason\":\"" + reason.name() + "\",\"message\":\"why\"}";
            Failure receipt = Wire.receiptAnswer(answer).failure();
            Failure jws = Wire.signedDataAnswer(answer).failure();
            assertEquals(new Failure(reason, "why", null), receipt);
            assertEquals(new Failure(reason, "why", null), jws);
            assertNull(receipt.cause());
        }
    }

    @Test
    void initAnswers() {
        assertEquals(3_145_729, Wire.initAnswer("{\"ok\":true,\"max_input_bytes\":3145729}"));
        assertEquals(1, Wire.initAnswer("{\"max_input_bytes\":1,\"ok\":true}"));
        InitRefused refused =
                assertThrows(InitRefused.class, () -> Wire.initAnswer("{\"ok\":false,\"message\":\"no root\"}"));
        assertEquals("no root", refused.getMessage());
        for (String bad : new String[] {
            "",
            "{}",
            "{\"ok\":1}",
            "{\"ok\":true}", // a module older than this library
            "{\"ok\":true,\"x\":1}",
            "{\"ok\":true,\"max_input_bytes\":0}",
            "{\"ok\":true,\"max_input_bytes\":-1}",
            "{\"ok\":true,\"max_input_bytes\":\"3145729\"}",
            "{\"ok\":true,\"max_input_bytes\":2147483648}",
            "{\"ok\":true,\"max_input_bytes\":3145729,\"x\":1}",
            "{\"ok\":false}",
            "[true]"
        }) {
            assertThrows(GuestFailure.class, () -> Wire.initAnswer(bad), bad);
        }
    }

    /** A reason outside 0.7's eight (such as the 0.6 core's INVALID_RECEIPT_FORMAT) is a module failure. */
    @Test
    void anAnswerOffTheWireFormatIsAModuleFailureNeverAVerdict() {
        String[] bad = {
            "",
            "not json",
            "{\"verified\":false,\"reason\":\"INVALID_RECEIPT_FORMAT\",\"message\":\"m\"}",
            "{\"verified\":false,\"reason\":\"MALFORMED\"}",
            "{\"verified\":false,\"reason\":\"MALFORMED\",\"message\":\"m\",\"extra\":1}",
            "{\"verified\":false,\"reason\":\"MALFORMED\",\"message\":\"m\"} trailing",
            "{\"verified\":false,\"reason\":\"MALFORMED\",\"message\":\"m\",\"message\":\"n\"}",
            "{\"verified\":\"yes\"}",
            "{\"verified\":true}",
            "{\"verified\":true,\"payload\":{}}",
            "{\"verified\":true,\"payload\":{},\"environment\":null}",
            "{\"verified\":true,\"payload\":\"a string, not a receipt\"}",
            "{\"verified\":true,\"payload\":{\"bundleId\":\"0.6 shape\"}",
        };
        for (String answer : bad) {
            assertThrows(GuestFailure.class, () -> Wire.receiptAnswer(answer), answer);
        }
        assertThrows(GuestFailure.class, () -> Wire.signedDataAnswer("{\"verified\":true,\"payload\":{}}"));
        assertThrows(
                GuestFailure.class,
                () -> Wire.signedDataAnswer("{\"verified\":true,\"payload\":{},\"environment\":null}"));
        assertThrows(GuestFailure.class, () -> Wire.endpointAnswer(""));
    }

    /** Each receipt field with the wrong JSON type is refused, one at a time. */
    @Test
    void aReceiptFieldOfTheWrongTypeIsRefused() throws Exception {
        String payload = Cases.byId("receipt/verify-genuine-sandbox-g5-against-apple-roots")
                .get("expected")
                .get("toJson")
                .asText();
        ObjectNode good = (ObjectNode) Cases.MAPPER.readTree(payload);
        String[][] mutations = {
            {"app_item_id", "0"}, // an id is a string
            {"app_item_id", "\"007\""}, // and canonical
            {"app_item_id", "\"9223372036854775808\""}, // and fits 64 bits
            {"receipt_creation_date_ms", "\"1\""}, // a date is a number
            {"receipt_creation_date_ms", "1.5"},
            {"receipt_creation_date_ms", "18446744073709551616"},
            {"preorder_date_ms", "\"1\""},
            {"preorder_date_ms", "1.5"},
            {"bundle_id_bytes", "\"not base64!\""},
            {"bundle_id_bytes", "\"QQ\""}, // padded
            {"in_app", "{}"},
            {"unknown_attributes", "[]"},
            {"unknown_attributes", "{\"x\":[]}"},
            {"unknown_attributes", "{\"13\":\"QQ==\"}"},
        };
        for (String[] mutation : mutations) {
            ObjectNode changed = good.deepCopy();
            changed.set(mutation[0], Cases.MAPPER.readTree(mutation[1]));
            String answer = "{\"verified\":true,\"payload\":" + changed + ",\"environment\":\"Sandbox\"}";
            assertThrows(GuestFailure.class, () -> Wire.receiptAnswer(answer), mutation[0] + "=" + mutation[1]);
        }
        ObjectNode missing = good.deepCopy();
        missing.remove("expiration_date_ms");
        assertThrows(
                GuestFailure.class,
                () -> Wire.receiptAnswer(
                        "{\"verified\":true,\"payload\":" + missing + ",\"environment\":\"Sandbox\"}"));
        // The control: the unchanged payload decodes, and without its
        // environment it does not.
        assertEquals(
                Environment.SANDBOX,
                Wire.receiptAnswer("{\"verified\":true,\"payload\":" + good + ",\"environment\":\"Sandbox\"}")
                        .payload()
                        .environment());
        assertThrows(GuestFailure.class, () -> Wire.receiptAnswer("{\"verified\":true,\"payload\":" + good + "}"));
    }

    /** Attribute 32 arrives as {@code preorder_date_ms}, a number or null, and is the module's to name. */
    @Test
    void thePreorderDateIsReadAsANumberOrNull() throws Exception {
        String payload = Cases.byId("receipt/missing-preorder-date-and-download-id-are-null")
                .get("expected")
                .get("toJson")
                .asText();
        ObjectNode good = (ObjectNode) Cases.MAPPER.readTree(payload);
        assertNull(Wire.receiptAnswer("{\"verified\":true,\"payload\":" + good + ",\"environment\":\"Sandbox\"}")
                .payload()
                .preorderDateMs());
        good.put("preorder_date_ms", 1_719_913_520_000L);
        ReceiptPayload read = Wire.receiptAnswer(
                        "{\"verified\":true,\"payload\":" + good + ",\"environment\":\"Sandbox\"}")
                .payload();
        assertEquals(Long.valueOf(1_719_913_520_000L), read.preorderDateMs());
        assertEquals(Cases.MAPPER.readTree(good.toString()), Cases.MAPPER.readTree(read.toJson()));
        // The key is part of the shape: a payload without it is not the 0.7 wire.
        good.remove("preorder_date_ms");
        assertThrows(
                GuestFailure.class,
                () -> Wire.receiptAnswer("{\"verified\":true,\"payload\":" + good + ",\"environment\":\"Sandbox\"}"));
    }

    @Test
    void unknownAttributesKeepTheirOrderAndBytes() {
        String answer = "{\"verified\":true,\"payload\":{\"receipt_type\":null,\"app_item_id\":\"-1\","
                + "\"bundle_id\":null,\"bundle_id_bytes\":null,\"application_version\":null,\"opaque_value\":null,"
                + "\"sha1_hash\":null,\"receipt_creation_date_ms\":null,\"download_id\":null,"
                + "\"version_external_identifier\":null,\"in_app\":[],\"original_purchase_date_ms\":null,"
                + "\"preorder_date_ms\":null,\"original_application_version\":null,\"expiration_date_ms\":null,"
                + "\"unknown_attributes\":{\"13\":[\"AQ==\",\"Ag==\"],\"-5\":[\"\"]}},\"environment\":null}";
        ReceiptPayload payload = Wire.receiptAnswer(answer).payload();
        assertEquals(Long.valueOf(-1), payload.appItemId());
        List<byte[]> values = payload.unknownAttributes().get(13);
        assertArrayEquals(new byte[] {1}, values.get(0));
        assertArrayEquals(new byte[] {2}, values.get(1));
        assertArrayEquals(new byte[0], payload.unknownAttributes().get(-5).get(0));
    }

    private static String quote(String text) {
        try {
            return Cases.MAPPER.writeValueAsString(text);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
