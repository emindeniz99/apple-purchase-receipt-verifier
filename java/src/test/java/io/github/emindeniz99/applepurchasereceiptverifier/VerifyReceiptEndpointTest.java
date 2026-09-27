package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.junit.jupiter.api.Test;

/**
 * verifyReceipt-compat semantics that the shared cases do not pin: the wire
 * types, the malformed-request statuses, the status table, and the date
 * fields that move with the clock. Every status-code routing verdict over the
 * shared fixtures lives in the cases file instead, asserted by
 * {@code ConformanceCasesTest}.
 */
class VerifyReceiptEndpointTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final byte[] OPAQUE = {1, 2, 3, 4, 5, 6, 7, 8};

    private static String respond(Environment environment, String body) {
        return Checks.verifier(SyntheticReceipts.root()).verifyReceiptEndpoint(environment, body);
    }

    private static String request(byte[] receipt) {
        return "{\"receipt-data\":\"" + Base64.getEncoder().encodeToString(receipt) + "\"}";
    }

    private static String request() {
        return request(SyntheticReceipts.der());
    }

    /**
     * What a language-neutral vector cannot pin: {@code request_date}, which
     * is "now", and the {@code _ms}/{@code _pst} companions of every date,
     * the COMPARISON.md "full fidelity" field set, present in Node too.
     */
    @Test
    void emitsTheRequestDateAndEveryDateCompanionField() throws Exception {
        JsonNode receipt =
                MAPPER.readTree(respond(Environment.SANDBOX, request())).get("receipt");
        assertNotNull(receipt.get("request_date_ms"));
        assertNotNull(receipt.get("request_date"));
        assertNotNull(receipt.get("request_date_pst"));
        JsonNode inApp = receipt.get("in_app");
        JsonNode coins = inApp.get(0).get("product_id").asText().equals("com.example.app.coins100")
                ? inApp.get(0)
                : inApp.get(1);
        assertNotNull(coins.get("purchase_date"));
        assertNotNull(coins.get("purchase_date_ms"));
        assertNotNull(coins.get("purchase_date_pst"));
        JsonNode vip =
                inApp.get(0).get("product_id").asText().equals("com.example.app.vip") ? inApp.get(0) : inApp.get(1);
        assertNotNull(vip.get("expires_date_ms"));
        assertNotNull(vip.get("expires_date_pst"));
    }

    @Test
    void reportsMalformedRequestsAs21002() {
        for (String body : new String[] {"{}", "{\"receipt-data\":\"\"}", "{\"receipt-data\":\"AQIDBA==\"}"}) {
            assertEquals("{\"status\":21002}", respond(Environment.SANDBOX, body), body);
        }
    }

    @Test
    void aNullEnvironmentIsAProgrammingErrorNotAStatus() {
        assertThrows(NullPointerException.class, () -> respond(null, request()));
    }

    @Test
    void rawJsonPinsTheWireTypes() throws Exception {
        String body = respond(Environment.SANDBOX, request());
        // Raw bytes, not just the parse: status is a JSON number and every
        // number-shaped receipt field is a JSON string, as Apple sends them.
        assertTrue(body.startsWith("{\"status\":0,"), body);
        assertTrue(body.contains("\"quantity\":\"1\""), body);
        assertTrue(body.contains("\"web_order_line_item_id\":\"42\""), body);
        JsonNode parsed = MAPPER.readTree(body);
        assertTrue(parsed.get("status").isNumber(), body);
        assertEquals("Sandbox", parsed.get("environment").asText());
        JsonNode receipt = parsed.get("receipt");
        assertTrue(receipt.get("receipt_creation_date_ms").isTextual());
        assertTrue(receipt.get("request_date_ms").isTextual());
        for (JsonNode purchase : receipt.get("in_app")) {
            assertTrue(purchase.get("quantity").isTextual());
            assertTrue(purchase.get("web_order_line_item_id").isTextual());
            assertTrue(purchase.get("purchase_date_ms").isTextual());
        }
    }

    @Test
    void rendersIsInIntroOfferPeriodAsAString() throws Exception {
        String receiptData = new String(
                        Files.readAllBytes(TestFixtures.publicReceipts().resolve("receipt-sandbox-g5.b64")),
                        StandardCharsets.US_ASCII)
                .trim();
        String body = Verifier.create(Config.defaults())
                .verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + receiptData + "\"}");
        assertTrue(body.contains("\"is_in_intro_offer_period\":\"false\""), body);
        JsonNode purchases = MAPPER.readTree(body).get("receipt").get("in_app");
        assertTrue(purchases.size() > 0);
        for (JsonNode purchase : purchases) {
            assertTrue(purchase.get("is_in_intro_offer_period").isTextual());
        }
    }

    @Test
    void emitsTheLegacyIdsAsNumbersAndIsTrialPeriodAsAString() throws Exception {
        TestPki pki = SyntheticReceipts.pki();
        List<byte[]> inApps = Arrays.asList(
                TestPki.inAppPurchase(
                        1,
                        "com.example.app.coins100",
                        "70000000000001",
                        "70000000000001",
                        "2024-01-15T12:00:00Z",
                        null,
                        Arrays.asList(integerAttribute(1713, 0L))),
                TestPki.inAppPurchase(
                        1,
                        "com.example.app.vip",
                        "70000000000002",
                        "70000000000002",
                        "2024-02-01T09:30:00Z",
                        "2030-02-01T09:30:00Z",
                        Arrays.asList(integerAttribute(1713, 1L))));
        byte[] receipt = pki.signReceipt(TestPki.receiptPayload(
                "Production",
                "com.example.app",
                "1.2.3",
                OPAQUE,
                new byte[20],
                "2024-08-06T12:00:00Z",
                inApps,
                true,
                null,
                new byte[] {1, 2, 3},
                Arrays.asList(
                        integerAttribute(1, 1234567890L),
                        integerAttribute(15, 9223372036854775807L),
                        integerAttribute(16, 456789012L))));
        String body = respond(Environment.PRODUCTION, request(receipt));
        // Raw bytes, not just the parse. Attribute 1 is echoed under both of
        // Apple's names, the three app-level ids are JSON NUMBERS (unlike
        // every other number-shaped receipt field, which Apple sends as a
        // string), and 1713 renders exactly as 1719 does. download_id is
        // 2^63-1, so the literal digits are the assertion: anything that
        // routed the value through a double would print ...488 here.
        assertTrue(body.contains("\"adam_id\":1234567890"), body);
        assertTrue(body.contains("\"app_item_id\":1234567890"), body);
        assertTrue(body.contains("\"download_id\":9223372036854775807"), body);
        assertTrue(body.contains("\"version_external_identifier\":456789012"), body);
        assertTrue(body.contains("\"is_trial_period\":\"false\""), body);
        assertTrue(body.contains("\"is_trial_period\":\"true\""), body);
        JsonNode parsed = MAPPER.readTree(body).get("receipt");
        assertTrue(parsed.get("adam_id").isNumber(), body);
        assertTrue(parsed.get("download_id").isNumber(), body);
        assertEquals(9223372036854775807L, parsed.get("download_id").asLong(), body);
        // Apple's own key order, which is also the order a reader of the two
        // answers side by side compares them in.
        assertTrue(
                body.indexOf("\"receipt_type\"") < body.indexOf("\"adam_id\"")
                        && body.indexOf("\"adam_id\"") < body.indexOf("\"app_item_id\"")
                        && body.indexOf("\"app_item_id\"") < body.indexOf("\"bundle_id\"")
                        && body.indexOf("\"bundle_id\"") < body.indexOf("\"application_version\"")
                        && body.indexOf("\"application_version\"") < body.indexOf("\"download_id\"")
                        && body.indexOf("\"download_id\"") < body.indexOf("\"version_external_identifier\""),
                body);
    }

    @Test
    void omitsTheLegacyIdKeysWhenTheReceiptCarriesNone() {
        // Absent, not JSON null: the shared sandbox receipt carries none of
        // the four, so none of their keys is in the answer at all.
        String body = respond(Environment.SANDBOX, request());
        for (String key : Arrays.asList(
                "adam_id", "app_item_id", "download_id", "version_external_identifier", "is_trial_period")) {
            assertFalse(body.contains("\"" + key + "\""), key + " is present in " + body);
        }
    }

    /** Apple omits web_order_line_item_id for consumables, where attribute 1711 is 0. */
    @Test
    void omitsWebOrderLineItemIdWhenItIsZero() throws Exception {
        TestPki pki = SyntheticReceipts.pki();
        byte[] receipt = pki.signReceipt(TestPki.receiptPayload(
                "com.example.app",
                "1.2.3",
                OPAQUE,
                new byte[20],
                "2024-08-06T12:00:00Z",
                Arrays.asList(consumable("com.example.app.zero", 0L), consumable("com.example.app.seven", 7L))));
        String body = respond(Environment.SANDBOX, request(receipt));
        JsonNode inApp = MAPPER.readTree(body).get("receipt").get("in_app");
        for (JsonNode purchase : inApp) {
            if (purchase.get("product_id").asText().endsWith(".zero")) {
                assertFalse(purchase.has("web_order_line_item_id"), body);
            } else {
                assertEquals("7", purchase.get("web_order_line_item_id").asText(), body);
            }
        }
        // The payload itself still says 0: omission is the endpoint's Apple
        // imitation, not a decode rule.
        ReceiptPayload payload = Checks.receipt(Checks.verifier(pki), receipt);
        assertTrue(payload.toJson().contains("\"web_order_line_item_id\":\"0\""), payload.toJson());
    }

    @Test
    void omitsReceiptAndEnvironmentOnNonZeroStatus() {
        assertEquals("{\"status\":21007}", respond(Environment.PRODUCTION, request()));
    }

    @Test
    void answers21002ForABodyThatIsNotAnObject() {
        String[] bodies = {
            "", "not json", "{", "[]", "[{\"receipt-data\":\"x\"}]", "null", "3", "\"receipt\"", "true", null
        };
        for (String body : bodies) {
            assertEquals("{\"status\":21002}", respond(Environment.SANDBOX, body), String.valueOf(body));
        }
    }

    /** password and exclude-old-transactions are read and ignored, as in 0.6. */
    @Test
    void ignoresPasswordAndExcludeOldTransactions() throws Exception {
        String plain = respond(Environment.SANDBOX, request());
        String withExtras = respond(
                Environment.SANDBOX,
                request().replace("}", ",\"password\":\"secret\",\"exclude-old-transactions\":true}"));
        assertEquals(withoutRequestDate(MAPPER.readTree(plain)), withoutRequestDate(MAPPER.readTree(withExtras)));
    }

    /**
     * The status table, the same in every port. 21009 is deterministic for
     * the same input, and 21005 and the 21100 to 21199 range, which invite a
     * retry, are never returned.
     */
    @Test
    void mapsEveryReasonToAppleStatusAsTheTableSays() {
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, Endpoint.status(Reason.MALFORMED));
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, Endpoint.status(Reason.TOO_LARGE));
        assertEquals(AppleStatus.RECEIPT_NOT_AUTHENTICATED, Endpoint.status(Reason.INVALID_SIGNATURE));
        assertEquals(AppleStatus.RECEIPT_NOT_AUTHENTICATED, Endpoint.status(Reason.UNTRUSTED_CHAIN));
        assertEquals(AppleStatus.RECEIPT_NOT_AUTHENTICATED, Endpoint.status(Reason.INVALID_CERTIFICATE));
        assertEquals(AppleStatus.RECEIPT_NOT_AUTHENTICATED, Endpoint.status(Reason.INVALID_CERTIFICATE_PURPOSE));
        assertEquals(AppleStatus.INTERNAL_DATA_ACCESS_ERROR, Endpoint.status(Reason.UNREADABLE_PAYLOAD));
        assertEquals(AppleStatus.INTERNAL_DATA_ACCESS_ERROR, Endpoint.status(Reason.INTERNAL_ERROR));
        for (Reason reason : Reason.values()) {
            int status = Endpoint.status(reason);
            assertTrue(status != AppleStatus.SERVER_UNAVAILABLE, reason.name());
            assertFalse(
                    status >= AppleStatus.INTERNAL_DATA_ACCESS_ERROR_RANGE_FIRST
                            && status <= AppleStatus.INTERNAL_DATA_ACCESS_ERROR_RANGE_LAST,
                    reason.name());
        }
    }

    @Test
    void unreadableSignedContentAnswers21009() throws Exception {
        // Signed content that is an INTEGER rather than the attribute SET.
        byte[] receipt = SyntheticReceipts.pki().signReceipt(new byte[] {0x02, 0x01, 0x01});
        assertEquals("{\"status\":21009}", respond(Environment.SANDBOX, request(receipt)));
    }

    @Test
    void aClockThatThrowsAnswers21009() throws Exception {
        Clock broken = new Clock() {
            @Override
            public java.time.ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(java.time.ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                throw new IllegalStateException("no time");
            }

            @Override
            public long millis() {
                throw new IllegalStateException("no time");
            }
        };
        Verifier verifier = Checks.verifier(broken, SyntheticReceipts.root());
        // request_date needs the clock.
        assertEquals("{\"status\":21009}", verifier.verifyReceiptEndpoint(Environment.SANDBOX, request()));
        // The clock is read only when a verdict needs it: input that fails
        // its own checks never reaches it, and a receipt that states its
        // creation date needs none.
        assertEquals("{\"status\":21002}", verifier.verifyReceiptEndpoint(Environment.SANDBOX, "{}"));
        assertEquals(Reason.MALFORMED, verifier.verifyReceipt("AAAA").failure().reason());
        assertEquals(Reason.MALFORMED, verifier.verifySignedData(null).failure().reason());
        assertTrue(verifier.verifyReceipt(SyntheticReceipts.base64()).verified());
        // A receipt without one is judged at the clock, which is broken.
        String dateless = Base64.getEncoder()
                .encodeToString(SyntheticReceipts.pki().signReceipt(new byte[] {0x31, 0x00}));
        Failure failure = verifier.verifyReceipt(dateless).failure();
        assertEquals(Reason.INTERNAL_ERROR, failure.reason());
        assertEquals("the configured clock failed", failure.message());
    }

    /**
     * request_date comes from the config clock, the endpoint's only
     * time-dependent output besides the chain fallback below.
     */
    @Test
    void theConfigClockDrivesTheRequestDate() throws Exception {
        Instant now = Instant.parse("2025-01-01T00:00:00Z");
        Verifier pinned = Checks.verifier(Clock.fixed(now, ZoneOffset.UTC), SyntheticReceipts.root());
        JsonNode receipt = MAPPER.readTree(pinned.verifyReceiptEndpoint(Environment.SANDBOX, request()))
                .get("receipt");
        assertEquals(
                String.valueOf(now.toEpochMilli()),
                receipt.get("request_date_ms").asText());
        assertEquals("2025-01-01 00:00:00 Etc/GMT", receipt.get("request_date").asText());
        assertEquals(
                "2024-12-31 16:00:00 America/Los_Angeles",
                receipt.get("request_date_pst").asText());
    }

    /**
     * The fixture receipt is a ProductionSandbox one: 0 on SANDBOX, 21007 on
     * PRODUCTION, with the routing following the enum.
     */
    @Test
    void routesOnTheTypedEnvironment() throws Exception {
        JsonNode sandbox = MAPPER.readTree(respond(Environment.SANDBOX, request()));
        assertEquals(0, sandbox.get("status").asInt());
        assertEquals("Sandbox", sandbox.get("environment").asText());
        assertEquals("{\"status\":21007}", respond(Environment.PRODUCTION, request()));
    }

    /**
     * A receipt carrying no creation date is judged against the config clock
     * (design 0.7: the clock is read for the chain fallback and for
     * request_date). A clock inside the expired chain's window accepts it;
     * the system clock does not. 0.6 deliberately ignored an injected clock
     * here; 0.7 reverses that on purpose.
     */
    @Test
    void theConfigClockJudgesADatelessReceiptsChain() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 730L * 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() - 365L * 86_400_000L);
        TestPki expired = TestPki.receipt(notBefore, notAfter);
        // An empty attribute-12 value is how a real receipt says "no creation
        // date", which is the only way to reach the clock fallback at all.
        byte[] payload = TestPki.receiptPayload(
                "com.example.app", "1.2.3", OPAQUE, new byte[20], "", Collections.<byte[]>emptyList());
        // Signed inside the window, since BouncyCastle also checks the signer
        // against the CMS signingTime (Apple's receipts carry none).
        String body = request(expired.signReceipt(payload, new Date(notBefore.getTime() + 86_400_000L)));

        assertEquals(
                "{\"status\":21003}", Checks.verifier(expired.root).verifyReceiptEndpoint(Environment.SANDBOX, body));
        Clock inside = Clock.fixed(notBefore.toInstant().plusMillis(86_400_000L), ZoneOffset.UTC);
        assertTrue(Checks.verifier(inside, expired.root)
                .verifyReceiptEndpoint(Environment.SANDBOX, body)
                .startsWith("{\"status\":0,"));
        for (Clock outside : Arrays.<Clock>asList(
                Clock.fixed(Instant.parse("2001-01-01T00:00:00Z"), ZoneOffset.UTC),
                Clock.fixed(Instant.parse("2099-01-01T00:00:00Z"), ZoneOffset.UTC))) {
            assertEquals(
                    "{\"status\":21003}",
                    Checks.verifier(outside, expired.root).verifyReceiptEndpoint(Environment.SANDBOX, body),
                    "clock " + outside);
        }
    }

    /** request_date is "now": two calls legitimately disagree on it. */
    private static JsonNode withoutRequestDate(JsonNode response) {
        JsonNode receipt = response.get("receipt");
        if (receipt != null) {
            ((com.fasterxml.jackson.databind.node.ObjectNode) receipt)
                    .remove(Arrays.asList("request_date", "request_date_ms", "request_date_pst"));
        }
        return response;
    }

    private static ASN1Encodable integerAttribute(int type, long value) throws Exception {
        return TestPki.attribute(type, new ASN1Integer(value).getEncoded());
    }

    /** An in-app purchase SET with exactly one attribute 1711, of {@code webOrderLineItemId}. */
    private static byte[] consumable(String productId, long webOrderLineItemId) throws Exception {
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        attributes.add(integerAttribute(1701, 1L));
        attributes.add(TestPki.attribute(1702, new DERUTF8String(productId).getEncoded()));
        attributes.add(TestPki.attribute(1703, new DERUTF8String("70000000000009").getEncoded()));
        attributes.add(TestPki.attribute(1704, new DERIA5String("2024-01-15T12:00:00Z").getEncoded()));
        attributes.add(integerAttribute(1711, webOrderLineItemId));
        return new DERSet(attributes).getEncoded();
    }
}
