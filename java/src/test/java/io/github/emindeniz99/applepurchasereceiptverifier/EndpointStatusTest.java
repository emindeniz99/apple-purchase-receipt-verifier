package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * What the endpoint answers, by receipt and by environment.
 *
 * <p>What matters here is what a caller builds a retry on. The status is
 * computed from the receipt's own {@code receipt_type}: a production endpoint
 * must never answer 0 for a sandbox receipt, or the 21007 routing that keeps
 * sandbox purchases out of production would be bypassed. 0.6 pinned this on a
 * result object that could be re-rendered for either environment; 0.7 has no
 * such object, so it is pinned on the two calls a caller makes.</p>
 */
class EndpointStatusTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    private static TestPki pki;
    private static Verifier verifier;
    private static final Map<String, String> RECEIPTS = new LinkedHashMap<String, String>();

    @BeforeAll
    static void setUp() throws Exception {
        pki = SyntheticReceipts.pki();
        verifier = Checks.verifier(Clock.fixed(NOW, ZoneOffset.UTC), pki.root);
        for (String type : Arrays.asList(
                "Production", "ProductionVPP", "ProductionSandbox", "ProductionVPPSandbox", "Xcode", null)) {
            byte[] payload = TestPki.receiptPayload(
                    type,
                    "com.example.app",
                    "1.2.3",
                    new byte[] {1, 2, 3, 4},
                    new byte[20],
                    "2024-08-06T12:00:00Z",
                    Collections.<byte[]>emptyList());
            RECEIPTS.put(String.valueOf(type), Base64.getEncoder().encodeToString(pki.signReceipt(payload)));
        }
        RECEIPTS.put(
                "foreign", Base64.getEncoder().encodeToString(TestPki.receipt().signReceipt(new byte[] {0x31, 0})));
        RECEIPTS.put("tampered", Base64.getEncoder().encodeToString(SyntheticReceipts.tamperedDer()));
    }

    private static String respond(Environment environment, String receiptData) {
        return verifier.verifyReceiptEndpoint(environment, "{\"receipt-data\":\"" + receiptData + "\"}");
    }

    private static int status(String response) {
        return Integer.parseInt(response.substring("{\"status\":".length()).split("[,}]")[0]);
    }

    /**
     * The whole routing table. A production receipt gives 0 on PRODUCTION
     * and 21008 on SANDBOX; a sandbox receipt, and one whose receipt_type is
     * missing or unknown (which fails closed as non-production), gives 21007
     * on PRODUCTION and 0 on SANDBOX; a failed verification answers the same
     * status on both.
     */
    @Test
    void routesFromTheReceiptsOwnType() {
        Object[][] table = {
            // receipt, status on PRODUCTION, status on SANDBOX, Environment.fromReceiptType
            {"Production", 0, 21008, Environment.PRODUCTION},
            {"ProductionVPP", 0, 21008, Environment.PRODUCTION},
            {"ProductionSandbox", 21007, 0, Environment.SANDBOX},
            {"ProductionVPPSandbox", 21007, 0, Environment.SANDBOX},
            {"Xcode", 21007, 0, null},
            {"null", 21007, 0, null},
            {"foreign", 21003, 21003, null},
            {"tampered", 21003, 21003, null},
        };
        for (Object[] row : table) {
            String name = (String) row[0];
            assertEquals(row[1], status(respond(Environment.PRODUCTION, RECEIPTS.get(name))), name + " on PRODUCTION");
            assertEquals(row[2], status(respond(Environment.SANDBOX, RECEIPTS.get(name))), name + " on SANDBOX");
            if (!name.equals("foreign") && !name.equals("tampered")) {
                // The helper states the same rule the endpoint routes on.
                ReceiptPayload payload =
                        verifier.verifyReceipt(RECEIPTS.get(name)).payload();
                assertEquals(row[3], Environment.fromReceiptType(payload.receiptType()), name);
            }
        }
    }

    @Test
    void aNonProductionReceiptNeverAnswersAProductionZero() {
        for (String name : Arrays.asList("ProductionSandbox", "ProductionVPPSandbox", "Xcode", "null")) {
            assertEquals("{\"status\":21007}", respond(Environment.PRODUCTION, RECEIPTS.get(name)), name);
        }
    }

    /** A non-zero status carries nothing but the status; 0 carries environment and receipt. */
    @Test
    void onlyStatusZeroCarriesTheReceipt() {
        for (Map.Entry<String, String> receipt : RECEIPTS.entrySet()) {
            for (Environment environment : Environment.values()) {
                String response = respond(environment, receipt.getValue());
                String label = receipt.getKey() + " on " + environment;
                if (status(response) == 0) {
                    assertTrue(
                            response.startsWith(
                                    "{\"status\":0,\"environment\":\"" + environment.value() + "\",\"receipt\":{"),
                            label + ": " + response);
                } else {
                    assertEquals("{\"status\":" + status(response) + "}", response, label);
                }
            }
        }
    }

    /** Deterministic: the same call with the same clock answers the same bytes. */
    @Test
    void answersTheSameBytesForTheSameCall() {
        String receipt = RECEIPTS.get("ProductionSandbox");
        assertEquals(respond(Environment.SANDBOX, receipt), respond(Environment.SANDBOX, receipt));
    }

    /**
     * Each failure, through the endpoint and through verifyReceipt: the
     * reason verifyReceipt names is the one the status table turns into the
     * status the endpoint answers.
     */
    @Test
    void eachFailureAnswersTheStatusOfItsReason() throws Exception {
        StringBuilder tooLarge = new StringBuilder("{\"receipt-data\":\"");
        while (tooLarge.length() <= Endpoint.MAX_REQUEST_BYTES) {
            tooLarge.append("AAAA");
        }
        tooLarge.append("\"}");

        Map<String, String> malformedBodies = new LinkedHashMap<String, String>();
        malformedBodies.put("body not JSON", "not json");
        malformedBodies.put("body a JSON array", "[{\"receipt-data\":\"AQIDBA==\"}]");
        malformedBodies.put("null body", null);
        malformedBodies.put("receipt-data missing", "{}");
        malformedBodies.put("receipt-data empty", "{\"receipt-data\":\"\"}");
        malformedBodies.put("receipt-data a number", "{\"receipt-data\":5}");
        malformedBodies.put("receipt-data a list", "{\"receipt-data\":[\"AQIDBA==\"]}");
        malformedBodies.put("receipt-data not base64", "{\"receipt-data\":\"not base64!\"}");
        malformedBodies.put("receipt-data not a receipt", "{\"receipt-data\":\"AQIDBA==\"}");
        malformedBodies.put("body too large", tooLarge.toString());
        for (Map.Entry<String, String> body : malformedBodies.entrySet()) {
            assertEquals(
                    "{\"status\":21002}",
                    verifier.verifyReceiptEndpoint(Environment.SANDBOX, body.getValue()),
                    body.getKey());
        }

        Map<String, Reason> receipts = new LinkedHashMap<String, Reason>();
        receipts.put("not base64!", Reason.MALFORMED);
        receipts.put("AQIDBA==", Reason.MALFORMED);
        receipts.put(RECEIPTS.get("foreign"), Reason.UNTRUSTED_CHAIN);
        receipts.put(RECEIPTS.get("tampered"), Reason.INVALID_SIGNATURE);
        receipts.put(
                Base64.getEncoder().encodeToString(pki.signReceipt(TestPki.singleAttributePayload(2, new byte[] {
                    0x0c, 0x01, (byte) 0xff
                }))),
                Reason.UNREADABLE_PAYLOAD);
        for (Map.Entry<String, Reason> receipt : receipts.entrySet()) {
            Reason reason = verifier.verifyReceipt(receipt.getKey()).failure().reason();
            assertEquals(receipt.getValue(), reason);
            for (Environment environment : Environment.values()) {
                assertEquals(
                        "{\"status\":" + Endpoint.status(reason) + "}",
                        respond(environment, receipt.getKey()),
                        reason + " on " + environment);
            }
        }
    }
}
