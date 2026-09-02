package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.VerifyReceiptEndpoint;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** verifyReceipt-compat semantics over the shared receipt fixture. */
class VerifyReceiptEndpointTest {

    private static final Path FIXTURES = Paths.get("..", "fixtures", "generated");

    private static VerifyReceiptEndpoint endpoint(boolean production) throws Exception {
        byte[] der = Files.readAllBytes(FIXTURES.resolve("receipt-root.der"));
        X509Certificate root = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
        return new VerifyReceiptEndpoint(Collections.singleton(root), production);
    }

    private static Map<String, Object> request() throws Exception {
        byte[] receipt = Files.readAllBytes(FIXTURES.resolve("receipt.der"));
        return Collections.singletonMap("receipt-data",
                Base64.getEncoder().encodeToString(receipt));
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** request_date is "now": two calls legitimately disagree on it. */
    private static JsonNode withoutRequestDate(JsonNode response) {
        JsonNode receipt = response.get("receipt");
        if (receipt != null) {
            ((ObjectNode) receipt).remove(java.util.Arrays.asList(
                    "request_date", "request_date_ms", "request_date_pst"));
        }
        return response;
    }

    @Test
    @SuppressWarnings("unchecked")
    void answersLikeVerifyReceiptForAValidSandboxReceipt() throws Exception {
        Map<String, Object> response = endpoint(false).verifyReceipt(request());
        assertEquals(0, response.get("status"));
        assertEquals("Sandbox", response.get("environment"));
        Map<String, Object> receipt = (Map<String, Object>) response.get("receipt");
        assertEquals("ProductionSandbox", receipt.get("receipt_type"));
        assertEquals("com.example.app", receipt.get("bundle_id"));
        assertEquals("1.2.3", receipt.get("application_version"));
        assertEquals("1.0", receipt.get("original_application_version"));
        assertEquals("2024-08-06 12:00:00 Etc/GMT", receipt.get("receipt_creation_date"));
        assertEquals("1722945600000", receipt.get("receipt_creation_date_ms"));
        assertEquals("2024-08-06 05:00:00 America/Los_Angeles",
                receipt.get("receipt_creation_date_pst"));
        // Full COMPARISON.md "full fidelity" field set (parity with Node).
        assertEquals("1.0", receipt.get("original_application_version"));
        assertNotNull(receipt.get("request_date_ms"));
        assertNotNull(receipt.get("request_date"));
        assertNotNull(receipt.get("request_date_pst"));
        List<Map<String, Object>> inApp = (List<Map<String, Object>>) receipt.get("in_app");
        assertEquals(2, inApp.size());
        Map<String, Object> coins = inApp.get(0).get("product_id").equals("com.example.app.coins100")
                ? inApp.get(0) : inApp.get(1);
        assertEquals("1", coins.get("quantity"));
        assertEquals("70000000000001", coins.get("transaction_id"));
        assertEquals("70000000000001", coins.get("original_transaction_id"));
        assertNotNull(coins.get("purchase_date"));
        assertNotNull(coins.get("purchase_date_ms"));
        assertNotNull(coins.get("purchase_date_pst"));
        Map<String, Object> vip = inApp.get(0).get("product_id").equals("com.example.app.vip")
                ? inApp.get(0) : inApp.get(1);
        assertEquals("2030-02-01 09:30:00 Etc/GMT", vip.get("expires_date"));
        assertNotNull(vip.get("expires_date_ms"));
        assertNotNull(vip.get("expires_date_pst"));
        assertEquals("42", vip.get("web_order_line_item_id"));
    }

    @Test
    void routesSandboxReceiptOnProductionTo21007() throws Exception {
        Map<String, Object> response = endpoint(true).verifyReceipt(request());
        assertEquals(21007, response.get("status"));
        assertNull(response.get("receipt"));
    }

    @Test
    void reportsMalformedRequestsAs21002() throws Exception {
        assertEquals(21002, endpoint(false)
                .verifyReceipt(Collections.<String, Object>emptyMap()).get("status"));
        assertEquals(21002, endpoint(false)
                .verifyReceipt(Collections.singletonMap("receipt-data", "AQIDBA==")).get("status"));
    }

    @Test
    void routesReceiptTypeVariantsPerAppleMatrix() throws Exception {
        // production types answer in Production and 21008 in Sandbox;
        // sandbox/missing types answer in Sandbox and 21007 in Production.
        String[][] cases = {
                {"receipt-type-production.der", "production"},
                {"receipt-type-vpp.der", "production"},
                {"receipt-type-vpp-sandbox.der", "sandbox"},
                {"receipt-no-type.der", "sandbox"},
        };
        for (String[] c : cases) {
            byte[] receipt = Files.readAllBytes(FIXTURES.resolve(c[0]));
            Map<String, Object> body = Collections.singletonMap("receipt-data",
                    Base64.getEncoder().encodeToString(receipt));
            boolean isProduction = c[1].equals("production");
            assertEquals(isProduction ? 0 : 21007,
                    endpoint(true).verifyReceipt(body).get("status"), c[0] + " on Production");
            assertEquals(isProduction ? 21008 : 0,
                    endpoint(false).verifyReceipt(body).get("status"), c[0] + " on Sandbox");
        }
    }

    @Test
    void reportsUnauthenticReceiptsAs21003() throws Exception {
        byte[] foreign = Files.readAllBytes(FIXTURES.resolve("receipt-foreign.der"));
        Map<String, Object> response = endpoint(false).verifyReceipt(
                Collections.singletonMap("receipt-data",
                        Base64.getEncoder().encodeToString(foreign)));
        assertEquals(21003, response.get("status"));
    }

    @Test
    void rawJsonOverloadPinsTheWireTypes() throws Exception {
        String body = endpoint(false).verifyReceipt(MAPPER.writeValueAsString(request()));
        // Raw bytes, not just the parse: status is a JSON number and every
        // number-shaped receipt field is a JSON string, as Apple sends them.
        assertTrue(body.contains("\"status\":0"), body);
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
    void rawJsonOverloadRendersIsInIntroOfferPeriodAsAString() throws Exception {
        Path publicReceipts = Paths.get("..", "fixtures", "public-receipts");
        String receiptData = new String(
                Files.readAllBytes(publicReceipts.resolve("receipt-sandbox-g5.b64")),
                StandardCharsets.US_ASCII).trim();
        String body = new VerifyReceiptEndpoint(AppleRootCerts.receiptRoots(), false)
                .verifyReceipt(MAPPER.writeValueAsString(
                        Collections.singletonMap("receipt-data", receiptData)));
        assertTrue(body.contains("\"is_in_intro_offer_period\":\"false\""), body);
        JsonNode purchases = MAPPER.readTree(body).get("receipt").get("in_app");
        assertTrue(purchases.size() > 0);
        for (JsonNode purchase : purchases) {
            assertTrue(purchase.get("is_in_intro_offer_period").isTextual());
        }
    }

    @Test
    void rawJsonOverloadOmitsReceiptAndEnvironmentOnNonZeroStatus() throws Exception {
        assertEquals("{\"status\":21007}",
                endpoint(true).verifyReceipt(MAPPER.writeValueAsString(request())));
    }

    @Test
    void rawJsonOverloadAnswers21002ForABodyThatIsNotAnObject() throws Exception {
        VerifyReceiptEndpoint endpoint = endpoint(false);
        String[] bodies = {"", "not json", "{", "[]", "[{\"receipt-data\":\"x\"}]",
                "null", "3", "\"receipt\"", "true", null};
        for (String body : bodies) {
            assertEquals("{\"status\":21002}", endpoint.verifyReceipt(body),
                    String.valueOf(body));
        }
    }

    @Test
    void rawJsonOverloadMatchesTheMapApi() throws Exception {
        VerifyReceiptEndpoint endpoint = endpoint(false);
        JsonNode viaMap = MAPPER.valueToTree(endpoint.verifyReceipt(request()));
        JsonNode viaJson = MAPPER.readTree(
                endpoint.verifyReceipt(MAPPER.writeValueAsString(request())));
        assertEquals(withoutRequestDate(viaMap), withoutRequestDate(viaJson));
    }
}
