package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * {@link Verifier#verifySignedData} over JWS signed by a generated PKI: the
 * structure, the chain, the markers, the signature, and the payload returned
 * unchanged.
 */
class SignedDataTest {

    private static final String BUNDLE = "com.example.app";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static TestPki pki;

    @BeforeAll
    static void setUp() throws Exception {
        pki = TestPki.jws();
    }

    /** Verifies {@code jws} under {@code trustedPki}'s root and parses the payload; a failure is thrown back. */
    private static JsonNode verify(TestPki trustedPki, String jws) throws Exception {
        return MAPPER.readTree(
                Checks.signedData(Checks.verifier(trustedPki), jws).json());
    }

    private static Reason failure(TestPki trustedPki, String jws) {
        return assertThrows(VerificationException.class, () -> verify(trustedPki, jws))
                .reason();
    }

    private static Map<String, Object> transactionClaims(String environment) {
        long now = System.currentTimeMillis();
        return TestPki.claims(
                "bundleId",
                BUNDLE,
                "environment",
                environment,
                "signedDate",
                now,
                "purchaseDate",
                now,
                "originalPurchaseDate",
                now,
                "productId",
                "com.example.app.pro",
                "transactionId",
                "2000000000000001",
                "originalTransactionId",
                "2000000000000001",
                "quantity",
                1,
                "type",
                "Non-Consumable",
                "inAppOwnershipType",
                "PURCHASED");
    }

    @Test
    void verifiesGenuineTransaction() throws Exception {
        JsonNode payload = verify(pki, pki.signJws(transactionClaims("Sandbox")));
        assertEquals(BUNDLE, payload.get("bundleId").asText());
        assertEquals("com.example.app.pro", payload.get("productId").asText());
        assertEquals("2000000000000001", payload.get("transactionId").asText());
        assertEquals("Sandbox", payload.get("environment").asText());
        assertEquals(1, payload.get("quantity").asInt());
    }

    @Test
    void returnsThePayloadExactlyAsSigned() throws Exception {
        // Not re-serialised: key order, spacing and number spelling are what
        // the signer wrote, so a caller hashing or storing json() gets the
        // signed bytes back.
        String payloadJson = "{ \"b\" : 1.50, \"a\":\"x\\/y\", \"signedDate\": " + System.currentTimeMillis() + " }";
        String jws = pki.signJwsWithHeader(headerJson(), payloadJson);
        assertEquals(payloadJson, Checks.signedData(Checks.verifier(pki), jws).json());
    }

    @Test
    void returnsWhateverEnvironmentAndBundleIdAppleSignedWithoutJudgingThem() throws Exception {
        // 0.6 took an accept set and a bundle id; 0.7 takes neither. What the
        // payload says comes back, and the result states its environment.
        Map<String, Object> claims = transactionClaims("Production");
        claims.put("bundleId", "com.other.app");
        String jws = pki.signJws(claims);
        JsonNode payload = verify(pki, jws);
        assertEquals("com.other.app", payload.get("bundleId").asText());
        assertEquals(
                Environment.PRODUCTION,
                Checks.signedData(Checks.verifier(pki), jws).environment());
    }

    @Test
    void rejectsTamperedPayload() throws Exception {
        String jws = pki.signJws(transactionClaims("Sandbox"));
        String[] parts = jws.split("\\.");
        Map<String, Object> forged = transactionClaims("Sandbox");
        forged.put("productId", "com.example.app.premium_forever");
        String forgedSegment = TestPki.b64url(MAPPER.writeValueAsString(forged).getBytes(StandardCharsets.UTF_8));
        String tampered = parts[0] + "." + forgedSegment + "." + parts[2];
        assertEquals(Reason.INVALID_SIGNATURE, failure(pki, tampered));
    }

    @Test
    void rejectsChainFromForeignRoot() throws Exception {
        TestPki foreign = TestPki.jws();
        assertEquals(Reason.UNTRUSTED_CHAIN, failure(pki, foreign.signJws(transactionClaims("Sandbox"))));
    }

    @Test
    void rejectsNonEs256Algorithm() throws Exception {
        Map<String, Object> header = new LinkedHashMap<String, Object>();
        header.put("alg", "RS256");
        header.put("x5c", pki.x5c());
        String jws = pki.signJwsWithHeader(
                MAPPER.writeValueAsString(header), MAPPER.writeValueAsString(transactionClaims("Sandbox")));
        assertEquals(Reason.MALFORMED, failure(pki, jws));
    }

    @Test
    void rejectsShortCertificateChain() throws Exception {
        Map<String, Object> header = new LinkedHashMap<String, Object>();
        header.put("alg", "ES256");
        header.put("x5c", pki.x5c().subList(0, 2));
        String jws = pki.signJwsWithHeader(
                MAPPER.writeValueAsString(header), MAPPER.writeValueAsString(transactionClaims("Sandbox")));
        assertEquals(Reason.MALFORMED, failure(pki, jws));
    }

    @Test
    void rejectsLeafWithoutAppleMarkerOid() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 86_400_000L);
        TestPki noOid = TestPki.jws(false, true, notBefore, notAfter);
        assertEquals(Reason.INVALID_CERTIFICATE_PURPOSE, failure(noOid, noOid.signJws(transactionClaims("Sandbox"))));
    }

    @Test
    void rejectsIntermediateWithoutAppleMarkerOid() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 86_400_000L);
        TestPki noOid = TestPki.jws(true, false, notBefore, notAfter);
        assertEquals(Reason.INVALID_CERTIFICATE_PURPOSE, failure(noOid, noOid.signJws(transactionClaims("Sandbox"))));
    }

    /**
     * The chain first, then the markers, as on the receipt path (owner,
     * 2026-09-27, Q21): a chain that does not reach a pinned root is
     * UNTRUSTED_CHAIN whatever markers it lacks.
     */
    @Test
    void aForeignChainWithoutMarkersIsAnUntrustedChain() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 86_400_000L);
        for (TestPki noOid : new TestPki[] {
            TestPki.jws(false, true, notBefore, notAfter), TestPki.jws(true, false, notBefore, notAfter)
        }) {
            assertEquals(Reason.UNTRUSTED_CHAIN, failure(pki, noOid.signJws(transactionClaims("Sandbox"))));
        }
    }

    /**
     * Validity before the signature (owner, 2026-09-27, Q22): a payload whose
     * chain is outside its window is INVALID_CERTIFICATE even when its
     * signature is also broken.
     */
    @Test
    void anExpiredChainOutranksABrokenSignature() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 730L * 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() - 365L * 86_400_000L);
        TestPki expired = TestPki.jws(true, true, notBefore, notAfter);
        String jws = expired.signJws(transactionClaims("Sandbox"));
        int signatureStart = jws.lastIndexOf('.') + 1;
        // The first character carries six whole bits, so changing it keeps
        // the segment canonical base64url.
        char flipped = jws.charAt(signatureStart) == 'A' ? 'B' : 'A';
        String broken = jws.substring(0, signatureStart) + flipped + jws.substring(signatureStart + 1);
        assertEquals(Reason.INVALID_CERTIFICATE, failure(expired, broken));
    }

    @Test
    void acceptsHistoricalPayloadSignedByNowExpiredCert() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 730L * 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() - 365L * 86_400_000L);
        TestPki expired = TestPki.jws(true, true, notBefore, notAfter);
        Map<String, Object> claims = transactionClaims("Sandbox");
        claims.put("signedDate", System.currentTimeMillis() - 547L * 86_400_000L);
        assertEquals(
                BUNDLE, verify(expired, expired.signJws(claims)).get("bundleId").asText());
    }

    @Test
    void rejectsFreshPayloadClaimingExpiredCertPeriod() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 730L * 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() - 365L * 86_400_000L);
        TestPki expired = TestPki.jws(true, true, notBefore, notAfter);
        assertEquals(Reason.INVALID_CERTIFICATE, failure(expired, expired.signJws(transactionClaims("Sandbox"))));
    }

    /** Freshness is the caller's decision (PLAN.md D5): an old payload still verifies. */
    @Test
    void neverRejectsAPayloadForItsAge() throws Exception {
        Map<String, Object> claims = transactionClaims("Sandbox");
        long signedAt = System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(10);
        claims.put("signedDate", signedAt);
        assertEquals(
                signedAt, verify(pki, pki.signJws(claims)).get("signedDate").asLong());
    }

    @Test
    void rejectsGarbageInput() {
        assertEquals(Reason.MALFORMED, failure(pki, "not-a-jws"));
    }

    /**
     * A compact JWS has exactly three segments. A fourth is not a JWE or an
     * extension to tolerate: anything that is not header.payload.signature
     * is rejected before a byte of it is decoded.
     */
    @Test
    void rejectsFourSegments() {
        assertEquals(Reason.MALFORMED, failure(pki, "a.b.c.d"));
    }

    /**
     * A signature segment that is not base64url is outer structure: MALFORMED
     * before any cryptography, even under a chain that would not verify.
     */
    @Test
    void rejectsABrokenSignatureSegmentBeforeTheChain() throws Exception {
        TestPki foreign = TestPki.jws();
        String jws = foreign.signJws(transactionClaims("Sandbox"));
        assertEquals(Reason.MALFORMED, failure(pki, jws.substring(0, jws.lastIndexOf('.') + 1) + "!!!"));
    }

    /**
     * Claims are UTF-8 on the wire (RFC 7519), whatever the JVM's default
     * charset is. Product ids, offer ids and storefront-facing strings can
     * carry non-ASCII text; decoding them with the platform charset would
     * hand the caller a different string than Apple signed. The literals are
     * Unicode escapes so this file's own encoding cannot mask the check.
     */
    @Test
    void nonAsciiClaimsRoundTripAsUtf8() throws Exception {
        String productId = "com.example.app.é€中";
        String offerIdentifier = "über-€-中文-😀";
        Map<String, Object> claims = transactionClaims("Sandbox");
        claims.put("productId", productId);
        claims.put("offerIdentifier", offerIdentifier);
        JsonNode payload = verify(pki, pki.signJws(claims));
        assertEquals(productId, payload.get("productId").asText());
        assertEquals(offerIdentifier, payload.get("offerIdentifier").asText());
    }

    @Test
    void returnsClaimsOfAnyType() throws Exception {
        // No typed model in between: what 0.6 refused as INTERNAL_ERROR for a
        // claim of the wrong type (a string quantity, a numeric product id)
        // is now the caller's to read.
        Map<String, Object> claims = TestPki.claims(
                "bundleId",
                "com.other.app",
                "signedDate",
                System.currentTimeMillis(),
                "quantity",
                "1",
                "productId",
                42,
                "price",
                1.5);
        JsonNode payload = verify(pki, pki.signJws(claims));
        assertEquals("1", payload.get("quantity").asText());
        assertEquals(42, payload.get("productId").asInt());

        TestPki foreign = TestPki.jws();
        assertEquals(Reason.UNTRUSTED_CHAIN, failure(pki, foreign.signJws(claims)));
    }

    @Test
    void rejectsEmptyTrustAnchors() {
        assertThrows(
                IllegalArgumentException.class,
                () -> Verifier.create(Config.builder()
                        .roots(Collections.<java.security.cert.X509Certificate>emptySet())
                        .build()));
    }

    // ------------------------------------------------ parse after signature

    /**
     * A payload that is not a JSON object does not fail before the signature
     * check: under a signature that verifies it is UNREADABLE_PAYLOAD, with
     * the parser's exception as the cause when there is one.
     */
    @Test
    void aSignedPayloadThatIsNotAnObjectIsUnreadable() throws Exception {
        for (String payload : new String[] {"[1,2]", "42", "", "{\"a\":", "{\"a\":1"}) {
            String jws = pki.signJwsWithHeader(headerJson(), payload);
            VerificationResult<JsonPayload> result = Checks.verifier(pki).verifySignedData(jws);
            assertFalse(result.verified(), payload);
            assertEquals(Reason.UNREADABLE_PAYLOAD, result.failure().reason(), payload);
        }
        VerificationResult<JsonPayload> broken =
                Checks.verifier(pki).verifySignedData(pki.signJwsWithHeader(headerJson(), "{\"a\":"));
        assertNotNull(broken.failure().cause());
    }

    /** ... and under a signature that does not verify, INVALID_SIGNATURE, never a parse failure. */
    @Test
    void anUnsignedPayloadThatIsNotAnObjectFailsTheSignature() throws Exception {
        String jws = pki.signJwsWithHeader(headerJson(), "{\"a\":1}");
        String[] parts = jws.split("\\.");
        String tampered = parts[0] + "." + TestPki.b64url("[1,2]".getBytes(StandardCharsets.UTF_8)) + "." + parts[2];
        assertEquals(Reason.INVALID_SIGNATURE, failure(pki, tampered));
    }

    /** A payload that is not UTF-8 is not JSON text: unreadable once signed. */
    @Test
    void aSignedPayloadThatIsNotUtf8IsUnreadable() throws Exception {
        String header = TestPki.b64url(headerJson().getBytes(StandardCharsets.UTF_8));
        String payload = TestPki.b64url(new byte[] {'{', '"', 'a', '"', ':', '"', (byte) 0xC3, '"', '}'});
        String jws = pki.signCompact(header + "." + payload);
        assertEquals(Reason.UNREADABLE_PAYLOAD, failure(pki, jws));
    }

    // ------------------------------------------------------------------ time

    /**
     * Certificate validity is judged at the payload's signedDate (PLAN.md
     * §2.1 step 4): a payload signed inside the window of a chain that has
     * since expired verifies, and one signed after it expired does not.
     */
    @Test
    void certificateValidityIsJudgedAtTheSignedDate() throws Exception {
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 730L * 86_400_000L);
        Date notAfter = new Date(now - 365L * 86_400_000L);
        TestPki expired = TestPki.jws(true, true, notBefore, notAfter);
        Map<String, Object> historical = transactionClaims("Sandbox");
        historical.put("signedDate", now - 547L * 86_400_000L);
        String insideWindow = expired.signJws(historical);
        String outsideWindow = expired.signJws(transactionClaims("Sandbox"));
        assertEquals(BUNDLE, verify(expired, insideWindow).get("bundleId").asText());
        assertEquals(Reason.INVALID_CERTIFICATE, failure(expired, outsideWindow));
    }

    /**
     * A payload without {@code signedDate} is judged at the config clock: an
     * expired chain fails under the system clock and passes under a clock set
     * inside its window. {@code receiptCreationDate} does not stand in for
     * {@code signedDate} in 0.7.
     */
    @Test
    void aDatelessPayloadIsJudgedAtTheConfigClock() throws Exception {
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 730L * 86_400_000L);
        Date notAfter = new Date(now - 365L * 86_400_000L);
        TestPki expired = TestPki.jws(true, true, notBefore, notAfter);
        Map<String, Object> dateless = transactionClaims("Sandbox");
        dateless.remove("signedDate");
        dateless.put("receiptCreationDate", now - 547L * 86_400_000L);
        String expiredJws = expired.signJws(dateless);
        assertEquals(Reason.INVALID_CERTIFICATE, failure(expired, expiredJws));
        assertEquals(BUNDLE, verify(pki, pki.signJws(dateless)).get("bundleId").asText());

        Clock insideTheWindow = Clock.fixed(Instant.ofEpochMilli(notBefore.getTime() + 86_400_000L), ZoneOffset.UTC);
        JsonPayload payload = Checks.signedData(Checks.verifier(insideTheWindow, expired.root), expiredJws);
        assertTrue(payload.json().contains(BUNDLE));
    }

    private static String headerJson() throws Exception {
        Map<String, Object> header = new LinkedHashMap<String, Object>();
        header.put("alg", "ES256");
        header.put("x5c", pki.x5c());
        return MAPPER.writeValueAsString(header);
    }
}
