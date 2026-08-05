package io.github.emindeniz99.applepurchase;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.emindeniz99.applepurchase.VerificationException.Reason;
import io.github.emindeniz99.applepurchase.jws.AppTransactionPayload;
import io.github.emindeniz99.applepurchase.jws.JwsVerifier;
import io.github.emindeniz99.applepurchase.jws.TransactionPayload;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwsVerifierTest {

    private static final String BUNDLE = "com.example.app";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static TestPki pki;

    @BeforeAll
    static void setUp() throws Exception {
        pki = TestPki.jws();
    }

    private static JwsVerifier verifier(TestPki trustedPki, Environment... envs) {
        return new JwsVerifier(Collections.singleton(trustedPki.root), BUNDLE,
                EnumSet.copyOf(Arrays.asList(envs)));
    }

    private static Map<String, Object> transactionClaims(String environment) {
        long now = System.currentTimeMillis();
        return TestPki.claims(
                "bundleId", BUNDLE,
                "environment", environment,
                "signedDate", now,
                "purchaseDate", now,
                "originalPurchaseDate", now,
                "productId", "com.example.app.pro",
                "transactionId", "2000000000000001",
                "originalTransactionId", "2000000000000001",
                "quantity", 1,
                "type", "Non-Consumable",
                "inAppOwnershipType", "PURCHASED");
    }

    @Test
    void verifiesGenuineTransaction() throws Exception {
        String jws = pki.signJws(transactionClaims("Sandbox"));
        TransactionPayload payload = verifier(pki, Environment.SANDBOX).verifyTransaction(jws);
        assertEquals(BUNDLE, payload.bundleId());
        assertEquals("com.example.app.pro", payload.productId());
        assertEquals("2000000000000001", payload.transactionId());
        assertEquals("Sandbox", payload.environment());
        assertEquals(Integer.valueOf(1), payload.quantity());
        assertTrue(payload.isActiveAt(new Date()));
    }

    @Test
    void acceptSetAllowsBothEnvironments() throws Exception {
        String sandbox = pki.signJws(transactionClaims("Sandbox"));
        String production = pki.signJws(transactionClaims("Production"));
        JwsVerifier both = verifier(pki, Environment.PRODUCTION, Environment.SANDBOX);
        assertEquals("Sandbox", both.verifyTransaction(sandbox).environment());
        assertEquals("Production", both.verifyTransaction(production).environment());
    }

    @Test
    void rejectsEnvironmentOutsideAcceptSet() throws Exception {
        String production = pki.signJws(transactionClaims("Production"));
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(pki, Environment.SANDBOX).verifyTransaction(production));
        assertEquals(Reason.WRONG_ENVIRONMENT, e.reason());
    }

    @Test
    void rejectsWrongBundleId() throws Exception {
        Map<String, Object> claims = transactionClaims("Sandbox");
        claims.put("bundleId", "com.attacker.app");
        String jws = pki.signJws(claims);
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(pki, Environment.SANDBOX).verifyTransaction(jws));
        assertEquals(Reason.WRONG_BUNDLE_ID, e.reason());
    }

    @Test
    void rejectsTamperedPayload() throws Exception {
        String jws = pki.signJws(transactionClaims("Sandbox"));
        String[] parts = jws.split("\\.");
        Map<String, Object> forged = transactionClaims("Sandbox");
        forged.put("productId", "com.example.app.premium_forever");
        String forgedSegment = TestPki.b64url(
                MAPPER.writeValueAsString(forged).getBytes(StandardCharsets.UTF_8));
        String tampered = parts[0] + "." + forgedSegment + "." + parts[2];
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(pki, Environment.SANDBOX).verifyTransaction(tampered));
        assertEquals(Reason.INVALID_SIGNATURE, e.reason());
    }

    @Test
    void rejectsChainFromForeignRoot() throws Exception {
        TestPki foreign = TestPki.jws();
        String jws = foreign.signJws(transactionClaims("Sandbox"));
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(pki, Environment.SANDBOX).verifyTransaction(jws));
        assertEquals(Reason.INVALID_CHAIN, e.reason());
    }

    @Test
    void rejectsNonEs256Algorithm() throws Exception {
        Map<String, Object> header = new LinkedHashMap<String, Object>();
        header.put("alg", "RS256");
        header.put("x5c", pki.x5c());
        String jws = pki.signJwsWithHeader(MAPPER.writeValueAsString(header),
                MAPPER.writeValueAsString(transactionClaims("Sandbox")));
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(pki, Environment.SANDBOX).verifyTransaction(jws));
        assertEquals(Reason.INVALID_JWS_FORMAT, e.reason());
    }

    @Test
    void rejectsShortCertificateChain() throws Exception {
        Map<String, Object> header = new LinkedHashMap<String, Object>();
        header.put("alg", "ES256");
        header.put("x5c", pki.x5c().subList(0, 2));
        String jws = pki.signJwsWithHeader(MAPPER.writeValueAsString(header),
                MAPPER.writeValueAsString(transactionClaims("Sandbox")));
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(pki, Environment.SANDBOX).verifyTransaction(jws));
        assertEquals(Reason.INVALID_JWS_FORMAT, e.reason());
    }

    @Test
    void rejectsLeafWithoutAppleMarkerOid() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 86_400_000L);
        TestPki noOid = TestPki.jws(false, true, notBefore, notAfter);
        String jws = noOid.signJws(transactionClaims("Sandbox"));
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(noOid, Environment.SANDBOX).verifyTransaction(jws));
        assertEquals(Reason.INVALID_CERTIFICATE_PURPOSE, e.reason());
    }

    @Test
    void rejectsIntermediateWithoutAppleMarkerOid() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 86_400_000L);
        TestPki noOid = TestPki.jws(true, false, notBefore, notAfter);
        String jws = noOid.signJws(transactionClaims("Sandbox"));
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(noOid, Environment.SANDBOX).verifyTransaction(jws));
        assertEquals(Reason.INVALID_CERTIFICATE_PURPOSE, e.reason());
    }

    @Test
    void acceptsHistoricalPayloadSignedByNowExpiredCert() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 730L * 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() - 365L * 86_400_000L);
        TestPki expired = TestPki.jws(true, true, notBefore, notAfter);
        Map<String, Object> claims = transactionClaims("Sandbox");
        claims.put("signedDate", System.currentTimeMillis() - 547L * 86_400_000L);
        String jws = expired.signJws(claims);
        assertEquals(BUNDLE, verifier(expired, Environment.SANDBOX)
                .verifyTransaction(jws).bundleId());
    }

    @Test
    void rejectsFreshPayloadClaimingExpiredCertPeriod() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 730L * 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() - 365L * 86_400_000L);
        TestPki expired = TestPki.jws(true, true, notBefore, notAfter);
        String jws = expired.signJws(transactionClaims("Sandbox"));
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(expired, Environment.SANDBOX).verifyTransaction(jws));
        assertEquals(Reason.INVALID_CHAIN, e.reason());
    }

    @Test
    void rejectsStalePayloadWhenMaxAgeConfigured() throws Exception {
        Map<String, Object> claims = transactionClaims("Sandbox");
        claims.put("signedDate", System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(10));
        String jws = pki.signJws(claims);
        JwsVerifier strict = new JwsVerifier(Collections.singleton(pki.root), BUNDLE,
                EnumSet.of(Environment.SANDBOX), null, TimeUnit.MINUTES.toMillis(1));
        VerificationException e = assertThrows(VerificationException.class,
                () -> strict.verifyTransaction(jws));
        assertEquals(Reason.STALE_PAYLOAD, e.reason());
    }

    @Test
    void rejectsGarbageInput() {
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(pki, Environment.SANDBOX).verifyTransaction("not-a-jws"));
        assertEquals(Reason.INVALID_JWS_FORMAT, e.reason());
    }

    @Test
    void expiredSubscriptionIsNotActive() throws Exception {
        Map<String, Object> claims = transactionClaims("Sandbox");
        claims.put("type", "Auto-Renewable Subscription");
        claims.put("expiresDate", System.currentTimeMillis() - 1000);
        String jws = pki.signJws(claims);
        TransactionPayload payload = verifier(pki, Environment.SANDBOX).verifyTransaction(jws);
        assertFalse(payload.isActiveAt(new Date()));
    }

    @Test
    void verifiesProductionAppTransactionWithMatchingAppleId() throws Exception {
        Map<String, Object> claims = TestPki.claims(
                "bundleId", BUNDLE,
                "receiptType", "Production",
                "appAppleId", 123456789L,
                "applicationVersion", "1.2.3",
                "originalApplicationVersion", "1.0",
                "receiptCreationDate", System.currentTimeMillis());
        String jws = pki.signJws(claims);
        JwsVerifier v = new JwsVerifier(Collections.singleton(pki.root), BUNDLE,
                EnumSet.of(Environment.PRODUCTION), 123456789L, null);
        AppTransactionPayload payload = v.verifyAppTransaction(jws);
        assertEquals(Long.valueOf(123456789L), payload.appAppleId());
        assertEquals("1.2.3", payload.applicationVersion());
    }

    @Test
    void rejectsProductionAppTransactionWithWrongAppleId() throws Exception {
        Map<String, Object> claims = TestPki.claims(
                "bundleId", BUNDLE,
                "receiptType", "Production",
                "appAppleId", 999L,
                "receiptCreationDate", System.currentTimeMillis());
        String jws = pki.signJws(claims);
        JwsVerifier v = new JwsVerifier(Collections.singleton(pki.root), BUNDLE,
                EnumSet.of(Environment.PRODUCTION), 123456789L, null);
        VerificationException e = assertThrows(VerificationException.class,
                () -> v.verifyAppTransaction(jws));
        assertEquals(Reason.WRONG_APP_APPLE_ID, e.reason());
    }

    @Test
    void sandboxAppTransactionNeedsNoAppleId() throws Exception {
        Map<String, Object> claims = TestPki.claims(
                "bundleId", BUNDLE,
                "receiptType", "Sandbox",
                "receiptCreationDate", System.currentTimeMillis());
        String jws = pki.signJws(claims);
        AppTransactionPayload payload = verifier(pki, Environment.SANDBOX).verifyAppTransaction(jws);
        assertNull(payload.appAppleId());
        assertEquals("Sandbox", payload.receiptType());
    }

    @Test
    void verifyRawSkipsClaimChecksButNotSignature() throws Exception {
        Map<String, Object> claims = TestPki.claims(
                "bundleId", "com.other.app",
                "signedDate", System.currentTimeMillis(),
                "autoRenewStatus", 1);
        Map<String, Object> raw = verifier(pki, Environment.SANDBOX)
                .verifyRaw(pki.signJws(claims));
        assertEquals("com.other.app", raw.get("bundleId"));
        assertEquals(1, raw.get("autoRenewStatus"));

        TestPki foreign = TestPki.jws();
        String forged = foreign.signJws(claims);
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(pki, Environment.SANDBOX).verifyRaw(forged));
        assertEquals(Reason.INVALID_CHAIN, e.reason());
    }

    @Test
    void rejectsEmptyTrustAnchors() {
        Set<java.security.cert.X509Certificate> empty = Collections.emptySet();
        assertThrows(IllegalArgumentException.class,
                () -> new JwsVerifier(empty, BUNDLE, EnumSet.of(Environment.SANDBOX)));
    }
}
