package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

/**
 * What the shared revocation cases in {@code fixtures/cases.json} cannot
 * reach: the compiled-in list and its pins, the size bounds (a list over
 * 1 MiB, more than 100,000 entries, more than 1,000 distrust entries), an
 * injected built-in list (docs/design/revocation.md §10), the message of a
 * revocation, and the API's defaults and copies.
 */
class RevocationTest {

    private static final String APPLE_ROOT_CA = "0274fe858b04726bb2c6fd7ba73fe4c63a1d076f6eff78373bdb81498151c86e";
    private static final String APPLE_ROOT_CA_G2 = "f7c4e71ce6446445f63c1e494b7270cfd1c6a846b1dfbc9c9e20ab2acddb8e5e";
    private static final String APPLE_ROOT_CA_G3 = "e691a373c3e637bf2d2e0abc6056ea4e5413c90414b47b0b0133ad3cb757be57";
    private static final String WWDR_G5 = "c4c7a18465d55f4f7d20ff2a525bceafb55d860fc3b59a1981b04783fd74f96b";
    private static final String WWDR_G6 = "ccb38ff9530770495de3a1cf2a9c868e7cbe76f871a46ee485699a7d32dd0bee";

    /** The test PKI's root and its WWDR-marked intermediate (fixtures/generated-0.7/revocation/). */
    private static final String TEST_ROOT = "c8141c84b50a0c9de9858aa932bda43827085af1284e521b7ba1937a66ff52e1";

    private static final String TEST_INTERMEDIATE = "a604eb835029c0019e7904b7c007eca2a68f799e9dcba0012fdd34660cbcd9fb";

    /** The instant the shared cases run at: the fresh test lists cover it. */
    private static final Clock CASES_CLOCK = Clock.fixed(Instant.parse("2026-11-05T00:00:00Z"), ZoneOffset.UTC);

    /**
     * SHA-256 of the two built-in issuers, kept apart from their base64 in
     * {@code AppleRevocations} so that both have to change together.
     */
    private static final Map<String, String> ISSUER_FINGERPRINTS = new LinkedHashMap<String, String>();

    static {
        ISSUER_FINGERPRINTS.put(
                "certs/revocation-issuers/AppleWWDRCAG5.cer",
                "53fd008278e5a595fe1e908ae9c5e5675f26243264a5a6438c023e3ce2870760");
        ISSUER_FINGERPRINTS.put(
                "certs/revocation-issuers/AppleWWDRCAG6.cer",
                "bdd4ed6e74691f0c2bfd01be0296197af1379e0418e2d300efa9c3bef642ca30");
    }

    // ------------------------------------------------------- the built-in list

    /**
     * The compiled-in list is {@code certs/revocations.json} byte for byte,
     * the file the weekly watch compares with Apple's lists. On a mismatch
     * the message is the array to paste into {@code AppleRevocations}.
     */
    @Test
    void theBuiltInListIsTheRepositorysCertsFile() throws Exception {
        byte[] file = Files.readAllBytes(TestFixtures.certs().resolve("revocations.json"));
        if (!Arrays.equals(file, AppleRevocations.json())) {
            StringBuilder lines = new StringBuilder();
            for (String line : new String(file, StandardCharsets.UTF_8).split("\n", -1)) {
                if (!line.isEmpty()) {
                    lines.append("        \"")
                            .append(line.replace("\\", "\\\\").replace("\"", "\\\""))
                            .append("\",\n");
                }
            }
            fail("AppleRevocations.JSON_LINES differs from certs/revocations.json; replace its lines with:\n" + lines);
        }
    }

    /** The two built-in issuers are {@code certs/revocation-issuers/} byte for byte, and Apple's. */
    @Test
    void theBuiltInIssuersAreTheRepositorysFilesAndPinned() throws Exception {
        Path repository = TestFixtures.certs().getParent();
        for (Map.Entry<String, String> issuer : ISSUER_FINGERPRINTS.entrySet()) {
            byte[] compiled = AppleRevocations.certificate(issuer.getKey());
            assertNotNull(compiled, issuer.getKey());
            assertArrayEquals(Files.readAllBytes(repository.resolve(issuer.getKey())), compiled, issuer.getKey());
            assertEquals(issuer.getValue(), sha256(compiled), issuer.getKey());
        }
        assertNull(AppleRevocations.certificate("certs/AppleRootCA-G3.cer"));
    }

    /** The compiled-in list reads as the file says: four issuers in order, nineteen entries. */
    @Test
    void theBuiltInListReadsAsDocumented() {
        BuiltInRevocations apple = BuiltInRevocations.apple();
        List<String> ids = new ArrayList<String>();
        List<String> lists = new ArrayList<String>();
        for (BuiltInRevocations.Issuer issuer : apple.issuers) {
            ids.add(issuer.id);
            lists.add(issuer.list);
        }
        assertEquals(Arrays.asList(APPLE_ROOT_CA, APPLE_ROOT_CA_G3, WWDR_G5, WWDR_G6), ids);
        assertEquals(
                Arrays.asList(
                        "http://crl.apple.com/root.crl",
                        "http://crl.apple.com/applerootcag3.crl",
                        "http://crl.apple.com/wwdrg5.crl",
                        "http://crl.apple.com/wwdrg6.crl"),
                lists);
        assertNull(apple.issuers.get(0).certificate);
        assertNull(apple.issuers.get(1).certificate);
        assertNotNull(apple.issuers.get(2).certificate);
        assertNotNull(apple.issuers.get(3).certificate);
        assertEquals(new BigInteger("0857", 16), apple.issuers.get(3).newestNumber);
        assertNull(apple.issuers.get(0).newestNumber);
        assertEquals(19, apple.revoked.size());
        assertTrue(apple.revoked.contains(BuiltInRevocations.key(APPLE_ROOT_CA, "3EDF4E5729AECD39")));
        assertTrue(apple.revoked.contains(BuiltInRevocations.key(WWDR_G6, "37D34791D02A56160329892A81C5A0EA")));
    }

    /**
     * Issuer ids agree with the refresh tool's, which hashes the same slices
     * with openssl, and do not depend on which provider parsed the
     * certificate.
     */
    @Test
    void issuerIdsAreTheRefreshToolsAndProviderIndependent() throws Exception {
        Map<String, String> byName = new LinkedHashMap<String, String>();
        CertificateFactory jdk = CertificateFactory.getInstance("X.509");
        for (X509Certificate root : AppleRootCerts.roots()) {
            String id = Der.names(root).issuerId();
            X509Certificate again =
                    (X509Certificate) jdk.generateCertificate(new ByteArrayInputStream(root.getEncoded()));
            assertEquals(id, Der.names(again).issuerId());
            byName.put(root.getSubjectX500Principal().getName(), id);
        }
        assertTrue(byName.containsValue(APPLE_ROOT_CA), byName.toString());
        assertTrue(byName.containsValue(APPLE_ROOT_CA_G2), byName.toString());
        assertTrue(byName.containsValue(APPLE_ROOT_CA_G3), byName.toString());
        assertEquals(TEST_ROOT, Der.names(testCertificate("root.der")).issuerId());
        assertEquals(
                TEST_INTERMEDIATE,
                Der.names(testCertificate("intermediate.der")).issuerId());
    }

    /** §2: how serials are written and how distrust serials are read. */
    @Test
    void serialsAreWrittenAsSectionTwoSays() {
        assertEquals("00", Der.serialHex(BigInteger.ZERO));
        assertEquals("02", Der.serialHex(BigInteger.valueOf(2)));
        assertEquals("80", Der.serialHex(BigInteger.valueOf(0x80)));
        assertEquals("0857", Der.serialHex(BigInteger.valueOf(2135)));
        assertNull(Der.serialHex(BigInteger.valueOf(-2)));
        String[][] read = {
            {"2", "02"},
            {"02", "02"},
            {"0002", "02"},
            {"0080", "80"},
            {"80", "80"},
            {"0", "00"},
            {"00", "00"},
            {"3edf4e5729aecd39", "3EDF4E5729AECD39"},
            {"1a", "1A"},
        };
        for (String[] pair : read) {
            assertEquals(pair[1], Der.normaliseHex(pair[0]), pair[0]);
        }
        for (String refused : new String[] {"", "-1", "+1", " 1", "1 ", "0x1", "g", "1٠"}) {
            assertNull(Der.normaliseHex(refused), "\"" + refused + "\"");
        }
    }

    // ------------------------------------------------------------- the bounds

    /** A list over 1 MiB is refused before it is parsed; one of exactly 1 MiB is parsed. */
    @Test
    void aListOverOneMebibyteIsRefusedForItsSize() {
        String over = refusal(Config.builder().revocationLists(Collections.singletonList(new byte[(1 << 20) + 1])));
        assertTrue(over.contains("revocationLists[0] is over 1 MiB"), over);
        String at = refusal(Config.builder().revocationLists(Collections.singletonList(new byte[1 << 20])));
        assertTrue(at.contains("revocationLists[0] is not a DER CRL"), at);
    }

    /**
     * More than 100,000 entries over all lists is refused, counted as each
     * list is read; exactly 100,000 passes the bound (and these lists are
     * then refused for having no signer).
     */
    @Test
    void moreThanOneHundredThousandEntriesInAllAreRefused() throws Exception {
        List<byte[]> full = Arrays.asList(entries(40_000), entries(40_000), entries(20_000));
        for (byte[] list : full) {
            assertTrue(list.length <= 1 << 20, "a test list is over 1 MiB: " + list.length);
        }
        String at = refusal(Config.builder().revocationLists(full));
        assertTrue(at.contains("names no configured root"), at);
        List<byte[]> over = new ArrayList<byte[]>(full);
        over.add(entries(1));
        String refused = refusal(Config.builder().revocationLists(over));
        assertTrue(refused.contains("more than 100000 entries"), refused);
    }

    /** More than 1,000 distrust entries are refused; 1,000 build. */
    @Test
    void moreThanOneThousandDistrustEntriesAreRefused() {
        List<RevokedCertificate> entries = new ArrayList<RevokedCertificate>();
        for (int i = 0; i < 1000; i++) {
            entries.add(new RevokedCertificate(TEST_ROOT, Integer.toHexString(i)));
        }
        Verifier.create(Config.builder().distrust(entries).build());
        entries.add(new RevokedCertificate(TEST_ROOT, "ffff"));
        String refused = refusal(Config.builder().distrust(entries));
        assertTrue(refused.contains("more than 1000"), refused);
    }

    // ------------------------------------------- an injected built-in list

    /**
     * §10: a built-in list naming the test intermediate revokes it under the
     * test root, with the built-in layer in the message, where the
     * compiled-in list lets the same JWS verify.
     */
    @Test
    void anInjectedBuiltInListRevokes() throws Exception {
        Config config = testConfig().build();
        String jws = testText("jws.jws");
        assertTrue(Verifier.create(config).verifySignedData(jws).verified());

        BuiltInRevocations injected = builtIn("[]", "[{\"issuer\":\"" + TEST_ROOT + "\",\"serial\":\"1a\"}]");
        VerificationResult<JsonPayload> result = new DefaultVerifier(config, injected).verifySignedData(jws);
        Failure failure = result.failure();
        assertNotNull(failure);
        assertEquals(Reason.CERTIFICATE_REVOKED, failure.reason());
        assertEquals("x5c certificate with serial 1A is revoked: built-in list", failure.message());
    }

    /**
     * A built-in issuer that is not an Apple certificate counts once it
     * chains to the configured roots: its list URL is reported, and a list
     * older than the newest it records is refused.
     */
    @Test
    void anInjectedBuiltInIssuerChainsToCustomRoots() throws Exception {
        String issuer = "{\"id\":\"" + TEST_INTERMEDIATE + "\",\"certificate\":\"intermediate\","
                + "\"list\":\"http://crl.example.test/injected.crl\","
                + "\"newest\":{\"crlNumber\":\"%s\",\"thisUpdate\":\"2026-11-01T00:00:00Z\"}}";
        Config fresh = testConfig()
                .revocationLists(Collections.singletonList(testBytes("crl-fresh-empty.der")))
                .build();
        // The fresh list's CRL Number is 10, 0A in hex: equal to newest is not older.
        DefaultVerifier current = new DefaultVerifier(fresh, builtIn("[" + String.format(issuer, "0A") + "]", "[]"));
        assertEquals(Collections.singletonList("http://crl.example.test/injected.crl"), current.revocationUrls());
        assertEquals(Instant.parse("2026-12-01T00:00:00Z"), current.revocationValidUntil());

        IllegalArgumentException older = assertThrows(
                IllegalArgumentException.class,
                () -> new DefaultVerifier(fresh, builtIn("[" + String.format(issuer, "0B") + "]", "[]")));
        assertTrue(older.getMessage().contains("revocationLists[0] is older than the newest list"), older.getMessage());
    }

    // ------------------------------------------------------------ messages

    /** The message names the layer and the serial, and nothing else from the input. */
    @Test
    void theMessageNamesTheLayerAndTheSerial() throws Exception {
        String jws = testText("jws.jws");
        Verifier distrusted = Verifier.create(testConfig()
                .distrust(Collections.singletonList(new RevokedCertificate(TEST_INTERMEDIATE.toUpperCase(), "0002")))
                .build());
        assertEquals(
                "x5c certificate with serial 02 is revoked: distrust",
                distrusted.verifySignedData(jws).failure().message());
        Verifier listed = Verifier.create(testConfig()
                .revocationIssuers(Collections.singletonList(testCertificate("intermediate.der")))
                .revocationLists(Collections.singletonList(testBytes("crl-fresh-revokes-leaves.der")))
                .build());
        assertEquals(
                "x5c certificate with serial 02 is revoked: Apple's list",
                listed.verifySignedData(jws).failure().message());
    }

    /** CERTIFICATE_REVOKED at the endpoint is 21003, as for every other certificate failure. */
    @Test
    void theEndpointAnswersARevokedReceipt21003() throws Exception {
        String receipt = java.util.Base64.getEncoder().encodeToString(testBytes("receipt.der"));
        String request = "{\"receipt-data\":\"" + receipt + "\"}";
        Verifier distrusted = Verifier.create(testConfig()
                .distrust(Collections.singletonList(new RevokedCertificate(TEST_ROOT, "1A")))
                .build());
        assertEquals(
                Reason.CERTIFICATE_REVOKED,
                distrusted.verifyReceipt(receipt).failure().reason());
        assertEquals("{\"status\":21003}", distrusted.verifyReceiptEndpoint(Environment.SANDBOX, request));
    }

    // ------------------------------------------------------------- the API

    /** A caller's own Verifier compiles without the two properties and reports nothing. */
    @Test
    void aSubstituteVerifierReportsNoRevocationState() {
        Verifier substitute = new Verifier() {
            @Override
            public VerificationResult<ReceiptPayload> verifyReceipt(@Nullable String base64) {
                throw new UnsupportedOperationException();
            }

            @Override
            public VerificationResult<JsonPayload> verifySignedData(@Nullable String jws) {
                throw new UnsupportedOperationException();
            }

            @Override
            public String verifyReceiptEndpoint(Environment environment, @Nullable String requestJson) {
                throw new UnsupportedOperationException();
            }
        };
        assertEquals(Collections.emptyList(), substitute.revocationUrls());
        assertNull(substitute.revocationValidUntil());
    }

    /** The default verifier: the four Apple list URLs, nothing held, so null. */
    @Test
    void theDefaultsReportTheFourAppleListsAndNoValidity() {
        Verifier verifier = Verifier.create(Config.defaults());
        assertEquals(
                Arrays.asList(
                        "http://crl.apple.com/root.crl",
                        "http://crl.apple.com/applerootcag3.crl",
                        "http://crl.apple.com/wwdrg5.crl",
                        "http://crl.apple.com/wwdrg6.crl"),
                verifier.revocationUrls());
        assertNull(verifier.revocationValidUntil());
        assertThrows(
                UnsupportedOperationException.class,
                () -> verifier.revocationUrls().clear());
    }

    /** Config copies the lists in and out, so no caller can change a verifier's lists after the fact. */
    @Test
    void theConfigCopiesItsLists() {
        byte[] list = {1, 2, 3};
        List<byte[]> given = new ArrayList<byte[]>(Collections.singletonList(list));
        Config config = Config.builder().revocationLists(given).build();
        list[0] = 9;
        given.clear();
        assertArrayEquals(new byte[] {1, 2, 3}, config.revocationLists().get(0));
        config.revocationLists().get(0)[0] = 9;
        assertArrayEquals(new byte[] {1, 2, 3}, config.revocationLists().get(0));
        assertThrows(
                UnsupportedOperationException.class,
                () -> config.revocationLists().clear());
        Config full = Config.builder()
                .distrust(Collections.singletonList(new RevokedCertificate(TEST_ROOT, "1")))
                .revocationIssuers(Collections.singletonList(
                        AppleRootCerts.roots().iterator().next()))
                .build();
        assertThrows(UnsupportedOperationException.class, () -> full.distrust().clear());
        assertThrows(
                UnsupportedOperationException.class,
                () -> full.revocationIssuers().clear());
        assertThrows(NullPointerException.class, () -> new RevokedCertificate(TEST_ROOT, null));
        assertEquals(new RevokedCertificate("ab", "1"), new RevokedCertificate("ab", "1"));
    }

    // ------------------------------------------------------------- helpers

    private static Config.Builder testConfig() throws Exception {
        return Config.builder()
                .roots(Collections.singletonList(testCertificate("root.der")))
                .clock(CASES_CLOCK);
    }

    private static String refusal(Config.Builder builder) {
        return assertThrows(IllegalArgumentException.class, () -> Verifier.create(builder.build()))
                .getMessage();
    }

    /** A built-in list with {@code issuers} and {@code revoked} as JSON arrays; "intermediate" is the test one. */
    private static BuiltInRevocations builtIn(String issuers, String revoked) {
        String json = "{\"comment\":\"test\",\"issuers\":" + issuers + ",\"revoked\":" + revoked + "}";
        return BuiltInRevocations.parse(json.getBytes(StandardCharsets.UTF_8), path -> {
            try {
                return "intermediate".equals(path) ? testBytes("intermediate.der") : null;
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
    }

    /** An unsigned-in-effect list (a throwaway key) with {@code count} entries. */
    private static byte[] entries(int count) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", BouncyCastle.PROVIDER);
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair key = generator.generateKeyPair();
        Date now = new Date(1_790_000_000_000L);
        X509v2CRLBuilder builder = new X509v2CRLBuilder(new X500Name("CN=APRV bound test"), now);
        builder.setNextUpdate(new Date(now.getTime() + 86_400_000L));
        for (int i = 1; i <= count; i++) {
            builder.addCRLEntry(BigInteger.valueOf(i), now, (Extensions) null);
        }
        return builder.build(new JcaContentSignerBuilder("SHA256withECDSA")
                        .setProvider(BouncyCastle.PROVIDER)
                        .build(key.getPrivate()))
                .getEncoded();
    }

    private static byte[] testBytes(String name) throws Exception {
        return Files.readAllBytes(
                TestFixtures.root().resolve("generated-0.7/revocation").resolve(name));
    }

    private static String testText(String name) throws Exception {
        return new String(testBytes(name), StandardCharsets.UTF_8).trim();
    }

    private static X509Certificate testCertificate(String name) throws Exception {
        return (X509Certificate)
                CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(testBytes(name)));
    }

    private static String sha256(byte[] bytes) throws Exception {
        StringBuilder hex = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(bytes)) {
            hex.append(String.format("%02x", Byte.valueOf(b)));
        }
        return hex.toString();
    }
}
