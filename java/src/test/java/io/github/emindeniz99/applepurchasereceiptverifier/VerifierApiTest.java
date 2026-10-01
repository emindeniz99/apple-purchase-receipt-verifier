package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Provider;
import java.security.ProviderException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * The public 0.7 surface as a caller meets it: the never-throw contract and
 * its one exception, the result and failure types, the parse-before-signature
 * rule, the JSON value of {@link ReceiptPayload#toJson()}, the model
 * types' copy semantics, and the helpers.
 */
class VerifierApiTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static Verifier verifier() {
        return Checks.verifier(SyntheticReceipts.root());
    }

    // ------------------------------------------------------------ contract

    @Test
    void aNullOrEmptyInputIsMalformedNotAThrow() {
        Verifier verifier = verifier();
        for (String input : new String[] {null, ""}) {
            assertEquals(
                    Reason.MALFORMED, verifier.verifyReceipt(input).failure().reason());
            assertEquals(
                    Reason.MALFORMED, verifier.verifySignedData(input).failure().reason());
            for (Environment environment : Environment.values()) {
                assertEquals("{\"status\":21002}", verifier.verifyReceiptEndpoint(environment, input));
            }
        }
    }

    @Test
    void aNullConfigOrEnvironmentIsAProgrammingError() {
        assertThrows(NullPointerException.class, () -> Verifier.create(null));
        assertThrows(NullPointerException.class, () -> verifier().verifyReceiptEndpoint(null, "{}"));
        assertThrows(NullPointerException.class, () -> Config.builder().clock(null));
    }

    @Test
    void anEmptyRootSetIsRefusedAtCreate() {
        Config empty =
                Config.builder().roots(Collections.<X509Certificate>emptySet()).build();
        assertTrue(empty.roots().isEmpty(), "the config itself may hold an empty set");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Verifier.create(empty));
        assertTrue(e.getMessage().contains("empty"), e.getMessage());
    }

    @Test
    void theDefaultsAreApplesThreeRootsAndTheSystemClock() {
        Config defaults = Config.defaults();
        assertEquals(3, defaults.roots().size());
        assertEquals(Clock.systemUTC(), defaults.clock());
        // Unset roots in a builder are the defaults too, so setting only the
        // clock keeps Apple's roots.
        assertEquals(
                defaults.roots(),
                Config.builder().clock(Clock.systemDefaultZone()).build().roots());
    }

    @Test
    void theConfigCopiesItsRootsAndHandsOutAnUnmodifiableSet() {
        Set<X509Certificate> roots = new LinkedHashSet<X509Certificate>();
        roots.add(SyntheticReceipts.root());
        Config config = Config.builder().roots(roots).build();
        roots.clear();
        assertEquals(1, config.roots().size());
        assertThrows(UnsupportedOperationException.class, () -> config.roots().clear());
        assertThrows(NullPointerException.class, () -> Config.builder().roots(Arrays.asList((X509Certificate) null)));
    }

    @Test
    void aResultCarriesExactlyOneOfPayloadAndFailure() throws Exception {
        Verifier verifier = verifier();
        List<VerificationResult<?>> results = new ArrayList<VerificationResult<?>>();
        results.add(verifier.verifyReceipt(SyntheticReceipts.base64()));
        results.add(verifier.verifyReceipt(Base64.getEncoder().encodeToString(SyntheticReceipts.tamperedDer())));
        results.add(verifier.verifyReceipt("AQIDBA=="));
        results.add(verifier.verifySignedData("a.b.c"));
        for (VerificationResult<?> result : results) {
            assertEquals(result.verified(), result.payload() != null, result.toString());
            assertEquals(result.verified(), result.failure() == null, result.toString());
        }
        assertTrue(results.get(0).verified());
        assertFalse(results.get(1).verified());
    }

    @Test
    void resultsAndFailuresCanBeBuiltForAMockedVerifier() {
        JsonPayload payload = new JsonPayload("{}");
        assertEquals(payload, VerificationResult.of(payload).payload());
        Failure failure = new Failure(Reason.UNTRUSTED_CHAIN, "a message", null);
        VerificationResult<JsonPayload> failed = VerificationResult.failed(failure);
        assertFalse(failed.verified());
        assertEquals(failure, failed.failure());
        assertThrows(NullPointerException.class, () -> VerificationResult.of(null));
        assertThrows(NullPointerException.class, () -> VerificationResult.failed(null));
        assertEquals(VerificationResult.of(payload), VerificationResult.of(new JsonPayload("{}")));
    }

    /**
     * The cause is kept for what an operator must see (the parser's exception
     * behind Apple-signed content that does not parse) and dropped for every
     * verdict about unverified input, whose parser messages can quote raw
     * certificate text.
     */
    @Test
    void theCauseIsKeptOnlyBehindUnreadablePayloadAndInternalError() throws Exception {
        Verifier verifier = verifier();
        Failure unreadable = verifier.verifyReceipt(Base64.getEncoder()
                        .encodeToString(SyntheticReceipts.pki().signReceipt(new byte[] {0x31, 0x05, 0x01})))
                .failure();
        assertEquals(Reason.UNREADABLE_PAYLOAD, unreadable.reason());
        assertNotNull(unreadable.cause(), "the parser's exception is the cause");

        Failure notBase64 = verifier.verifyReceipt("not base64!!").failure();
        assertEquals(Reason.MALFORMED, notBase64.reason());
        assertNull(notBase64.cause());

        Failure foreign = verifier.verifyReceipt(
                        Base64.getEncoder().encodeToString(TestPki.receipt().signReceipt(new byte[] {0x31, 0})))
                .failure();
        assertEquals(Reason.UNTRUSTED_CHAIN, foreign.reason());
        assertNull(foreign.cause());
    }

    // ----------------------------------------------- parse after signature

    /**
     * A payload inside a well-formed envelope that does not parse is carried
     * past the chain and signature checks: UNREADABLE_PAYLOAD when the
     * signature verifies, INVALID_SIGNATURE when it does not, the chain's
     * verdict when the chain fails. Never MALFORMED, which would let an
     * unverified sender choose the reason a caller sees.
     */
    @Test
    void anUnparseableReceiptPayloadIsJudgedAfterTheSignature() throws Exception {
        byte[] notAsn1 = {0x31, 0x05, 0x01};
        byte[] signed = SyntheticReceipts.pki().signReceipt(notAsn1);
        assertEquals(Reason.UNREADABLE_PAYLOAD, reason(signed));
        assertEquals(Reason.INVALID_SIGNATURE, reason(TestPki.corruptSignatures(signed, 1)));
        assertEquals(Reason.UNTRUSTED_CHAIN, reason(TestPki.receipt().signReceipt(notAsn1)));
    }

    /** A broken envelope is MALFORMED before any cryptography. */
    @Test
    void aBrokenEnvelopeIsMalformed() throws Exception {
        assertEquals(
                Reason.MALFORMED, verifier().verifyReceipt("AQIDBA==").failure().reason());
        byte[] genuine = SyntheticReceipts.der();
        assertEquals(Reason.MALFORMED, reason(Arrays.copyOf(genuine, genuine.length - 1)));
    }

    private static Reason reason(byte[] der) {
        return verifier()
                .verifyReceipt(Base64.getEncoder().encodeToString(der))
                .failure()
                .reason();
    }

    // ---------------------------------------------------------------- JSON

    /** Ports agree on the value of toJson(), not its bytes: compare parsed trees. */
    private static void assertSameJsonValue(String expected, String actual) throws Exception {
        assertEquals(MAPPER.readTree(expected), MAPPER.readTree(actual), actual);
    }

    private static ReceiptPayload withAttributes(Map<Integer, List<byte[]>> unknown) {
        return new ReceiptPayload(
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                Collections.<InAppPurchase>emptyList(),
                null,
                null,
                null,
                unknown);
    }

    @Test
    void toJsonWritesEveryKeyWithNullForMissing() throws Exception {
        ReceiptPayload empty = new ReceiptPayload(
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                Collections.<InAppPurchase>emptyList(),
                null,
                null,
                null,
                Collections.<Integer, List<byte[]>>emptyMap());
        assertSameJsonValue(
                "{\"receipt_type\":null,\"app_item_id\":null,\"bundle_id\":null,\"bundle_id_bytes\":null,"
                        + "\"application_version\":null,\"opaque_value\":null,\"sha1_hash\":null,"
                        + "\"receipt_creation_date_ms\":null,\"download_id\":null,"
                        + "\"version_external_identifier\":null,\"in_app\":[],\"original_purchase_date_ms\":null,"
                        + "\"original_application_version\":null,\"expiration_date_ms\":null,"
                        + "\"unknown_attributes\":{}}",
                empty.toJson());
    }

    /**
     * The value every port must produce: ids as strings, dates as numbers,
     * padded base64, and strings that survive escaping (control characters,
     * {@code /}, non-ASCII) unchanged.
     */
    @Test
    void toJsonHasTheDesignsValue() throws Exception {
        Map<Integer, List<byte[]>> unknown = new LinkedHashMap<Integer, List<byte[]>>();
        unknown.put(13, Arrays.asList(new byte[] {1}, new byte[] {(byte) 0xfb, (byte) 0xff}));
        unknown.put(9, Collections.<byte[]>emptyList());
        Map<Integer, List<byte[]>> purchaseUnknown = new LinkedHashMap<Integer, List<byte[]>>();
        purchaseUnknown.put(1720, Arrays.asList(new byte[] {0}));
        InAppPurchase purchase = new InAppPurchase(
                1L,
                "com.example.é中😀/\"q\"\\\n\u001f\u007f ",
                "2000000000000001",
                1705320000000L,
                "2000000000000001",
                1705320000000L,
                null,
                123456789012345678L,
                null,
                Boolean.TRUE,
                Boolean.FALSE,
                purchaseUnknown);
        ReceiptPayload payload = new ReceiptPayload(
                "ProductionSandbox",
                0L,
                "com.example.app",
                "com.example.app".getBytes(StandardCharsets.UTF_8),
                "1.2.3",
                new byte[] {1, 2, 3, 4, 5},
                new byte[] {-1},
                1722945600000L,
                9223372036854775807L,
                -1L,
                Arrays.asList(purchase),
                1722945600000L,
                "1.0",
                null,
                unknown);
        assertSameJsonValue(
                "{\"receipt_type\":\"ProductionSandbox\",\"app_item_id\":\"0\",\"bundle_id\":\"com.example.app\","
                        + "\"bundle_id_bytes\":\"Y29tLmV4YW1wbGUuYXBw\",\"application_version\":\"1.2.3\","
                        + "\"opaque_value\":\"AQIDBAU=\",\"sha1_hash\":\"/w==\","
                        + "\"receipt_creation_date_ms\":1722945600000,\"download_id\":\"9223372036854775807\","
                        + "\"version_external_identifier\":\"-1\",\"in_app\":[{\"quantity\":1,"
                        + "\"product_id\":\"com.example.é中😀/\\\"q\\\"\\\\\\n\\u001f\u007f \","
                        + "\"transaction_id\":\"2000000000000001\",\"purchase_date_ms\":1705320000000,"
                        + "\"original_transaction_id\":\"2000000000000001\",\"original_purchase_date_ms\":1705320000000,"
                        + "\"expires_date_ms\":null,\"web_order_line_item_id\":\"123456789012345678\","
                        + "\"cancellation_date_ms\":null,\"is_trial_period\":true,\"is_in_intro_offer_period\":false,"
                        + "\"unknown_attributes\":{\"1720\":[\"AA==\"]}}],"
                        + "\"original_purchase_date_ms\":1722945600000,\"original_application_version\":\"1.0\","
                        + "\"expiration_date_ms\":null,\"unknown_attributes\":{\"9\":[],\"13\":[\"AQ==\",\"+/8=\"]}}",
                payload.toJson());
        assertEquals(payload.toJson(), payload.toString());
    }

    @Test
    void toJsonIsValidUtf8EvenForALoneSurrogate() throws Exception {
        // Either half of a surrogate pair alone is no character UTF-8 can
        // carry. toJson() escapes it, so the text stays ASCII and the string
        // parses back unchanged.
        InAppPurchase purchase = new InAppPurchase(
                null,
                "a\uD83D|\uDE00b|\uD83D\uDE00",
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                Collections.<Integer, List<byte[]>>emptyMap());
        ReceiptPayload payload = new ReceiptPayload(
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                Arrays.asList(purchase),
                null,
                null,
                null,
                Collections.<Integer, List<byte[]>>emptyMap());
        String json = payload.toJson();
        for (int i = 0; i < json.length(); i++) {
            assertTrue(json.charAt(i) < 0x80, json);
        }
        assertEquals(
                "a\uD83D|\uDE00b|\uD83D\uDE00",
                MAPPER.readTree(json).get("in_app").get(0).get("product_id").asText());
    }

    @Test
    void unknownAttributesAreEqualExactlyWhenTheirJsonValueIs() throws Exception {
        // The order types were collected in is not part of the value; each
        // type's own list order is.
        Map<Integer, List<byte[]>> ascending = new LinkedHashMap<Integer, List<byte[]>>();
        ascending.put(9, Collections.singletonList(new byte[] {1}));
        ascending.put(13, Arrays.asList(new byte[] {2}, new byte[] {3}));
        Map<Integer, List<byte[]>> descending = new LinkedHashMap<Integer, List<byte[]>>();
        descending.put(13, Arrays.asList(new byte[] {2}, new byte[] {3}));
        descending.put(9, Collections.singletonList(new byte[] {1}));
        Map<Integer, List<byte[]>> reordered = new LinkedHashMap<Integer, List<byte[]>>();
        reordered.put(9, Collections.singletonList(new byte[] {1}));
        reordered.put(13, Arrays.asList(new byte[] {3}, new byte[] {2}));

        assertSameJsonValue(
                withAttributes(ascending).toJson(), withAttributes(descending).toJson());
        assertEquals(withAttributes(ascending), withAttributes(descending));
        assertEquals(
                withAttributes(ascending).hashCode(), withAttributes(descending).hashCode());
        assertNotEquals(
                MAPPER.readTree(withAttributes(ascending).toJson()),
                MAPPER.readTree(withAttributes(reordered).toJson()));
        assertNotEquals(withAttributes(ascending), withAttributes(reordered));
    }

    /** The JSON of a verified receipt parses back to the getters, key for key. */
    @Test
    void toJsonOfAVerifiedReceiptMatchesItsGetters() throws Exception {
        ReceiptPayload payload =
                verifier().verifyReceipt(SyntheticReceipts.base64()).payload();
        JsonNode json = MAPPER.readTree(payload.toJson());
        List<String> keys = new ArrayList<String>();
        for (Iterator<String> names = json.fieldNames(); names.hasNext(); ) {
            keys.add(names.next());
        }
        assertEquals(
                Arrays.asList(
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
                        "unknown_attributes"),
                keys);
        assertEquals(payload.bundleId(), json.get("bundle_id").asText());
        assertArrayEquals(
                payload.bundleIdBytes(),
                Base64.getDecoder().decode(json.get("bundle_id_bytes").asText()));
        assertEquals(1722945600000L, json.get("receipt_creation_date_ms").asLong());
        assertEquals(1722945600000L, payload.receiptCreationDateMs().longValue());
        assertTrue(json.get("app_item_id").isNull());
        assertEquals(2, json.get("in_app").size());
        assertEquals(
                "42", json.get("in_app").get(0).get("web_order_line_item_id").asText());
        assertTrue(json.get("in_app").get(0).get("is_trial_period").isNull());
        assertEquals("AQID", json.get("unknown_attributes").get("9999").get(0).asText());
    }

    // ------------------------------------------------------------ models

    @Test
    void bytesAndUnknownAttributesAreCopiedInAndOut() {
        byte[] opaque = {1, 2, 3};
        List<byte[]> values = new ArrayList<byte[]>(Arrays.asList(new byte[] {7}));
        Map<Integer, List<byte[]>> unknown = new LinkedHashMap<Integer, List<byte[]>>();
        unknown.put(13, values);
        ReceiptPayload payload = new ReceiptPayload(
                null,
                null,
                null,
                null,
                null,
                opaque,
                null,
                null,
                null,
                null,
                Collections.<InAppPurchase>emptyList(),
                null,
                null,
                null,
                unknown);
        opaque[0] = 9;
        values.get(0)[0] = 9;
        values.add(new byte[] {8});
        unknown.put(14, values);
        assertArrayEquals(new byte[] {1, 2, 3}, payload.opaqueValue());
        assertEquals(Collections.singleton(13), payload.unknownAttributes().keySet());
        assertArrayEquals(new byte[] {7}, payload.unknownAttributes().get(13).get(0));

        payload.opaqueValue()[0] = 9;
        payload.unknownAttributes().get(13).get(0)[0] = 9;
        assertArrayEquals(new byte[] {1, 2, 3}, payload.opaqueValue());
        assertArrayEquals(new byte[] {7}, payload.unknownAttributes().get(13).get(0));
        assertThrows(
                UnsupportedOperationException.class,
                () -> payload.unknownAttributes().put(1, values));
        assertThrows(UnsupportedOperationException.class, () -> payload.inApp().add(null));
    }

    @Test
    void theModelsCompareByValue() {
        ReceiptPayload first =
                verifier().verifyReceipt(SyntheticReceipts.base64()).payload();
        ReceiptPayload second =
                verifier().verifyReceipt(SyntheticReceipts.base64()).payload();
        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
        assertEquals(first.inApp().get(0), second.inApp().get(0));
        assertNotEquals(first.inApp().get(0), first.inApp().get(1));
        ReceiptPayload rebuilt = new ReceiptPayload(
                first.receiptType(),
                first.appItemId(),
                first.bundleId(),
                first.bundleIdBytes(),
                first.applicationVersion(),
                first.opaqueValue(),
                first.sha1Hash(),
                first.receiptCreationDateMs(),
                first.downloadId(),
                first.versionExternalIdentifier(),
                first.inApp(),
                first.originalPurchaseDateMs(),
                first.originalApplicationVersion(),
                first.expirationDateMs(),
                first.unknownAttributes());
        assertEquals(first, rebuilt);
        assertEquals(first.toJson(), rebuilt.toJson());
    }

    // ------------------------------------------------------------ helpers

    @Test
    void environmentMapsApplesValuesAndDecidesNothing() {
        assertEquals(Environment.PRODUCTION, Environment.fromReceiptType("Production"));
        assertEquals(Environment.PRODUCTION, Environment.fromReceiptType("ProductionVPP"));
        assertEquals(Environment.SANDBOX, Environment.fromReceiptType("ProductionSandbox"));
        assertEquals(Environment.SANDBOX, Environment.fromReceiptType("ProductionVPPSandbox"));
        for (String other : Arrays.asList("Xcode", "Sandbox", "production", "", null)) {
            assertNull(Environment.fromReceiptType(other), String.valueOf(other));
        }
        assertEquals(Environment.PRODUCTION, Environment.fromJwsEnvironment("Production"));
        assertEquals(Environment.SANDBOX, Environment.fromJwsEnvironment("Sandbox"));
        for (String other : Arrays.asList("Xcode", "LocalTesting", "ProductionSandbox", "sandbox", "", null)) {
            assertNull(Environment.fromJwsEnvironment(other), String.valueOf(other));
        }
        assertEquals(2, Environment.values().length);
    }

    @Test
    void appleStatusNamesApplesCodes() {
        assertEquals(0, AppleStatus.OK);
        assertEquals(21002, AppleStatus.MALFORMED_RECEIPT_DATA);
        assertEquals(21003, AppleStatus.RECEIPT_NOT_AUTHENTICATED);
        assertEquals(21005, AppleStatus.SERVER_UNAVAILABLE);
        assertEquals(21007, AppleStatus.SANDBOX_RECEIPT_ON_PRODUCTION);
        assertEquals(21008, AppleStatus.PRODUCTION_RECEIPT_ON_SANDBOX);
        assertEquals(21009, AppleStatus.INTERNAL_DATA_ACCESS_ERROR);
        assertEquals(21010, AppleStatus.ACCOUNT_NOT_FOUND);
        assertEquals(21100, AppleStatus.INTERNAL_DATA_ACCESS_ERROR_RANGE_FIRST);
        assertEquals(21199, AppleStatus.INTERNAL_DATA_ACCESS_ERROR_RANGE_LAST);
    }

    /** Version.CURRENT and the pom move together (release-please bumps both). */
    @Test
    void theVersionConstantIsThePomVersion() throws Exception {
        String pom = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        Matcher version = Pattern.compile(
                        "<artifactId>apple-purchase-receipt-verifier</artifactId>\\s*<version>([^<]+)</version>")
                .matcher(pom);
        assertTrue(version.find(), "no project version in pom.xml");
        assertEquals(version.group(1), Version.CURRENT);
    }

    /**
     * Static state built on first use (the bounded Jackson factories, the
     * BouncyCastle provider) is built by Verifier.create, so a dependency
     * below its floor fails there and not inside a verify method documented
     * never to throw.
     */
    @Test
    void aClassWhoseStaticStateFailsFailsConstructionWithTheDependencyFloor() {
        Runnable broken = () -> assertEquals(0, BrokenStaticState.VALUE);
        IllegalStateException first =
                assertThrows(IllegalStateException.class, () -> DefaultVerifier.initialise(broken));
        assertTrue(first.getCause() instanceof ExceptionInInitializerError, String.valueOf(first.getCause()));
        assertTrue(first.getMessage().contains("jackson-core 2.16"), first.getMessage());
        // The floors are a guess; the real error is named, since it may be
        // something else, such as a JRE whose tzdb lacks the Pacific zone.
        assertTrue(first.getMessage().contains(ExceptionInInitializerError.class.getName()), first.getMessage());
        assertTrue(first.getMessage().contains("as a missing Jackson method would"), first.getMessage());
        // A second attempt meets the class already failed, which is a
        // NoClassDefFoundError: reported the same way.
        IllegalStateException second =
                assertThrows(IllegalStateException.class, () -> DefaultVerifier.initialise(broken));
        assertTrue(second.getCause() instanceof NoClassDefFoundError, String.valueOf(second.getCause()));
        // The real classes initialise.
        assertNotNull(Verifier.create(Config.defaults()));
    }

    /**
     * The decoders catch only RuntimeException, so a BouncyCastle class they
     * link against that is missing from an older jar (ASN1UTF8String and
     * ASN1IA5String arrived in bcprov 1.70) would throw a LinkageError out of
     * verifyReceipt, which must not throw. Verifier.create loads each of them
     * first, so the old jar fails there instead.
     */
    @Test
    void theStaticStateLoadsEveryBouncyCastleClassTheDecodersName() throws Exception {
        String dir = "src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/";
        String verifier =
                new String(Files.readAllBytes(Paths.get(dir, "DefaultVerifier.java")), StandardCharsets.UTF_8);
        Matcher body =
                Pattern.compile("void buildStaticState\\(\\) \\{([^}]*)}").matcher(verifier);
        assertTrue(body.find(), "no buildStaticState in DefaultVerifier.java");
        Pattern bouncyCastleImport = Pattern.compile("(?m)^import (org\\.bouncycastle\\.[\\w.]*\\.(\\w+));$");
        int scanned = 0;
        for (String decoder : Arrays.asList("ReceiptDecoder.java", "JwsCore.java")) {
            String code = new String(Files.readAllBytes(Paths.get(dir, decoder)), StandardCharsets.UTF_8);
            Matcher imported = bouncyCastleImport.matcher(code);
            while (imported.find()) {
                scanned++;
                assertTrue(
                        verifier.contains("import " + imported.group(1) + ";")
                                && body.group(1).contains("requireNonNull(" + imported.group(2) + ".class);"),
                        decoder + " links against " + imported.group(1)
                                + ", which buildStaticState does not load, so an old bcprov fails a verify call");
            }
        }
        assertTrue(scanned > 0, "no BouncyCastle import was found, so the check above scanned nothing");
    }

    /**
     * The probe checks each bundled root's own signature, so a healthy JVM
     * must verify all three on the BouncyCastle provider, the SHA-1 RSA root
     * included, or every deployment would fail at create.
     */
    @Test
    void eachBundledRootVerifiesItsOwnSignatureOnBouncyCastle() throws Exception {
        assertEquals(3, AppleRootCerts.roots().size());
        for (X509Certificate root : AppleRootCerts.roots()) {
            root.verify(root.getPublicKey(), BouncyCastle.PROVIDER);
        }
        DefaultVerifier.probeRuntime(BouncyCastle.PROVIDER, AppleRootCerts.roots());
        assertNotNull(Verifier.create(Config.defaults()));
    }

    /**
     * A runtime that cannot verify must fail at create, where a deployment
     * sees it, and not answer INTERNAL_ERROR on the first request.
     */
    @Test
    void aProviderWithoutTheEnginesFailsTheProbe() {
        Provider empty = new Provider("Empty", 1.0, "offers no services") {
            private static final long serialVersionUID = 1L;
        };
        IllegalStateException e = assertThrows(
                IllegalStateException.class, () -> DefaultVerifier.probeRuntime(empty, AppleRootCerts.roots()));
        assertTrue(e.getMessage().startsWith("this runtime cannot verify Apple signatures"), e.getMessage());
        assertNotNull(e.getCause());
    }

    /**
     * A FIPS or stripped provider can throw ProviderException, which is
     * unchecked. Verifier.create promises IllegalStateException for a runtime
     * that cannot verify, so the probe must not let it escape as it is.
     */
    @Test
    void aProviderThatThrowsUncheckedFailsTheProbeAsIllegalState() {
        ProviderException boom = new ProviderException("boom");
        Provider throwing = new Provider("Throwing", 1.0, "throws on every lookup") {
            private static final long serialVersionUID = 1L;

            @Override
            public synchronized Service getService(String type, String algorithm) {
                throw boom;
            }
        };
        IllegalStateException e = assertThrows(
                IllegalStateException.class, () -> DefaultVerifier.probeRuntime(throwing, AppleRootCerts.roots()));
        assertTrue(e.getMessage().startsWith("this runtime cannot verify Apple signatures"), e.getMessage());
        assertEquals(boom, e.getCause());
    }

    /** The probe is on unless turned off, and turning it off still builds a verifier. */
    @Test
    void theRuntimeProbeIsOnByDefaultAndCanBeTurnedOff() {
        assertTrue(Config.defaults().runtimeProbe());
        assertTrue(Config.builder().build().runtimeProbe());
        Config off = Config.builder().runtimeProbe(false).build();
        assertFalse(off.runtimeProbe());
        assertNotNull(Verifier.create(off));
    }

    /** Stands in for a class whose static initialiser meets a dependency below its floor. */
    static final class BrokenStaticState {
        static final int VALUE = fail();

        private static int fail() {
            throw new UnsupportedOperationException("as a missing Jackson method would");
        }
    }

    /**
     * Only the API types are public; the implementation is package-private.
     * The implementation side is every other top-level class compiled into
     * the package, read from the build output, so a class added later is
     * checked without being listed here.
     */
    @Test
    void onlyTheApiTypesArePublic() throws Exception {
        List<Class<?>> api = Arrays.<Class<?>>asList(
                Verifier.class,
                Config.class,
                Config.Builder.class,
                VerificationResult.class,
                Failure.class,
                Reason.class,
                ReceiptPayload.class,
                InAppPurchase.class,
                JsonPayload.class,
                Environment.class,
                Version.class,
                AppleStatus.class);
        for (Class<?> type : api) {
            assertTrue(java.lang.reflect.Modifier.isPublic(type.getModifiers()), type.getName());
        }
        java.nio.file.Path packageDir = Paths.get(Verifier.class
                        .getProtectionDomain()
                        .getCodeSource()
                        .getLocation()
                        .toURI())
                .resolve(Verifier.class.getPackage().getName().replace('.', '/'));
        List<String> implementation = new ArrayList<String>();
        try (java.nio.file.DirectoryStream<java.nio.file.Path> classes =
                Files.newDirectoryStream(packageDir, "*.class")) {
            for (java.nio.file.Path file : classes) {
                String simple = file.getFileName().toString().replace(".class", "");
                if (simple.contains("$") || simple.equals("package-info")) {
                    continue;
                }
                Class<?> type = Class.forName(Verifier.class.getPackage().getName() + "." + simple);
                if (!api.contains(type)) {
                    implementation.add(simple);
                    assertFalse(java.lang.reflect.Modifier.isPublic(type.getModifiers()), type.getName());
                }
            }
        }
        // The scan found the build output, including the newest classes.
        assertTrue(implementation.contains("ReceiptDecoder"), implementation.toString());
        assertTrue(implementation.contains("Endpoint"), implementation.toString());
        assertTrue(implementation.contains("ReceiptCertificates"), implementation.toString());
    }
}
