package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.InAppPurchase;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class ReceiptVerifierTest {

    private static final String BUNDLE = "com.example.app";
    private static final byte[] GUID = {
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        (byte) 0x88,
        (byte) 0x99,
        (byte) 0xaa,
        (byte) 0xbb,
        (byte) 0xcc,
        (byte) 0xdd,
        (byte) 0xee,
        (byte) 0xff,
        0x00
    };
    private static final byte[] OPAQUE = {1, 2, 3, 4, 5, 6, 7, 8};

    private static TestPki pki;
    private static Instant creationDate;
    private static byte[] receiptDer;

    @BeforeAll
    static void setUp() throws Exception {
        pki = TestPki.receipt();
        creationDate = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        receiptDer = pki.signReceipt(payload(BUNDLE, creationDate.toString()));
    }

    private static byte[] payload(String bundleId, String creationDate) throws Exception {
        byte[] hash = TestPki.deviceHash(GUID, OPAQUE, bundleId);
        List<byte[]> inApps = Arrays.asList(
                TestPki.inAppPurchase(
                        1,
                        "com.example.app.coins100",
                        "70000000000001",
                        "70000000000001",
                        "2024-01-15T12:00:00Z",
                        null),
                TestPki.inAppPurchase(
                        1,
                        "com.example.app.vip",
                        "70000000000002",
                        "70000000000002",
                        "2024-02-01T09:30:00Z",
                        "2030-02-01T09:30:00Z"));
        return TestPki.receiptPayload(bundleId, "1.2.3", OPAQUE, hash, creationDate, inApps);
    }

    private static ReceiptVerifier verifier(TestPki trustedPki, String bundleId) {
        return new ReceiptVerifier(Collections.singleton(trustedPki.root), bundleId);
    }

    private static InAppPurchase byProduct(AppReceipt receipt, String productId) {
        for (InAppPurchase p : receipt.inAppPurchases()) {
            if (productId.equals(p.productId())) {
                return p;
            }
        }
        throw new AssertionError("no purchase with productId " + productId);
    }

    @Test
    void verifiesGenuineReceipt() throws Exception {
        AppReceipt receipt = verifier(pki, BUNDLE).verify(receiptDer);
        assertEquals(BUNDLE, receipt.bundleId());
        assertEquals("1.2.3", receipt.appVersion());
        assertEquals("1.0", receipt.originalAppVersion());
        assertEquals(creationDate, receipt.creationDate());
        assertNull(receipt.expirationDate());
        assertArrayEquals(OPAQUE, receipt.opaqueValue());
        assertEquals(2, receipt.inAppPurchases().size());

        InAppPurchase coins = byProduct(receipt, "com.example.app.coins100");
        assertEquals("70000000000001", coins.transactionId());
        assertEquals(Long.valueOf(1), coins.quantity());
        assertEquals(Instant.parse("2024-01-15T12:00:00Z"), coins.purchaseDate());
        assertNull(coins.expiresDate());

        InAppPurchase vip = byProduct(receipt, "com.example.app.vip");
        assertEquals(Instant.parse("2030-02-01T09:30:00Z"), vip.expiresDate());
        assertEquals(Long.valueOf(42), vip.webOrderLineItemId());
    }

    @Test
    void verifiesBase64Transport() throws Exception {
        String base64 = Base64.getEncoder().encodeToString(receiptDer);
        assertEquals(BUNDLE, verifier(pki, BUNDLE).verify(base64).bundleId());
    }

    @Test
    void rejectsWrongBundleId() {
        VerificationException e = assertThrows(
                VerificationException.class,
                () -> verifier(pki, "com.other.app").verify(receiptDer));
        assertEquals(Reason.WRONG_BUNDLE_ID, e.reason());
    }

    @Test
    void rejectsTamperedPayload() {
        byte[] tampered = receiptDer.clone();
        int at = indexOf(tampered, BUNDLE.getBytes(StandardCharsets.UTF_8));
        tampered[at] ^= 0x01;
        VerificationException e = assertThrows(
                VerificationException.class, () -> verifier(pki, BUNDLE).verify(tampered));
        assertEquals(Reason.INVALID_SIGNATURE, e.reason());
    }

    @Test
    void rejectsReceiptFromForeignRoot() throws Exception {
        TestPki foreign = TestPki.receipt();
        byte[] forged = foreign.signReceipt(payload(BUNDLE, creationDate.toString()));
        VerificationException e = assertThrows(
                VerificationException.class, () -> verifier(pki, BUNDLE).verify(forged));
        assertEquals(Reason.INVALID_CHAIN, e.reason());
    }

    @Test
    void rejectsTwinCertificateForgery() throws Exception {
        // The chain check must validate the exact certificate that later verifies
        // the signature. Selecting the PKIX target by subject instead would path to
        // the genuine leaf while the attacker's twin — same issuer, serial and
        // subject, different key, embedded first so it is the one picked — supplies
        // the key the signature is checked against, and the forgery is accepted.
        byte[] forged = pki.signReceiptWithTwinCert(payload(BUNDLE, creationDate.toString()));
        VerificationException e = assertThrows(
                VerificationException.class, () -> verifier(pki, BUNDLE).verify(forged));
        assertEquals(Reason.INVALID_CHAIN, e.reason());
    }

    @Test
    void rejectsReceiptEmbeddingMoreCertificatesThanTheLimit() throws Exception {
        // Genuine receipts embed one to three certificates, so eleven is a flood.
        // Everything else about this receipt is valid — unbounded it verifies —
        // so what rejects it is the count and nothing else. That the count is
        // checked before any of the eleven is decoded is the test below.
        byte[] flooded = pki.signReceiptWithPadding(payload(BUNDLE, creationDate.toString()), 8);
        VerificationException e = assertThrows(
                VerificationException.class, () -> verifier(pki, BUNDLE).verify(flooded));
        assertEquals(Reason.INVALID_CHAIN, e.reason());
        assertTrue(e.getMessage().contains("11 certificates, more than the maximum of 10"), e.getMessage());
    }

    @Test
    void admitsAReceiptEmbeddingExactlyTheMaximum() throws Exception {
        // Seven padding certificates and the chain's own three is exactly the
        // maximum, so the count stands aside and the receipt verifies as it
        // would without them.
        byte[] padded = pki.signReceiptWithPadding(payload(BUNDLE, creationDate.toString()), 7);
        assertEquals(
                10, new CMSSignedData(padded).getCertificates().getMatches(null).size());
        assertEquals(BUNDLE, verifier(pki, BUNDLE).verify(padded).bundleId());
    }

    @Test
    void countsEmbeddedCertificatesBeforeDecodingAnyOfThem() throws Exception {
        // Eight of the eleven are certificates the JCA refuses to decode, so
        // where the count is checked decides which rejection a caller sees:
        // counting first names the count, decoding first dies in the converter
        // and reports "chain validation unavailable" instead. That is the only
        // difference the two orderings have — the cost they differ by is not
        // observable from a test (see the mesh below).
        byte[] flooded = pki.signReceiptWithUndecodablePadding(payload(BUNDLE, creationDate.toString()), 8);
        VerificationException e = assertThrows(
                VerificationException.class, () -> verifier(pki, BUNDLE).verify(flooded));
        assertEquals(Reason.INVALID_CHAIN, e.reason());
        assertTrue(e.getMessage().contains("11 certificates, more than the maximum of 10"), e.getMessage());
    }

    @Test
    void countsEmbeddedCertificatesBeforeResolvingTheSigner() throws Exception {
        // Where the count guard sits relative to the signer lookup is the one
        // ordering the tests above cannot see, since neither step decodes a
        // certificate. This bag is over the bound AND omits the signer, so the
        // guard where it is reports the bound, while a guard that runs after
        // the lookup tells the caller the receipt is malformed instead — the
        // same test swift carries as testTheCountGuardRunsBeforeTheSignerIsResolved.
        byte[] flooded = pki.signReceiptOmittingSigner(payload(BUNDLE, creationDate.toString()), 11);
        VerificationException e = assertThrows(
                VerificationException.class, () -> verifier(pki, BUNDLE).verify(flooded));
        assertEquals(Reason.INVALID_CHAIN, e.reason());
        assertTrue(e.getMessage().contains("11 certificates, more than the maximum of 10"), e.getMessage());
    }

    @Test
    void rejectsCrossSignedCertificateMeshWithoutWalkingIt() throws Exception {
        // Fourteen layers of two cross-signed certificates each: the pair in a
        // layer shares a subject name and a key, so either is a valid issuer for
        // the layer below, and the top layer names an issuer that is not embedded.
        // A verifier that explores paths before it bounds anything walks 2^14 of
        // them to reject this — the shape swift-certificates spends seconds on.
        // It costs the sender almost nothing to send: 29 certificates in 21,655
        // bytes, a quarter of the genuine legacy receipt under
        // fixtures/public-receipts (79,104 bytes), so no caller-side size limit
        // can substitute for the count bound.
        byte[] mesh = pki.signReceiptWithCrossSignedMesh(payload(BUNDLE, creationDate.toString()), 14, 2);

        VerificationException e = assertThrows(
                VerificationException.class, () -> verifier(pki, BUNDLE).verify(mesh));
        // Rejected on the count, so no path is built at all.
        assertEquals(Reason.INVALID_CHAIN, e.reason());
        assertTrue(e.getMessage().contains("more than the maximum of 10"), e.getMessage());
        // No wall-clock budget here: on this JDK the mesh is not expensive to
        // walk, so a timing assertion could not fail. Measured through this
        // same verify() with the count guard removed, on Temurin 17.0.3 —
        // javac has no optimizing build mode, the JIT does that work, so these
        // are medians of 50 calls after 200 warm-up rounds: 1.0 ms at fourteen
        // layers, 1.4 at eighteen, 1.5 at twenty-two (cold, the first call in
        // a fresh JVM, each is 6-24 ms of JIT). The cost tracks the
        // certificates decoded — 29, 37 and 45 of them — rather than
        // 2^layers, because PKIXBuilderParameters defaults maxPathLength to 5
        // and abandons every path early. Java's real protection against this
        // shape is that depth bound, not the count; the count bound is what
        // makes the rejection independent of a JDK default this class never
        // states and does not control, and what keeps the four implementations
        // agreeing on what a receipt may embed.
    }

    @Test
    void rejectsCorruptedSignatureBytes() throws Exception {
        // Chain, payload and message digest all stay genuine here, so the CMS
        // signature check is the only thing left that can reject this receipt —
        // every other negative test trips a BouncyCastle CMSException first.
        byte[] corrupted = receiptDer.clone();
        byte[] signature = new CMSSignedData(receiptDer)
                .getSignerInfos()
                .getSigners()
                .iterator()
                .next()
                .getSignature();
        // A mid-signature bit keeps the value below the modulus, so the RSA check
        // returns false rather than erroring out as a CMSException.
        corrupted[indexOf(corrupted, signature) + signature.length / 2] ^= 0x01;
        VerificationException e = assertThrows(
                VerificationException.class, () -> verifier(pki, BUNDLE).verify(corrupted));
        assertEquals(Reason.INVALID_SIGNATURE, e.reason());
    }

    @Test
    void enforcesDeviceHashWhenGuidSupplied() throws Exception {
        AppReceipt receipt = verifier(pki, BUNDLE).verify(receiptDer, GUID);
        assertNotNull(receipt.sha1Hash());

        byte[] wrongGuid = GUID.clone();
        wrongGuid[0] ^= 0x01;
        VerificationException e = assertThrows(
                VerificationException.class, () -> verifier(pki, BUNDLE).verify(receiptDer, wrongGuid));
        assertEquals(Reason.DEVICE_HASH_MISMATCH, e.reason());
    }

    @Test
    void rejectsTrailingBytesAfterCms() {
        byte[] padded = new byte[receiptDer.length + 4];
        System.arraycopy(receiptDer, 0, padded, 0, receiptDer.length);
        VerificationException e = assertThrows(
                VerificationException.class, () -> verifier(pki, BUNDLE).verify(padded));
        assertEquals(Reason.INVALID_RECEIPT_FORMAT, e.reason());
    }

    @Test
    void exposesUnknownAttributesForForwardCompatibility() throws Exception {
        AppReceipt receipt = verifier(pki, BUNDLE).verify(receiptDer);
        assertArrayEquals(
                new byte[] {1, 2, 3}, receipt.unknownAttributes().get(9999).get(0));
    }

    @Test
    void rejectsGarbageBytes() {
        VerificationException e = assertThrows(
                VerificationException.class, () -> verifier(pki, BUNDLE).verify(new byte[] {1, 2, 3, 4}));
        assertEquals(Reason.INVALID_RECEIPT_FORMAT, e.reason());
    }

    @Test
    void rejectsDateOutsideRepresentableRange() throws Exception {
        // Instant.parse accepts an expanded year (+1000000000-...) whose epoch
        // millis overflow a long; that conversion runs before verification, so it
        // must surface as the library's VerificationException, not escape as a raw
        // runtime exception past the declared throws clause.
        byte[] receipt = pki.signReceipt(payload(BUNDLE, "+1000000000-01-01T00:00:00Z"));
        VerificationException e = assertThrows(
                VerificationException.class, () -> verifier(pki, BUNDLE).verify(receipt));
        assertEquals(Reason.INVALID_RECEIPT_FORMAT, e.reason());
    }

    @Test
    void rejectsAttributeTypeTooWideToHoldRatherThanTruncatingIt() throws Exception {
        // 2^64 + 2 is the bundle-id attribute type with a 65th bit set, and the
        // parser holds the type in a long: keeping the low 64 bits would make
        // this attribute the bundle id, and the receipt would verify as
        // com.example.app on a type the parser never proved it could hold. It is
        // rejected on its width instead, before the switch that assigns meaning.
        byte[] receipt = pki.signReceipt(TestPki.singleAttributePayload(
                BigInteger.ONE.shiftLeft(64).add(BigInteger.valueOf(2)), new DERUTF8String(BUNDLE).getEncoded()));
        VerificationException e = assertThrows(
                VerificationException.class, () -> verifier(pki, BUNDLE).verify(receipt));
        assertEquals(Reason.INVALID_RECEIPT_FORMAT, e.reason());
        assertTrue(e.getMessage().contains("out of range"), e.getMessage());
    }

    @Test
    void rejectsAttributeTypeBeyondIntRangeRatherThanRenamingIt() throws Exception {
        // One level down from the test above: these types fit the long the
        // parser holds them in, but not the int an attribute type is. A
        // truncating cast would alias 2^32 + 2 onto the bundle-id type; this
        // parser used to avoid that by rewriting any such type to -1 and
        // filing it under unknownAttributes, which is its own bug — -1 is not
        // a valid attribute type, and reporting the receipt as carrying an
        // attribute it does not carry is how two ports start disagreeing about
        // what a receipt says. The receipt is rejected instead. node, python
        // and swift agree.
        for (BigInteger type : Arrays.asList(
                BigInteger.ONE.shiftLeft(31), // 2^31, one past int
                BigInteger.ONE.shiftLeft(32).add(BigInteger.valueOf(2)), // aliases the bundle id
                BigInteger.valueOf(Long.MAX_VALUE))) { // the widest long
            byte[] receipt =
                    pki.signReceipt(TestPki.singleAttributePayload(type, new DERUTF8String(BUNDLE).getEncoded()));
            VerificationException e = assertThrows(
                    VerificationException.class, () -> verifier(pki, BUNDLE).verify(receipt), type.toString());
            assertEquals(Reason.INVALID_RECEIPT_FORMAT, e.reason(), type.toString());
            assertTrue(e.getMessage().contains("out of range"), e.getMessage());
        }
    }

    @Test
    void keepsAnAttributeTypeAtIntMaxAsItselfRatherThanRejectingIt() throws Exception {
        // The boundary the rule above draws, from the other side: 2^31 - 1 is
        // representable, so it is kept as itself and reaches unknownAttributes
        // under its own number — and nothing is ever filed under -1.
        byte[] receipt = pki.signReceipt(
                TestPki.singleAttributePayload(BigInteger.valueOf(Integer.MAX_VALUE), new byte[] {1, 2, 3}));
        AppReceipt parsed = ReceiptVerifier.verifyReceiptCore(receipt, Collections.singleton(pki.root));
        assertArrayEquals(
                new byte[] {1, 2, 3},
                parsed.unknownAttributes().get(Integer.MAX_VALUE).get(0));
        assertNull(parsed.unknownAttributes().get(-1));
    }

    // ------------------------------------- the certificate-validity clock (1)

    /**
     * Chain validity is judged at the receipt's creation date, and — for a
     * receipt that carries none — at the system clock (PLAN.md §2.2 step 2's
     * "else current time"). Both halves are asserted here with one receipt
     * shape carrying no creation date at all: expired chain rejected, current
     * chain accepted, on real time alone.
     */
    @Test
    void receiptWithoutACreationDateIsJudgedAgainstTheSystemClock() throws Exception {
        // An empty attribute-12 value is how a real receipt says "no date"
        // (decodeDate maps it to null), so this is the fallback's real input.
        byte[] datelessPayload = payload(BUNDLE, "");
        Date notBefore = new Date(System.currentTimeMillis() - 730L * 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() - 365L * 86_400_000L);
        TestPki expired = TestPki.receipt(notBefore, notAfter);

        AppReceipt current = verifier(pki, BUNDLE).verify(pki.signReceipt(datelessPayload));
        assertNull(current.creationDate(), "the fixture must carry no creation date");

        byte[] stale = expired.signReceipt(datelessPayload);
        VerificationException e = assertThrows(
                VerificationException.class, () -> verifier(expired, BUNDLE).verify(stale));
        assertEquals(Reason.INVALID_CHAIN, e.reason());
    }

    /**
     * And there is no way to point that fallback anywhere else: ReceiptVerifier
     * takes no clock, in any constructor or method. Java used to offer one
     * (a three-argument constructor) while node, python and swift did not,
     * which made an injected clock able to decide a certificate-validity
     * verdict — a caller pinning a clock to test staleness, or to work around
     * skew, could thereby accept a chain expired in real time. The option is
     * gone; this test is what keeps it gone.
     */
    @Test
    void receiptVerifierExposesNoClockOption() {
        for (Constructor<?> constructor : ReceiptVerifier.class.getConstructors()) {
            for (Class<?> parameter : constructor.getParameterTypes()) {
                assertNotEquals(
                        Clock.class, parameter, "ReceiptVerifier constructor " + constructor + " takes a Clock");
            }
        }
        for (Method method : ReceiptVerifier.class.getMethods()) {
            for (Class<?> parameter : method.getParameterTypes()) {
                assertNotEquals(Clock.class, parameter, "ReceiptVerifier." + method.getName() + " takes a Clock");
            }
        }
    }

    // ---------------------------------------- verifyReceiptCore is public (3)

    /**
     * The chain + signature primitive without the bundle-id claim check is
     * public and static, the same surface node exports as
     * {@code verifyReceiptCore} and python as {@code verify_receipt_core}. It
     * used to be package-private here, which is why the endpoint had to build
     * a ReceiptVerifier around a wildcard bundle id to reach it.
     */
    @Test
    void verifyReceiptCoreIsPublicAndChecksNoBundleId() throws Exception {
        Method core = ReceiptVerifier.class.getMethod("verifyReceiptCore", byte[].class, Set.class);
        assertTrue(Modifier.isPublic(core.getModifiers()), "verifyReceiptCore must be public");
        assertTrue(Modifier.isStatic(core.getModifiers()), "verifyReceiptCore must be static");

        Set<java.security.cert.X509Certificate> roots = Collections.singleton(pki.root);
        // The bundle id comes back unjudged: verify() with a different id
        // rejects the very same receipt.
        assertEquals(
                BUNDLE, ReceiptVerifier.verifyReceiptCore(receiptDer, roots).bundleId());
        VerificationException wrong = assertThrows(
                VerificationException.class,
                () -> verifier(pki, "com.example.other").verify(receiptDer));
        assertEquals(Reason.WRONG_BUNDLE_ID, wrong.reason());

        // Everything else is still enforced: an untrusted root does not verify,
        // and an empty root set is refused rather than trusted.
        TestPki stranger = TestPki.receipt();
        VerificationException chain = assertThrows(
                VerificationException.class,
                () -> ReceiptVerifier.verifyReceiptCore(receiptDer, Collections.singleton(stranger.root)));
        assertEquals(Reason.INVALID_CHAIN, chain.reason());
        assertThrows(
                IllegalArgumentException.class,
                () -> ReceiptVerifier.verifyReceiptCore(
                        receiptDer, Collections.<java.security.cert.X509Certificate>emptySet()));
    }

    @Test
    void boundsAttributeIntegersAtTheEdgeOfALong() throws Exception {
        // Long.MAX_VALUE is the widest value the parser holds, 2^63 is one past
        // it and -1 the first negative; a comparison one step wider lets each
        // of those two through, 2^63 as Long.MIN_VALUE and -1 as itself.
        for (BigInteger type : Arrays.asList(BigInteger.ONE.shiftLeft(63), BigInteger.valueOf(-1))) {
            byte[] receipt = pki.signReceipt(TestPki.singleAttributePayload(type, new byte[0]));
            VerificationException e = assertThrows(
                    VerificationException.class, () -> verifier(pki, BUNDLE).verify(receipt), type.toString());
            assertEquals(Reason.INVALID_RECEIPT_FORMAT, e.reason(), type.toString());
            assertTrue(e.getMessage().contains("out of range"), e.getMessage());
        }
        List<byte[]> inApps = Collections.singletonList(TestPki.inAppPurchase(
                Long.MAX_VALUE,
                "com.example.app.coins100",
                "70000000000001",
                "70000000000001",
                "2024-01-15T12:00:00Z",
                null));
        byte[] receipt = pki.signReceipt(TestPki.receiptPayload(
                BUNDLE, "1.2.3", OPAQUE, TestPki.deviceHash(GUID, OPAQUE, BUNDLE), creationDate.toString(), inApps));
        InAppPurchase coins = byProduct(verifier(pki, BUNDLE).verify(receipt), "com.example.app.coins100");
        assertEquals(Long.valueOf(Long.MAX_VALUE), coins.quantity());
    }

    @Test
    void rejectsUnsignedBase64Garbage() {
        VerificationException e = assertThrows(
                VerificationException.class, () -> verifier(pki, BUNDLE).verify("!!!not-base64!!!"));
        assertEquals(Reason.INVALID_RECEIPT_FORMAT, e.reason());
    }

    @Test
    void acceptsHistoricalReceiptSignedByNowExpiredCert() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 730L * 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() - 365L * 86_400_000L);
        TestPki expired = TestPki.receipt(notBefore, notAfter);
        Instant signedAt = Instant.now().minus(547, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
        byte[] historical = expired.signReceipt(payload(BUNDLE, signedAt.toString()), Date.from(signedAt));
        AppReceipt receipt = verifier(expired, BUNDLE).verify(historical);
        assertEquals(signedAt, receipt.creationDate());
    }

    @Test
    void rejectsFreshReceiptFromExpiredCert() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 730L * 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() - 365L * 86_400_000L);
        TestPki expired = TestPki.receipt(notBefore, notAfter);
        byte[] fresh = expired.signReceipt(payload(BUNDLE, Instant.now().toString()));
        VerificationException e = assertThrows(
                VerificationException.class, () -> verifier(expired, BUNDLE).verify(fresh));
        assertEquals(Reason.INVALID_CHAIN, e.reason());
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i;
            }
        }
        throw new AssertionError("needle not found in receipt bytes");
    }
}
