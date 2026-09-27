package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * {@link Verifier#verifyReceipt} over receipts signed by a generated PKI: the
 * decode, the chain, the markers, the signature and every bound.
 */
class ReceiptVerificationTest {

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

    /** Verifies {@code der} under {@code trustedPki}'s root; a failure is thrown back (see {@link Checks}). */
    private static ReceiptPayload verify(TestPki trustedPki, byte[] der) throws VerificationException {
        return Checks.receipt(Checks.verifier(trustedPki), der);
    }

    /** One receipt attribute whose value is the DER of {@code value}. */
    private static ASN1Encodable integerAttribute(int type, long value) throws Exception {
        return TestPki.attribute(type, new ASN1Integer(value).getEncoded());
    }

    private static InAppPurchase byProduct(ReceiptPayload receipt, String productId) {
        for (InAppPurchase p : receipt.inApp()) {
            if (productId.equals(p.productId())) {
                return p;
            }
        }
        throw new AssertionError("no purchase with productId " + productId);
    }

    @Test
    void verifiesGenuineReceipt() throws Exception {
        ReceiptPayload receipt = verify(pki, receiptDer);
        assertEquals(BUNDLE, receipt.bundleId());
        assertEquals("1.2.3", receipt.applicationVersion());
        assertEquals("1.0", receipt.originalApplicationVersion());
        assertEquals(Long.valueOf(creationDate.toEpochMilli()), receipt.receiptCreationDateMs());
        assertNull(receipt.expirationDateMs());
        assertArrayEquals(OPAQUE, receipt.opaqueValue());
        assertEquals(2, receipt.inApp().size());

        InAppPurchase coins = byProduct(receipt, "com.example.app.coins100");
        assertEquals("70000000000001", coins.transactionId());
        assertEquals(Long.valueOf(1), coins.quantity());
        assertEquals(Long.valueOf(Instant.parse("2024-01-15T12:00:00Z").toEpochMilli()), coins.purchaseDateMs());
        assertNull(coins.expiresDateMs());

        InAppPurchase vip = byProduct(receipt, "com.example.app.vip");
        assertEquals(Long.valueOf(Instant.parse("2030-02-01T09:30:00Z").toEpochMilli()), vip.expiresDateMs());
        assertEquals(Long.valueOf(42), vip.webOrderLineItemId());
    }

    @Test
    void decodesTheLegacyIdAttributes() throws Exception {
        byte[] hash = TestPki.deviceHash(GUID, OPAQUE, BUNDLE);
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
        byte[] der = pki.signReceipt(TestPki.receiptPayload(
                "Production",
                BUNDLE,
                "1.2.3",
                OPAQUE,
                hash,
                creationDate.toString(),
                inApps,
                true,
                null,
                new byte[] {1, 2, 3},
                Arrays.asList(
                        integerAttribute(1, 1234567890L),
                        integerAttribute(15, 9223372036854775807L),
                        integerAttribute(16, 456789012L))));

        ReceiptPayload receipt = verify(pki, der);
        assertEquals(Long.valueOf(1234567890L), receipt.appItemId());
        // 2^63-1: the exact digits are the point. Apple's download_id runs to
        // eighteen of them, past what a double can hold.
        assertEquals(Long.valueOf(9223372036854775807L), receipt.downloadId());
        assertEquals(Long.valueOf(456789012L), receipt.versionExternalIdentifier());
        assertEquals(
                Boolean.FALSE, byProduct(receipt, "com.example.app.coins100").isTrialPeriod());
        assertEquals(Boolean.TRUE, byProduct(receipt, "com.example.app.vip").isTrialPeriod());

        // Modelled now, so they leave unknownAttributes — where every one of
        // them used to land — while 9999 stays, proving the map still works.
        assertNull(receipt.unknownAttributes().get(1));
        assertNull(receipt.unknownAttributes().get(15));
        assertNull(receipt.unknownAttributes().get(16));
        assertNotNull(receipt.unknownAttributes().get(9999));
        assertNull(byProduct(receipt, "com.example.app.vip").unknownAttributes().get(1713));
    }

    @Test
    void legacyIdAttributesAreNullWhenTheReceiptDoesNotCarryThem() throws Exception {
        // Absent is not zero: the shared payload carries none of the four.
        ReceiptPayload receipt = verify(pki, receiptDer);
        assertNull(receipt.appItemId());
        assertNull(receipt.downloadId());
        assertNull(receipt.versionExternalIdentifier());
        assertNull(byProduct(receipt, "com.example.app.coins100").isTrialPeriod());
    }

    @Test
    void verifiesBase64Transport() throws Exception {
        String base64 = Base64.getEncoder().encodeToString(receiptDer);
        assertEquals(BUNDLE, Checks.receipt(Checks.verifier(pki), base64).bundleId());
    }

    @Test
    void returnsWhateverBundleIdAppleSignedWithoutJudgingIt() throws Exception {
        // 0.6 took the caller's bundle id and refused any other. 0.7 takes
        // none: a receipt for another app verifies and says which app it is
        // for, and comparing that is the caller's check.
        byte[] other = pki.signReceipt(payload("com.other.app", creationDate.toString()));
        assertEquals("com.other.app", verify(pki, other).bundleId());
    }

    @Test
    void rejectsTamperedPayload() {
        byte[] tampered = receiptDer.clone();
        int at = indexOf(tampered, BUNDLE.getBytes(StandardCharsets.UTF_8));
        tampered[at] ^= 0x01;
        VerificationException e = assertThrows(VerificationException.class, () -> verify(pki, tampered));
        assertEquals(Reason.INVALID_SIGNATURE, e.reason());
    }

    @Test
    void rejectsReceiptFromForeignRoot() throws Exception {
        TestPki foreign = TestPki.receipt();
        byte[] forged = foreign.signReceipt(payload(BUNDLE, creationDate.toString()));
        VerificationException e = assertThrows(VerificationException.class, () -> verify(pki, forged));
        assertEquals(Reason.UNTRUSTED_CHAIN, e.reason());
    }

    @Test
    void rejectsTwinCertificateForgery() throws Exception {
        // The chain check must validate the exact certificate that later verifies
        // the signature. Selecting the PKIX target by subject instead would path to
        // the genuine leaf while the attacker's twin — same issuer, serial and
        // subject, different key, embedded first so it is the one picked — supplies
        // the key the signature is checked against, and the forgery is accepted.
        byte[] forged = pki.signReceiptWithTwinCert(payload(BUNDLE, creationDate.toString()));
        VerificationException e = assertThrows(VerificationException.class, () -> verify(pki, forged));
        assertEquals(Reason.UNTRUSTED_CHAIN, e.reason());
    }

    @Test
    void rejectsReceiptEmbeddingMoreCertificatesThanTheLimit() throws Exception {
        // Genuine receipts embed one to three certificates, so eleven is a flood.
        // Everything else about this receipt is valid — unbounded it verifies —
        // so what rejects it is the count and nothing else. That the count is
        // checked before any of the eleven is decoded is the test below.
        byte[] flooded = pki.signReceiptWithPadding(payload(BUNDLE, creationDate.toString()), 8);
        VerificationException e = assertThrows(VerificationException.class, () -> verify(pki, flooded));
        assertEquals(Reason.MALFORMED, e.reason());
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
        assertEquals(BUNDLE, verify(pki, padded).bundleId());
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
        VerificationException e = assertThrows(VerificationException.class, () -> verify(pki, flooded));
        assertEquals(Reason.MALFORMED, e.reason());
        assertTrue(e.getMessage().contains("11 certificates, more than the maximum of 10"), e.getMessage());
    }

    @Test
    void countsEmbeddedCertificatesBeforeResolvingTheSigner() throws Exception {
        // Where the count guard sits relative to the signer lookup is the one
        // ordering the tests above cannot see, since neither step decodes a
        // certificate. This bag is over the bound AND omits the signer, so the
        // guard where it is reports the bound, while a guard that runs after
        // the lookup reports the missing signer instead. Both are MALFORMED
        // since 0.7, so the message tells them apart; swift carries the same
        // test as testTheCountGuardRunsBeforeTheSignerIsResolved.
        byte[] flooded = pki.signReceiptOmittingSigner(payload(BUNDLE, creationDate.toString()), 11);
        VerificationException e = assertThrows(VerificationException.class, () -> verify(pki, flooded));
        assertEquals(Reason.MALFORMED, e.reason());
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

        VerificationException e = assertThrows(VerificationException.class, () -> verify(pki, mesh));
        // Rejected on the count, so no path is built at all.
        assertEquals(Reason.MALFORMED, e.reason());
        assertTrue(e.getMessage().contains("more than the maximum of 10"), e.getMessage());
        // No wall-clock budget here: on this JDK the mesh is not expensive to
        // walk, so a timing assertion could not fail. Measured through this
        // same verify() with the count guard removed, on Temurin 17.0.3 —
        // javac has no optimizing build mode, the JIT does that work, so these
        // are medians of 50 calls after 200 warm-up rounds: 1.0 ms at fourteen
        // layers, 1.4 at eighteen, 1.5 at twenty-two (cold, the first call in
        // a fresh JVM, each is 6-24 ms of JIT). The cost tracks the
        // certificates decoded — 29, 37 and 45 of them — rather than
        // 2^layers, because the builder abandons every path at the port-wide
        // maximum path length. Java's real protection against this shape is
        // that depth bound, not the count; the count bound is what keeps the
        // implementations agreeing on what a receipt may embed.
    }

    @Test
    void acceptsAPathOfExactlyTheMaximumLength() throws Exception {
        // Six certificates below the anchor — leaf plus five intermediates —
        // is the longest path every port accepts (go MaxPathLength, rust
        // MAX_PATH_LENGTH, node/php/ruby/python/dotnet the same constant at 6,
        // each counting certificates walked from the leaf with the anchor
        // excluded). A port that reads its own bound as "intermediates" is off
        // by one here and rejects a chain the others take.
        TestPki deep = TestPki.deepReceipt(5, 0);
        ReceiptPayload receipt = verify(deep, deep.signReceipt(payload(BUNDLE, creationDate.toString())));
        assertEquals(BUNDLE, receipt.bundleId());
    }

    @Test
    void rejectsAPathOneHopOverTheMaximumLength() throws Exception {
        // Seven certificates below the anchor. Every other port stops the walk
        // after six and raises InvalidChain; the reason code is the contract,
        // so this pins that java reaches the same verdict rather than a
        // format or signature complaint.
        TestPki deep = TestPki.deepReceipt(6, 0);
        byte[] tooLong = deep.signReceipt(payload(BUNDLE, creationDate.toString()));
        VerificationException e = assertThrows(VerificationException.class, () -> verify(deep, tooLong));
        assertEquals(Reason.UNTRUSTED_CHAIN, e.reason());
    }

    @Test
    void countsSelfIssuedCertificatesTowardsTheMaximumLength() throws Exception {
        // The same seven certificates below the anchor, except that the last
        // one repeats its issuer's subject name. PKIX exempts self-issued
        // intermediates from maxPathLength (RFC 5280 6.1.4), so the builder
        // alone would return this path even though it is a hop too long. The
        // top-down walk counts every hop, stops at six and never reaches the
        // signer, so the signer is refused before the builder runs.
        TestPki deep = TestPki.deepReceipt(5, 1);
        byte[] tooLong = deep.signReceipt(payload(BUNDLE, creationDate.toString()));
        VerificationException e = assertThrows(VerificationException.class, () -> verify(deep, tooLong));
        assertEquals(Reason.UNTRUSTED_CHAIN, e.reason());
        assertTrue(e.getMessage().contains("not issued under a pinned Apple root"), e.getMessage());
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
        VerificationException e = assertThrows(VerificationException.class, () -> verify(pki, corrupted));
        assertEquals(Reason.INVALID_SIGNATURE, e.reason());
    }

    @Test
    void exposesEverythingTheDeviceHashNeeds() throws Exception {
        // The library no longer takes a device GUID. What it returns instead is
        // the three attribute values Apple's formula hashes, as the receipt
        // carries them, so a caller computes SHA-1(guid || opaque || bundle id
        // bytes) and compares it with sha1Hash. The README shows this loop.
        ReceiptPayload receipt = verify(pki, receiptDer);
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(GUID);
        sha1.update(receipt.opaqueValue());
        sha1.update(receipt.bundleIdBytes());
        assertArrayEquals(receipt.sha1Hash(), sha1.digest());

        byte[] wrongGuid = GUID.clone();
        wrongGuid[0] ^= 0x01;
        sha1.update(wrongGuid);
        sha1.update(receipt.opaqueValue());
        sha1.update(receipt.bundleIdBytes());
        assertFalse(Arrays.equals(receipt.sha1Hash(), sha1.digest()));
    }

    @Test
    void rejectsTrailingBytesAfterCms() {
        byte[] padded = new byte[receiptDer.length + 4];
        System.arraycopy(receiptDer, 0, padded, 0, receiptDer.length);
        VerificationException e = assertThrows(VerificationException.class, () -> verify(pki, padded));
        assertEquals(Reason.MALFORMED, e.reason());
    }

    @Test
    void exposesUnknownAttributesForForwardCompatibility() throws Exception {
        ReceiptPayload receipt = verify(pki, receiptDer);
        assertArrayEquals(
                new byte[] {1, 2, 3}, receipt.unknownAttributes().get(9999).get(0));
    }

    @Test
    void rejectsGarbageBytes() {
        VerificationException e = assertThrows(VerificationException.class, () -> verify(pki, new byte[] {1, 2, 3, 4}));
        assertEquals(Reason.MALFORMED, e.reason());
    }

    @Test
    void decodesADateOutsideRepresentableRangeAsMissing() throws Exception {
        // Instant.parse accepts an expanded year (+1000000000-...) whose epoch
        // millis overflow a long. Before trust that only moves the chain instant
        // to the clock; after the chain and signature pass, the decode reports
        // the date as missing, as it does any date that does not parse, rather
        // than letting the ArithmeticException out or refusing the receipt.
        byte[] receipt = pki.signReceipt(payload(BUNDLE, "+1000000000-01-01T00:00:00Z"));
        assertNull(verify(pki, receipt).receiptCreationDateMs());
        byte[] garbled = pki.signReceipt(payload(BUNDLE, "not a date"));
        assertNull(verify(pki, garbled).receiptCreationDateMs());
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
        VerificationException e = assertThrows(VerificationException.class, () -> verify(pki, receipt));
        assertEquals(Reason.UNREADABLE_PAYLOAD, e.reason());
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
            VerificationException e =
                    assertThrows(VerificationException.class, () -> verify(pki, receipt), type.toString());
            assertEquals(Reason.UNREADABLE_PAYLOAD, e.reason(), type.toString());
            assertTrue(e.getMessage().contains("out of range"), e.getMessage());
        }
    }

    /**
     * String attributes are UTF8String or IA5String, as in Apple's receipts
     * and in every other port. Any other ASN.1 string type used to decode
     * too: a BIT STRING through BouncyCastle's getString() as "#" plus hex,
     * so a bundle id was compared in a form the receipt never stated.
     */
    @Test
    void acceptsOnlyUtf8OrIa5StringsForStringAttributes() throws Exception {
        byte[] ia5 = pki.signReceipt(TestPki.singleAttributePayload(2, new DERIA5String(BUNDLE).getEncoded()));
        assertEquals(BUNDLE, verify(pki, ia5).bundleId());
        for (byte[] value : Arrays.asList(
                new DERBitString(BUNDLE.getBytes(StandardCharsets.US_ASCII)).getEncoded(),
                new DERUniversalString(BUNDLE.getBytes(StandardCharsets.US_ASCII)).getEncoded(),
                new DERPrintableString(BUNDLE).getEncoded(),
                new DERBMPString(BUNDLE).getEncoded())) {
            // Not decoded as a string, and not lost: the octets stay in
            // bundleIdBytes, where the device-hash computation reads them.
            ReceiptPayload receipt = verify(pki, pki.signReceipt(TestPki.singleAttributePayload(2, value)));
            assertNull(receipt.bundleId(), Arrays.toString(value));
            assertArrayEquals(value, receipt.bundleIdBytes(), Arrays.toString(value));
        }
    }

    @Test
    void keepsAnAttributeTypeAtIntMaxAsItselfRatherThanRejectingIt() throws Exception {
        // The boundary the rule above draws, from the other side: 2^31 - 1 is
        // representable, so it is kept as itself and reaches unknownAttributes
        // under its own number — and nothing is ever filed under -1.
        byte[] receipt = pki.signReceipt(
                TestPki.singleAttributePayload(BigInteger.valueOf(Integer.MAX_VALUE), new byte[] {1, 2, 3}));
        ReceiptPayload parsed = verify(pki, receipt);
        assertArrayEquals(
                new byte[] {1, 2, 3},
                parsed.unknownAttributes().get(Integer.MAX_VALUE).get(0));
        assertNull(parsed.unknownAttributes().get(-1));
    }

    // --------------------------------------- the certificate-validity clock

    /**
     * Chain validity is judged at the receipt's creation date, and, for a
     * receipt that carries none, at the config clock. Both halves are asserted
     * with one receipt shape carrying no creation date at all: under the
     * system clock an expired chain is rejected and a current one accepted;
     * a clock set inside the expired chain's window accepts it.
     */
    @Test
    void receiptWithoutACreationDateIsJudgedAgainstTheConfigClock() throws Exception {
        // An empty attribute-12 value is how a real receipt says "no date"
        // (decodeDate maps it to null), so this is the fallback's real input.
        byte[] datelessPayload = payload(BUNDLE, "");
        Date notBefore = new Date(System.currentTimeMillis() - 730L * 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() - 365L * 86_400_000L);
        TestPki expired = TestPki.receipt(notBefore, notAfter);

        ReceiptPayload current = verify(pki, pki.signReceipt(datelessPayload));
        assertNull(current.receiptCreationDateMs(), "the fixture must carry no creation date");

        // Signed inside the chain's window: BouncyCastle also checks the signer
        // against a CMS signingTime attribute when there is one (Apple's
        // receipts carry none), and this one must not be what rejects it.
        Date signedAt = new Date(notBefore.getTime() + 86_400_000L);
        byte[] stale = expired.signReceipt(datelessPayload, signedAt);
        VerificationException e = assertThrows(VerificationException.class, () -> verify(expired, stale));
        assertEquals(Reason.INVALID_CERTIFICATE, e.reason());

        Clock insideTheWindow = Clock.fixed(Instant.ofEpochMilli(notBefore.getTime() + 86_400_000L), ZoneOffset.UTC);
        assertEquals(
                BUNDLE,
                Checks.receipt(Checks.verifier(insideTheWindow, expired.root), stale)
                        .bundleId());
    }

    /** A creation date the receipt does carry wins over the clock, whatever the clock says. */
    @Test
    void theClockDoesNotOverrideACreationDate() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 730L * 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() - 365L * 86_400_000L);
        TestPki expired = TestPki.receipt(notBefore, notAfter);
        byte[] fresh = expired.signReceipt(
                payload(BUNDLE, Instant.now().truncatedTo(ChronoUnit.SECONDS).toString()));
        Clock insideTheWindow = Clock.fixed(Instant.ofEpochMilli(notBefore.getTime() + 86_400_000L), ZoneOffset.UTC);
        VerificationException e = assertThrows(
                VerificationException.class,
                () -> Checks.receipt(Checks.verifier(insideTheWindow, expired.root), fresh));
        assertEquals(Reason.INVALID_CERTIFICATE, e.reason());
    }

    @Test
    void anEmptyRootSetIsRefusedAtStartup() throws Exception {
        assertThrows(
                IllegalArgumentException.class,
                () -> Verifier.create(Config.builder()
                        .roots(Collections.<java.security.cert.X509Certificate>emptySet())
                        .build()));
        // And a receipt under a root that is not pinned does not verify.
        TestPki stranger = TestPki.receipt();
        VerificationException chain =
                assertThrows(VerificationException.class, () -> Checks.receipt(Checks.verifier(stranger), receiptDer));
        assertEquals(Reason.UNTRUSTED_CHAIN, chain.reason());
    }

    @Test
    void boundsAttributeIntegersAtTheEdgeOfALong() throws Exception {
        // Long.MAX_VALUE is the widest value the parser holds, 2^63 is one past
        // it and -1 the first negative; a comparison one step wider lets each
        // of those two through, 2^63 as Long.MIN_VALUE and -1 as itself.
        for (BigInteger type : Arrays.asList(BigInteger.ONE.shiftLeft(63), BigInteger.valueOf(-1))) {
            byte[] receipt = pki.signReceipt(TestPki.singleAttributePayload(type, new byte[0]));
            VerificationException e =
                    assertThrows(VerificationException.class, () -> verify(pki, receipt), type.toString());
            assertEquals(Reason.UNREADABLE_PAYLOAD, e.reason(), type.toString());
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
        InAppPurchase coins = byProduct(verify(pki, receipt), "com.example.app.coins100");
        assertEquals(Long.valueOf(Long.MAX_VALUE), coins.quantity());
    }

    @Test
    void rejectsUnsignedBase64Garbage() {
        VerificationException e = assertThrows(
                VerificationException.class, () -> Checks.receipt(Checks.verifier(pki), "!!!not-base64!!!"));
        assertEquals(Reason.MALFORMED, e.reason());
    }

    /**
     * Intentional: the pre-2018 per-transaction receipt (base64 around an
     * old-style plist holding "purchase-info") is not supported. Apple's
     * ReceiptUtility reads a transaction id out of it without verifying
     * anything; this library only returns what it has verified, and that
     * format is not the PKCS#7 container the signature lives in. Apple's own
     * mock of it must fail as a format error, and the endpoint must answer
     * 21002 like Apple's service does for data it cannot read.
     */
    @Test
    void rejectsTheLegacyPurchaseInfoTransactionReceipt() throws Exception {
        String legacy = new String(
                        Files.readAllBytes(
                                TestFixtures.root().resolve("apple-official/mock_signed_data/legacyTransaction")),
                        StandardCharsets.US_ASCII)
                .trim();
        Verifier apple = Verifier.create(Config.defaults());
        VerificationException e = assertThrows(VerificationException.class, () -> Checks.receipt(apple, legacy));
        assertEquals(Reason.MALFORMED, e.reason(), e.getMessage());

        assertEquals(
                "{\"status\":21002}",
                apple.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + legacy + "\"}"));
    }

    @Test
    void acceptsHistoricalReceiptSignedByNowExpiredCert() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 730L * 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() - 365L * 86_400_000L);
        TestPki expired = TestPki.receipt(notBefore, notAfter);
        Instant signedAt = Instant.now().minus(547, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
        byte[] historical = expired.signReceipt(payload(BUNDLE, signedAt.toString()), Date.from(signedAt));
        ReceiptPayload receipt = verify(expired, historical);
        assertEquals(Long.valueOf(signedAt.toEpochMilli()), receipt.receiptCreationDateMs());
    }

    @Test
    void rejectsFreshReceiptFromExpiredCert() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 730L * 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() - 365L * 86_400_000L);
        TestPki expired = TestPki.receipt(notBefore, notAfter);
        byte[] fresh = expired.signReceipt(
                payload(BUNDLE, Instant.now().truncatedTo(ChronoUnit.SECONDS).toString()));
        VerificationException e = assertThrows(VerificationException.class, () -> verify(expired, fresh));
        assertEquals(Reason.INVALID_CERTIFICATE, e.reason());
    }

    /**
     * Validity before the signature (owner, 2026-09-27, Q22): a receipt whose
     * chain is outside its window at the creation date is INVALID_CERTIFICATE
     * even when its signature is also broken.
     */
    @Test
    void anExpiredChainOutranksABrokenSignature() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 730L * 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() - 365L * 86_400_000L);
        TestPki expired = TestPki.receipt(notBefore, notAfter);
        byte[] fresh = TestPki.corruptSignatures(
                expired.signReceipt(payload(
                        BUNDLE, Instant.now().truncatedTo(ChronoUnit.SECONDS).toString())),
                1);
        VerificationException e = assertThrows(VerificationException.class, () -> verify(expired, fresh));
        assertEquals(Reason.INVALID_CERTIFICATE, e.reason());
        // The control: the same corruption inside the window is the signature.
        Instant signedAt = Instant.now().minus(547, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
        byte[] historical = TestPki.corruptSignatures(
                expired.signReceipt(payload(BUNDLE, signedAt.toString()), Date.from(signedAt)), 1);
        e = assertThrows(VerificationException.class, () -> verify(expired, historical));
        assertEquals(Reason.INVALID_SIGNATURE, e.reason());
    }

    // ------------------------------------------------ several SignerInfos

    @Test
    void verifiesWhenOneSignerVerifiesBesideABrokenOne() throws Exception {
        // All SignerInfos sign the same content, so an extra signer cannot
        // change what Apple signed: one that verifies under a pinned chain is
        // enough, whichever order DER puts the two in.
        TestPki foreign = TestPki.receipt();
        byte[] receipt =
                TestPki.signReceiptByEach(payload(BUNDLE, creationDate.toString()), Arrays.asList(pki, foreign));
        assertEquals(2, new CMSSignedData(receipt).getSignerInfos().size());
        assertEquals(BUNDLE, verify(pki, receipt).bundleId());
        // The same receipt under the other root verifies through the other signer.
        assertEquals(BUNDLE, verify(foreign, receipt).bundleId());
    }

    @Test
    void verifiesWhenTheSecondSignerIsTheOneThatVerifies() throws Exception {
        // Two SignerInfos under the same trusted chain, the first one in
        // receipt order corrupted: the loop must go on to the second rather
        // than stop at the first failure.
        byte[] both = TestPki.signReceiptByEach(payload(BUNDLE, creationDate.toString()), Arrays.asList(pki, pki));
        byte[] firstBroken = TestPki.corruptSignatures(both, 1);
        assertEquals(BUNDLE, verify(pki, firstBroken).bundleId());
    }

    @Test
    void failsWithInvalidSignatureWhenEverySignerIsBroken() throws Exception {
        byte[] both = TestPki.signReceiptByEach(payload(BUNDLE, creationDate.toString()), Arrays.asList(pki, pki));
        byte[] bothBroken = TestPki.corruptSignatures(both, 2);
        VerificationException e = assertThrows(VerificationException.class, () -> verify(pki, bothBroken));
        assertEquals(Reason.INVALID_SIGNATURE, e.reason());
    }

    @Test
    void refusesMoreThanFourSignerInfosBeforeCheckingAny() throws Exception {
        byte[] four =
                TestPki.signReceiptByEach(payload(BUNDLE, creationDate.toString()), Arrays.asList(pki, pki, pki, pki));
        assertEquals(BUNDLE, verify(pki, four).bundleId());
        byte[] five = TestPki.signReceiptByEach(
                payload(BUNDLE, creationDate.toString()), Arrays.asList(pki, pki, pki, pki, pki));
        VerificationException e = assertThrows(VerificationException.class, () -> verify(pki, five));
        assertEquals(Reason.MALFORMED, e.reason());
        assertTrue(e.getMessage().contains("5 SignerInfos, more than the maximum of 4"), e.getMessage());
    }

    // ------------------------------------------------------ marker OIDs

    @Test
    void rejectsAnIntermediateWithoutTheWwdrMarker() throws Exception {
        // New in 0.7: the receipt path checks the intermediate's marker as the
        // JWS path always has. Everything else about this chain is valid.
        TestPki unmarked = TestPki.receipt(
                new Date(System.currentTimeMillis() - 86_400_000L),
                new Date(System.currentTimeMillis() + 86_400_000L),
                true,
                false);
        byte[] receipt = unmarked.signReceipt(payload(BUNDLE, creationDate.toString()));
        VerificationException e = assertThrows(VerificationException.class, () -> verify(unmarked, receipt));
        assertEquals(Reason.INVALID_CERTIFICATE_PURPOSE, e.reason());
        assertTrue(e.getMessage().contains("WWDR"), e.getMessage());
    }

    @Test
    void rejectsASignerIssuedStraightByTheRoot() throws Exception {
        // No intermediate at all means no WWDR certificate to carry the marker.
        TestPki shallow = TestPki.deepReceipt(0, 0);
        byte[] receipt = shallow.signReceipt(payload(BUNDLE, creationDate.toString()));
        VerificationException e = assertThrows(VerificationException.class, () -> verify(shallow, receipt));
        assertEquals(Reason.INVALID_CERTIFICATE_PURPOSE, e.reason());
    }

    // ------------------------------------------------------ decode rules

    @Test
    void reportsNegativeIntegersAndReadsAnyNonZeroFlagAsTrue() throws Exception {
        // The decoder reports what the receipt carries: an INTEGER that fits a
        // signed 64-bit value, negative ones included. Flags are 0 for false
        // and anything else for true.
        List<byte[]> inApps = Arrays.asList(TestPki.inAppPurchase(
                1,
                "com.example.app.coins100",
                "70000000000001",
                "70000000000001",
                "2024-01-15T12:00:00Z",
                null,
                Arrays.asList(integerAttribute(1713, 2L), integerAttribute(1719, -1L))));
        byte[] der = pki.signReceipt(TestPki.receiptPayload(
                "Production",
                BUNDLE,
                "1.2.3",
                OPAQUE,
                TestPki.deviceHash(GUID, OPAQUE, BUNDLE),
                creationDate.toString(),
                inApps,
                true,
                null,
                new byte[] {1, 2, 3},
                Arrays.asList(integerAttribute(1, -5L), integerAttribute(15, Long.MIN_VALUE))));
        ReceiptPayload receipt = verify(pki, der);
        assertEquals(Long.valueOf(-5L), receipt.appItemId());
        assertEquals(Long.valueOf(Long.MIN_VALUE), receipt.downloadId());
        InAppPurchase coins = byProduct(receipt, "com.example.app.coins100");
        assertEquals(Boolean.TRUE, coins.isTrialPeriod());
        assertEquals(Boolean.TRUE, coins.isInIntroOfferPeriod());
    }

    @Test
    void anIntegerWiderThanALongIsKeptRaw() throws Exception {
        byte[] value = new ASN1Integer(BigInteger.ONE.shiftLeft(63)).getEncoded();
        ReceiptPayload receipt = verify(pki, pki.signReceipt(TestPki.singleAttributePayload(15, value)));
        assertNull(receipt.downloadId());
        assertArrayEquals(value, receipt.unknownAttributes().get(15).get(0));
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
