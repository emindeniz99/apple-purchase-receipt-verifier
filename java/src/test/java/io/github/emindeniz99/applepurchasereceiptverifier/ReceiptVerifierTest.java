package io.github.emindeniz99.applepurchasereceiptverifier;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.InAppPurchase;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ReceiptVerifierTest {

    private static final String BUNDLE = "com.example.app";
    private static final byte[] GUID = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88,
            (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff, 0x00};
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
                TestPki.inAppPurchase(1, "com.example.app.coins100", "70000000000001",
                        "70000000000001", "2024-01-15T12:00:00Z", null),
                TestPki.inAppPurchase(1, "com.example.app.vip", "70000000000002",
                        "70000000000002", "2024-02-01T09:30:00Z", "2030-02-01T09:30:00Z"));
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
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(pki, "com.other.app").verify(receiptDer));
        assertEquals(Reason.WRONG_BUNDLE_ID, e.reason());
    }

    @Test
    void rejectsTamperedPayload() {
        byte[] tampered = receiptDer.clone();
        int at = indexOf(tampered, BUNDLE.getBytes(StandardCharsets.UTF_8));
        tampered[at] ^= 0x01;
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(pki, BUNDLE).verify(tampered));
        assertEquals(Reason.INVALID_SIGNATURE, e.reason());
    }

    @Test
    void rejectsReceiptFromForeignRoot() throws Exception {
        TestPki foreign = TestPki.receipt();
        byte[] forged = foreign.signReceipt(payload(BUNDLE, creationDate.toString()));
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(pki, BUNDLE).verify(forged));
        assertEquals(Reason.INVALID_CHAIN, e.reason());
    }

    @Test
    void enforcesDeviceHashWhenGuidSupplied() throws Exception {
        AppReceipt receipt = verifier(pki, BUNDLE).verify(receiptDer, GUID);
        assertNotNull(receipt.sha1Hash());

        byte[] wrongGuid = GUID.clone();
        wrongGuid[0] ^= 0x01;
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(pki, BUNDLE).verify(receiptDer, wrongGuid));
        assertEquals(Reason.DEVICE_HASH_MISMATCH, e.reason());
    }

    @Test
    void rejectsTrailingBytesAfterCms() {
        byte[] padded = new byte[receiptDer.length + 4];
        System.arraycopy(receiptDer, 0, padded, 0, receiptDer.length);
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(pki, BUNDLE).verify(padded));
        assertEquals(Reason.INVALID_RECEIPT_FORMAT, e.reason());
    }

    @Test
    void exposesUnknownAttributesForForwardCompatibility() throws Exception {
        AppReceipt receipt = verifier(pki, BUNDLE).verify(receiptDer);
        assertArrayEquals(new byte[]{1, 2, 3},
                receipt.unknownAttributes().get(9999).get(0));
    }

    @Test
    void rejectsGarbageBytes() {
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(pki, BUNDLE).verify(new byte[]{1, 2, 3, 4}));
        assertEquals(Reason.INVALID_RECEIPT_FORMAT, e.reason());
    }

    @Test
    void rejectsDateOutsideRepresentableRange() throws Exception {
        // Instant.parse accepts an expanded year (+1000000000-...) whose epoch
        // millis overflow a long; that conversion runs before verification, so it
        // must surface as the library's VerificationException, not escape as a raw
        // runtime exception past the declared throws clause.
        byte[] receipt = pki.signReceipt(payload(BUNDLE, "+1000000000-01-01T00:00:00Z"));
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(pki, BUNDLE).verify(receipt));
        assertEquals(Reason.INVALID_RECEIPT_FORMAT, e.reason());
    }

    @Test
    void rejectsUnsignedBase64Garbage() {
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(pki, BUNDLE).verify("!!!not-base64!!!"));
        assertEquals(Reason.INVALID_RECEIPT_FORMAT, e.reason());
    }

    @Test
    void acceptsHistoricalReceiptSignedByNowExpiredCert() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 730L * 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() - 365L * 86_400_000L);
        TestPki expired = TestPki.receipt(notBefore, notAfter);
        Instant signedAt = Instant.now().minus(547, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
        byte[] historical = expired.signReceipt(payload(BUNDLE, signedAt.toString()),
                Date.from(signedAt));
        AppReceipt receipt = verifier(expired, BUNDLE).verify(historical);
        assertEquals(signedAt, receipt.creationDate());
    }

    @Test
    void rejectsFreshReceiptFromExpiredCert() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 730L * 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() - 365L * 86_400_000L);
        TestPki expired = TestPki.receipt(notBefore, notAfter);
        byte[] fresh = expired.signReceipt(payload(BUNDLE, Instant.now().toString()));
        VerificationException e = assertThrows(VerificationException.class,
                () -> verifier(expired, BUNDLE).verify(fresh));
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
