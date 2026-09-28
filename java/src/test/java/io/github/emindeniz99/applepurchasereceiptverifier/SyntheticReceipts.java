package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

/**
 * The shared generated receipt ({@code fixtures/generated/receipt.der}),
 * signed again in this JVM under a {@link TestPki} whose intermediate carries
 * Apple's WWDR marker.
 *
 * <p>0.7 checks that marker on the receipt path, and the receipts committed
 * under {@code fixtures/generated/} were generated before it, so every one of
 * them now fails as INVALID_CERTIFICATE_PURPOSE. Unit tests that need a
 * receipt that verifies take it from here instead: the same payload and dates
 * as {@code FixtureGeneratorTest} writes, fresh keys, built once per JVM.</p>
 */
final class SyntheticReceipts {

    static final String BUNDLE = "com.example.app";

    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final long CHAIN_NOT_BEFORE = 1704067200000L; // 2024-01-01
    private static final long CHAIN_NOT_AFTER = 2524608000000L; // 2050-01-01
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

    private static final TestPki PKI;
    private static final byte[] RECEIPT;
    private static final byte[] TAMPERED;

    static {
        try {
            PKI = TestPki.receipt(new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
            byte[] payload = TestPki.receiptPayload(
                    BUNDLE,
                    "1.2.3",
                    OPAQUE,
                    TestPki.deviceHash(GUID, OPAQUE, BUNDLE),
                    CREATION_DATE,
                    Arrays.asList(
                            TestPki.inAppPurchase(
                                    1,
                                    BUNDLE + ".coins100",
                                    "70000000000001",
                                    "70000000000001",
                                    "2024-01-15T12:00:00Z",
                                    null),
                            TestPki.inAppPurchase(
                                    1,
                                    BUNDLE + ".vip",
                                    "70000000000002",
                                    "70000000000002",
                                    "2024-02-01T09:30:00Z",
                                    "2030-02-01T09:30:00Z")));
            RECEIPT = PKI.signReceipt(payload, new Date(SIGNED_DATE));
            TAMPERED = RECEIPT.clone();
            byte[] product = (BUNDLE + ".vip").getBytes(StandardCharsets.US_ASCII);
            TAMPERED[indexOf(TAMPERED, product) + product.length - 1] ^= 0x01;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private SyntheticReceipts() {}

    static X509Certificate root() {
        return PKI.root;
    }

    static TestPki pki() {
        return PKI;
    }

    /** The receipt's DER: a ProductionSandbox receipt with two purchases. */
    static byte[] der() {
        return RECEIPT.clone();
    }

    static String base64() {
        return Base64.getEncoder().encodeToString(RECEIPT);
    }

    /** The same receipt with one payload byte changed, so its signature no longer verifies. */
    static byte[] tamperedDer() {
        return TAMPERED.clone();
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length && match; j++) {
                match = haystack[i + j] == needle[j];
            }
            if (match) {
                return i;
            }
        }
        throw new AssertionError("needle not found");
    }
}
