package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.cert.TrustAnchor;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Contract containment for hostile receipts. BouncyCastle's ASN.1 and CMS
 * entry points report malformed input with UNCHECKED exceptions, so a few
 * bytes of attacker input can raise a raw {@code IllegalArgumentException}
 * deep inside verification.
 *
 * <p>These tests pin the contract itself rather than any one BouncyCastle
 * exception type: the set of types a parser can throw is not knowable. The
 * verifier never throws, and its last-resort catch reports an escaped
 * exception as INTERNAL_ERROR ("alert, do not retry"), which hostile input
 * must never be able to raise at will. So the assertion is: nothing escapes,
 * and no hostile receipt is answered INTERNAL_ERROR.</p>
 */
class HostileReceiptInputTest {

    private static final String BUNDLE = "com.example.app";
    private static final byte[] GUID = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88};
    private static final byte[] OPAQUE = {1, 2, 3, 4, 5, 6, 7, 8};

    private static TestPki pki;
    private static Verifier verifier;
    private static byte[] receiptDer;

    @BeforeAll
    static void setUp() throws Exception {
        pki = TestPki.receipt();
        verifier = Checks.verifier(pki);
        String creationDate = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
        receiptDer = pki.signReceipt(TestPki.receiptPayload(
                BUNDLE,
                "1.2.3",
                OPAQUE,
                TestPki.deviceHash(GUID, OPAQUE, BUNDLE),
                creationDate,
                Collections.singletonList(TestPki.inAppPurchase(
                        1,
                        "com.example.app.coins100",
                        "70000000000001",
                        "70000000000001",
                        "2024-01-15T12:00:00Z",
                        null))));
    }

    @Test
    void containsBitStringPadFailureFromElevenCharactersOfBase64() {
        // Reaches BC's ASN1BitString before any crypto runs: "invalid pad bits detected".
        VerificationException e = assertThrows(VerificationException.class, () -> verify("MIADAggAAAA="));
        assertEquals(Reason.MALFORMED, e.reason());
    }

    @Test
    void containsInvalidUtf8AttributeValue() throws Exception {
        // A UTF8String whose single content byte is 0xFF: ASN1UTF8String.getString()
        // rejects it with IllegalArgumentException. That must not leak: the
        // bundle id decodes to null and its octets are still returned.
        byte[] value = {0x0c, 0x01, (byte) 0xff};
        ReceiptPayload payload = verify(pki.signReceipt(TestPki.singleAttributePayload(2, value)));
        assertNull(payload.bundleId());
        assertArrayEquals(value, payload.bundleIdBytes());
    }

    @Test
    void nothingEscapesStructurallyHostileBlobs() throws Exception {
        for (Map.Entry<String, byte[]> blob : hostileBlobs().entrySet()) {
            try {
                verify(blob.getValue());
                throw new AssertionError("verify() accepted " + blob.getKey());
            } catch (VerificationException expected) {
                // The whole contract: every rejection arrives as this type.
            } catch (RuntimeException e) {
                throw new AssertionError("verify() leaked " + e.getClass().getName() + " for " + blob.getKey(), e);
            }
        }
    }

    @Test
    void nothingEscapesMutationsOfAGenuineReceipt() {
        // The review that found this defect measured the leak rate by mutating a
        // genuine receipt; a fixed seed keeps any future failure replayable.
        Random random = new Random(20260822L);
        for (int i = 0; i < 2000; i++) {
            byte[] mutated = receiptDer.clone();
            for (int edit = random.nextInt(4) + 1; edit > 0; edit--) {
                mutated[random.nextInt(mutated.length)] = (byte) random.nextInt(256);
            }
            try {
                verify(mutated);
            } catch (VerificationException expected) {
                // A mutation that lands in a region nothing reads may still verify,
                // so only the escaping type is asserted, not the rejection.
            } catch (RuntimeException e) {
                throw new AssertionError(
                        "mutation " + i + " leaked " + e.getClass().getName(), e);
            }
        }
    }

    /**
     * An unchecked exception BouncyCastle throws before trust is MALFORMED
     * {@code "unexpected <class>"}, and the exception itself is the caller's
     * cause: the message names only the class, so it stays free of input,
     * and the cause is the developer's one clue to what BouncyCastle
     * rejected. A
     * MALFORMED the library decided itself still carries no cause, whether
     * or not a parser exception stood behind it, since its message already
     * says what was refused.
     */
    @Test
    void anUncheckedExceptionBeforeTrustIsTheCauseOfItsMalformed() throws Exception {
        byte[] wrongShape = hostileBlobs().get("signerInfos[0] is the wrong shape");
        Set<TrustAnchor> anchors = AppleTrust.anchors(Collections.singleton(pki.root));
        long now = System.currentTimeMillis();

        VerificationException thrown =
                assertThrows(VerificationException.class, () -> ReceiptCore.verifyDer(wrongShape, anchors, now));
        Throwable raised = thrown.getCause();
        assertTrue(raised instanceof RuntimeException, String.valueOf(raised));
        assertSame(raised, thrown.toFailure().cause());

        Failure failure = verifier.verifyReceipt(Base64.getEncoder().encodeToString(wrongShape))
                .failure();
        assertEquals(Reason.MALFORMED, failure.reason());
        Throwable cause = failure.cause();
        assertNotNull(cause, "the unchecked exception is the cause");
        assertEquals("unexpected " + cause.getClass().getName(), failure.message());
        assertTrue(
                Arrays.stream(cause.getStackTrace())
                        .anyMatch(f -> f.getClassName().startsWith("org.bouncycastle.")),
                "BouncyCastle threw it");

        Failure empty = verifier.verifyReceipt("").failure();
        assertEquals(Reason.MALFORMED, empty.reason());
        assertNull(empty.cause());

        byte[] truncated = hostileBlobs().get("truncated SEQUENCE header");
        VerificationException refused =
                assertThrows(VerificationException.class, () -> ReceiptCore.verifyDer(truncated, anchors, now));
        assertEquals(Reason.MALFORMED, refused.reason());
        assertNotNull(refused.getCause(), "the parser's exception stands behind it");
        assertNull(refused.toFailure().cause());
    }

    private static ReceiptPayload verify(byte[] der) throws VerificationException {
        return verify(Base64.getEncoder().encodeToString(der));
    }

    /**
     * The public call, with a failure thrown back as by {@link Checks}. An
     * INTERNAL_ERROR is the outer catch having caught what the checks should
     * have contained, so it fails the test as a leak.
     */
    private static ReceiptPayload verify(String base64) throws VerificationException {
        VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(base64);
        if (!result.verified() && result.failure().reason() == Reason.INTERNAL_ERROR) {
            throw new AssertionError(
                    "leaked " + result.failure().message(), result.failure().cause());
        }
        return Checks.unwrap(result);
    }

    /** Blobs that are hostile in shape rather than in content. */
    private static Map<String, byte[]> hostileBlobs() throws Exception {
        Map<String, byte[]> blobs = new LinkedHashMap<String, byte[]>();
        blobs.put("non-CMS junk", new byte[] {0x30, 0x03, 0x02, 0x01, 0x00});
        blobs.put("truncated SEQUENCE header", new byte[] {0x30, (byte) 0x82, 0x10});
        blobs.put(
                "certificates[0] is not a certificate", respin(new DERSet(new DERSequence(new ASN1Integer(1))), null));
        blobs.put("signerInfos[0] is the wrong shape", respin(null, new DERSet(new DERSequence(new ASN1Integer(1)))));
        blobs.put("bogus signature-algorithm OID", bogusSignatureAlgorithm());
        return blobs;
    }

    /**
     * Re-emits the genuine receipt with the certificates and/or signerInfos
     * replaced. Assembled as a raw SEQUENCE because BC's {@code SignedData}
     * constructor parses every SignerInfo to compute the version, which a
     * deliberately wrong-shaped entry would break here instead of in verify().
     */
    private static byte[] respin(ASN1Set certificates, ASN1Set signerInfos) throws Exception {
        SignedData genuine = signedData();
        ASN1EncodableVector fields = new ASN1EncodableVector();
        fields.add(genuine.getVersion());
        fields.add(genuine.getDigestAlgorithms());
        fields.add(genuine.getEncapContentInfo());
        fields.add(new DERTaggedObject(false, 0, certificates != null ? certificates : genuine.getCertificates()));
        fields.add(signerInfos != null ? signerInfos : genuine.getSignerInfos());
        return new ContentInfo(CMSObjectIdentifiers.signedData, new DERSequence(fields)).getEncoded();
    }

    private static byte[] bogusSignatureAlgorithm() throws Exception {
        SignerInfo genuine =
                SignerInfo.getInstance(signedData().getSignerInfos().getObjectAt(0));
        SignerInfo mutated = new SignerInfo(
                genuine.getSID(),
                genuine.getDigestAlgorithm(),
                genuine.getAuthenticatedAttributes(),
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4.5.6.7.8"), DERNull.INSTANCE),
                genuine.getEncryptedDigest(),
                genuine.getUnauthenticatedAttributes());
        return respin(null, new DERSet(mutated));
    }

    private static SignedData signedData() throws Exception {
        return SignedData.getInstance(
                ContentInfo.getInstance(ASN1Primitive.fromByteArray(receiptDer)).getContent());
    }
}
