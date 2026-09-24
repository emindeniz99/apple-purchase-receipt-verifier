package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The SignerInfo checks that run after the chain has passed: the signer's key
 * type, the digest allowlist, and which SignerInfo is looked at. Each receipt
 * here is signed by a certificate that chains to the pinned test root and
 * carries the receipt-signing marker, so the check under test is the only
 * one that can decide the verdict.
 */
class ReceiptSignerInfoTest {

    private static final String BUNDLE = "com.example.app";
    private static final String MARKER_OID = "1.2.840.113635.100.6.11.1";

    private static TestPki pki;
    private static byte[] payload;
    private static Date signedAt;

    @BeforeAll
    static void setUp() throws Exception {
        pki = TestPki.receipt();
        Instant creation = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        signedAt = Date.from(creation);
        payload = TestPki.receiptPayload(
                BUNDLE,
                "1.0",
                new byte[] {1, 2, 3, 4},
                new byte[20],
                creation.toString(),
                Collections.<byte[]>emptyList());
    }

    /**
     * Receipt signatures are RSA. A signer certificate with any other key is
     * refused before BouncyCastle is asked to verify with it, so a key type
     * the check was never designed for cannot be the one that passes.
     */
    @Test
    void aSignerWithANonRsaKeyIsAnInvalidSignature() throws Exception {
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair signerKey = ec.generateKeyPair();
        X509Certificate signer = signerUnderTheIntermediate(signerKey);
        byte[] receipt = signAs(signerKey, "SHA256withECDSA", signer);

        VerificationException e =
                assertThrows(VerificationException.class, () -> verifier().verify(receipt));
        assertEquals(Reason.INVALID_SIGNATURE, e.reason(), e.getMessage());
        assertTrue(e.getMessage().contains("not RSA"), e.getMessage());
    }

    /**
     * Apple signs receipts with SHA-1 or SHA-256. A SignerInfo naming any
     * other digest is not a receipt this library knows how to judge, so it is
     * refused as a format defect rather than verified under a digest nobody
     * reviewed.
     */
    @Test
    void aDigestOutsideTheAllowlistIsAnInvalidReceiptFormat() throws Exception {
        KeyPair signerKey = rsaKeyPair();
        X509Certificate signer = signerUnderTheIntermediate(signerKey);
        byte[] receipt = signAs(signerKey, "SHA512withRSA", signer);

        VerificationException e =
                assertThrows(VerificationException.class, () -> verifier().verify(receipt));
        assertEquals(Reason.INVALID_RECEIPT_FORMAT, e.reason(), e.getMessage());
        assertTrue(e.getMessage().contains("unsupported receipt digest algorithm"), e.getMessage());
    }

    /** Control for the two tests above: the same construction with an allowed digest and key verifies. */
    @Test
    void theSameConstructionWithAnRsaKeyAndSha256Verifies() throws Exception {
        KeyPair signerKey = rsaKeyPair();
        X509Certificate signer = signerUnderTheIntermediate(signerKey);
        AppReceipt receipt = verifier().verify(signAs(signerKey, "SHA256withRSA", signer));
        assertEquals(BUNDLE, receipt.bundleId());
    }

    /**
     * Current behaviour, pinned so a change to it is deliberate: only the
     * first SignerInfo is checked, and any after it are ignored. A receipt
     * whose first signer is genuine verifies even when a second signer is a
     * stranger; swap the two and it fails on the stranger's chain. Apple's
     * receipts carry exactly one SignerInfo; refusing more than one is on the
     * roadmap.
     */
    @Test
    void onlyTheFirstSignerInfoIsChecked() throws Exception {
        KeyPair genuineKey = rsaKeyPair();
        X509Certificate genuine = signerUnderTheIntermediate(genuineKey);
        KeyPair strangerKey = rsaKeyPair();
        X509Certificate stranger = TestPki.cert(
                "CN=Stranger",
                strangerKey,
                "CN=Stranger",
                strangerKey.getPrivate(),
                false,
                MARKER_OID,
                pki.leaf.getNotBefore(),
                pki.leaf.getNotAfter(),
                "SHA256withRSA");
        byte[] fromGenuine = signAs(genuineKey, "SHA256withRSA", genuine);
        byte[] fromStranger = signAs(strangerKey, "SHA256withRSA", stranger);

        AppReceipt receipt = verifier().verify(withSignerInfosInOrder(fromGenuine, fromStranger, stranger));
        assertEquals(BUNDLE, receipt.bundleId());

        byte[] strangerFirst = withSignerInfosInOrder(fromStranger, fromGenuine, genuine);
        VerificationException e =
                assertThrows(VerificationException.class, () -> verifier().verify(strangerFirst));
        assertEquals(Reason.INVALID_CHAIN, e.reason(), e.getMessage());
    }

    private static ReceiptVerifier verifier() {
        return new ReceiptVerifier(Collections.singleton(pki.root), BUNDLE);
    }

    private static X509Certificate signerUnderTheIntermediate(KeyPair signerKey) throws Exception {
        return TestPki.cert(
                "CN=Fake Receipt Signing",
                signerKey,
                "CN=Fake WWDR CA",
                pki.intermediateKey,
                false,
                MARKER_OID,
                pki.leaf.getNotBefore(),
                pki.leaf.getNotAfter(),
                "SHA256withRSA");
    }

    private static byte[] signAs(KeyPair signerKey, String sigAlg, X509Certificate signer) throws Exception {
        List<X509CertificateHolder> embedded = new ArrayList<X509CertificateHolder>();
        for (X509Certificate certificate : Arrays.asList(signer, pki.intermediate, pki.root)) {
            embedded.add(new X509CertificateHolder(certificate.getEncoded()));
        }
        return TestPki.signReceiptAs(payload, signedAt, signerKey.getPrivate(), sigAlg, embedded.get(0), embedded);
    }

    /**
     * {@code first}'s SignedData with {@code second}'s SignerInfo appended and
     * {@code extra} added to the certificates. The SET is written in the
     * order given (DL, not DER, which would sort it), so which SignerInfo
     * comes first is the test's choice rather than an accident of encoding.
     */
    private static byte[] withSignerInfosInOrder(byte[] first, byte[] second, X509Certificate extra) throws Exception {
        SignedData a = signedData(first);
        SignedData b = signedData(second);
        ASN1EncodableVector signerInfos = new ASN1EncodableVector();
        signerInfos.add(a.getSignerInfos().getObjectAt(0));
        signerInfos.add(b.getSignerInfos().getObjectAt(0));
        ASN1EncodableVector certificates = new ASN1EncodableVector();
        for (ASN1Encodable certificate : a.getCertificates()) {
            certificates.add(certificate);
        }
        certificates.add(new X509CertificateHolder(extra.getEncoded()).toASN1Structure());
        SignedData combined = new SignedData(
                a.getDigestAlgorithms(),
                a.getEncapContentInfo(),
                new DLSet(certificates),
                (ASN1Set) null,
                new DLSet(signerInfos));
        return new ContentInfo(CMSObjectIdentifiers.signedData, combined).getEncoded();
    }

    private static SignedData signedData(byte[] cms) throws Exception {
        return SignedData.getInstance(new CMSSignedData(cms).toASN1Structure().getContent());
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        return rsa.generateKeyPair();
    }
}
