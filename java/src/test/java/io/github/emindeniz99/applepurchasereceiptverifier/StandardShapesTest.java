package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Shapes the standards allow in an Apple-signed input, which Java used to
 * refuse and the core accepts (owner, Q69, 2026-10-06). Each input is
 * genuine apart from the one shape, so the shape is the only thing that can
 * refuse it. The shared cases on {@link StandardShapeFixtures}' files hold
 * the core to the same answers.
 */
class StandardShapesTest {

    private static StandardShapeFixtures fixtures;
    private static Verifier receipts;
    private static Verifier jws;

    @BeforeAll
    static void setUp() throws Exception {
        fixtures = new StandardShapeFixtures();
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        X509Certificate receiptRoot = converter.getCertificate(fixtures.receiptRoot);
        X509Certificate jwsRoot = converter.getCertificate(fixtures.jwsRoot);
        receipts = Checks.verifier(receiptRoot);
        jws = Checks.verifier(jwsRoot);
    }

    /**
     * A renewed certificate keeps its key, so its subjectKeyIdentifier names
     * the expired one too, and the bag may hold both in either order. Every
     * certificate the SignerInfo names is tried, as the SignerInfos are.
     */
    @Test
    void aRenewedSignerBehindItsExpiredCopyVerifies() throws Exception {
        Checks.receipt(receipts, fixtures.renewedSignerBehindItsExpiredCopy());
    }

    /** RFC 5652 10.2.2: the bag may carry attribute and other certificates, which name no signer. */
    @Test
    void attributeAndOtherCertificatesInTheBagAreSkipped() throws Exception {
        Checks.receipt(receipts, fixtures.attributeAndOtherCertificatesInTheBag());
    }

    /** RFC 5280 4.2.1.12 lets extendedKeyUsage be critical on any certificate, a CA's included. */
    @Test
    void aCriticalExtendedKeyUsageOnTheIntermediateVerifies() throws Exception {
        Checks.receipt(receipts, fixtures.receiptUnderIntermediateWith(StandardShapeFixtures.criticalEku()));
        Checks.signedData(jws, fixtures.jwsUnderIntermediateWith(StandardShapeFixtures.criticalEku()));
    }

    /** Only extendedKeyUsage is marked processed: an unknown critical extension still refuses the chain. */
    @Test
    void anUnknownCriticalExtensionOnTheIntermediateIsStillRefused() throws Exception {
        Extension unknown = new Extension(new ASN1ObjectIdentifier("2.999.3"), true, DERNull.INSTANCE.getEncoded());
        byte[] receipt = fixtures.receiptUnderIntermediateWith(unknown);
        String token = fixtures.jwsUnderIntermediateWith(unknown);
        assertEquals(
                Reason.UNTRUSTED_CHAIN,
                assertThrows(VerificationException.class, () -> Checks.receipt(receipts, receipt))
                        .reason());
        assertEquals(
                Reason.UNTRUSTED_CHAIN,
                assertThrows(VerificationException.class, () -> Checks.signedData(jws, token))
                        .reason());
    }
}
