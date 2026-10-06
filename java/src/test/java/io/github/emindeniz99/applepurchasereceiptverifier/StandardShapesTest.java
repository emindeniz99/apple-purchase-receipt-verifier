package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.cert.X509Certificate;
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
}
