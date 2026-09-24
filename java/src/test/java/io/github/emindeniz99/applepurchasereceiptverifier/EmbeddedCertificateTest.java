package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.CollectionStore;
import org.junit.jupiter.api.Test;

/**
 * A certificate in the receipt's bag that is not the signer, and whose public
 * key is on an unimplemented curve.
 *
 * <p>BouncyCastle decodes a certificate's key lazily and, when it cannot,
 * raises an unchecked exception from wherever the key is first read, which
 * for a non-signer certificate is inside the path builder. The receipt path
 * decodes every embedded certificate's key first, so this is
 * INVALID_CERTIFICATE, as the same key is on the signer
 * ({@code receipt/reject-signer-on-an-unimplemented-curve}) and on a JWS
 * intermediate ({@code transaction/reject-x5c-unimplemented-curve}), and not
 * an INVALID_RECEIPT_FORMAT carrying an internal exception's text.</p>
 *
 * <p>The certificate bag is outside what the CMS signature covers, so adding
 * the certificate leaves the receipt genuine in every other way: the test
 * first shows it verifies without the addition.</p>
 */
class EmbeddedCertificateTest {

    private static final Path GENERATED = Paths.get("..", "fixtures", "generated");

    private static X509Certificate root(String name) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(GENERATED.resolve(name))));
    }

    @Test
    void aNonSignerCertificateWithAnUnreadableKeyIsInvalidCertificate() throws Exception {
        byte[] genuine = Files.readAllBytes(GENERATED.resolve("receipt.der"));
        X509Certificate receiptRoot = root("receipt-root.der");
        assertNotNull(ReceiptVerifier.verifyReceiptCore(genuine, Collections.singleton(receiptRoot)));

        CMSSignedData cms = new CMSSignedData(genuine);
        List<X509CertificateHolder> bag =
                new ArrayList<X509CertificateHolder>(cms.getCertificates().getMatches(null));
        CMSSignedData withBadKey =
                new CMSSignedData(Files.readAllBytes(GENERATED.resolve("receipt-signer-unimplemented-curve.der")));
        bag.addAll(withBadKey.getCertificates().getMatches(null));
        byte[] tampered = CMSSignedData.replaceCertificatesAndCRLs(
                        cms, new CollectionStore<X509CertificateHolder>(bag), null, null)
                .getEncoded();

        VerificationException e = assertThrows(
                VerificationException.class,
                () -> ReceiptVerifier.verifyReceiptCore(tampered, Collections.singleton(receiptRoot)));
        assertEquals(Reason.INVALID_CERTIFICATE, e.reason(), e.getMessage());
    }
}
