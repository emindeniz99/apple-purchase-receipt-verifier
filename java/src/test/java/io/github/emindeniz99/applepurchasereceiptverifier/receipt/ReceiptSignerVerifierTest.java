package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

/**
 * {@link ReceiptVerifier#signerVerifier} assembles the CMS signature verifier
 * that {@code JcaSimpleSignerInfoVerifierBuilder} used to build, sharing the
 * two lookup tables the builder rebuilt on every receipt. The CMS signature is
 * the check that makes a receipt Apple's, so the assembled verifier has to
 * reach the same verdict as the builder's on every receipt: genuine,
 * generated, and corrupted in the signature, the signed content or anywhere
 * else a parse still survives.
 */
class ReceiptSignerVerifierTest {

    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    @Test
    void reachesTheBuildersVerdictOnEveryReceipt() throws IOException {
        int valid = 0;
        int invalid = 0;
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        for (byte[] input : ReceiptDerTest.corpus()) {
            SignerInformation signer;
            X509Certificate certificate;
            try {
                CMSSignedData cms = new CMSSignedData(input);
                signer = cms.getSignerInfos().getSigners().iterator().next();
                @SuppressWarnings("unchecked")
                Collection<X509CertificateHolder> matches =
                        cms.getCertificates().getMatches(signer.getSID());
                certificate = converter.getCertificate(matches.iterator().next());
            } catch (Exception e) {
                continue; // no signer to verify; the verifier rejects it earlier
            }
            String expected = outcome(signer, certificate, true);
            assertEquals(expected, outcome(signer, certificate, false), "verdict differs");
            if (expected.equals("verified true")) {
                valid++;
            } else {
                invalid++;
            }
        }
        assertTrue(valid > 100, "only " + valid + " signatures verified");
        assertTrue(invalid > 100, "only " + invalid + " signatures failed");
    }

    private static String outcome(SignerInformation signer, X509Certificate certificate, boolean builder) {
        try {
            return "verified "
                    + signer.verify(
                            builder
                                    ? new JcaSimpleSignerInfoVerifierBuilder()
                                            .setProvider(PROVIDER)
                                            .build(certificate)
                                    : ReceiptVerifier.signerVerifier(certificate));
        } catch (Exception e) {
            return e.getClass().getName() + ": " + e.getMessage();
        }
    }
}
