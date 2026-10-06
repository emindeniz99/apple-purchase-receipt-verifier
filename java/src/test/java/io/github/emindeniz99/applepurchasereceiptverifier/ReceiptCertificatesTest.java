package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Collections;
import java.util.Date;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.junit.jupiter.api.Test;

/**
 * Every certificate a SignerInfo names is tried (owner Q69), and each try
 * costs a chain build and a signature check. Anyone relaying a receipt can
 * copy the signer into the unsigned bag, up to the bag's cap, so equal copies
 * are tried once: they would get the same verdict.
 */
class ReceiptCertificatesTest {

    @Test
    void copiesOfTheSignerAreTriedOnce() throws Exception {
        TestPki pki = TestPki.receipt(new Date(1704067200000L), new Date(2524608000000L));
        byte[] payload = TestPki.receiptPayload(
                "com.example.app",
                "1.2.3",
                new byte[] {1, 2, 3, 4},
                new byte[20],
                "2024-08-06T12:00:00Z",
                Collections.<byte[]>emptyList());
        CMSSignedData cms = new CMSSignedData(pki.signReceiptWithLeafCopies(payload, 3));
        SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();

        ReceiptCertificates certificates = ReceiptCertificates.decode(cms);

        assertEquals(5, certificates.all().size(), "the bag keeps every copy");
        assertEquals(1, certificates.signers(signer).size());
        Checks.receipt(Checks.verifier(pki.root), pki.signReceiptWithLeafCopies(payload, 3));
    }
}
