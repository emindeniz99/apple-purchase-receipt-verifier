package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.jspecify.annotations.Nullable;

/** A receipt's embedded certificate bag, every entry decoded once except its public key. */
final class ReceiptCertificates {

    final List<X509Certificate> all = new ArrayList<>();
    private final List<X509CertificateHolder> holders = new ArrayList<>();

    private ReceiptCertificates() {}

    /**
     * Decodes every entry of the raw {@code certificates} set. The bag is
     * unsigned, so an entry that does not decode is a defect of the receipt:
     * MALFORMED, whichever certificate it was meant to be.
     */
    static ReceiptCertificates decode(@Nullable ASN1Set certificateSet) throws VerificationException {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BouncyCastle.PROVIDER);
        ReceiptCertificates certificates = new ReceiptCertificates();
        if (certificateSet == null) {
            return certificates;
        }
        for (int i = 0; i < certificateSet.size(); i++) {
            try {
                X509CertificateHolder holder = new X509CertificateHolder(
                        certificateSet.getObjectAt(i).toASN1Primitive().getEncoded("DER"));
                X509Certificate certificate = converter.getCertificate(holder);
                // Forces BouncyCastle's lazy signature decode here, not inside
                // the path builder. The key is not read: see
                // ReceiptCore.authenticatedTopDown.
                certificate.getSignature();
                certificates.all.add(certificate);
                certificates.holders.add(holder);
            } catch (IOException | CertificateException | RuntimeException e) {
                throw new VerificationException(
                        Reason.MALFORMED, "an embedded certificate is not a valid certificate", e);
            }
        }
        return certificates;
    }

    /** The first embedded certificate carrying the issuer and serial {@code signer} names. */
    X509Certificate signer(SignerInformation signer) throws VerificationException {
        SignerId sid = signer.getSID();
        for (int i = 0; i < holders.size(); i++) {
            if (sid.match(holders.get(i))) {
                return all.get(i);
            }
        }
        throw new VerificationException(Reason.MALFORMED, "signer certificate not embedded");
    }

    /**
     * The raw {@code certificates [0] IMPLICIT SET}, or null when there is
     * none: counted against the cap before a single entry is decoded.
     */
    static @Nullable ASN1Set embeddedCertificateSet(CMSSignedData cms) {
        return SignedData.getInstance(cms.toASN1Structure().getContent()).getCertificates();
    }
}
