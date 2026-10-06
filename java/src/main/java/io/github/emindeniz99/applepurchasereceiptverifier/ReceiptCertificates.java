package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;

/** A receipt's embedded certificate bag, every entry decoded once except its public key. */
final class ReceiptCertificates {

    /** Genuine receipts embed one to three; checked before any is decoded. */
    static final int MAX_EMBEDDED_CERTIFICATES = 10;

    private final List<X509Certificate> all = new ArrayList<>();
    private final List<X509CertificateHolder> holders = new ArrayList<>();

    private ReceiptCertificates() {}

    /** Every embedded certificate, in receipt order. */
    List<X509Certificate> all() {
        return Collections.unmodifiableList(all);
    }

    /**
     * Decodes every Certificate entry of the raw {@code certificates [0]
     * IMPLICIT SET}, after counting the set against
     * {@link #MAX_EMBEDDED_CERTIFICATES}. The other CertificateChoices
     * (RFC 5652 10.2.2: {@code [0]} to {@code [3]}, each a SEQUENCE) name no
     * signer and are skipped. The bag is unsigned, so an entry that does not
     * decode is a defect of the receipt: MALFORMED, whichever certificate it
     * was meant to be.
     */
    static ReceiptCertificates decode(CMSSignedData cms) throws VerificationException {
        ASN1Set certificateSet =
                SignedData.getInstance(cms.toASN1Structure().getContent()).getCertificates();
        int embeddedCount = certificateSet == null ? 0 : certificateSet.size();
        if (embeddedCount > MAX_EMBEDDED_CERTIFICATES) {
            throw new VerificationException(
                    Reason.MALFORMED,
                    "receipt embeds " + embeddedCount + " certificates, more than the maximum of "
                            + MAX_EMBEDDED_CERTIFICATES);
        }
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BouncyCastle.PROVIDER);
        ReceiptCertificates certificates = new ReceiptCertificates();
        if (certificateSet == null) {
            return certificates;
        }
        for (int i = 0; i < certificateSet.size(); i++) {
            ASN1Encodable entry = certificateSet.getObjectAt(i);
            try {
                if (entry instanceof ASN1TaggedObject
                        && ((ASN1TaggedObject) entry).getTagClass() == BERTags.CONTEXT_SPECIFIC
                        && ((ASN1TaggedObject) entry).getTagNo() <= 3) {
                    ASN1Sequence.getInstance((ASN1TaggedObject) entry, false);
                    continue;
                }
                X509CertificateHolder holder =
                        new X509CertificateHolder(entry.toASN1Primitive().getEncoded("DER"));
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

    /**
     * Every embedded certificate that {@code signer}'s SignerId matches, by
     * issuer and serial number or by subjectKeyIdentifier, in receipt order.
     * More than one can: a renewed certificate keeps its key and so its
     * subjectKeyIdentifier, and anyone relaying a receipt can add a copy of
     * the signer's identity to the bag.
     */
    List<X509Certificate> signers(SignerInformation signer) throws VerificationException {
        SignerId sid = signer.getSID();
        List<X509Certificate> matches = new ArrayList<>();
        for (int i = 0; i < holders.size(); i++) {
            if (sid.match(holders.get(i))) {
                matches.add(all.get(i));
            }
        }
        if (matches.isEmpty()) {
            throw new VerificationException(Reason.MALFORMED, "signer certificate not embedded");
        }
        return matches;
    }
}
