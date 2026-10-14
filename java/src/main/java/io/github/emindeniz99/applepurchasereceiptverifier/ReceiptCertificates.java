package io.github.emindeniz99.applepurchasereceiptverifier;

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
import org.bouncycastle.asn1.x500.style.BCStrictStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;

/**
 * A receipt's embedded certificate bag, decoded once per receipt, not per
 * SignerInfo, without any public key.
 */
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
     * signer and are skipped, and so is a certificate
     * {@link PreTrustScreen#readCertificate} passes over. The bag is
     * unsigned, so an entry under the cap that does not decode is a defect of
     * the receipt: MALFORMED, whichever certificate it was meant to be. One
     * over the cap is passed over before it is parsed, decodable or not.
     */
    static ReceiptCertificates decode(SignedData signedData) throws VerificationException {
        ASN1Set certificateSet = signedData.getCertificates();
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
                    // Only checks that the entry is a SEQUENCE; one that is
                    // not throws and is MALFORMED below.
                    ASN1Sequence.getInstance((ASN1TaggedObject) entry, false);
                    continue;
                }
                X509CertificateHolder holder = PreTrustScreen.readCertificate(entry);
                // A certificate Apple could not have issued names no signer
                // and vouches for nothing: it is passed over, not refused.
                if (holder == null) {
                    continue;
                }
                certificates.all.add(converter.getCertificate(holder));
                certificates.holders.add(holder);
            } catch (CertificateException | RuntimeException e) {
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
     * the signer's identity to the bag. Equal certificates are returned once.
     *
     * <p>Issuers are compared with BouncyCastle's strict style, which keeps
     * RDN order (RFC 5280 section 7.1) and is linear. {@code X500Name.equals},
     * which {@code SignerId.match} uses, ignores RDN order and costs time
     * quadratic in the RDN count of two names nobody has authenticated yet.
     * So a SignerId listing the certificate's RDNs in another order names
     * no certificate. Both names hold strings only, the SignerId's checked
     * by {@link PreTrustScreen#appleShaped} and every certificate's in
     * {@link #decode}, so the comparison re-encodes no value.</p>
     */
    List<X509Certificate> signers(SignerInformation signer) throws VerificationException {
        SignerId sid = signer.getSID();
        List<X509Certificate> matches = new ArrayList<>();
        for (int i = 0; i < holders.size(); i++) {
            X509CertificateHolder holder = holders.get(i);
            boolean match = sid.getSerialNumber() != null
                    ? sid.getSerialNumber().equals(holder.getSerialNumber())
                            && BCStrictStyle.INSTANCE.areEqual(sid.getIssuer(), holder.getIssuer())
                    // The subjectKeyIdentifier form: BouncyCastle compares
                    // key identifiers only, never a name.
                    : sid.match(holder);
            // A byte-identical copy gets the same verdict, so it is tried once.
            if (match && !matches.contains(all.get(i))) {
                matches.add(all.get(i));
            }
        }
        if (matches.isEmpty()) {
            throw new VerificationException(Reason.MALFORMED, "signer certificate not embedded");
        }
        return matches;
    }
}
