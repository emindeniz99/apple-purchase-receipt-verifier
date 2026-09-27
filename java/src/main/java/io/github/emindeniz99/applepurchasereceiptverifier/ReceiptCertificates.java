package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.jspecify.annotations.Nullable;

/**
 * A receipt's embedded certificate bag: every entry decoded once, except its
 * public key, and the verdict for the entry a SignerInfo names.
 */
final class ReceiptCertificates {

    private ReceiptCertificates() {}

    /**
     * The embedded certificate bag, decoded once for every SignerInfo: the
     * entries that decoded, with their holders, and the ones that did not.
     */
    static final class EmbeddedCertificates {
        final List<X509Certificate> all = new ArrayList<X509Certificate>();
        /** Parallel to {@link #all}. */
        final List<X509CertificateHolder> holders = new ArrayList<X509CertificateHolder>();

        final List<UnreadableEntry> unreadable = new ArrayList<UnreadableEntry>();

        /**
         * The certificates carrying the issuer and serial {@code signer}
         * names, in bag order and never empty, or the verdict for the bag.
         * The bag is unsigned, so more than one can match: a certificate
         * with the signer's identity on another key can sit ahead of the
         * genuine one, and the caller tries each.
         * The signer's own entry not decoding is INVALID_CERTIFICATE, as an
         * unreadable x5c entry is on the JWS path; any other entry not
         * decoding is MALFORMED, because the bag is unsigned and bytes that
         * cannot be read there are a defect of the receipt, not of a
         * certificate. A broken signer outranks a broken stranger.
         */
        List<X509Certificate> signers(SignerInformation signer) throws VerificationException {
            SignerId sid = signer.getSID();
            for (UnreadableEntry entry : unreadable) {
                // An entry the holder refused has its identity read from the
                // raw DER; see namesTheSigner.
                boolean isSigner = entry.holder != null
                        ? sid.match(entry.holder)
                        : entry.raw != null && namesTheSigner(entry.raw, sid);
                if (isSigner) {
                    throw new VerificationException(
                            Reason.INVALID_CERTIFICATE, "receipt signer certificate does not decode", entry.error);
                }
            }
            if (!unreadable.isEmpty()) {
                throw new VerificationException(
                        Reason.MALFORMED,
                        "an embedded certificate is not a valid certificate",
                        unreadable.get(0).error);
            }
            List<X509Certificate> matches = new ArrayList<X509Certificate>();
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

    /** An embedded entry that did not decode, with as much of it as was read. */
    private static final class UnreadableEntry {
        final byte @Nullable [] raw;
        final @Nullable X509CertificateHolder holder;
        final Exception error;

        UnreadableEntry(byte @Nullable [] raw, @Nullable X509CertificateHolder holder, Exception error) {
            this.raw = raw;
            this.holder = holder;
            this.error = error;
        }
    }

    /**
     * Decodes every embedded certificate, except its public key.
     *
     * <p>This is the only place a receipt certificate is decoded, so a
     * defect gets one verdict whichever layer finds it: the X.509 structure,
     * a basicConstraints or keyUsage value (which only the JCA object
     * decodes), or a signature BIT STRING that is not whole octets (which
     * BouncyCastle reads lazily, and would otherwise throw from inside the
     * path builder). Keys are decoded later, and only for certificates a
     * pinned root vouches for; see {@code ReceiptCore.authenticatedTopDown}. Which
     * verdict an entry that does not decode gets is decided per SignerInfo,
     * in {@link EmbeddedCertificates#signers}.</p>
     *
     * <p>This walk over the raw set, and {@link #namesTheSigner}, exist so
     * that the two can be told apart for an entry no decoder accepts.
     * {@code cms.getCertificates()} decodes every entry eagerly and throws on
     * the first bad one without saying which, so a broken signer (version
     * 11, an extension carried twice, an unimplemented curve, a corrupt
     * extension) could not be told from a broken stranger. Do not replace
     * this walk with {@code cms.getCertificates()}.</p>
     */
    static EmbeddedCertificates decodeEmbedded(@Nullable ASN1Set certificateSet) {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BouncyCastle.PROVIDER);
        EmbeddedCertificates certificates = new EmbeddedCertificates();
        int embeddedCount = certificateSet == null ? 0 : certificateSet.size();
        for (int i = 0; i < embeddedCount; i++) {
            byte @Nullable [] raw = null;
            @Nullable X509CertificateHolder holder = null;
            try {
                raw = certificateSet.getObjectAt(i).toASN1Primitive().getEncoded("DER");
                holder = new X509CertificateHolder(raw);
                X509Certificate certificate = converter.getCertificate(holder);
                // Result unused: reading it here is what makes a lazily
                // decoded signature fail in this loop. The key is not read:
                // see ReceiptCore.authenticatedTopDown.
                certificate.getSignature();
                certificates.all.add(certificate);
                certificates.holders.add(holder);
            } catch (Exception e) {
                certificates.unreadable.add(new UnreadableEntry(raw, holder, e));
            }
        }
        return certificates;
    }

    /**
     * Whether {@code raw} carries the issuer Name and serialNumber
     * {@code sid} names, read as generic ASN.1 because the entries asked
     * about are the ones {@link X509CertificateHolder} refused. Inferring it
     * from the entries that did decode would blame the wrong entry whenever
     * the receipt names a certificate it does not carry.
     *
     * <p>{@code TBSCertificate ::= SEQUENCE { [0] version DEFAULT v1,
     * serialNumber INTEGER, signature AlgorithmIdentifier, issuer Name,
     * ... }}: anything without that shape is not an identity and cannot
     * match.</p>
     */
    private static boolean namesTheSigner(byte[] raw, SignerId sid) {
        try {
            ASN1Sequence certificate = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(raw));
            ASN1Encodable first = certificate.getObjectAt(0);
            if (!(first instanceof ASN1Sequence)) {
                return false;
            }
            ASN1Sequence tbs = (ASN1Sequence) first;
            int index = tbs.getObjectAt(0) instanceof ASN1TaggedObject ? 1 : 0;
            BigInteger serial = ASN1Integer.getInstance(tbs.getObjectAt(index)).getValue();
            X500Name issuer = X500Name.getInstance(tbs.getObjectAt(index + 2));
            return serial.equals(sid.getSerialNumber()) && issuer.equals(sid.getIssuer());
        } catch (RuntimeException | IOException e) {
            return false;
        }
    }

    /**
     * The raw {@code certificates [0] IMPLICIT SET} of the SignedData, or
     * null when the receipt carries none. BouncyCastle's ASN.1
     * {@link SignedData} hands the set back undecoded, so an entry no
     * certificate decoder accepts is still counted and still locatable.
     */
    static @Nullable ASN1Set embeddedCertificateSet(CMSSignedData cms) {
        return SignedData.getInstance(cms.toASN1Structure().getContent()).getCertificates();
    }
}
