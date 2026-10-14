package io.github.emindeniz99.applepurchasereceiptverifier;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1External;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.jspecify.annotations.Nullable;

/**
 * What runs on bytes nobody has vouched for yet, before anything is
 * trusted: the shapes Apple never issues that would cost BouncyCastle
 * super-linear work, refused or passed over first. It reads a certificate
 * entry of the receipt's bag or of an {@code x5c} header without its key
 * ({@link #readCertificate}), counting the entry's extensions before the
 * parse ({@link #tooManyExtensions}), decoding the signature BIT STRING
 * BouncyCastle would otherwise read lazily, and screening the parts of it
 * the X.509 grammar leaves open ({@link #convertible}). {@link ReceiptCore} applies
 * the same two screens to a SignerInfo's issuer name ({@link #stringsOnly})
 * and algorithm parameters ({@link #holdsSet}). None of it decides trust;
 * that is {@link AppleTrust}.
 */
final class PreTrustScreen {

    /**
     * The most extensions a certificate may carry, counted before it is
     * parsed. BouncyCastle keeps a certificate's extensions in a
     * {@code java.util.Hashtable} keyed by OID, whose hash is an unkeyed
     * function of the OID's octets and whose buckets are lists, so
     * distinct OIDs of one hash make building the table quadratic in their
     * number. Apple's certificates carry three to eight. Each insert scans
     * the bucket twice, so at this cap one table costs at most about a
     * million OID comparisons, a few hundred milliseconds at the longest
     * OIDs BouncyCastle admits (each comparison is {@code Arrays.equals}
     * over up to 4,096 octets), and a certificate's table is built at least
     * twice: an estimate from the sources, not timed. A certificate over it
     * is passed over, as one {@link #convertible} rejects.
     */
    static final int MAX_CERTIFICATE_EXTENSIONS = 1000;

    private PreTrustScreen() {}

    /**
     * One Certificate entry, of the receipt's bag or of an {@code x5c}
     * header, read without decoding its key, or null for an entry passed
     * over: one over {@link #MAX_CERTIFICATE_EXTENSIONS}, counted before the
     * parse builds BouncyCastle's table of them, or one {@link #convertible}
     * passes over, which the conversion would spend seconds on. An entry
     * under the cap that does not parse throws.
     */
    static @Nullable X509CertificateHolder readCertificate(ASN1Encodable entry) {
        if (tooManyExtensions(entry)) {
            return null;
        }
        // Read as parsed, not re-encoded: DER sorts every SET by its
        // members' encodings, seconds for a cap-sized nested entry.
        X509CertificateHolder holder = new X509CertificateHolder(Certificate.getInstance(entry));
        // getOctets throws for a signature BIT STRING with unused bits, so
        // such an entry fails here as one that does not decode. Left to the
        // top-down walk, signedBy would swallow the throw and count the
        // entry as unsigned: a stranger passed over, an x5c leaf
        // UNTRUSTED_CHAIN.
        holder.toASN1Structure().getSignature().getOctets();
        return convertible(holder.toASN1Structure()) ? holder : null;
    }

    /**
     * Whether {@code certificate}, a Certificate not yet parsed, carries more
     * than {@link #MAX_CERTIFICATE_EXTENSIONS} extensions. Every {@code [3]}
     * field of the TBS after its first counts wherever it stands, a superset
     * of the fields BouncyCastle parses as extensions, which it reads only
     * after the subject's key. The first is not counted: BouncyCastle reads a
     * tagged first field as the version whatever its tag number, so a
     * {@code [3]} there is never an extensions table. Only the outer
     * Certificate and TBS SEQUENCEs and the counted fields are checked, and a
     * shape that fails those throws. The rest is not read, so an entry over
     * the cap is passed over whether or not its parse would succeed: the
     * count must come first, as the parse is what builds the table.
     */
    static boolean tooManyExtensions(ASN1Encodable certificate) {
        ASN1Sequence tbs =
                ASN1Sequence.getInstance(ASN1Sequence.getInstance(certificate).getObjectAt(0));
        int count = 0;
        for (int i = 1; i < tbs.size(); i++) {
            ASN1Encodable field = tbs.getObjectAt(i);
            if (field instanceof ASN1TaggedObject && ((ASN1TaggedObject) field).getTagNo() == 3) {
                count +=
                        ASN1Sequence.getInstance((ASN1TaggedObject) field, true).size();
            }
        }
        return count > MAX_CERTIFICATE_EXTENSIONS;
    }

    /**
     * Whether BouncyCastle can turn {@code certificate} into a JCA object, and
     * verify and compare that object, without sorting a SET the sender
     * nested. Encoding to DER sorts every SET by its members' encodings, at a
     * cost that grows with the nesting, and BouncyCastle's X.509 object
     * DER-encodes the names and the signature parameters as it is built, the
     * TBS as it is verified and the whole certificate as it is compared.
     *
     * <p>The X.509 grammar leaves two places open to any ASN.1, and
     * BouncyCastle parses the rest strictly or keeps it as octets (extension
     * values, the key, the signature): an attribute value in the issuer or
     * subject name, and the parameters of the three AlgorithmIdentifiers
     * (the TBS signature, the outer signatureAlgorithm, the key's). So the
     * certificate is convertible when every name value is a string and no
     * parameters hold a SET. Apple's names hold PrintableString and
     * UTF8String, and no signature or key algorithm defines a SET in its
     * parameters, so a certificate that is not convertible is not one Apple
     * issued. The one SET left, an RDN's SET OF values, BouncyCastle 1.86
     * sorts in N log N.</p>
     */
    static boolean convertible(Certificate certificate) {
        TBSCertificate tbs = certificate.getTBSCertificate();
        return stringsOnly(tbs.getIssuer())
                && stringsOnly(tbs.getSubject())
                && !holdsSet(tbs.getSignature().getParameters())
                && !holdsSet(certificate.getSignatureAlgorithm().getParameters())
                && !holdsSet(tbs.getSubjectPublicKeyInfo().getAlgorithm().getParameters());
    }

    /** Whether every attribute value in {@code name} is a string. */
    static boolean stringsOnly(X500Name name) {
        for (RDN rdn : name.getRDNs()) {
            for (AttributeTypeAndValue value : rdn.getTypesAndValues()) {
                if (!(value.getValue() instanceof ASN1String)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Whether {@code value} is a SET or holds one inside a SEQUENCE, a
     * tagged object, or an EXTERNAL's content or data value descriptor, the
     * containers BouncyCastle's parser builds besides constructed strings,
     * which hold only strings. BouncyCastle puts any EXTERNAL element that is
     * not an OID, an INTEGER or a tagged object in the descriptor, a SET
     * included. The depth is the parser's own bound.
     */
    static boolean holdsSet(@Nullable ASN1Encodable value) {
        if (value == null) {
            return false;
        }
        ASN1Primitive primitive = value.toASN1Primitive();
        if (primitive instanceof ASN1Set) {
            return true;
        }
        if (primitive instanceof ASN1Sequence) {
            for (ASN1Encodable member : (ASN1Sequence) primitive) {
                if (holdsSet(member)) {
                    return true;
                }
            }
            return false;
        }
        if (primitive instanceof ASN1TaggedObject) {
            return holdsSet(((ASN1TaggedObject) primitive).getBaseObject());
        }
        if (primitive instanceof ASN1External) {
            ASN1External external = (ASN1External) primitive;
            return holdsSet(external.getDataValueDescriptor()) || holdsSet(external.getExternalContent());
        }
        return false;
    }
}
