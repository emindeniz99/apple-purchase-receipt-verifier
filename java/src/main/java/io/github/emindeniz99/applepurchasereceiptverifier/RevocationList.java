package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.jspecify.annotations.Nullable;

/**
 * One revocation list (an X.509 CRL) as {@link Revocation} uses it: read
 * whole when the verifier is built, never at a verify call
 * (docs/design/revocation.md §4).
 *
 * <p>The structure is read twice: by BouncyCastle for the values, and by
 * {@link Der} for the bytes as they stand, since the signature covers the
 * TBSCertList as sent and the issuer Name is compared byte for byte.</p>
 */
final class RevocationList {

    /** The largest list accepted, 1 MiB. Apple's frozen 2.3 MB WWDR G1 list is refused. */
    static final int MAX_LIST_BYTES = 1 << 20;

    /** RFC 5280 5.3.1 reasonCode values the check treats apart. */
    static final int CERTIFICATE_HOLD = 6;

    static final int REMOVE_FROM_CRL = 8;

    /** An entry with no reasonCode. */
    static final int NO_REASON = -1;

    /** A reasonCode that is unknown, repeated or does not read: it revokes. */
    static final int UNREADABLE_REASON = Integer.MAX_VALUE;

    /** The CRL extensions this profile interprets, so a critical one is understood. */
    private static final Set<ASN1ObjectIdentifier> SUPPORTED_CRITICAL =
            new HashSet<>(Arrays.asList(Extension.authorityKeyIdentifier, Extension.cRLNumber));

    /** The entry extensions this profile interprets, so a critical one is understood. */
    private static final Set<ASN1ObjectIdentifier> SUPPORTED_CRITICAL_ENTRY =
            new HashSet<>(Arrays.asList(Extension.reasonCode, Extension.invalidityDate));

    /** The file as passed; the tie between two lists sorts on it. */
    final byte[] der;

    /** The TBSCertList as sent: what the signature covers. */
    private final byte[] tbs;

    /** The {@code issuer} Name as sent. */
    final byte[] issuer;

    private final AlgorithmIdentifier signatureAlgorithm;

    /** Whether the outer signatureAlgorithm is byte-identical to the TBS's (RFC 5280 5.1.1.2). */
    private final boolean algorithmsAgree;

    private final byte @Nullable [] signature;

    /** Whether the list carries an AuthorityKeyIdentifier. */
    final boolean hasAuthorityKeyIdentifier;

    /** Its keyIdentifier; null when there is no AKI, or an AKI without one. */
    final byte @Nullable [] authorityKeyIdentifier;

    final long thisUpdate;

    final @Nullable Long nextUpdate;

    final @Nullable BigInteger crlNumber;

    /** Why the profile ignores this list; null when it is used. */
    final @Nullable String unsupported;

    /** The number of entries, for the bound on all lists together. */
    final int entryCount;

    /**
     * Each listed serial, as {@link Der#serialHex} writes it, to its
     * reasonCode or {@link #NO_REASON}. A negative serial is left out: it is
     * never matched.
     */
    final Map<String, Integer> entries;

    private RevocationList(byte[] der) {
        this.der = der;
        Der.Tlv whole = Der.whole(der);
        List<Der.Tlv> outer = Der.children(der, whole);
        if (whole.tag != 0x30 || outer.size() != 3 || outer.get(0).tag != 0x30 || outer.get(1).tag != 0x30) {
            throw new IllegalArgumentException("not a CertificateList");
        }
        List<Der.Tlv> tbsFields = Der.children(der, outer.get(0));
        int i = !tbsFields.isEmpty() && tbsFields.get(0).tag == 0x02 ? 1 : 0;
        if (tbsFields.size() < i + 3 || tbsFields.get(i + 1).tag != 0x30) {
            throw new IllegalArgumentException("not a TBSCertList");
        }
        this.tbs = outer.get(0).bytes(der);
        this.issuer = tbsFields.get(i + 1).bytes(der);
        this.algorithmsAgree =
                Arrays.equals(tbsFields.get(i).bytes(der), outer.get(1).bytes(der));

        // The structure is walked by hand rather than with BouncyCastle's
        // CertificateList, TBSCertList and Extensions: those refuse a
        // repeated extension and decode an extension's value eagerly, where
        // the profile ignores the list or reads the value as one that does
        // not read (§4), as the core does.
        ASN1Sequence certificateList;
        try {
            certificateList = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(der));
        } catch (IOException e) {
            throw new IllegalArgumentException("not a CertificateList", e);
        }
        if (certificateList.size() != 3) {
            throw new IllegalArgumentException("not a CertificateList");
        }
        ASN1Sequence fields = ASN1Sequence.getInstance(certificateList.getObjectAt(0));
        this.signatureAlgorithm = AlgorithmIdentifier.getInstance(certificateList.getObjectAt(1));
        byte[] bits;
        try {
            bits = ASN1BitString.getInstance(certificateList.getObjectAt(2)).getOctets();
        } catch (IllegalStateException e) {
            // A BIT STRING with pad bits holds no signature.
            bits = null;
        }
        this.signature = bits;

        int at = 0;
        ASN1Integer version = null;
        if (fields.size() > at && fields.getObjectAt(at) instanceof ASN1Integer) {
            version = (ASN1Integer) fields.getObjectAt(at++);
        }
        AlgorithmIdentifier.getInstance(field(fields, at++));
        X500Name.getInstance(field(fields, at++));
        this.thisUpdate = wholeSeconds(time(field(fields, at++)).getDate().getTime());
        String unsupported = null;
        Long next = null;
        if (at < fields.size()
                && (fields.getObjectAt(at) instanceof ASN1UTCTime
                        || fields.getObjectAt(at) instanceof ASN1GeneralizedTime)) {
            Time nextTime = time(fields.getObjectAt(at));
            try {
                next = wholeSeconds(nextTime.getDate().getTime());
            } catch (RuntimeException e) {
                unsupported = "its nextUpdate does not read";
            }
            at++;
        } else {
            unsupported = "it has no nextUpdate";
        }
        this.nextUpdate = next;
        ASN1Sequence revoked = null;
        if (at < fields.size() && !(fields.getObjectAt(at) instanceof ASN1TaggedObject)) {
            revoked = ASN1Sequence.getInstance(fields.getObjectAt(at++));
        }
        ASN1Sequence listExtensions = null;
        if (at < fields.size()) {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(fields.getObjectAt(at++));
            if (tagged.getTagClass() != BERTags.CONTEXT_SPECIFIC || tagged.getTagNo() != 0) {
                throw new IllegalArgumentException("not a TBSCertList");
            }
            listExtensions = ASN1Sequence.getInstance(tagged, true);
        }
        if (at != fields.size()) {
            throw new IllegalArgumentException("not a TBSCertList");
        }

        if (version == null || !version.hasValue(1)) {
            unsupported = "it is not a version 2 list";
        }

        byte[] keyIdentifier = null;
        boolean hasAki = false;
        BigInteger number = null;
        List<Extension> extensions = extensions(listExtensions);
        for (Extension extension : extensions) {
            ASN1ObjectIdentifier oid = extension.getExtnId();
            if (oid.equals(Extension.authorityKeyIdentifier)) {
                // A repeated or unreadable AuthorityKeyIdentifier refuses
                // the list, as one without a keyIdentifier does.
                if (hasAki) {
                    throw new IllegalArgumentException("the AuthorityKeyIdentifier is repeated");
                }
                hasAki = true;
                keyIdentifier = AuthorityKeyIdentifier.getInstance(extension.getParsedValue())
                        .getKeyIdentifier();
            } else if (oid.equals(Extension.cRLNumber)) {
                // A CRL Number that is repeated, negative or does not read
                // puts the list outside the profile, and the list then has
                // no number for its age and for choosing the kept list.
                if (count(extensions, oid) > 1) {
                    unsupported = "its CRL Number is repeated";
                } else {
                    try {
                        number = ASN1Integer.getInstance(extension.getParsedValue())
                                .getValue();
                    } catch (RuntimeException e) {
                        unsupported = "its CRL Number does not read";
                    }
                    if (number != null && number.signum() < 0) {
                        number = null;
                        unsupported = "its CRL Number is negative";
                    }
                }
            } else if (unsupported == null) {
                if (oid.equals(Extension.issuingDistributionPoint)) {
                    unsupported = "it has an IssuingDistributionPoint";
                } else if (oid.equals(Extension.deltaCRLIndicator)) {
                    unsupported = "it is a delta list";
                } else if (oid.equals(Extension.freshestCRL)) {
                    unsupported = "it has a FreshestCRL";
                } else if (extension.isCritical() && !SUPPORTED_CRITICAL.contains(oid)) {
                    unsupported = "it has an unsupported critical extension";
                }
            }
        }
        this.hasAuthorityKeyIdentifier = hasAki;
        this.authorityKeyIdentifier = keyIdentifier;
        this.crlNumber = number;

        Map<String, Integer> listed = new HashMap<>();
        Set<BigInteger> seen = new HashSet<>();
        int count = 0;
        for (ASN1Encodable element : revoked == null ? new ASN1Encodable[0] : revoked.toArray()) {
            ASN1Sequence entry = ASN1Sequence.getInstance(element);
            if (entry.size() < 2 || entry.size() > 3) {
                throw new IllegalArgumentException("not a revokedCertificates entry");
            }
            count++;
            BigInteger serial = ASN1Integer.getInstance(entry.getObjectAt(0)).getValue();
            time(entry.getObjectAt(1));
            if (!seen.add(serial) && unsupported == null) {
                unsupported = "it lists a serial twice";
            }
            int reason = NO_REASON;
            List<Extension> entryExtensions =
                    extensions(entry.size() == 3 ? ASN1Sequence.getInstance(entry.getObjectAt(2)) : null);
            for (Extension extension : entryExtensions) {
                ASN1ObjectIdentifier oid = extension.getExtnId();
                if (oid.equals(Extension.reasonCode)) {
                    // A reasonCode that is repeated or does not read revokes,
                    // as an unknown code and no reason do; only 6 and 8 are
                    // treated apart, so a large value must not wrap onto them.
                    reason = UNREADABLE_REASON;
                    if (count(entryExtensions, oid) == 1) {
                        try {
                            BigInteger code = ASN1Enumerated.getInstance(extension.getParsedValue())
                                    .getValue();
                            reason = code.signum() >= 0 && code.bitLength() < 31 ? code.intValue() : UNREADABLE_REASON;
                        } catch (RuntimeException e) {
                            reason = UNREADABLE_REASON;
                        }
                    }
                } else if (unsupported == null) {
                    if (oid.equals(Extension.certificateIssuer)) {
                        unsupported = "it has an indirect entry";
                    } else if (extension.isCritical() && !SUPPORTED_CRITICAL_ENTRY.contains(oid)) {
                        unsupported = "an entry has an unsupported critical extension";
                    }
                }
            }
            String hex = Der.serialHex(serial);
            if (hex != null) {
                listed.put(hex, reason);
            }
        }
        this.unsupported = unsupported;
        this.entryCount = count;
        this.entries = Collections.unmodifiableMap(listed);
    }

    /**
     * A thisUpdate, nextUpdate or revocationDate, after the length floors
     * OpenSSL's decoder applies to the two time types: a UTCTime of at least
     * 13 octets, a GeneralizedTime of at least 15 (tasn_dec.c). A shorter
     * one (no seconds, no zone) is not RFC 5280's DER form, the core refuses
     * the list as not a DER CRL, and so does this; BouncyCastle alone would
     * read it, a zoneless GeneralizedTime in the JVM's own time zone. Only
     * the floors are applied, not a full DER check, which would refuse what
     * OpenSSL reads (a 15-octet UTCTime with a {@code +0000} offset).
     */
    private static Time time(ASN1Encodable value) {
        ASN1Primitive primitive = value.toASN1Primitive();
        int floor;
        if (primitive instanceof ASN1UTCTime) {
            floor = 13;
        } else if (primitive instanceof ASN1GeneralizedTime) {
            floor = 15;
        } else {
            throw new IllegalArgumentException("not a Time");
        }
        byte[] encoded;
        try {
            encoded = primitive.getEncoded();
        } catch (IOException e) {
            throw new IllegalArgumentException("not a Time", e);
        }
        // A content of 128 octets or more has a long-form length and is over either floor.
        if ((encoded[1] & 0x80) == 0 && encoded[1] < floor) {
            throw new IllegalArgumentException("a time shorter than its DER form");
        }
        return Time.getInstance(primitive);
    }

    /**
     * A list time to the whole second, as the core reads one: OpenSSL keeps
     * no fraction of a GeneralizedTime (RFC 5280 forbids one), so two lists
     * a fraction apart tie, and a fraction of a nextUpdate does not stretch
     * a list's freshness or {@code revocationValidUntil}.
     */
    private static long wholeSeconds(long millis) {
        return Math.floorDiv(millis, 1000L) * 1000L;
    }

    /** The TBSCertList field at {@code index}, which must be there. */
    private static ASN1Encodable field(ASN1Sequence fields, int index) {
        if (index >= fields.size()) {
            throw new IllegalArgumentException("not a TBSCertList");
        }
        return fields.getObjectAt(index);
    }

    /**
     * Each Extension of an Extensions SEQUENCE, in order, an OID that
     * repeats included; none for {@code null}. A value is not decoded here.
     */
    private static List<Extension> extensions(@Nullable ASN1Sequence sequence) {
        List<Extension> extensions = new ArrayList<>();
        if (sequence != null) {
            for (ASN1Encodable element : sequence) {
                extensions.add(Extension.getInstance(element));
            }
        }
        return extensions;
    }

    private static int count(List<Extension> extensions, ASN1ObjectIdentifier oid) {
        int count = 0;
        for (Extension extension : extensions) {
            if (extension.getExtnId().equals(oid)) {
                count++;
            }
        }
        return count;
    }

    /**
     * Reads {@code der} as one CRL in DER, with nothing after it.
     *
     * @throws IllegalArgumentException when it is not one, or a value this
     *     profile reads (a time, an extension it interprets, a serial) does
     *     not decode
     */
    static RevocationList parse(byte[] der) {
        try {
            return new RevocationList(der);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            // BouncyCastle reports content it cannot read with assorted
            // unchecked exceptions.
            throw new IllegalArgumentException("not a CertificateList", e);
        }
    }

    /**
     * Whether {@code key} signed this list. The signature label is the
     * list's own, so it gets the refusals a certificate's gets
     * ({@link AppleTrust#signedBy}): the composite label, a refused digest,
     * an RSASSA-PSS salt the key cannot hold. A SHA-1 signature is accepted:
     * the signer is pinned, and Apple Root CA signs its list with it.
     */
    boolean signedBy(PublicKey key) {
        if (!algorithmsAgree || signature == null) {
            return false;
        }
        try {
            if (AppleTrust.GENERIC_COMPOSITE_SIGNATURE.equals(
                            signatureAlgorithm.getAlgorithm().getId())
                    || ReceiptCore.namesRefusedDigest(signatureAlgorithm)
                    || !AppleTrust.saltFits(signatureAlgorithm, key)) {
                return false;
            }
            ContentVerifier verifier = new JcaContentVerifierProviderBuilder()
                    .setProvider(BouncyCastle.PROVIDER)
                    .build(key)
                    .get(signatureAlgorithm);
            try (OutputStream out = verifier.getOutputStream()) {
                out.write(tbs);
            }
            return verifier.verify(signature);
        } catch (Exception e) {
            // A key or label BouncyCastle cannot verify with: not this signer.
            return false;
        }
    }
}
