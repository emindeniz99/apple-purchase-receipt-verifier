package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.TBSCertList;
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

        CertificateList list;
        try {
            list = CertificateList.getInstance(ASN1Primitive.fromByteArray(der));
        } catch (IOException e) {
            throw new IllegalArgumentException("not a CertificateList", e);
        }
        TBSCertList fields = list.getTBSCertList();
        this.signatureAlgorithm = list.getSignatureAlgorithm();
        byte[] bits;
        try {
            bits = list.getSignature().getOctets();
        } catch (IllegalStateException e) {
            // A BIT STRING with pad bits holds no signature.
            bits = null;
        }
        this.signature = bits;
        this.thisUpdate = fields.getThisUpdate().getDate().getTime();
        this.nextUpdate = fields.getNextUpdate() == null
                ? null
                : fields.getNextUpdate().getDate().getTime();

        String unsupported = null;
        ASN1Integer version = fields.getVersion();
        if (version == null || !version.hasValue(1)) {
            unsupported = "it is not a version 2 list";
        } else if (nextUpdate == null) {
            unsupported = "it has no nextUpdate";
        }

        Extensions extensions = fields.getExtensions();
        byte[] keyIdentifier = null;
        boolean hasAki = false;
        BigInteger number = null;
        if (extensions != null) {
            for (ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
                Extension extension = extensions.getExtension(oid);
                if (oid.equals(Extension.authorityKeyIdentifier)) {
                    hasAki = true;
                    keyIdentifier = AuthorityKeyIdentifier.getInstance(extension.getParsedValue())
                            .getKeyIdentifier();
                } else if (oid.equals(Extension.cRLNumber)) {
                    number = ASN1Integer.getInstance(extension.getParsedValue()).getValue();
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
        }
        this.hasAuthorityKeyIdentifier = hasAki;
        this.authorityKeyIdentifier = keyIdentifier;
        this.crlNumber = number;

        Map<String, Integer> listed = new HashMap<>();
        Set<BigInteger> seen = new HashSet<>();
        int count = 0;
        Enumeration<?> revoked = fields.getRevokedCertificateEnumeration();
        while (revoked.hasMoreElements()) {
            TBSCertList.CRLEntry entry = (TBSCertList.CRLEntry) revoked.nextElement();
            count++;
            BigInteger serial = entry.getUserCertificate().getValue();
            if (!seen.add(serial) && unsupported == null) {
                unsupported = "it lists a serial twice";
            }
            int reason = NO_REASON;
            Extensions entryExtensions = entry.getExtensions();
            if (entryExtensions != null) {
                for (ASN1ObjectIdentifier oid : entryExtensions.getExtensionOIDs()) {
                    Extension extension = entryExtensions.getExtension(oid);
                    if (oid.equals(Extension.reasonCode)) {
                        BigInteger code = ASN1Enumerated.getInstance(extension.getParsedValue())
                                .getValue();
                        // An unknown code revokes, as no reason does; only
                        // 6 and 8 are treated apart, so a large value must
                        // not wrap onto them.
                        reason = code.signum() >= 0 && code.bitLength() < 31 ? code.intValue() : Integer.MAX_VALUE;
                    } else if (unsupported == null) {
                        if (oid.equals(Extension.certificateIssuer)) {
                            unsupported = "it has an indirect entry";
                        } else if (extension.isCritical() && !SUPPORTED_CRITICAL_ENTRY.contains(oid)) {
                            unsupported = "an entry has an unsupported critical extension";
                        }
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
