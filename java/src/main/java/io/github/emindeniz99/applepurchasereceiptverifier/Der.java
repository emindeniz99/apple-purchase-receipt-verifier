package io.github.emindeniz99.applepurchasereceiptverifier;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.jspecify.annotations.Nullable;

/**
 * The byte slices revocation needs, read from an encoding as it stands, and
 * the identifiers built from them (docs/design/revocation.md §2).
 *
 * <p>BouncyCastle hands back a re-encoding: {@code getEncoded()} of a
 * certificate it parsed writes DER, which sorts the AVAs of a SET. An issuer
 * id hashes the Name as the certificate encodes it, so the slices come from
 * the bytes themselves, walked here tag by tag. Only definite lengths are
 * read; anything else is refused with {@link IllegalArgumentException}.</p>
 */
final class Der {

    private Der() {}

    /** One element: its tag octet, and where its header, content and end are. */
    static final class Tlv {
        final int tag;
        final int start;
        final int contentStart;
        final int end;

        private Tlv(int tag, int start, int contentStart, int end) {
            this.tag = tag;
            this.start = start;
            this.contentStart = contentStart;
            this.end = end;
        }

        /** The whole element, header included. */
        byte[] bytes(byte[] in) {
            return Arrays.copyOfRange(in, start, end);
        }
    }

    /**
     * The element at {@code pos}, which must end by {@code limit}. Low tag
     * numbers only (every tag a certificate or a CRL uses up to the fields
     * read here), and definite lengths of at most four octets.
     */
    static Tlv read(byte[] in, int pos, int limit) {
        if (pos + 2 > limit) {
            throw new IllegalArgumentException("truncated element");
        }
        int tag = in[pos] & 0xff;
        if ((tag & 0x1f) == 0x1f) {
            throw new IllegalArgumentException("high tag number");
        }
        int first = in[pos + 1] & 0xff;
        int contentStart = pos + 2;
        long length;
        if (first < 0x80) {
            length = first;
        } else {
            int octets = first & 0x7f;
            if (octets == 0 || octets > 4 || contentStart + octets > limit) {
                throw new IllegalArgumentException("indefinite or oversized length");
            }
            length = 0;
            for (int i = 0; i < octets; i++) {
                length = (length << 8) | (in[contentStart + i] & 0xff);
            }
            contentStart += octets;
        }
        if (length > limit - contentStart) {
            throw new IllegalArgumentException("element runs past its container");
        }
        return new Tlv(tag, pos, contentStart, contentStart + (int) length);
    }

    /** The elements inside {@code parent}, which must fill it exactly. */
    static List<Tlv> children(byte[] in, Tlv parent) {
        List<Tlv> children = new ArrayList<>();
        int pos = parent.contentStart;
        while (pos < parent.end) {
            Tlv child = read(in, pos, parent.end);
            children.add(child);
            pos = child.end;
        }
        return children;
    }

    /** The one element {@code in} holds, with nothing after it. */
    static Tlv whole(byte[] in) {
        Tlv tlv = read(in, 0, in.length);
        if (tlv.end != in.length) {
            throw new IllegalArgumentException("bytes after the element");
        }
        return tlv;
    }

    /** A certificate's {@code issuer}, {@code subject} and {@code subjectPublicKeyInfo}, as encoded. */
    static final class CertificateNames {
        final byte[] issuer;
        final byte[] subject;
        final byte[] subjectPublicKeyInfo;

        CertificateNames(byte[] issuer, byte[] subject, byte[] subjectPublicKeyInfo) {
            this.issuer = issuer;
            this.subject = subject;
            this.subjectPublicKeyInfo = subjectPublicKeyInfo;
        }

        /** The issuer id of the certificate these came from, as an issuer of others. */
        String issuerId() {
            return Der.sha256Hex(subject, subjectPublicKeyInfo);
        }
    }

    /**
     * The three slices of {@code certificate}'s TBSCertificate, from the bytes
     * {@code getEncoded()} returns. A JDK certificate returns the bytes it was
     * read from; one BouncyCastle parsed returns DER, which equals what was
     * signed for any certificate whose signature BouncyCastle verified. When
     * the encoding cannot be walked (an indefinite length), the slices come
     * from a DER re-encoding instead.
     */
    static CertificateNames names(X509Certificate certificate) {
        byte[] der;
        try {
            der = certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException("certificate does not encode", e);
        }
        try {
            return names(der);
        } catch (IllegalArgumentException e) {
            TBSCertificate tbs =
                    org.bouncycastle.asn1.x509.Certificate.getInstance(der).getTBSCertificate();
            try {
                return new CertificateNames(
                        tbs.getIssuer().getEncoded(ASN1Encoding.DER),
                        tbs.getSubject().getEncoded(ASN1Encoding.DER),
                        tbs.getSubjectPublicKeyInfo().getEncoded(ASN1Encoding.DER));
            } catch (java.io.IOException io) {
                throw new IllegalArgumentException("certificate does not encode", io);
            }
        }
    }

    /**
     * Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
     * signatureValue }; tbsCertificate ::= SEQUENCE { [0] version OPTIONAL,
     * serialNumber, signature, issuer, validity, subject,
     * subjectPublicKeyInfo, ... }.
     */
    static CertificateNames names(byte[] certificateDer) {
        Tlv certificate = whole(certificateDer);
        List<Tlv> outer = children(certificateDer, certificate);
        if (certificate.tag != 0x30 || outer.isEmpty() || outer.get(0).tag != 0x30) {
            throw new IllegalArgumentException("not a certificate");
        }
        List<Tlv> tbs = children(certificateDer, outer.get(0));
        int i = !tbs.isEmpty() && tbs.get(0).tag == 0xa0 ? 1 : 0;
        if (tbs.size() < i + 6) {
            throw new IllegalArgumentException("TBSCertificate too short");
        }
        Tlv issuer = tbs.get(i + 2);
        Tlv subject = tbs.get(i + 4);
        Tlv key = tbs.get(i + 5);
        if (tbs.get(i).tag != 0x02 || issuer.tag != 0x30 || subject.tag != 0x30 || key.tag != 0x30) {
            throw new IllegalArgumentException("not a TBSCertificate");
        }
        return new CertificateNames(
                issuer.bytes(certificateDer), subject.bytes(certificateDer), key.bytes(certificateDer));
    }

    /** Lowercase hex of SHA-256 over the parts, in order. */
    static String sha256Hex(byte[]... parts) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256", BouncyCastle.PROVIDER);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        for (byte[] part : parts) {
            digest.update(part);
        }
        byte[] hash = digest.digest();
        StringBuilder hex = new StringBuilder(hash.length * 2);
        for (byte b : hash) {
            hex.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        }
        return hex.toString();
    }

    /**
     * A serial number or CRL Number as §2 writes it: uppercase hex, an even
     * number of digits, no leading {@code 00} pair unless the value is zero
     * ({@code "00"}). Null for a negative value, which is never matched.
     */
    static @Nullable String serialHex(BigInteger value) {
        if (value.signum() < 0) {
            return null;
        }
        String hex = value.toString(16).toUpperCase(Locale.ROOT);
        return hex.length() % 2 == 0 ? hex : "0" + hex;
    }

    /**
     * {@code text} read as hex (either case, any number of digits, at least
     * one) and written as {@link #serialHex}; null when it is anything
     * else, a sign or a space included.
     */
    static @Nullable String normaliseHex(String text) {
        if (text.isEmpty() || !isHex(text)) {
            return null;
        }
        return serialHex(new BigInteger(text, 16));
    }

    /** Whether every character is an ASCII hex digit. */
    static boolean isHex(String text) {
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (!(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')) {
                return false;
            }
        }
        return true;
    }
}
