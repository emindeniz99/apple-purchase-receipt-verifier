package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Writes the inputs of the shared cases that pin how a certificate the chain
 * uses is read, and two CMS structure rules, into the directory given as the
 * first argument (default {@code fixtures/generated-0.7}). Every file is
 * prefixed {@code der-}.
 *
 * <p>For each format there is one pinned root and, per case, a chain under it
 * whose intermediate (the receipt's embedded WWDR certificate, or the JWS's
 * {@code x5c[1]}) carries exactly one defect: an unknown extension marked
 * critical, a non-minimal long-form length on the outer SEQUENCE, an
 * indefinite length on the outer SEQUENCE, a fourth element in the
 * Certificate SEQUENCE, the extensions field [3] twice, or a basicConstraints
 * cA BOOLEAN whose content is 01 or empty. Defects inside the
 * TBSCertificate are signed by the root, so the certificate's own signature
 * is genuine; defects outside it leave the signature untouched. Receipt
 * envelopes are written byte by byte so the defective certificate keeps its
 * exact encoding.</p>
 *
 * <p>The CMS cases use the genuine chain: the SignedData certificates field
 * [0] twice (both copies carrying the chain), a SignerInfo whose signedAttrs
 * carry messageDigest twice (both correct), and one whose contentType
 * attribute names id-signedData while the eContentType is id-data. Their
 * SignerInfo is re-signed so the signature is genuine.</p>
 *
 * <p>All chains are valid 2024-01-01 to 2050-01-01; receipts and JWS are
 * dated 2024-08-06. Run it the way {@link ReviewParityFixtures} documents.
 * Each run mints fresh keys.</p>
 */
public final class CertificateDerFixtures {

    private static final String BUNDLE = "com.example.app";
    private static final String LEAF_OID = "1.2.840.113635.100.6.11.1";
    private static final String WWDR_OID = "1.2.840.113635.100.6.2.1";
    private static final ASN1ObjectIdentifier UNKNOWN_OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.55555.1.1");
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";

    private static long serial = 2000;

    private final Date nb = new Date(1704067200000L); // 2024-01-01
    private final Date na = new Date(2524608000000L); // 2050-01-01
    private Path out;

    private CertificateDerFixtures() {}

    public static void main(String[] args) throws Exception {
        CertificateDerFixtures generator = new CertificateDerFixtures();
        generator.out =
                args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(generator.out);
        generator.receipts();
        generator.jws();
    }

    /** One chain's keys and certificates; the intermediate varies per case. */
    private final class Chain {
        final String alg;
        final String sigAlg;
        final String prefix;
        final KeyPair root;
        final X509CertificateHolder rootCert;

        Chain(String prefix, boolean rsa) throws Exception {
            this.prefix = prefix;
            this.alg = rsa ? "RSA" : "EC";
            this.sigAlg = rsa ? "SHA256withRSA" : "SHA256withECDSA";
            root = newKeys();
            X509v3CertificateBuilder builder = builder("CN=" + prefix + " Root", root, "CN=" + prefix + " Root");
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            rootCert = build(builder, root.getPrivate());
        }

        KeyPair newKeys() throws Exception {
            return keys(alg);
        }

        X509v3CertificateBuilder builder(String subject, KeyPair subjectKeys, String issuer) throws Exception {
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    new X500Name(issuer),
                    BigInteger.valueOf(serial++),
                    nb,
                    na,
                    new X500Name(subject),
                    subjectKeys.getPublic());
            return builder;
        }

        X509CertificateHolder build(X509v3CertificateBuilder builder, PrivateKey issuerKey) throws Exception {
            return builder.build(new JcaContentSignerBuilder(sigAlg).build(issuerKey));
        }

        /** Intermediate builder with the usual extensions, basicConstraints given raw when not null. */
        X509v3CertificateBuilder intermediate(KeyPair keys, byte[] basicConstraints) throws Exception {
            X509v3CertificateBuilder builder = builder("CN=" + prefix + " WWDR CA", keys, "CN=" + prefix + " Root");
            if (basicConstraints == null) {
                builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            } else {
                builder.addExtension(Extension.basicConstraints, true, basicConstraints);
            }
            builder.addExtension(new ASN1ObjectIdentifier(WWDR_OID), false, DERNull.INSTANCE);
            return builder;
        }

        X509CertificateHolder leaf(KeyPair leafKeys, KeyPair interKeys) throws Exception {
            X509v3CertificateBuilder builder =
                    builder("CN=" + prefix + " Signing", leafKeys, "CN=" + prefix + " WWDR CA");
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(new ASN1ObjectIdentifier(LEAF_OID), false, DERNull.INSTANCE);
            return build(builder, interKeys.getPrivate());
        }

        /** The intermediate's encoding for {@code defect}, signed by the root where the TBS changes. */
        byte[] intermediate(String defect, KeyPair keys) throws Exception {
            switch (defect) {
                case "genuine":
                    return build(intermediate(keys, null), root.getPrivate()).getEncoded();
                case "unknown-critical-extension": {
                    X509v3CertificateBuilder builder = intermediate(keys, null);
                    builder.addExtension(UNKNOWN_OID, true, DERNull.INSTANCE);
                    return build(builder, root.getPrivate()).getEncoded();
                }
                case "non-minimal-length":
                    return nonMinimalLength(intermediate("genuine", keys));
                case "indefinite-length":
                    return indefiniteLength(intermediate("genuine", keys));
                case "fourth-element":
                    return appendElement(intermediate("genuine", keys), new byte[] {0x05, 0x00});
                case "extensions-twice":
                    return extensionsTwice(build(intermediate(keys, null), root.getPrivate()));
                case "ca-boolean-01":
                    return build(intermediate(keys, new byte[] {0x30, 0x03, 0x01, 0x01, 0x01}), root.getPrivate())
                            .getEncoded();
                case "ca-boolean-empty":
                    return build(intermediate(keys, new byte[] {0x30, 0x02, 0x01, 0x00}), root.getPrivate())
                            .getEncoded();
                default:
                    throw new IllegalArgumentException(defect);
            }
        }

        /** The TBS with its [3] field repeated, re-signed by the root. */
        byte[] extensionsTwice(X509CertificateHolder genuine) throws Exception {
            ASN1Sequence tbs =
                    ASN1Sequence.getInstance(genuine.toASN1Structure().getTBSCertificate());
            ASN1EncodableVector fields = new ASN1EncodableVector();
            for (ASN1Encodable field : tbs) {
                fields.add(field);
            }
            fields.add(tbs.getObjectAt(tbs.size() - 1));
            byte[] tbsBytes = new DERSequence(fields).getEncoded(ASN1Encoding.DER);
            Signature signer = Signature.getInstance(sigAlg);
            signer.initSign(root.getPrivate());
            signer.update(tbsBytes);
            ASN1EncodableVector certificate = new ASN1EncodableVector();
            certificate.add(ASN1Primitive.fromByteArray(tbsBytes));
            certificate.add(genuine.toASN1Structure().getSignatureAlgorithm());
            certificate.add(new DERBitString(signer.sign()));
            return new DERSequence(certificate).getEncoded(ASN1Encoding.DER);
        }
    }

    private static final String[] DEFECTS = {
        "unknown-critical-extension",
        "non-minimal-length",
        "indefinite-length",
        "fourth-element",
        "extensions-twice",
        "ca-boolean-01",
        "ca-boolean-empty",
    };

    // --- receipts ------------------------------------------------------------

    private void receipts() throws Exception {
        Chain chain = new Chain("DER Receipt", true);
        write("der-receipt-root.der", chain.rootCert.getEncoded());
        byte[] payload = TestPki.receiptPayload(
                BUNDLE, "1.2.3", new byte[] {1, 2, 3, 4}, new byte[20], CREATION_DATE, Collections.<byte[]>emptyList());
        for (String defect : DEFECTS) {
            write("der-receipt-intermediate-" + defect + ".der", receipt(chain, defect, payload));
        }

        // CMS structure, genuine chain.
        KeyPair interKeys = chain.newKeys();
        byte[] inter = chain.intermediate("genuine", interKeys);
        KeyPair leafKeys = chain.newKeys();
        X509CertificateHolder leaf = chain.leaf(leafKeys, interKeys);
        byte[] genuine = der(TestPki.signReceiptAs(
                payload,
                new Date(SIGNED_DATE),
                leafKeys.getPrivate(),
                "SHA256withRSA",
                leaf,
                Arrays.asList(leaf, new X509CertificateHolder(inter), chain.rootCert)));
        List<byte[]> certificates = Arrays.asList(leaf.getEncoded(), inter, chain.rootCert.getEncoded());

        List<byte[]> fields = signedDataFields(genuine);
        List<byte[]> twice = new ArrayList<byte[]>(fields);
        twice.add(4, tlv(0xa0, concat(certificates)));
        write("der-receipt-certificates-field-twice.der", contentInfo(twice));

        byte[] digest = MessageDigest.getInstance("SHA-256").digest(payload);
        write(
                "der-receipt-message-digest-twice.der",
                withSignedAttributes(
                        genuine,
                        leafKeys.getPrivate(),
                        attribute(CMSAttributes.contentType, CMSObjectIdentifiers.data),
                        attribute(CMSAttributes.messageDigest, new DEROctetString(digest)),
                        attribute(CMSAttributes.messageDigest, new DEROctetString(digest))));
        write(
                "der-receipt-content-type-attribute-mismatch.der",
                withSignedAttributes(
                        genuine,
                        leafKeys.getPrivate(),
                        attribute(CMSAttributes.contentType, CMSObjectIdentifiers.signedData),
                        attribute(CMSAttributes.messageDigest, new DEROctetString(digest))));
    }

    private byte[] receipt(Chain chain, String defect, byte[] payload) throws Exception {
        KeyPair interKeys = chain.newKeys();
        byte[] inter = chain.intermediate(defect, interKeys);
        KeyPair leafKeys = chain.newKeys();
        X509CertificateHolder leaf = chain.leaf(leafKeys, interKeys);
        X509CertificateHolder genuineInter = new X509CertificateHolder(chain.intermediate("genuine", interKeys));
        byte[] cms = der(TestPki.signReceiptAs(
                payload,
                new Date(SIGNED_DATE),
                leafKeys.getPrivate(),
                "SHA256withRSA",
                leaf,
                Arrays.asList(leaf, genuineInter, chain.rootCert)));
        List<byte[]> fields = signedDataFields(cms);
        for (int i = 0; i < fields.size(); i++) {
            if ((fields.get(i)[0] & 0xff) == 0xa0) {
                fields.set(i, tlv(0xa0, concat(Arrays.asList(leaf.getEncoded(), inter, chain.rootCert.getEncoded()))));
            }
        }
        return contentInfo(fields);
    }

    /** {@code cms} with its one SignerInfo re-signed over the given signedAttrs. */
    private static byte[] withSignedAttributes(byte[] cms, PrivateKey key, Attribute... attributes) throws Exception {
        SignedData data = SignedData.getInstance(
                ContentInfo.getInstance(ASN1Primitive.fromByteArray(cms)).getContent());
        SignerInfo original = SignerInfo.getInstance(data.getSignerInfos().getObjectAt(0));
        ASN1EncodableVector vector = new ASN1EncodableVector();
        for (Attribute attribute : attributes) {
            vector.add(attribute);
        }
        DERSet signedAttrs = new DERSet(vector);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update(signedAttrs.getEncoded(ASN1Encoding.DER));
        SignerInfo resigned = new SignerInfo(
                original.getSID(),
                original.getDigestAlgorithm(),
                signedAttrs,
                original.getDigestEncryptionAlgorithm(),
                new DEROctetString(signer.sign()),
                null);
        List<byte[]> fields = signedDataFields(cms);
        fields.set(fields.size() - 1, new DERSet(resigned).getEncoded(ASN1Encoding.DER));
        return contentInfo(fields);
    }

    private static Attribute attribute(ASN1ObjectIdentifier type, ASN1Encodable value) {
        return new Attribute(type, new DERSet(value));
    }

    // --- JWS -----------------------------------------------------------------

    private void jws() throws Exception {
        Chain chain = new Chain("DER JWS", false);
        write("der-jws-root.der", chain.rootCert.getEncoded());
        for (String defect : DEFECTS) {
            KeyPair interKeys = chain.newKeys();
            byte[] inter = chain.intermediate(defect, interKeys);
            KeyPair leafKeys = chain.newKeys();
            X509CertificateHolder leaf = chain.leaf(leafKeys, interKeys);
            write(
                    "der-jws-intermediate-" + defect + ".jws",
                    signJws(leafKeys, leaf.getEncoded(), inter, chain.rootCert.getEncoded()));
        }
    }

    private static byte[] signJws(KeyPair leafKeys, byte[] leaf, byte[] inter, byte[] root) throws Exception {
        String header = "{\"alg\":\"ES256\",\"x5c\":[\"" + TestPki.b64(leaf) + "\",\"" + TestPki.b64(inter) + "\",\""
                + TestPki.b64(root) + "\"]}";
        String payload = "{\"bundleId\":\"" + BUNDLE + "\",\"environment\":\"Sandbox\",\"signedDate\":" + SIGNED_DATE
                + ",\"productId\":\"" + BUNDLE + ".pro\",\"transactionId\":\"2000000000000001\"}";
        String input = TestPki.b64url(header.getBytes(StandardCharsets.UTF_8)) + "."
                + TestPki.b64url(payload.getBytes(StandardCharsets.UTF_8));
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(leafKeys.getPrivate());
        signer.update(input.getBytes(StandardCharsets.US_ASCII));
        return (input + "." + TestPki.b64url(p1363(signer.sign()))).getBytes(StandardCharsets.US_ASCII);
    }

    // --- byte-level DER --------------------------------------------------------

    private static byte[] der(byte[] ber) throws Exception {
        return ASN1Primitive.fromByteArray(ber).getEncoded(ASN1Encoding.DER);
    }

    /** The raw TLVs inside the SignedData of a definite-length ContentInfo. */
    private static List<byte[]> signedDataFields(byte[] contentInfo) {
        List<byte[]> outer = children(contentInfo);
        byte[] explicit = outer.get(1);
        byte[] signedData = children(explicit).get(0);
        return children(signedData);
    }

    private static byte[] contentInfo(List<byte[]> signedDataFields) throws Exception {
        byte[] signedData = tlv(0x30, concat(signedDataFields));
        return tlv(0x30, concat(Arrays.asList(CMSObjectIdentifiers.signedData.getEncoded(), tlv(0xa0, signedData))));
    }

    /** The child TLVs of a definite-length constructed TLV. */
    private static List<byte[]> children(byte[] tlv) {
        int[] header = header(tlv, 0);
        List<byte[]> out = new ArrayList<byte[]>();
        int at = header[0];
        int end = header[0] + header[1];
        while (at < end) {
            int[] child = header(tlv, at);
            int childEnd = child[0] + child[1];
            out.add(Arrays.copyOfRange(tlv, at, childEnd));
            at = childEnd;
        }
        return out;
    }

    /** {contents offset, contents length} of the definite-length TLV at {@code at}. */
    private static int[] header(byte[] der, int at) {
        int lengthByte = der[at + 1] & 0xff;
        if (lengthByte < 0x80) {
            return new int[] {at + 2, lengthByte};
        }
        int count = lengthByte & 0x7f;
        int length = 0;
        for (int i = 0; i < count; i++) {
            length = (length << 8) | (der[at + 2 + i] & 0xff);
        }
        return new int[] {at + 2 + count, length};
    }

    private static byte[] tlv(int tag, byte[] contents) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int length = contents.length;
        if (length < 0x80) {
            out.write(length);
        } else if (length < 0x100) {
            out.write(0x81);
            out.write(length);
        } else if (length < 0x10000) {
            out.write(0x82);
            out.write(length >> 8);
            out.write(length);
        } else {
            out.write(0x83);
            out.write(length >> 16);
            out.write(length >> 8);
            out.write(length);
        }
        out.write(contents, 0, contents.length);
        return out.toByteArray();
    }

    private static byte[] contents(byte[] tlv) {
        int[] header = header(tlv, 0);
        return Arrays.copyOfRange(tlv, header[0], header[0] + header[1]);
    }

    /** The certificate with its outer length in four octets, two of them leading zeros. */
    private static byte[] nonMinimalLength(byte[] certificate) {
        byte[] body = contents(certificate);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30);
        out.write(0x84);
        out.write(body.length >>> 24);
        out.write(body.length >>> 16);
        out.write(body.length >>> 8);
        out.write(body.length);
        out.write(body, 0, body.length);
        return out.toByteArray();
    }

    /** The certificate with its outer SEQUENCE in indefinite-length form. */
    private static byte[] indefiniteLength(byte[] certificate) {
        byte[] body = contents(certificate);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30);
        out.write(0x80);
        out.write(body, 0, body.length);
        out.write(0x00);
        out.write(0x00);
        return out.toByteArray();
    }

    private static byte[] appendElement(byte[] certificate, byte[] element) {
        return tlv(0x30, concat(Arrays.asList(contents(certificate), element)));
    }

    private static byte[] concat(List<byte[]> parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }

    private static KeyPair keys(String algorithm) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
        if ("EC".equals(algorithm)) {
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
        } else {
            kpg.initialize(2048);
        }
        return kpg.generateKeyPair();
    }

    /** An ECDSA DER signature as the 64-byte r || s a JWS carries. */
    private static byte[] p1363(byte[] der) {
        ASN1Sequence sequence = ASN1Sequence.getInstance(der);
        byte[] out = new byte[64];
        copy(ASN1Integer.getInstance(sequence.getObjectAt(0)).getValue(), out, 0);
        copy(ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue(), out, 32);
        return out;
    }

    private static void copy(BigInteger value, byte[] out, int offset) {
        byte[] bytes = value.toByteArray();
        int start = Math.max(0, bytes.length - 32);
        int length = bytes.length - start;
        System.arraycopy(bytes, start, out, offset + 32 - length, length);
    }

    private void write(String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
