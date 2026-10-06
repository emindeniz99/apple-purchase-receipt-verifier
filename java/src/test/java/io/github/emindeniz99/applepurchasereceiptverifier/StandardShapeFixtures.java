package io.github.emindeniz99.applepurchasereceiptverifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.AttributeCertificateIssuer;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2AttributeCertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * Writes the inputs of the shared cases on shapes the standards allow in
 * an Apple-signed input (owner, Q69 and Q72, 2026-10-06) into the directory given
 * as the first argument (default {@code fixtures/generated-0.7}). Every file
 * is prefixed {@code standard-}.
 *
 * <ul>
 *   <li>{@code standard-receipt-renewed-signer-behind-its-expired-copy.der}:
 *       the SignerInfo names its signer by subjectKeyIdentifier (RFC 5652
 *       5.3), and the bag carries, ahead of the signer, an earlier
 *       certificate for the same key and subject that expired before the
 *       creation date, as a renewal leaves (RFC 5280 4.2.1.2).</li>
 *   <li>{@code standard-receipt-attribute-and-other-certificates-in-the-bag.der}:
 *       the bag carries a v2AttrCert {@code [2]} and an other {@code [3]}
 *       entry (RFC 5652 10.2.2) ahead of the chain.</li>
 *   <li>{@code standard-receipt-intermediate-with-a-critical-eku.der} and
 *       {@code standard-jws-intermediate-with-a-critical-eku.jws}: the
 *       intermediate carries a critical extendedKeyUsage (RFC 5280
 *       4.2.1.12).</li>
 *   <li>{@code standard-receipt-intermediate-with-a-critical-crldp.der} and
 *       {@code standard-jws-intermediate-with-a-critical-crldp.jws}: the
 *       intermediate carries a critical cRLDistributionPoints (RFC 5280
 *       4.2.1.13), which the core reads and Java now accepts too (owner,
 *       Q72, 2026-10-06).</li>
 *   <li>{@code standard-receipt-signing-time-before-the-signer.der}: the
 *       signed attributes carry a signingTime before the signer's notBefore
 *       (RFC 5652 11.3 ties it to no validity check), and
 *       {@code standard-receipt-signing-time-before-the-signer-bad-signature.der}
 *       the same receipt with one signature bit flipped.</li>
 * </ul>
 *
 * <p>The other receipts carry no signed attributes, as Apple's do not. Every
 * chain is valid from 2024-01-01 to 2050-01-01, except the expired copy
 * (to 2024-06-01), and receipts and the JWS are dated 2024-08-06. The roots
 * are {@code standard-receipt-root.der} and {@code standard-jws-root.der}.</p>
 *
 * <p>Run it the way {@link ReviewParityFixtures} documents. Each run mints
 * fresh keys, so regenerating changes every file and its
 * {@code contentSha256}.</p>
 */
public final class StandardShapeFixtures {

    private static final String LEAF_OID = "1.2.840.113635.100.6.11.1";
    private static final String WWDR_OID = "1.2.840.113635.100.6.2.1";
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final Date NOT_BEFORE = new Date(1704067200000L); // 2024-01-01
    private static final Date RENEWED = new Date(1717200000000L); // 2024-06-01
    private static final Date NOT_AFTER = new Date(2524608000000L); // 2050-01-01
    static final byte[] PAYLOAD = payload();

    private long serial = 1;
    final KeyPair receiptRootKeys = keys("RSA");
    final X509CertificateHolder receiptRoot;
    final KeyPair jwsRootKeys = keys("EC");
    final X509CertificateHolder jwsRoot;

    StandardShapeFixtures() throws Exception {
        receiptRoot = certificate(
                "CN=Standard Receipt Root",
                receiptRootKeys,
                "CN=Standard Receipt Root",
                receiptRootKeys.getPrivate(),
                NOT_BEFORE,
                true,
                null,
                null);
        jwsRoot = certificate(
                "CN=Standard JWS Root",
                jwsRootKeys,
                "CN=Standard JWS Root",
                jwsRootKeys.getPrivate(),
                NOT_BEFORE,
                true,
                null,
                null);
    }

    public static void main(String[] args) throws Exception {
        Path out = args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(out);
        StandardShapeFixtures f = new StandardShapeFixtures();
        byte[] signingTime = f.signingTimeBeforeTheSigner();
        write(out, "standard-receipt-root.der", f.receiptRoot.getEncoded());
        write(out, "standard-jws-root.der", f.jwsRoot.getEncoded());
        write(
                out,
                "standard-receipt-renewed-signer-behind-its-expired-copy.der",
                f.renewedSignerBehindItsExpiredCopy());
        write(
                out,
                "standard-receipt-attribute-and-other-certificates-in-the-bag.der",
                f.attributeAndOtherCertificatesInTheBag());
        write(
                out,
                "standard-receipt-intermediate-with-a-critical-eku.der",
                f.receiptUnderIntermediateWith(criticalEku()));
        write(
                out,
                "standard-jws-intermediate-with-a-critical-eku.jws",
                f.jwsUnderIntermediateWith(criticalEku()).getBytes(StandardCharsets.US_ASCII));
        write(
                out,
                "standard-receipt-intermediate-with-a-critical-crldp.der",
                f.receiptUnderIntermediateWith(criticalCrlDistributionPoints()));
        write(
                out,
                "standard-jws-intermediate-with-a-critical-crldp.jws",
                f.jwsUnderIntermediateWith(criticalCrlDistributionPoints()).getBytes(StandardCharsets.US_ASCII));
        write(out, "standard-receipt-signing-time-before-the-signer.der", signingTime);
        write(
                out,
                "standard-receipt-signing-time-before-the-signer-bad-signature.der",
                TestPki.corruptSignatures(signingTime, 1));
    }

    /** A critical extendedKeyUsage, as RFC 5280 4.2.1.12 allows on any certificate. */
    static Extension criticalEku() throws Exception {
        return new Extension(
                Extension.extendedKeyUsage,
                true,
                new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_codeSigning, KeyPurposeId.id_kp_clientAuth})
                        .getEncoded());
    }

    /** A critical cRLDistributionPoints naming one CRL by URI (RFC 5280 4.2.1.13). */
    static Extension criticalCrlDistributionPoints() throws Exception {
        DistributionPoint point = new DistributionPoint(
                new DistributionPointName(new GeneralNames(
                        new GeneralName(GeneralName.uniformResourceIdentifier, "http://crl.example.com/wwdr.crl"))),
                null,
                null);
        return new Extension(
                Extension.cRLDistributionPoints, true, new CRLDistPoint(new DistributionPoint[] {point}).getEncoded());
    }

    /** A leaf signed by its subjectKeyIdentifier, its expired predecessor on the same key ahead of it. */
    byte[] renewedSignerBehindItsExpiredCopy() throws Exception {
        KeyPair interKeys = keys("RSA");
        X509CertificateHolder inter = intermediate(interKeys, null);
        KeyPair leafKeys = keys("RSA");
        X509CertificateHolder expired = leaf(leafKeys, interKeys.getPrivate(), NOT_BEFORE, RENEWED);
        X509CertificateHolder renewed = leaf(leafKeys, interKeys.getPrivate(), RENEWED, NOT_AFTER);
        byte[] keyId = new JcaX509ExtensionUtils()
                .createSubjectKeyIdentifier(leafKeys.getPublic())
                .getKeyIdentifier();
        return receipt(
                leafKeys,
                null,
                keyId,
                null,
                Arrays.<ASN1Encodable>asList(
                        expired.toASN1Structure(), renewed.toASN1Structure(), inter.toASN1Structure()));
    }

    /** The genuine chain behind a v2AttrCert [2] and an other [3] entry. */
    byte[] attributeAndOtherCertificatesInTheBag() throws Exception {
        KeyPair interKeys = keys("RSA");
        X509CertificateHolder inter = intermediate(interKeys, null);
        KeyPair leafKeys = keys("RSA");
        X509CertificateHolder leaf = leaf(leafKeys, interKeys.getPrivate(), NOT_BEFORE, NOT_AFTER);
        X509v2AttributeCertificateBuilder attribute = new X509v2AttributeCertificateBuilder(
                new AttributeCertificateHolder(leaf),
                new AttributeCertificateIssuer(new X500Name("CN=Standard WWDR CA")),
                BigInteger.valueOf(serial++),
                NOT_BEFORE,
                NOT_AFTER);
        attribute.addAttribute(new ASN1ObjectIdentifier("2.999.1"), new DERUTF8String("role"));
        ASN1Encodable attributeCertificate =
                attribute.build(signer(interKeys.getPrivate())).toASN1Structure();
        ASN1Encodable other =
                new DERSequence(new ASN1Encodable[] {new ASN1ObjectIdentifier("2.999.2"), DERNull.INSTANCE});
        return receipt(
                leafKeys,
                leaf,
                null,
                null,
                Arrays.<ASN1Encodable>asList(
                        new DERTaggedObject(false, 2, attributeCertificate),
                        new DERTaggedObject(false, 3, other),
                        leaf.toASN1Structure(),
                        inter.toASN1Structure()));
    }

    /** A genuine receipt whose intermediate carries {@code extension} besides its marker. */
    byte[] receiptUnderIntermediateWith(Extension extension) throws Exception {
        KeyPair interKeys = keys("RSA");
        X509CertificateHolder inter = intermediate(interKeys, extension);
        KeyPair leafKeys = keys("RSA");
        X509CertificateHolder leaf = leaf(leafKeys, interKeys.getPrivate(), NOT_BEFORE, NOT_AFTER);
        return receipt(
                leafKeys,
                leaf,
                null,
                null,
                Arrays.<ASN1Encodable>asList(leaf.toASN1Structure(), inter.toASN1Structure()));
    }

    /** A genuine JWS whose x5c intermediate carries {@code extension} besides its marker. */
    String jwsUnderIntermediateWith(Extension extension) throws Exception {
        KeyPair interKeys = keys("EC");
        X509CertificateHolder inter = certificate(
                "CN=Standard JWS WWDR CA",
                interKeys,
                "CN=Standard JWS Root",
                jwsRootKeys.getPrivate(),
                NOT_BEFORE,
                true,
                WWDR_OID,
                extension);
        KeyPair leafKeys = keys("EC");
        X509CertificateHolder leaf = certificate(
                "CN=Standard JWS Signing",
                leafKeys,
                "CN=Standard JWS WWDR CA",
                interKeys.getPrivate(),
                NOT_BEFORE,
                false,
                LEAF_OID,
                null);
        String header = "{\"alg\":\"ES256\",\"x5c\":[\"" + TestPki.b64(leaf.getEncoded()) + "\",\""
                + TestPki.b64(inter.getEncoded()) + "\",\"" + TestPki.b64(jwsRoot.getEncoded()) + "\"]}";
        String claims =
                "{\"bundleId\":\"com.example.app\",\"environment\":\"Sandbox\",\"signedDate\":" + SIGNED_DATE + "}";
        String input = TestPki.b64url(header.getBytes(StandardCharsets.UTF_8)) + "."
                + TestPki.b64url(claims.getBytes(StandardCharsets.UTF_8));
        Signature es256 = Signature.getInstance("SHA256withPLAIN-ECDSA", TestPki.BC);
        es256.initSign(leafKeys.getPrivate());
        es256.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + TestPki.b64url(es256.sign());
    }

    /** A genuine receipt with signed attributes whose signingTime is a year before the signer's notBefore. */
    byte[] signingTimeBeforeTheSigner() throws Exception {
        KeyPair interKeys = keys("RSA");
        X509CertificateHolder inter = intermediate(interKeys, null);
        KeyPair leafKeys = keys("RSA");
        X509CertificateHolder leaf = leaf(leafKeys, interKeys.getPrivate(), NOT_BEFORE, NOT_AFTER);
        Date signingTime = new Date(NOT_BEFORE.getTime() - 365L * 86_400_000L);
        return receipt(
                leafKeys,
                leaf,
                null,
                signingTime,
                Arrays.<ASN1Encodable>asList(leaf.toASN1Structure(), inter.toASN1Structure()));
    }

    private X509CertificateHolder intermediate(KeyPair keys, Extension extension) throws Exception {
        return certificate(
                "CN=Standard WWDR CA",
                keys,
                "CN=Standard Receipt Root",
                receiptRootKeys.getPrivate(),
                NOT_BEFORE,
                true,
                WWDR_OID,
                extension);
    }

    private X509CertificateHolder leaf(KeyPair keys, PrivateKey issuerKey, Date notBefore, Date notAfter)
            throws Exception {
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=Standard WWDR CA"),
                BigInteger.valueOf(serial++),
                notBefore,
                notAfter,
                new X500Name("CN=Standard Receipt Signing"),
                keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keys.getPublic()));
        builder.addExtension(new ASN1ObjectIdentifier(LEAF_OID), false, DERNull.INSTANCE);
        return builder.build(signer(issuerKey));
    }

    private X509CertificateHolder certificate(
            String subject,
            KeyPair keys,
            String issuer,
            PrivateKey issuerKey,
            Date notBefore,
            boolean ca,
            String markerOid,
            Extension extension)
            throws Exception {
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(issuer),
                BigInteger.valueOf(serial++),
                notBefore,
                NOT_AFTER,
                new X500Name(subject),
                keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (markerOid != null) {
            builder.addExtension(new ASN1ObjectIdentifier(markerOid), false, DERNull.INSTANCE);
        }
        if (extension != null) {
            builder.addExtension(extension);
        }
        return builder.build(signer(issuerKey));
    }

    /**
     * A receipt over {@link #PAYLOAD} whose SignerInfo names {@code signer},
     * or the key {@code keyId} when it is given; with no {@code signingTime}
     * it carries no signed attributes. The bag is {@code bag}, in that order.
     */
    private static byte[] receipt(
            KeyPair keys, X509CertificateHolder signer, byte[] keyId, Date signingTime, List<ASN1Encodable> bag)
            throws Exception {
        JcaSignerInfoGeneratorBuilder info = new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider(TestPki.BC).build());
        if (signingTime == null) {
            info.setDirectSignature(true);
        } else {
            info.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(
                    new AttributeTable(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(signingTime))))));
        }
        ContentSigner contentSigner = signer(keys.getPrivate());
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(
                keyId != null ? info.build(contentSigner, keyId) : info.build(contentSigner, signer));
        SignedData signed = SignedData.getInstance(generator
                .generate(new CMSProcessableByteArray(PAYLOAD), true)
                .toASN1Structure()
                .getContent());
        DLSet certificates = new DLSet(bag.toArray(new ASN1Encodable[0]));
        // Built by hand: SignedData's own encoding is DER, which sorts the
        // SET; its constructor still works out the version the bag implies.
        ASN1Encodable[] fields = {
            new SignedData(
                            signed.getDigestAlgorithms(),
                            signed.getEncapContentInfo(),
                            certificates,
                            null,
                            signed.getSignerInfos())
                    .getVersion(),
            signed.getDigestAlgorithms(),
            signed.getEncapContentInfo(),
            new DLTaggedObject(false, 0, certificates),
            signed.getSignerInfos()
        };
        return new DLSequence(new ASN1Encodable[] {
                    CMSObjectIdentifiers.signedData, new DLTaggedObject(true, 0, new DLSequence(fields))
                })
                .getEncoded(ASN1Encoding.DL);
    }

    private static ContentSigner signer(PrivateKey key) throws Exception {
        return new JcaContentSignerBuilder("RSA".equals(key.getAlgorithm()) ? "SHA256withRSA" : "SHA256withECDSA")
                .setProvider(TestPki.BC)
                .build(key);
    }

    private static byte[] payload() {
        try {
            return TestPki.receiptPayload(
                    "com.example.app",
                    "1.2.3",
                    new byte[] {1, 2, 3, 4},
                    new byte[20],
                    "2024-08-06T12:00:00Z",
                    Collections.<byte[]>emptyList());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static KeyPair keys(String algorithm) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
            if ("EC".equals(algorithm)) {
                generator.initialize(new ECGenParameterSpec("secp256r1"));
            } else {
                generator.initialize(2048);
            }
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
