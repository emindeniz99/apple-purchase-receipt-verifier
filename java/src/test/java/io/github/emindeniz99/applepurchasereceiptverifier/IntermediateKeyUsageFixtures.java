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
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Writes the inputs of the shared cases on the intermediate's keyUsage
 * extension into the directory given as the first argument (default
 * {@code fixtures/generated-0.7}). Every file is prefixed {@code keyusage-}.
 *
 * <p>For each format there is a pinned root and two chains under it whose
 * only defect is the intermediate's keyUsage: once an extension whose value
 * does not decode (a BIT STRING claiming five content octets and carrying
 * two), once a well-formed keyUsage of digitalSignature alone, without
 * keyCertSign. Everything else is genuine: the markers, the validity window
 * (2024-01-01 to 2050-01-01, receipts and JWS dated 2024-08-06) and every
 * signature.</p>
 *
 * <p>The intermediates are kept as encoded bytes and never handed to the
 * JDK certificate parser, which would refuse the malformed extension.</p>
 *
 * <p>Run it the way {@link ReviewParityFixtures} documents. Each run mints
 * fresh keys, so regenerating changes every file and its
 * {@code contentSha256}.</p>
 */
public final class IntermediateKeyUsageFixtures {

    private static final String BUNDLE = "com.example.app";
    private static final String LEAF_OID = "1.2.840.113635.100.6.11.1";
    private static final String WWDR_OID = "1.2.840.113635.100.6.2.1";
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";

    /** A BIT STRING claiming five content octets and carrying two: not a KeyUsage. */
    private static final byte[] MALFORMED_KEY_USAGE = {0x03, 0x05, 0x01, 0x06};

    private static long serial = 1000;

    private final Date nb = new Date(1704067200000L); // 2024-01-01
    private final Date na = new Date(2524608000000L); // 2050-01-01
    private Path out;

    private IntermediateKeyUsageFixtures() {}

    public static void main(String[] args) throws Exception {
        IntermediateKeyUsageFixtures generator = new IntermediateKeyUsageFixtures();
        generator.out =
                args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(generator.out);
        generator.receipts();
        generator.jws();
    }

    private void receipts() throws Exception {
        KeyPair root = keys("RSA");
        X509CertificateHolder rootCert = certificate(
                "CN=KeyUsage Receipt Root",
                root,
                "CN=KeyUsage Receipt Root",
                root.getPrivate(),
                true,
                null,
                null,
                "SHA256withRSA");
        write("keyusage-receipt-root.der", rootCert.getEncoded());
        byte[] payload = TestPki.receiptPayload(
                BUNDLE, "1.2.3", new byte[] {1, 2, 3, 4}, new byte[20], CREATION_DATE, Collections.<byte[]>emptyList());
        write("keyusage-receipt-intermediate-malformed.der", receipt(root, rootCert, MALFORMED_KEY_USAGE, payload));
        write(
                "keyusage-receipt-intermediate-without-keycertsign.der",
                receipt(root, rootCert, new KeyUsage(KeyUsage.digitalSignature).getEncoded(), payload));
    }

    private byte[] receipt(KeyPair root, X509CertificateHolder rootCert, byte[] keyUsage, byte[] payload)
            throws Exception {
        KeyPair inter = keys("RSA");
        X509CertificateHolder interCert = certificate(
                "CN=KeyUsage WWDR CA",
                inter,
                "CN=KeyUsage Receipt Root",
                root.getPrivate(),
                true,
                WWDR_OID,
                keyUsage,
                "SHA256withRSA");
        KeyPair leaf = keys("RSA");
        X509CertificateHolder leafCert = certificate(
                "CN=KeyUsage Receipt Signing",
                leaf,
                "CN=KeyUsage WWDR CA",
                inter.getPrivate(),
                false,
                LEAF_OID,
                null,
                "SHA256withRSA");
        List<X509CertificateHolder> embedded = Arrays.asList(leafCert, interCert, rootCert);
        return TestPki.signReceiptAs(
                payload, new Date(SIGNED_DATE), leaf.getPrivate(), "SHA256withRSA", leafCert, embedded);
    }

    private void jws() throws Exception {
        KeyPair root = keys("EC");
        X509CertificateHolder rootCert = certificate(
                "CN=KeyUsage JWS Root",
                root,
                "CN=KeyUsage JWS Root",
                root.getPrivate(),
                true,
                null,
                null,
                "SHA256withECDSA");
        write("keyusage-jws-root.der", rootCert.getEncoded());
        write("keyusage-jws-intermediate-malformed.jws", jws(root, rootCert, MALFORMED_KEY_USAGE));
        write(
                "keyusage-jws-intermediate-without-keycertsign.jws",
                jws(root, rootCert, new KeyUsage(KeyUsage.digitalSignature).getEncoded()));
    }

    private byte[] jws(KeyPair root, X509CertificateHolder rootCert, byte[] keyUsage) throws Exception {
        KeyPair inter = keys("EC");
        X509CertificateHolder interCert = certificate(
                "CN=KeyUsage JWS WWDR CA",
                inter,
                "CN=KeyUsage JWS Root",
                root.getPrivate(),
                true,
                WWDR_OID,
                keyUsage,
                "SHA256withECDSA");
        KeyPair leaf = keys("EC");
        X509CertificateHolder leafCert = certificate(
                "CN=KeyUsage JWS Signing",
                leaf,
                "CN=KeyUsage JWS WWDR CA",
                inter.getPrivate(),
                false,
                LEAF_OID,
                null,
                "SHA256withECDSA");
        String header = "{\"alg\":\"ES256\",\"x5c\":[\"" + TestPki.b64(leafCert.getEncoded()) + "\",\""
                + TestPki.b64(interCert.getEncoded()) + "\",\"" + TestPki.b64(rootCert.getEncoded()) + "\"]}";
        String claims = "{\"bundleId\":\"" + BUNDLE + "\",\"environment\":\"Sandbox\",\"signedDate\":" + SIGNED_DATE
                + ",\"productId\":\"" + BUNDLE + ".pro\",\"transactionId\":\"2000000000000001\"}";
        String input = TestPki.b64url(header.getBytes(StandardCharsets.UTF_8)) + "."
                + TestPki.b64url(claims.getBytes(StandardCharsets.UTF_8));
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(leaf.getPrivate());
        signer.update(input.getBytes(StandardCharsets.US_ASCII));
        return (input + "." + TestPki.b64url(p1363(signer.sign()))).getBytes(StandardCharsets.US_ASCII);
    }

    /** A certificate kept as a holder; {@code keyUsage}, when given, is the raw extnValue. */
    private X509CertificateHolder certificate(
            String subject,
            KeyPair subjectKeys,
            String issuer,
            PrivateKey issuerKey,
            boolean ca,
            String markerOid,
            byte[] keyUsage,
            String sigAlg)
            throws Exception {
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(issuer),
                BigInteger.valueOf(serial++),
                nb,
                na,
                new X500Name(subject),
                subjectKeys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (keyUsage != null) {
            builder.addExtension(Extension.keyUsage, true, keyUsage);
        }
        if (markerOid != null) {
            builder.addExtension(new ASN1ObjectIdentifier(markerOid), false, DERNull.INSTANCE);
        }
        return builder.build(new JcaContentSignerBuilder(sigAlg).build(issuerKey));
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
        copy(((org.bouncycastle.asn1.ASN1Integer) sequence.getObjectAt(0)).getValue(), out, 0);
        copy(((org.bouncycastle.asn1.ASN1Integer) sequence.getObjectAt(1)).getValue(), out, 32);
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
