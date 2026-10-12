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
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Writes the inputs of the shared cases on a certificate whose
 * SubjectPublicKeyInfo names a key algorithm no implementation knows
 * ({@value #UNKNOWN_KEY_ALGORITHM}, with 32 zero octets as the key) into the
 * directory given as the first argument (default
 * {@code fixtures/generated-0.7}). Every file is prefixed
 * {@code unknown-key-}.
 *
 * <p>BouncyCastle's {@code X509Certificate.getPublicKey()} returns
 * {@code null} for such a key where it throws for one it cannot build, so
 * the cases pin that both are the certificate's defect. One file per position, each under its own pinned
 * root:</p>
 *
 * <ul>
 *   <li>{@code unknown-key-receipt-signer.der}: the receipt's signer, signed
 *       by the genuine intermediate; the CMS signature is made with an
 *       unrelated RSA key, since the certificate carries none.</li>
 *   <li>{@code unknown-key-receipt-intermediate.der}: the intermediate,
 *       signed by the root; the signer is signed by an unrelated RSA key
 *       for the same reason, and signs the CMS with its own.</li>
 *   <li>{@code unknown-key-jws-leaf.jws}: x5c[0], signed by the genuine
 *       intermediate; the JWS is signed by an unrelated P-256 key.</li>
 *   <li>{@code unknown-key-jws-intermediate.jws}: x5c[1], signed by the
 *       root; the leaf is signed by an unrelated P-256 key and signs the
 *       JWS with its own.</li>
 * </ul>
 *
 * <p>Everything else is genuine: the markers, the validity window
 * (2024-01-01 to 2050-01-01, receipts and JWS dated 2024-08-06) and the
 * root's signature. Run it the way {@link ReviewParityFixtures} documents.
 * Each run mints fresh keys, so regenerating changes every file and its
 * {@code contentSha256}.</p>
 */
public final class UnknownKeyAlgorithmFixtures {

    private static final String BUNDLE = "com.example.app";
    private static final String LEAF_OID = "1.2.840.113635.100.6.11.1";
    private static final String WWDR_OID = "1.2.840.113635.100.6.2.1";
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";

    /** An OID no key algorithm is registered under. */
    static final String UNKNOWN_KEY_ALGORITHM = "1.2.3.4.5.6";

    private static final SubjectPublicKeyInfo UNKNOWN_KEY = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(new ASN1ObjectIdentifier(UNKNOWN_KEY_ALGORITHM)), new byte[32]);

    private static long serial = 1000;

    private final Date nb = new Date(1704067200000L); // 2024-01-01
    private final Date na = new Date(2524608000000L); // 2050-01-01
    private Path out;

    private UnknownKeyAlgorithmFixtures() {}

    public static void main(String[] args) throws Exception {
        UnknownKeyAlgorithmFixtures generator = new UnknownKeyAlgorithmFixtures();
        generator.out =
                args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(generator.out);
        generator.receipts();
        generator.jws();
    }

    private void receipts() throws Exception {
        KeyPair root = keys("RSA");
        X509CertificateHolder rootCert = certificate(
                "CN=Unknown Key Receipt Root",
                spki(root),
                "CN=Unknown Key Receipt Root",
                root.getPrivate(),
                true,
                null,
                "SHA256withRSA");
        write("unknown-key-receipt-root.der", rootCert.getEncoded());
        byte[] payload = TestPki.receiptPayload(
                BUNDLE, "1.2.3", new byte[] {1, 2, 3, 4}, new byte[20], CREATION_DATE, Collections.<byte[]>emptyList());

        KeyPair inter = keys("RSA");
        X509CertificateHolder interCert = certificate(
                "CN=Unknown Key WWDR CA",
                spki(inter),
                "CN=Unknown Key Receipt Root",
                root.getPrivate(),
                true,
                WWDR_OID,
                "SHA256withRSA");
        X509CertificateHolder unknownSigner = certificate(
                "CN=Unknown Key Receipt Signing",
                UNKNOWN_KEY,
                "CN=Unknown Key WWDR CA",
                inter.getPrivate(),
                false,
                LEAF_OID,
                "SHA256withRSA");
        write(
                "unknown-key-receipt-signer.der",
                TestPki.signReceiptAs(
                        payload,
                        new Date(SIGNED_DATE),
                        keys("RSA").getPrivate(),
                        "SHA256withRSA",
                        unknownSigner,
                        Arrays.asList(unknownSigner, interCert, rootCert)));

        X509CertificateHolder unknownInter = certificate(
                "CN=Unknown Key WWDR CA",
                UNKNOWN_KEY,
                "CN=Unknown Key Receipt Root",
                root.getPrivate(),
                true,
                WWDR_OID,
                "SHA256withRSA");
        KeyPair leaf = keys("RSA");
        X509CertificateHolder leafCert = certificate(
                "CN=Unknown Key Receipt Signing",
                spki(leaf),
                "CN=Unknown Key WWDR CA",
                keys("RSA").getPrivate(),
                false,
                LEAF_OID,
                "SHA256withRSA");
        write(
                "unknown-key-receipt-intermediate.der",
                TestPki.signReceiptAs(
                        payload,
                        new Date(SIGNED_DATE),
                        leaf.getPrivate(),
                        "SHA256withRSA",
                        leafCert,
                        Arrays.asList(leafCert, unknownInter, rootCert)));
    }

    private void jws() throws Exception {
        KeyPair root = keys("EC");
        X509CertificateHolder rootCert = certificate(
                "CN=Unknown Key JWS Root",
                spki(root),
                "CN=Unknown Key JWS Root",
                root.getPrivate(),
                true,
                null,
                "SHA256withECDSA");
        write("unknown-key-jws-root.der", rootCert.getEncoded());

        KeyPair inter = keys("EC");
        X509CertificateHolder interCert = certificate(
                "CN=Unknown Key JWS WWDR CA",
                spki(inter),
                "CN=Unknown Key JWS Root",
                root.getPrivate(),
                true,
                WWDR_OID,
                "SHA256withECDSA");
        X509CertificateHolder unknownLeaf = certificate(
                "CN=Unknown Key JWS Signing",
                UNKNOWN_KEY,
                "CN=Unknown Key JWS WWDR CA",
                inter.getPrivate(),
                false,
                LEAF_OID,
                "SHA256withECDSA");
        write(
                "unknown-key-jws-leaf.jws",
                jws(Arrays.asList(unknownLeaf, interCert, rootCert), keys("EC").getPrivate()));

        X509CertificateHolder unknownInter = certificate(
                "CN=Unknown Key JWS WWDR CA",
                UNKNOWN_KEY,
                "CN=Unknown Key JWS Root",
                root.getPrivate(),
                true,
                WWDR_OID,
                "SHA256withECDSA");
        KeyPair leaf = keys("EC");
        X509CertificateHolder leafCert = certificate(
                "CN=Unknown Key JWS Signing",
                spki(leaf),
                "CN=Unknown Key JWS WWDR CA",
                keys("EC").getPrivate(),
                false,
                LEAF_OID,
                "SHA256withECDSA");
        write(
                "unknown-key-jws-intermediate.jws",
                jws(Arrays.asList(leafCert, unknownInter, rootCert), leaf.getPrivate()));
    }

    private static byte[] jws(List<X509CertificateHolder> x5c, PrivateKey signingKey) throws Exception {
        String header =
                "{\"alg\":\"ES256\",\"x5c\":[\"" + TestPki.b64(x5c.get(0).getEncoded()) + "\",\""
                        + TestPki.b64(x5c.get(1).getEncoded()) + "\",\""
                        + TestPki.b64(x5c.get(2).getEncoded()) + "\"]}";
        String claims = "{\"bundleId\":\"" + BUNDLE + "\",\"environment\":\"Sandbox\",\"signedDate\":" + SIGNED_DATE
                + ",\"productId\":\"" + BUNDLE + ".pro\",\"transactionId\":\"2000000000000001\"}";
        String input = TestPki.b64url(header.getBytes(StandardCharsets.UTF_8)) + "."
                + TestPki.b64url(claims.getBytes(StandardCharsets.UTF_8));
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(signingKey);
        signer.update(input.getBytes(StandardCharsets.US_ASCII));
        return (input + "." + TestPki.b64url(p1363(signer.sign()))).getBytes(StandardCharsets.US_ASCII);
    }

    private X509CertificateHolder certificate(
            String subject,
            SubjectPublicKeyInfo subjectKey,
            String issuer,
            PrivateKey issuerKey,
            boolean ca,
            String markerOid,
            String sigAlg)
            throws Exception {
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                new X500Name(issuer), BigInteger.valueOf(serial++), nb, na, new X500Name(subject), subjectKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (markerOid != null) {
            builder.addExtension(new ASN1ObjectIdentifier(markerOid), false, DERNull.INSTANCE);
        }
        return builder.build(new JcaContentSignerBuilder(sigAlg).build(issuerKey));
    }

    private static SubjectPublicKeyInfo spki(KeyPair keys) {
        return SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());
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
        copy(((ASN1Integer) sequence.getObjectAt(0)).getValue(), out, 0);
        copy(((ASN1Integer) sequence.getObjectAt(1)).getValue(), out, 32);
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
