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
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * Writes the inputs of four shared cases no earlier generator covered into
 * the directory given as the first argument (default
 * {@code fixtures/generated-0.7}). Every file is prefixed {@code coverage-}.
 *
 * <ul>
 *   <li>{@code coverage-jws-high-s-signature.jws}: a genuine JWS whose ES256
 *       signature is rewritten from (r, s) to (r, n - s) so that s is above
 *       n / 2. The header and payload are unchanged and the pair still
 *       verifies (DECISIONS.md R44).</li>
 *   <li>{@code coverage-jws-crit-names-an-unknown-parameter.jws}: a genuine
 *       JWS whose signed header carries {@code crit} naming a parameter no
 *       implementation understands, the parameter present beside it
 *       (RFC 7515 4.1.11; R44).</li>
 *   <li>{@code coverage-jws-x5c1-is-the-root.jws}: a genuine JWS whose leaf
 *       the root issued directly, with x5c of leaf, root, root. The root
 *       carries the WWDR marker, so the path's shape is the only thing
 *       wrong with it.</li>
 *   <li>{@code coverage-receipt-without-econtent.der}: a receipt whose
 *       SignedData carries no eContent: the signature is over the payload,
 *       but the payload is detached (RFC 5652 5.2).</li>
 * </ul>
 *
 * <p>Every chain is valid from 2024-01-01 to 2050-01-01 and the JWS are
 * dated 2024-08-06. The roots are {@code coverage-jws-root.der} and
 * {@code coverage-receipt-root.der}. Run it the way
 * {@link ReviewParityFixtures} documents. Each run mints fresh keys, so
 * regenerating changes every file and its {@code contentSha256}.</p>
 */
public final class ShapeCoverageFixtures {

    private static final String LEAF_OID = "1.2.840.113635.100.6.11.1";
    private static final String WWDR_OID = "1.2.840.113635.100.6.2.1";
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final Date NOT_BEFORE = new Date(1704067200000L); // 2024-01-01
    private static final Date NOT_AFTER = new Date(2524608000000L); // 2050-01-01
    private static final String CLAIMS =
            "{\"bundleId\":\"com.example.app\",\"environment\":\"Sandbox\",\"signedDate\":" + SIGNED_DATE + "}";

    private ShapeCoverageFixtures() {}

    public static void main(String[] args) throws Exception {
        Path out = args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(out);

        KeyPair rootKeys = keys("EC");
        X509Certificate root = TestPki.cert(
                "CN=Coverage JWS Root",
                rootKeys,
                "CN=Coverage JWS Root",
                rootKeys.getPrivate(),
                true,
                WWDR_OID,
                NOT_BEFORE,
                NOT_AFTER,
                "SHA256withECDSA");
        KeyPair interKeys = keys("EC");
        X509Certificate inter = TestPki.cert(
                "CN=Coverage JWS WWDR CA",
                interKeys,
                "CN=Coverage JWS Root",
                rootKeys.getPrivate(),
                true,
                WWDR_OID,
                NOT_BEFORE,
                NOT_AFTER,
                "SHA256withECDSA");
        KeyPair leafKeys = keys("EC");
        X509Certificate leaf = TestPki.cert(
                "CN=Coverage JWS Signing",
                leafKeys,
                "CN=Coverage JWS WWDR CA",
                interKeys.getPrivate(),
                false,
                LEAF_OID,
                NOT_BEFORE,
                NOT_AFTER,
                "SHA256withECDSA");
        write(out, "coverage-jws-root.der", root.getEncoded());

        String x5c = x5c(leaf, inter, root);
        write(
                out,
                "coverage-jws-high-s-signature.jws",
                ascii(highS(jws("{\"alg\":\"ES256\",\"x5c\":" + x5c + "}", leafKeys.getPrivate()))));
        write(
                out,
                "coverage-jws-crit-names-an-unknown-parameter.jws",
                ascii(jws(
                        "{\"alg\":\"ES256\",\"crit\":[\"com.example.unknown\"],\"com.example.unknown\":true,\"x5c\":"
                                + x5c + "}",
                        leafKeys.getPrivate())));

        KeyPair directKeys = keys("EC");
        X509Certificate direct = TestPki.cert(
                "CN=Coverage JWS Signing Under The Root",
                directKeys,
                "CN=Coverage JWS Root",
                rootKeys.getPrivate(),
                false,
                LEAF_OID,
                NOT_BEFORE,
                NOT_AFTER,
                "SHA256withECDSA");
        write(
                out,
                "coverage-jws-x5c1-is-the-root.jws",
                ascii(jws("{\"alg\":\"ES256\",\"x5c\":" + x5c(direct, root, root) + "}", directKeys.getPrivate())));

        KeyPair receiptRootKeys = keys("RSA");
        X509Certificate receiptRoot = TestPki.cert(
                "CN=Coverage Receipt Root",
                receiptRootKeys,
                "CN=Coverage Receipt Root",
                receiptRootKeys.getPrivate(),
                true,
                null,
                NOT_BEFORE,
                NOT_AFTER,
                "SHA256withRSA");
        KeyPair receiptInterKeys = keys("RSA");
        X509Certificate receiptInter = TestPki.cert(
                "CN=Coverage WWDR CA",
                receiptInterKeys,
                "CN=Coverage Receipt Root",
                receiptRootKeys.getPrivate(),
                true,
                WWDR_OID,
                NOT_BEFORE,
                NOT_AFTER,
                "SHA256withRSA");
        KeyPair signerKeys = keys("RSA");
        X509Certificate signer = TestPki.cert(
                "CN=Coverage Receipt Signing",
                signerKeys,
                "CN=Coverage WWDR CA",
                receiptInterKeys.getPrivate(),
                false,
                LEAF_OID,
                NOT_BEFORE,
                NOT_AFTER,
                "SHA256withRSA");
        write(out, "coverage-receipt-root.der", receiptRoot.getEncoded());
        write(
                out,
                "coverage-receipt-without-econtent.der",
                detachedReceipt(signerKeys.getPrivate(), signer, receiptInter));
    }

    /** A compact ES256 JWS over {@link #CLAIMS} with {@code header}, signed by {@code key}, low or high S as it falls. */
    private static String jws(String header, PrivateKey key) throws Exception {
        String input = TestPki.b64url(header.getBytes(StandardCharsets.UTF_8)) + "."
                + TestPki.b64url(CLAIMS.getBytes(StandardCharsets.UTF_8));
        Signature es256 = Signature.getInstance("SHA256withPLAIN-ECDSA", TestPki.BC);
        es256.initSign(key);
        es256.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + TestPki.b64url(es256.sign());
    }

    /** {@code jws} with its signature (r, s) as (r, n - s) when s is at or below n / 2, so s ends above it. */
    private static String highS(String jws) {
        int dot = jws.lastIndexOf('.');
        byte[] signature = Base64.getUrlDecoder().decode(jws.substring(dot + 1));
        BigInteger n = P256_ORDER;
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, 32, 64));
        if (s.compareTo(n.shiftRight(1)) <= 0) {
            s = n.subtract(s);
        }
        if (s.compareTo(n.shiftRight(1)) <= 0 || s.compareTo(n) >= 0) {
            throw new IllegalStateException("s is not high");
        }
        byte[] fixed = s.toByteArray();
        byte[] rewritten = Arrays.copyOf(signature, 64);
        Arrays.fill(rewritten, 32, 64, (byte) 0);
        int start = fixed.length > 32 ? fixed.length - 32 : 0;
        System.arraycopy(fixed, start, rewritten, 64 - (fixed.length - start), fixed.length - start);
        return jws.substring(0, dot + 1) + TestPki.b64url(rewritten);
    }

    /** The order n of P-256 (SEC 2 2.4.2). */
    private static final BigInteger P256_ORDER =
            new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

    /** A receipt signed over the standard payload with no signed attributes, the payload left out of the SignedData. */
    private static byte[] detachedReceipt(PrivateKey key, X509Certificate signer, X509Certificate intermediate)
            throws Exception {
        byte[] payload = TestPki.receiptPayload(
                "com.example.app",
                "1.2.3",
                new byte[] {1, 2, 3, 4},
                new byte[20],
                "2024-08-06T12:00:00Z",
                Collections.<byte[]>emptyList());
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder()
                        .setProvider(TestPki.BC)
                        .build())
                .setDirectSignature(true)
                .build(
                        new JcaContentSignerBuilder("SHA256withRSA")
                                .setProvider(TestPki.BC)
                                .build(key),
                        signer));
        generator.addCertificates(new JcaCertStore(Arrays.asList(signer, intermediate)));
        byte[] detached =
                generator.generate(new CMSProcessableByteArray(payload), false).getEncoded();
        // Re-read, since the generated object keeps the content it signed.
        CMSSignedData reread = new CMSSignedData(detached);
        if (reread.getSignedContent() != null) {
            throw new IllegalStateException("content is attached");
        }
        // The signature covers the payload, so the receipt is genuine but for the missing eContent.
        if (!new CMSSignedData(new CMSProcessableByteArray(payload), detached)
                .getSignerInfos()
                .getSigners()
                .iterator()
                .next()
                .verify(new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider(TestPki.BC)
                        .build(signer))) {
            throw new IllegalStateException("signature does not cover the payload");
        }
        return detached;
    }

    private static String x5c(X509Certificate... certificates) throws Exception {
        StringBuilder array = new StringBuilder("[");
        for (int i = 0; i < certificates.length; i++) {
            array.append(i == 0 ? "\"" : ",\"")
                    .append(TestPki.b64(certificates[i].getEncoded()))
                    .append('"');
        }
        return array.append(']').toString();
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static KeyPair keys(String algorithm) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        if ("EC".equals(algorithm)) {
            generator.initialize(new ECGenParameterSpec("secp256r1"));
        } else {
            generator.initialize(2048);
        }
        return generator.generateKeyPair();
    }

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
