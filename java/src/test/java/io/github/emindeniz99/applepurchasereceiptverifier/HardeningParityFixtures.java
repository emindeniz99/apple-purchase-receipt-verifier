package io.github.emindeniz99.applepurchasereceiptverifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Writes the hardening-parity inputs the 0.7 shared cases add
 * (docs/design/0.7-hardening-parity.md, "Shared cases to add"), into the
 * directory given as the first argument. Three groups:
 *
 * <ul>
 *   <li><b>DoS (T1, T2, T3).</b> Certificates carrying an oversized RSA
 *       modulus that no pinned root vouches for. A top-down chain check
 *       (#161) never parses such a key, so T1 and T2 fail as UNTRUSTED_CHAIN
 *       and the genuine T3 verifies, all within the shared time budget; an
 *       implementation that decodes or verifies with the key first spends
 *       seconds. The keys are fabricated moduli with no small factor, as in
 *       {@link UnauthenticatedKeyCostTest}, so no key pair is generated and
 *       the stranger's private key never exists; the case still holds because
 *       the cost is the modexp or the primality test on the public modulus,
 *       which runs before a signature is compared. Every oversized certificate
 *       carries the marker OID its position needs, so a broken implementation
 *       reaches the chain step rather than stopping at the purpose check.</li>
 *   <li><b>Signer algorithms (T4).</b> Receipts the receipt PKI signs with an
 *       ECDSA P-256 signer, with a SHA-384 digest and with RSA-PSS; each
 *       verifies (owner Q15, change 3), and one with a flipped content byte is
 *       INVALID_SIGNATURE.</li>
 * </ul>
 *
 * <p>Two roots are emitted: {@code hardening-jws-root.der} for T1 and
 * {@code hardening-receipt-root.der} for T2, T3 and T4.</p>
 *
 * <p>A {@code main} like the other generators. Regenerate with:</p>
 *
 * <pre>
 * mvn -B -q -f java/pom.xml test-compile
 * mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
 * java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
 *      io.github.emindeniz99.applepurchasereceiptverifier.HardeningParityFixtures \
 *      fixtures/generated-0.7
 * </pre>
 *
 * <p>Each run mints fresh keys and fresh random moduli, so regenerating
 * changes every byte of these files and every {@code contentSha256} in
 * fixtures/cases.json that records them.</p>
 */
public final class HardeningParityFixtures {

    private static final String BUNDLE = "com.example.app";
    private static final String LEAF_OID = "1.2.840.113635.100.6.11.1";
    private static final String INTERMEDIATE_OID = "1.2.840.113635.100.6.2.1";
    private static final String RSA = "SHA256withRSA";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BigInteger SMALL_PRIMES = smallPrimes();

    private static final long NOT_BEFORE = 1704067200000L; // 2024-01-01
    private static final long NOT_AFTER = 2524608000000L; // 2050-01-01
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";

    /** A single key big enough that one RSA operation over it costs seconds (Go: ~5 s). */
    private static final int DOS_SINGLE_BITS = 262144;

    /** Smaller keys for the multi-certificate cases, where the verifies add up. */
    private static final int DOS_MULTI_BITS = 65536;

    private static final byte[] GUID = {
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        (byte) 0x88,
        (byte) 0x99,
        (byte) 0xaa,
        (byte) 0xbb,
        (byte) 0xcc,
        (byte) 0xdd,
        (byte) 0xee,
        (byte) 0xff,
        0x00
    };
    private static final byte[] OPAQUE = {1, 2, 3, 4, 5, 6, 7, 8};

    private KeyPair attacker;

    private HardeningParityFixtures() {}

    public static void main(String[] args) throws Exception {
        Path out = args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(out);
        new HardeningParityFixtures().run(out);
    }

    private void run(Path out) throws Exception {
        attacker = rsa(2048);
        writeJwsDos(out);
        writeReceiptDos(out);
        writeSignerAlgorithms(out);
    }

    // --- T1: oversized key in an untrusted x5c[1] ------------------------

    private void writeJwsDos(Path out) throws Exception {
        Date nb = new Date(NOT_BEFORE);
        Date na = new Date(NOT_AFTER);
        KeyPair rootKp = ec();
        X509Certificate root = TestPki.cert(
                "CN=Hardening JWS Root",
                rootKp,
                "CN=Hardening JWS Root",
                rootKp.getPrivate(),
                true,
                null,
                nb,
                na,
                "SHA256withECDSA");
        write(out, "hardening-jws-root.der", root.getEncoded());

        // x5c[1]: subject the intermediate name, issuer the root name, but
        // signed by the attacker, not the root, and carrying the oversized
        // key. A top-down check verifies it against the root's key, which
        // fails, without ever touching this modulus.
        X509CertificateHolder hugeIntermediate = hugeKeyCertificate(
                DOS_SINGLE_BITS, "CN=Hardening JWS WWDR", "CN=Hardening JWS Root", INTERMEDIATE_OID, nb, na);
        // x5c[0]: a normal leaf claiming that intermediate as issuer, attacker
        // signed, with the leaf marker so a broken port reaches the chain.
        KeyPair leafKp = ec();
        X509CertificateHolder leaf = new X509CertificateHolder(TestPki.cert(
                        "CN=Hardening JWS Leaf",
                        leafKp,
                        "CN=Hardening JWS WWDR",
                        attacker.getPrivate(),
                        false,
                        LEAF_OID,
                        nb,
                        na,
                        RSA)
                .getEncoded());

        String header = "{\"alg\":\"ES256\",\"x5c\":[\"" + b64(leaf) + "\",\"" + b64(hugeIntermediate) + "\",\""
                + b64(new X509CertificateHolder(root.getEncoded())) + "\"]}";
        String jws = TestPki.b64url(header.getBytes(StandardCharsets.UTF_8)) + "."
                + TestPki.b64url(("{\"signedDate\":" + SIGNED_DATE + "}").getBytes(StandardCharsets.UTF_8)) + "."
                + TestPki.b64url(new byte[64]);
        write(out, "jws-untrusted-oversized-x5c.jws", jws.getBytes(StandardCharsets.US_ASCII));
    }

    // --- T2 and T3: oversized keys in the receipt certificate bag ---------

    private void writeReceiptDos(Path out) throws Exception {
        Date nb = new Date(NOT_BEFORE);
        Date na = new Date(NOT_AFTER);
        KeyPair rootKp = rsa(2048);
        X509Certificate root = TestPki.cert(
                "CN=Hardening Receipt Root",
                rootKp,
                "CN=Hardening Receipt Root",
                rootKp.getPrivate(),
                true,
                null,
                nb,
                na,
                RSA);
        KeyPair interKp = rsa(2048);
        X509Certificate intermediate = TestPki.cert(
                "CN=Hardening Receipt WWDR",
                interKp,
                "CN=Hardening Receipt Root",
                rootKp.getPrivate(),
                true,
                INTERMEDIATE_OID,
                nb,
                na,
                RSA);
        write(out, "hardening-receipt-root.der", root.getEncoded());

        byte[] payload = payload();

        // T2: the signer names the intermediate as issuer, and the only
        // certificates that could be it are eight strangers with oversized
        // keys, none vouched for by the root. UNTRUSTED_CHAIN, no genuine
        // intermediate present.
        KeyPair signerKp = rsa(2048);
        X509CertificateHolder signer = new X509CertificateHolder(TestPki.cert(
                        "CN=Hardening Receipt Signing",
                        signerKp,
                        "CN=Hardening Receipt WWDR",
                        attacker.getPrivate(),
                        false,
                        LEAF_OID,
                        nb,
                        na,
                        RSA)
                .getEncoded());
        List<X509CertificateHolder> t2 = new ArrayList<X509CertificateHolder>();
        t2.add(signer);
        for (int i = 0; i < 8; i++) {
            t2.add(hugeKeyCertificate(
                    DOS_MULTI_BITS,
                    "CN=Hardening Receipt WWDR",
                    "CN=Hardening Receipt Root",
                    INTERMEDIATE_OID,
                    nb,
                    na));
        }
        write(
                out,
                "receipt-untrusted-oversized-intermediates.der",
                TestPki.signReceiptAs(payload, new Date(SIGNED_DATE), signerKp.getPrivate(), RSA, signer, t2));

        // T3: a genuine chain that verifies, padded with seven oversized
        // strangers named like the intermediate. Q16: the strangers are
        // ignored and the receipt verifies. Ten certificates, at the cap.
        KeyPair genuineSignerKp = rsa(2048);
        X509CertificateHolder genuineSigner = new X509CertificateHolder(TestPki.cert(
                        "CN=Hardening Receipt Signing",
                        genuineSignerKp,
                        "CN=Hardening Receipt WWDR",
                        interKp.getPrivate(),
                        false,
                        LEAF_OID,
                        nb,
                        na,
                        RSA)
                .getEncoded());
        List<X509CertificateHolder> t3 = new ArrayList<X509CertificateHolder>();
        t3.add(genuineSigner);
        t3.add(new X509CertificateHolder(intermediate.getEncoded()));
        t3.add(new X509CertificateHolder(root.getEncoded()));
        for (int i = 0; i < 7; i++) {
            t3.add(hugeKeyCertificate(
                    DOS_MULTI_BITS,
                    "CN=Hardening Receipt WWDR",
                    "CN=Hardening Receipt Root",
                    INTERMEDIATE_OID,
                    nb,
                    na));
        }
        write(
                out,
                "receipt-genuine-padded-with-oversized-strangers.der",
                TestPki.signReceiptAs(
                        payload, new Date(SIGNED_DATE), genuineSignerKp.getPrivate(), RSA, genuineSigner, t3));
    }

    // --- T4: any signer algorithm ---------------------------------------

    private void writeSignerAlgorithms(Path out) throws Exception {
        Date nb = new Date(NOT_BEFORE);
        Date na = new Date(NOT_AFTER);
        KeyPair rootKp = rsa(2048);
        X509Certificate root = TestPki.cert(
                "CN=Signer Alg Root", rootKp, "CN=Signer Alg Root", rootKp.getPrivate(), true, null, nb, na, RSA);
        KeyPair interKp = rsa(2048);
        X509Certificate intermediate = TestPki.cert(
                "CN=Signer Alg WWDR",
                interKp,
                "CN=Signer Alg Root",
                rootKp.getPrivate(),
                true,
                INTERMEDIATE_OID,
                nb,
                na,
                RSA);
        write(out, "signer-alg-root.der", root.getEncoded());
        byte[] payload = payload();

        byte[] ecdsa = signerReceipt(payload, ec(), "SHA256withECDSA", intermediate, interKp, root);
        write(out, "receipt-signer-ecdsa-p256.der", ecdsa);
        write(out, "receipt-signer-ecdsa-p256-tampered.der", tamperContentByte(ecdsa));
        write(
                out,
                "receipt-signer-sha384.der",
                signerReceipt(payload, rsa(2048), "SHA384withRSA", intermediate, interKp, root));
        write(
                out,
                "receipt-signer-rsa-pss.der",
                signerReceipt(payload, rsa(2048), "SHA256withRSAandMGF1", intermediate, interKp, root));
    }

    private byte[] signerReceipt(
            byte[] payload,
            KeyPair signerKp,
            String cmsAlgorithm,
            X509Certificate intermediate,
            KeyPair interKp,
            X509Certificate root)
            throws Exception {
        X509CertificateHolder signer = new X509CertificateHolder(TestPki.cert(
                        "CN=Signer Alg Signing",
                        signerKp,
                        name(intermediate),
                        interKp.getPrivate(),
                        false,
                        LEAF_OID,
                        intermediate.getNotBefore(),
                        intermediate.getNotAfter(),
                        RSA)
                .getEncoded());
        List<X509CertificateHolder> embedded = Arrays.asList(
                signer,
                new X509CertificateHolder(intermediate.getEncoded()),
                new X509CertificateHolder(root.getEncoded()));
        return TestPki.signReceiptAs(
                payload, new Date(SIGNED_DATE), signerKp.getPrivate(), cmsAlgorithm, signer, embedded);
    }

    // --- helpers ---------------------------------------------------------

    private byte[] payload() throws Exception {
        return TestPki.receiptPayload(
                BUNDLE,
                "1.2.3",
                OPAQUE,
                TestPki.deviceHash(GUID, OPAQUE, BUNDLE),
                CREATION_DATE,
                Collections.<byte[]>emptyList());
    }

    /**
     * Flips one byte of the receipt's encapsulated content, leaving every
     * length and the certificate bag intact, so only the CMS digest changes.
     * The content is the last OCTET STRING inside the eContent, and its bytes
     * appear verbatim in the DER; the bundle id byte is the flip point, as in
     * the genuine-receipt tamper test.
     */
    private static byte[] tamperContentByte(byte[] der) {
        byte[] needle = BUNDLE.getBytes(StandardCharsets.UTF_8);
        int at = indexOf(der, needle);
        if (at < 0) {
            throw new IllegalStateException("bundle id not found in the receipt");
        }
        byte[] copy = der.clone();
        copy[at + needle.length - 1] ^= 0x01;
        return copy;
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private X509CertificateHolder hugeKeyCertificate(
            int bits, String subject, String issuer, String markerOid, Date nb, Date na) throws Exception {
        BigInteger modulus;
        do {
            modulus = new BigInteger(bits, RANDOM).setBit(bits - 1).setBit(0);
        } while (!modulus.gcd(SMALL_PRIMES).equals(BigInteger.ONE));
        SubjectPublicKeyInfo key = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                new RSAPublicKey(modulus, BigInteger.valueOf(65537)));
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                new X500Name(issuer), new BigInteger(64, RANDOM), nb, na, new X500Name(subject), key);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(new ASN1ObjectIdentifier(markerOid), false, DERNull.INSTANCE);
        return builder.build(new JcaContentSignerBuilder(RSA).build(attacker.getPrivate()));
    }

    private static String name(X509Certificate certificate) {
        return certificate.getSubjectX500Principal().getName();
    }

    private static String b64(X509CertificateHolder holder) throws Exception {
        return Base64.getEncoder().encodeToString(holder.getEncoded());
    }

    private static KeyPair rsa(int bits) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(bits);
        return kpg.generateKeyPair();
    }

    private static KeyPair ec() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static BigInteger smallPrimes() {
        BigInteger product = BigInteger.ONE;
        for (int i = 3; i < 10000; i += 2) {
            if (BigInteger.valueOf(i).isProbablePrime(30)) {
                product = product.multiply(BigInteger.valueOf(i));
            }
        }
        return product;
    }

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
