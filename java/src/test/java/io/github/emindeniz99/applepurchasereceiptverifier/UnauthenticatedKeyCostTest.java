package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Certificates nobody trusted yet must cost almost nothing to reject.
 *
 * <p>BouncyCastle validates an RSA key as it decodes it, and the primality
 * test in that validation takes one to two seconds for a 16384-bit modulus.
 * The attacker picks a fresh modulus for every request, so BouncyCastle's
 * cache of validated moduli does not help. When every embedded key was
 * decoded before the chain was checked, a receipt of a few KB carrying such keys
 * cost about 14 seconds of CPU. The verifiers now decode a key only after
 * a pinned root has vouched for its certificate, so these inputs are
 * rejected, or ignored, in milliseconds.</p>
 *
 * <p>The bound is generous so a slow CI runner does not fail it; the
 * regression it guards against is two orders of magnitude slower.</p>
 */
class UnauthenticatedKeyCostTest {

    private static final String BUNDLE = "com.example.app";
    private static final long BOUND_MS = 2000;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BigInteger SMALL_PRIMES = smallPrimes();

    private static KeyPair attacker;

    @BeforeAll
    static void setUp() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        attacker = rsa.generateKeyPair();
    }

    @Test
    void aGenuineReceiptPaddedWithHugeKeysVerifiesQuickly() throws Exception {
        TestPki pki = TestPki.receipt();
        KeyPair signerKey = rsa2048();
        X509CertificateHolder signer = signerUnder(pki, signerKey);
        List<X509CertificateHolder> embedded = new ArrayList<X509CertificateHolder>();
        embedded.add(signer);
        embedded.add(new X509CertificateHolder(pki.intermediate.getEncoded()));
        for (int i = 0; i < 8; i++) {
            embedded.add(hugeKeyCertificate(name(pki.intermediate), name(pki.root), null, pki));
        }
        byte[] receipt = receiptSignedBy(signerKey, signer, embedded);

        long start = System.nanoTime();
        AppReceipt verified = new ReceiptVerifier(Collections.singleton(pki.root), BUNDLE).verify(receipt);
        assertFast(start);
        assertEquals(BUNDLE, verified.bundleId());
    }

    @Test
    void aReceiptWhoseOnlyIntermediatesHaveHugeKeysIsRefusedQuickly() throws Exception {
        TestPki pki = TestPki.receipt();
        KeyPair signerKey = rsa2048();
        X509CertificateHolder signer = signerUnder(pki, signerKey);
        List<X509CertificateHolder> embedded = new ArrayList<X509CertificateHolder>();
        embedded.add(signer);
        for (int i = 0; i < 9; i++) {
            embedded.add(hugeKeyCertificate(name(pki.intermediate), name(pki.root), null, pki));
        }
        byte[] receipt = receiptSignedBy(signerKey, signer, embedded);

        long start = System.nanoTime();
        VerificationException e = assertThrows(
                VerificationException.class,
                () -> new ReceiptVerifier(Collections.singleton(pki.root), BUNDLE).verify(receipt));
        assertFast(start);
        assertEquals(Reason.INVALID_CHAIN, e.reason(), e.getMessage());
    }

    @Test
    void aJwsWhoseCertificatesHaveHugeKeysIsRefusedQuickly() throws Exception {
        TestPki pki = TestPki.jws();
        String leaf = TestPki.b64(hugeKeyCertificate("CN=Fake Leaf", name(pki.intermediate), AppleTrustOids.LEAF, pki)
                .getEncoded());
        String intermediate =
                TestPki.b64(hugeKeyCertificate(name(pki.intermediate), name(pki.root), AppleTrustOids.INTERMEDIATE, pki)
                        .getEncoded());
        String root = TestPki.b64(
                hugeKeyCertificate(name(pki.root), name(pki.root), null, pki).getEncoded());
        String header = "{\"alg\":\"ES256\",\"x5c\":[\"" + leaf + "\",\"" + intermediate + "\",\"" + root + "\"]}";
        String jws = TestPki.b64url(header.getBytes(StandardCharsets.UTF_8)) + "."
                + TestPki.b64url("{}".getBytes(StandardCharsets.UTF_8)) + "."
                + TestPki.b64url(new byte[64]);
        JwsVerifier verifier =
                new JwsVerifier(Collections.singleton(pki.root), BUNDLE, EnumSet.of(Environment.SANDBOX));

        long start = System.nanoTime();
        VerificationException e = assertThrows(VerificationException.class, () -> verifier.verifyRaw(jws));
        assertFast(start);
        assertEquals(Reason.INVALID_CHAIN, e.reason(), e.getMessage());
    }

    /** The Apple marker OIDs, so the JWS test reaches the chain check rather than the purpose check. */
    private static final class AppleTrustOids {
        static final String LEAF = "1.2.840.113635.100.6.11.1";
        static final String INTERMEDIATE = "1.2.840.113635.100.6.2.1";
    }

    private static void assertFast(long startNanos) {
        long ms = (System.nanoTime() - startNanos) / 1_000_000;
        assertTrue(ms < BOUND_MS, "took " + ms + " ms");
    }

    /**
     * A CA certificate signed by the attacker, claiming {@code issuer}, whose
     * key is a random 16384-bit modulus with no factor below 10000, so
     * BouncyCastle's cheap small-factor check passes and only the expensive
     * primality test could reject it.
     */
    private static X509CertificateHolder hugeKeyCertificate(
            String subject, String issuer, String markerOid, TestPki pki) throws Exception {
        BigInteger modulus;
        do {
            modulus = new BigInteger(16384, RANDOM).setBit(16383).setBit(0);
        } while (!modulus.gcd(SMALL_PRIMES).equals(BigInteger.ONE));
        SubjectPublicKeyInfo key = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                new RSAPublicKey(modulus, BigInteger.valueOf(65537)));
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                new X500Name(issuer),
                new BigInteger(64, RANDOM),
                pki.leaf.getNotBefore(),
                pki.leaf.getNotAfter(),
                new X500Name(subject),
                key);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        if (markerOid != null) {
            builder.addExtension(new ASN1ObjectIdentifier(markerOid), false, DERNull.INSTANCE);
        }
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(attacker.getPrivate()));
    }

    private static X509CertificateHolder signerUnder(TestPki pki, KeyPair signerKey) throws Exception {
        return new X509CertificateHolder(TestPki.cert(
                        "CN=Fake Receipt Signing",
                        signerKey,
                        name(pki.intermediate),
                        pki.intermediateKey,
                        false,
                        AppleTrustOids.LEAF,
                        pki.leaf.getNotBefore(),
                        pki.leaf.getNotAfter(),
                        "SHA256withRSA")
                .getEncoded());
    }

    private static byte[] receiptSignedBy(
            KeyPair signerKey, X509CertificateHolder signer, List<X509CertificateHolder> embedded) throws Exception {
        Instant creation = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        byte[] payload = TestPki.receiptPayload(
                BUNDLE,
                "1.0",
                new byte[] {1, 2, 3, 4},
                new byte[20],
                creation.toString(),
                Collections.<byte[]>emptyList());
        return TestPki.signReceiptAs(
                payload, Date.from(creation), signerKey.getPrivate(), "SHA256withRSA", signer, embedded);
    }

    private static String name(java.security.cert.X509Certificate certificate) {
        return certificate.getSubjectX500Principal().getName();
    }

    private static KeyPair rsa2048() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        return rsa.generateKeyPair();
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
}
