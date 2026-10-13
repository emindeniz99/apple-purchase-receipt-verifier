package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
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
 * a pinned root, or a CA it vouched for, has vouched for its certificate,
 * so these inputs are rejected, or ignored, in milliseconds.</p>
 *
 * <p>The bound is generous so a slow CI runner does not fail it; the
 * regression it guards against is two orders of magnitude slower.</p>
 */
class UnauthenticatedKeyCostTest {

    private static final String BUNDLE = "com.example.app";
    private static final long BOUND_MS = 2000;

    /** The largest receipt DER whose base64 fits the cap. */
    private static final int CAP_DER = ReceiptCore.MAX_RECEIPT_BYTES / 4 * 3;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BigInteger SMALL_PRIMES = smallPrimes();

    /** Issuer RDNs for the name-comparison test: about 7.5 s cold with BouncyCastle's comparison. */
    private static final int RDNS = 8000;

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
            embedded.add(hugeKeyCertificate(name(pki.intermediate), name(pki.root), null, pki, attacker));
        }
        byte[] receipt = receiptSignedBy(signerKey, Collections.singletonList(signer), embedded);

        long start = System.nanoTime();
        ReceiptPayload verified = Checks.receipt(Checks.verifier(pki), receipt);
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
            embedded.add(hugeKeyCertificate(name(pki.intermediate), name(pki.root), null, pki, attacker));
        }
        byte[] receipt = receiptSignedBy(signerKey, Collections.singletonList(signer), embedded);

        long start = System.nanoTime();
        VerificationException e =
                assertThrows(VerificationException.class, () -> Checks.receipt(Checks.verifier(pki), receipt));
        assertFast(start);
        assertEquals(Reason.UNTRUSTED_CHAIN, e.reason(), e.getMessage());
    }

    @Test
    void hugeKeysSignedByAnEndEntityThePinnedRootVouchesForAreNeverDecoded() throws Exception {
        // A developer certificate is an end entity under Apple's WWDR
        // intermediate, and its private key belongs to the developer. Signed
        // by that key: seven CA certificates with huge keys, and one more
        // certificate naming them as its issuer. If the end entity could
        // vouch, checking that last certificate would decode all seven keys
        // (13 to 18 s measured).
        TestPki pki = TestPki.receipt();
        KeyPair developerKey = rsa2048();
        X509CertificateHolder developer = new X509CertificateHolder(TestPki.cert(
                        "CN=Some Developer",
                        developerKey,
                        name(pki.intermediate),
                        pki.intermediateKey,
                        false,
                        null,
                        pki.leaf.getNotBefore(),
                        pki.leaf.getNotAfter(),
                        "SHA256withRSA")
                .getEncoded());
        List<X509CertificateHolder> embedded = new ArrayList<X509CertificateHolder>();
        embedded.add(developer);
        embedded.add(new X509CertificateHolder(pki.intermediate.getEncoded()));
        for (int i = 0; i < 7; i++) {
            embedded.add(hugeKeyCertificate("CN=Attacker CA", "CN=Some Developer", null, pki, developerKey));
        }
        embedded.add(new X509CertificateHolder(TestPki.cert(
                        "CN=Victim",
                        rsa2048(),
                        "CN=Attacker CA",
                        developerKey.getPrivate(),
                        false,
                        null,
                        pki.leaf.getNotBefore(),
                        pki.leaf.getNotAfter(),
                        "SHA256withRSA")
                .getEncoded()));
        byte[] receipt = receiptSignedBy(developerKey, Collections.singletonList(developer), embedded);

        long start = System.nanoTime();
        VerificationException e =
                assertThrows(VerificationException.class, () -> Checks.receipt(Checks.verifier(pki), receipt));
        assertFast(start);
        // The developer's chain is genuine; it only lacks the receipt-signing marker.
        assertEquals(Reason.INVALID_CERTIFICATE_PURPOSE, e.reason(), e.getMessage());
    }

    @Test
    void aJwsWhoseCertificatesHaveHugeKeysIsRefusedQuickly() throws Exception {
        TestPki pki = TestPki.jws();
        String leaf = TestPki.b64(
                hugeKeyCertificate("CN=Fake Leaf", name(pki.intermediate), AppleTrustOids.LEAF, pki, attacker)
                        .getEncoded());
        String intermediate = TestPki.b64(
                hugeKeyCertificate(name(pki.intermediate), name(pki.root), AppleTrustOids.INTERMEDIATE, pki, attacker)
                        .getEncoded());
        String root = TestPki.b64(hugeKeyCertificate(name(pki.root), name(pki.root), null, pki, attacker)
                .getEncoded());
        String header = "{\"alg\":\"ES256\",\"x5c\":[\"" + leaf + "\",\"" + intermediate + "\",\"" + root + "\"]}";
        String jws = TestPki.b64url(header.getBytes(StandardCharsets.UTF_8)) + "."
                + TestPki.b64url("{}".getBytes(StandardCharsets.UTF_8)) + "."
                + TestPki.b64url(new byte[64]);
        Verifier verifier = Checks.verifier(pki);

        long start = System.nanoTime();
        VerificationException e = assertThrows(VerificationException.class, () -> Checks.signedData(verifier, jws));
        assertFast(start);
        assertEquals(Reason.UNTRUSTED_CHAIN, e.reason(), e.getMessage());
    }

    @Test
    void aSignerIdWhoseIssuerReordersTheCertificatesRdnsIsRefusedQuickly() throws Exception {
        // The SignerInfo names its certificate by issuer and serial number,
        // and the one embedded certificate has that serial and the same
        // issuer RDNs in the opposite order. BouncyCastle's X500Name.equals
        // ignores RDN order and is quadratic in the RDN count: matching the
        // two took 7 to 8 s before anything was authenticated. The JDK's
        // comparison keeps RDN order, so no certificate matches.
        TestPki pki = TestPki.receipt();
        KeyPair signerKey = rsa2048();
        BigInteger serial = BigInteger.valueOf(42);
        X509CertificateHolder named = certificateWithIssuer(manyCns(RDNS - 1, -1), serial, signerKey);
        X509CertificateHolder embedded = certificateWithIssuer(manyCns(0, 1), serial, signerKey);
        byte[] receipt =
                receiptSignedBy(signerKey, Collections.singletonList(named), Collections.singletonList(embedded));

        long start = System.nanoTime();
        VerificationException e =
                assertThrows(VerificationException.class, () -> Checks.receipt(Checks.verifier(pki), receipt));
        assertFast(start);
        assertEquals(Reason.MALFORMED, e.reason(), e.getMessage());
        assertEquals("signer certificate not embedded", e.getMessage());
    }

    @Test
    void twoSignerIdsWhoseIssuersReorderEachOthersRdnsAreRefusedQuickly() throws Exception {
        // Two SignerInfos with one serial number and the same issuer RDNs in
        // opposite orders, and one embedded certificate whose issuer rotates
        // them by one, so neither SignerInfo names it. BouncyCastle's
        // SignerInformationStore keys the SignerInfos by SignerId; the two
        // collide on the order-insensitive hash and are compared with
        // X500Name.equals, 7 s before any certificate is looked at. One
        // store per SignerInfo compares nothing.
        TestPki pki = TestPki.receipt();
        KeyPair signerKey = rsa2048();
        BigInteger serial = BigInteger.valueOf(42);
        List<X509CertificateHolder> named = Arrays.asList(
                certificateWithIssuer(manyCns(0, 1), serial, signerKey),
                certificateWithIssuer(manyCns(RDNS - 1, -1), serial, signerKey));
        X509CertificateHolder embedded = certificateWithIssuer(manyCns(1, 1), serial, signerKey);
        byte[] receipt = receiptSignedBy(signerKey, named, Collections.singletonList(embedded));

        long start = System.nanoTime();
        VerificationException e =
                assertThrows(VerificationException.class, () -> Checks.receipt(Checks.verifier(pki), receipt));
        assertFast(start);
        assertEquals(Reason.MALFORMED, e.reason(), e.getMessage());
        assertEquals("signer certificate not embedded", e.getMessage());
    }

    @Test
    void capSizedContentUnderTheSlowestDigestIsRefusedBeforeItIsDigested() throws Exception {
        // The SignerInfo's digestAlgorithm is the sender's choice and is not
        // signed. BouncyCastle digests the whole encapsulated content with
        // it, once per SignerInfo, before it compares the messageDigest
        // attribute or checks the signature. Nothing here needs a key: four
        // SignerInfos name the genuine receipt signer, which chains to the
        // pinned root and carries the marker, declare GOST R 34.11-94 (the
        // slowest digest BouncyCastle resolves) and are signed by an
        // unrelated key, over content just under the cap. Digesting it cost
        // about 1.2 s warm and up to 1.8 s cold on Java 8; the digest is now
        // refused before a byte is digested (DECISIONS.md R20).
        TestPki pki = TestPki.receipt();
        X509CertificateHolder leaf = new X509CertificateHolder(pki.leaf.getEncoded());
        List<X509CertificateHolder> signers = Arrays.asList(leaf, leaf, leaf, leaf);
        List<X509CertificateHolder> embedded =
                Arrays.asList(leaf, new X509CertificateHolder(pki.intermediate.getEncoded()));
        int overhead = slowDigestReceipt(1000, signers, embedded).length - 1000;
        // Less a margin for the longer length octets of the larger content.
        byte[] receipt = slowDigestReceipt(CAP_DER - overhead - 64, signers, embedded);

        long start = System.nanoTime();
        VerificationException e =
                assertThrows(VerificationException.class, () -> Checks.receipt(Checks.verifier(pki), receipt));
        assertFast(start);
        assertEquals(Reason.INVALID_SIGNATURE, e.reason(), e.getMessage());
        assertEquals("CMS verifier refused the signer info: digest 1.2.643.2.2.9 is refused", e.getMessage());
    }

    @Test
    void aBagEntryOfNestedSetsIsRefusedWithoutBeingReEncoded() throws Exception {
        // The unsigned certificate bag gains one entry, a SEQUENCE of SETs
        // nested 30 deep, just under the cap. Re-encoding a SET to DER sorts
        // it by its members' encodings, so re-encoding the entry before
        // parsing it as a certificate cost about 3.1 s. It is now parsed as
        // it stands and refused as no certificate.
        TestPki pki = TestPki.receipt();
        SignedData genuine = signedData(pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16])));
        ASN1EncodableVector bag = new ASN1EncodableVector();
        for (int i = 0; i < genuine.getCertificates().size(); i++) {
            bag.add(genuine.getCertificates().getObjectAt(i));
        }
        bag.add(nestedSets(30, CAP_DER - 16384));
        byte[] receipt = receipt(genuine, new DLSet(bag), genuine.getSignerInfos());

        VerificationException e = refusedFast(pki, receipt);
        assertEquals(Reason.MALFORMED, e.reason(), e.getMessage());
        assertEquals("an embedded certificate is not a valid certificate", e.getMessage());
    }

    @Test
    void aSignerIdWhoseIssuerValueIsNestedSetsIsRefusedBeforeItIsCompared() throws Exception {
        // The SignerInfo's issuer is one CN whose value is a SEQUENCE of SETs
        // nested 30 deep, just under the cap, and the bag holds ten
        // certificates with its serial number. BouncyCastle re-encodes a
        // value that is not a string to compare or hash a name, so hashing
        // the SignerId and comparing it with each certificate cost about
        // 10.8 s before anything was trusted.
        assertSignerIdRefusedQuickly(nestedSets(30, CAP_DER - 32768));
    }

    @Test
    void aSignerIdWhoseIssuerValueIsALargeFlatSequenceIsRefusedBeforeItIsCompared() throws Exception {
        // The same with no nesting: a SEQUENCE of INTEGERs just under the
        // cap. 4.5 to 12.5 s before.
        ASN1EncodableVector integers = new ASN1EncodableVector();
        for (int i = 0; i < (CAP_DER - 32768) / 3; i++) {
            integers.add(new ASN1Integer(1));
        }
        assertSignerIdRefusedQuickly(new DLSequence(integers));
    }

    @Test
    void aSignerInfoLabelledMd2WithRsaIsRefusedBeforeItsSignedAttributesAreHashed() throws Exception {
        // The signatureAlgorithm is unsigned too, and BouncyCastle hashes the
        // signed attributes with the digest it names before it checks the
        // signature. The genuine signer's SignerInfo, its signed attributes
        // padded to just under the cap, relabelled md2WithRSAEncryption: 250
        // ms of MD2 before, eight times the same input under SHA-256.
        TestPki pki = TestPki.receipt();
        SignedData genuine = signedData(pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16])));
        SignerInfo signer = SignerInfo.getInstance(genuine.getSignerInfos().getObjectAt(0));
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        for (int i = 0; i < signer.getAuthenticatedAttributes().size(); i++) {
            attributes.add(signer.getAuthenticatedAttributes().getObjectAt(i));
        }
        attributes.add(new Attribute(
                new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1"),
                new DERSet(new DEROctetString(new byte[CAP_DER - 16384]))));
        byte[] receipt = relabelled(
                genuine,
                signer,
                new DERSet(attributes),
                new AlgorithmIdentifier(PKCSObjectIdentifiers.md2WithRSAEncryption, DERNull.INSTANCE));

        long start = System.nanoTime();
        VerificationException e =
                assertThrows(VerificationException.class, () -> Checks.receipt(Checks.verifier(pki), receipt));
        assertFast(start);
        assertEquals(Reason.INVALID_SIGNATURE, e.reason(), e.getMessage());
        assertEquals(
                "CMS verifier refused the signer info: signature algorithm 1.2.840.113549.1.1.2 is refused",
                e.getMessage());
    }

    @Test
    void aSignerInfoLabelledRsaPssWithAHugeSaltIsRefusedBeforeAnythingIsAllocated() throws Exception {
        // RSASSA-PSS parameters are unsigned, and BouncyCastle allocates an
        // array of saltLength bytes while it builds the verifier: with a
        // saltLength of 1,000,000,000, an OutOfMemoryError out of
        // verifyReceipt, before a signature byte was compared.
        TestPki pki = TestPki.receipt();
        SignedData genuine = signedData(pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16])));
        SignerInfo signer = SignerInfo.getInstance(genuine.getSignerInfos().getObjectAt(0));
        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        AlgorithmIdentifier pss = new AlgorithmIdentifier(
                PKCSObjectIdentifiers.id_RSASSA_PSS,
                new RSASSAPSSparams(
                        sha256,
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha256),
                        new ASN1Integer(1_000_000_000),
                        new ASN1Integer(1)));
        byte[] receipt = relabelled(genuine, signer, signer.getAuthenticatedAttributes(), pss);

        long start = System.nanoTime();
        VerificationException e =
                assertThrows(VerificationException.class, () -> Checks.receipt(Checks.verifier(pki), receipt));
        assertFast(start);
        assertEquals(Reason.INVALID_SIGNATURE, e.reason(), e.getMessage());
        assertEquals(
                "CMS verifier refused the signer info: signature algorithm 1.2.840.113549.1.1.10 is refused",
                e.getMessage());
    }

    /** {@code issuerValue} as the one CN of the SignerInfo's issuer, beside a full bag sharing its serial. */
    private static void assertSignerIdRefusedQuickly(ASN1Encodable issuerValue) throws Exception {
        TestPki pki = TestPki.receipt();
        SignedData genuine = signedData(pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16])));
        SignerInfo signer = SignerInfo.getInstance(genuine.getSignerInfos().getObjectAt(0));
        BigInteger serial = BigInteger.valueOf(4242);
        X509CertificateHolder named = certificateWithIssuer(new X500Name("CN=x"), serial, attacker);
        ASN1EncodableVector bag = new ASN1EncodableVector();
        for (int i = 0; i < ReceiptCertificates.MAX_EMBEDDED_CERTIFICATES; i++) {
            bag.add(named.toASN1Structure());
        }
        // Built from definite-length types throughout: BouncyCastle's own
        // SignerInfo and name classes encode as DER, which would sort the
        // nested SETs while the input is built.
        DLSequence issuer = new DLSequence(new DLSet(new DLSequence(new ASN1Encodable[] {BCStyle.CN, issuerValue})));
        DLSequence naming = new DLSequence(new ASN1Encodable[] {
            new ASN1Integer(1),
            new DLSequence(new ASN1Encodable[] {issuer, new ASN1Integer(serial)}),
            signer.getDigestAlgorithm(),
            new DLTaggedObject(false, 0, signer.getAuthenticatedAttributes()),
            signer.getDigestEncryptionAlgorithm(),
            signer.getEncryptedDigest()
        });
        byte[] receipt = receipt(genuine, new DLSet(bag), new DLSet(naming));

        VerificationException e = refusedFast(pki, receipt);
        assertEquals(Reason.MALFORMED, e.reason(), e.getMessage());
        assertEquals("signer certificate not embedded", e.getMessage());
    }

    /** A SEQUENCE of chains of SETs {@code depth} deep, each SET a chain and an INTEGER, of about {@code bytes}. */
    private static DLSequence nestedSets(int depth, int bytes) throws Exception {
        ASN1Encodable chain = new ASN1Integer(7);
        for (int i = 0; i < depth; i++) {
            chain = new DLSet(new ASN1Encodable[] {chain, new ASN1Integer(1)});
        }
        int chainBytes = chain.toASN1Primitive().getEncoded(ASN1Encoding.DL).length;
        ASN1EncodableVector chains = new ASN1EncodableVector();
        for (int i = 0; i < bytes / chainBytes; i++) {
            chains.add(chain);
        }
        return new DLSequence(chains);
    }

    private static SignedData signedData(byte[] receipt) {
        return SignedData.getInstance(ContentInfo.getInstance(receipt).getContent());
    }

    /** {@code genuine} with {@code signer} relabelled {@code signatureAlgorithm} and carrying {@code signedAttributes}. */
    private static byte[] relabelled(
            SignedData genuine, SignerInfo signer, ASN1Set signedAttributes, AlgorithmIdentifier signatureAlgorithm)
            throws Exception {
        SignerInfo relabelled = new SignerInfo(
                signer.getSID(),
                signer.getDigestAlgorithm(),
                signedAttributes,
                signatureAlgorithm,
                signer.getEncryptedDigest(),
                (ASN1Set) null);
        return receipt(genuine, genuine.getCertificates(), new DLSet(relabelled));
    }

    /**
     * {@code genuine}'s content in a receipt with {@code certificates} and
     * {@code signerInfos}, encoded definite-length as built: DER would sort
     * the sets, which is the cost under test.
     */
    private static byte[] receipt(SignedData genuine, ASN1Set certificates, ASN1Set signerInfos) throws Exception {
        DLSequence signedData = new DLSequence(new ASN1Encodable[] {
            new ASN1Integer(1),
            genuine.getDigestAlgorithms(),
            genuine.getEncapContentInfo(),
            new DLTaggedObject(false, 0, certificates),
            signerInfos
        });
        byte[] receipt = new DLSequence(
                        new ASN1Encodable[] {CMSObjectIdentifiers.signedData, new DLTaggedObject(true, 0, signedData)})
                .getEncoded(ASN1Encoding.DL);
        assertTrue(receipt.length <= CAP_DER, "the receipt is over the cap: " + receipt.length);
        return receipt;
    }

    /** The Apple marker OIDs, so the JWS test reaches the chain check rather than the purpose check. */
    private static final class AppleTrustOids {
        static final String LEAF = "1.2.840.113635.100.6.11.1";
        static final String INTERMEDIATE = "1.2.840.113635.100.6.2.1";
    }

    /**
     * Verifies {@code receipt} twice and asserts the faster refusal fits the
     * bound: these inputs are cap-sized trees whose parse alone costs 0.3 to
     * 0.9 s, and one garbage collection can double a single call.
     */
    private static VerificationException refusedFast(TestPki pki, byte[] receipt) {
        long best = Long.MAX_VALUE;
        VerificationException refused = null;
        for (int i = 0; i < 2; i++) {
            long start = System.nanoTime();
            refused = assertThrows(VerificationException.class, () -> Checks.receipt(Checks.verifier(pki), receipt));
            best = Math.min(best, (System.nanoTime() - start) / 1_000_000);
        }
        assertTrue(best < BOUND_MS, "took " + best + " ms");
        return refused;
    }

    private static void assertFast(long startNanos) {
        long ms = (System.nanoTime() - startNanos) / 1_000_000;
        assertTrue(ms < BOUND_MS, "took " + ms + " ms");
    }

    /**
     * A CA certificate signed by {@code signer}, claiming {@code issuer},
     * whose key is a random 16384-bit modulus with no factor below 10000, so
     * BouncyCastle's cheap small-factor check passes and only the expensive
     * primality test could reject it.
     */
    private static X509CertificateHolder hugeKeyCertificate(
            String subject, String issuer, String markerOid, TestPki pki, KeyPair signer) throws Exception {
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
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(signer.getPrivate()));
    }

    /** {@link #RDNS} CN RDNs, numbered {@code first}, {@code first + step}, ... modulo {@link #RDNS}. */
    private static X500Name manyCns(int first, int step) {
        RDN[] rdns = new RDN[RDNS];
        for (int i = 0; i < RDNS; i++) {
            int n = Math.floorMod(first + i * step, RDNS);
            rdns[i] = new RDN(BCStyle.CN, new DERUTF8String(String.format("%06d", n)));
        }
        return new X500Name(rdns);
    }

    private static X509CertificateHolder certificateWithIssuer(X500Name issuer, BigInteger serial, KeyPair key)
            throws Exception {
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                issuer,
                serial,
                Date.from(Instant.now().minus(1, ChronoUnit.DAYS)),
                Date.from(Instant.now().plus(365, ChronoUnit.DAYS)),
                new X500Name("CN=Signer"),
                SubjectPublicKeyInfo.getInstance(key.getPublic().getEncoded()));
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate()));
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
            KeyPair signerKey, List<X509CertificateHolder> signers, List<X509CertificateHolder> embedded)
            throws Exception {
        Instant creation = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        byte[] payload = TestPki.receiptPayload(
                BUNDLE,
                "1.0",
                new byte[] {1, 2, 3, 4},
                new byte[20],
                creation.toString(),
                Collections.<byte[]>emptyList());
        return TestPki.signReceiptAs(
                payload, Date.from(creation), signerKey.getPrivate(), "SHA256withRSA", signers, embedded);
    }

    /**
     * DER CMS over one attribute of {@code valueBytes} zero bytes, one
     * SignerInfo per entry of {@code signers}, each declaring GOST R
     * 34.11-94 as its digest and signed by {@link #attacker}.
     */
    private static byte[] slowDigestReceipt(
            int valueBytes, List<X509CertificateHolder> signers, List<X509CertificateHolder> embedded)
            throws Exception {
        byte[] payload = TestPki.singleAttributePayload(9999, new byte[valueBytes]);
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(TestPki.BC)
                .build(attacker.getPrivate());
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        for (X509CertificateHolder signer : signers) {
            generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder()
                            .setProvider(TestPki.BC)
                            .build())
                    .setContentDigest(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3411))
                    .build(contentSigner, signer));
        }
        generator.addCertificates(new CollectionStore<X509CertificateHolder>(embedded));
        return generator.generate(new CMSProcessableByteArray(payload), true).getEncoded(ASN1Encoding.DER);
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
