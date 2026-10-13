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
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTCTime;
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

    /**
     * A saltLength RFC 8017 does not allow, whose low 32 bits, all
     * BouncyCastle reads, are 1,000,000,000.
     */
    private static final long NEGATIVE_SALT = -3_294_967_296L;

    /** The largest receipt DER whose base64 fits the cap. */
    private static final int CAP_DER = ReceiptCore.MAX_RECEIPT_BYTES / 4 * 3;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final AlgorithmIdentifier SHA256_WITH_RSA =
            new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);
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
    void aBagCertificateWhoseSubjectHoldsNestedSetsIsPassedOverUnconverted() throws Exception {
        // The genuine receipt and one more bag entry shaped as a certificate
        // the root issued, whose subject CN is a SEQUENCE of SETs nested 30
        // deep, just under the cap. BouncyCastle's X.509 object DER-encodes
        // the names as it is built and the TBS as it is verified, and DER
        // sorts every SET: 4.1 to 4.7 s a call, and the receipt verified.
        // Apple's names hold strings, so the entry is passed over.
        TestPki pki = TestPki.receipt();
        acceptedFast(
                pki,
                withBagEntry(
                        pki,
                        certificateShaped(
                                SHA256_WITH_RSA,
                                subject(pki.root),
                                cnOf(nestedSets(30, CAP_DER - 16384)),
                                key(pki.leaf))));
    }

    @Test
    void aBagCertificateWhoseKeyParametersHoldNestedSetsIsPassedOverUnconverted() throws Exception {
        // The same value as the key's AlgorithmIdentifier parameters, which
        // BouncyCastle compares and encodes the same way: 4.1 to 4.2 s. No key
        // algorithm defines a SET in its parameters.
        TestPki pki = TestPki.receipt();
        SubjectPublicKeyInfo key = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, nestedSets(30, CAP_DER - 16384)),
                key(pki.leaf).getPublicKeyData().getBytes());
        acceptedFast(
                pki,
                withBagEntry(pki, certificateShaped(SHA256_WITH_RSA, subject(pki.root), new X500Name("CN=x"), key)));
    }

    @Test
    void aBagCertificateWhoseKeyParametersHoldNestedSetsInAnExternalIsPassedOverUnconverted() throws Exception {
        // The same value as an EXTERNAL's data value descriptor, where
        // BouncyCastle puts any element that is not an OID, an INTEGER or a
        // tagged object: 4.1 to 4.3 s, and the receipt verified, while the
        // walk read only the EXTERNAL's content.
        TestPki pki = TestPki.receipt();
        SubjectPublicKeyInfo key = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, external(nestedSets(30, CAP_DER - 16384))),
                key(pki.leaf).getPublicKeyData().getBytes());
        acceptedFast(
                pki,
                withBagEntry(pki, certificateShaped(SHA256_WITH_RSA, subject(pki.root), new X500Name("CN=x"), key)));
    }

    @Test
    void aBagCertificateWithNestedSetsInsideAnExtensionStaysCheap() throws Exception {
        // Extension values are octets to the shape rule: a subjectAltName
        // whose directoryName holds the nested value passes and is converted.
        // It stays cheap only because BouncyCastle decodes subjectAltName
        // lazily, never before trust; a release that decoded it as the
        // certificate is built would fail here, not in a deployment.
        TestPki pki = TestPki.receipt();
        byte[] names = new DLSequence(new DLTaggedObject(true, 4, cnOf(nestedSets(30, CAP_DER - 16384))))
                .getEncoded(ASN1Encoding.DL);
        DLSequence subjectAltName =
                new DLSequence(new ASN1Encodable[] {Extension.subjectAlternativeName, new DEROctetString(names)});
        acceptedFast(
                pki,
                withBagEntry(
                        pki,
                        certificateShaped(
                                SHA256_WITH_RSA,
                                subject(pki.root),
                                new X500Name("CN=x"),
                                key(pki.leaf),
                                subjectAltName)));
    }

    @Test
    void aBagCertificateWithOneWideRdnStaysCheap() throws Exception {
        // The one SET the shape rule cannot leave out is an RDN's SET OF
        // values, which DER sorts: here 100,000 string values in descending
        // order. BouncyCastle 1.86 encodes each value once and sorts the
        // encodings in N log N; a release that went back to an insertion sort
        // would fail here.
        TestPki pki = TestPki.receipt();
        ASN1EncodableVector values = new ASN1EncodableVector();
        for (int i = 100_000; i > 0; i--) {
            values.add(new DLSequence(new ASN1Encodable[] {BCStyle.CN, new DERUTF8String(String.format("%06d", i))}));
        }
        acceptedFast(
                pki,
                withBagEntry(
                        pki,
                        certificateShaped(
                                SHA256_WITH_RSA, subject(pki.root), new DLSequence(new DLSet(values)), key(pki.leaf))));
    }

    @Test
    void aJwsCertificateWhoseSubjectHoldsNestedSetsIsPassedOverUnconverted() throws Exception {
        // The JWS twin, at the 256 KiB cap: x5c[2], which the pinned anchor
        // stands in for, carries the nested subject, and the JWS verifies.
        TestPki pki = TestPki.jws();
        String leaf = TestPki.b64(pki.leaf.getEncoded());
        String intermediate = TestPki.b64(pki.intermediate.getEncoded());
        String root = TestPki.b64(certificateShaped(
                        SHA256_WITH_RSA,
                        subject(pki.root),
                        cnOf(nestedSets(30, JwsCore.MAX_JWS_BYTES * 9 / 16 - 4096)),
                        key(pki.leaf))
                .getEncoded(ASN1Encoding.DL));
        String jws = pki.signJwsWithHeader(
                "{\"alg\":\"ES256\",\"x5c\":[\"" + leaf + "\",\"" + intermediate + "\",\"" + root + "\"]}", "{}");
        assertTrue(jws.length() <= JwsCore.MAX_JWS_BYTES, "the JWS is over the cap: " + jws.length());
        Verifier verifier = Checks.verifier(pki);

        long best = Long.MAX_VALUE;
        for (int i = 0; i < 2; i++) {
            long start = System.nanoTime();
            Checks.signedData(verifier, jws);
            best = Math.min(best, (System.nanoTime() - start) / 1_000_000);
        }
        assertTrue(best < BOUND_MS, "took " + best + " ms");
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

    @Test
    void aBagEntryLabelledRsaPssWithAHugeSaltIsPassedOverBeforeAnythingIsAllocated() throws Exception {
        // A bag entry that names the root as its issuer reaches the signature
        // check, and its label is as unsigned as the rest of it. Labelled
        // RSASSA-PSS, BouncyCastle allocated an array of saltLength bytes while
        // it built the verifier: with 2,147,483,647 an OutOfMemoryError out of
        // verifyReceipt from a 3.5 KB receipt, with 1,000,000,000 about 1 GB a
        // call and 1 to 32 s. BouncyCastle reads only the low 32 bits, so
        // -3,294,967,296 allocated 1,000,000,000 bytes too, and a bound that
        // compared the whole integer let it through as short. None fits the
        // root's 2048-bit key, so the entry is not signed by the root and the
        // genuine chain decides.
        TestPki pki = TestPki.receipt();
        for (long saltLength : new long[] {Integer.MAX_VALUE, 1_000_000_000, NEGATIVE_SALT}) {
            byte[] receipt = withBagEntry(
                    pki, certificateShaped(pss(saltLength), subject(pki.root), new X500Name("CN=x"), key(pki.leaf)));

            long start = System.nanoTime();
            Checks.receipt(Checks.verifier(pki), receipt);
            assertFast(start);
        }
    }

    @Test
    void aJwsIntermediateLabelledRsaPssWithAHugeSaltIsRefusedBeforeAnythingIsAllocated() throws Exception {
        // The JWS twin: x5c[1] names an RSA root as its issuer, so its
        // signature is checked under the root's key, with the same allocation.
        TestPki jws = TestPki.jws();
        TestPki rsa = TestPki.receipt();
        for (long saltLength : new long[] {Integer.MAX_VALUE, NEGATIVE_SALT}) {
            byte[] intermediate = certificateShaped(
                            pss(saltLength), subject(rsa.root), new X500Name("CN=x"), key(jws.leaf))
                    .getEncoded(ASN1Encoding.DL);
            String token = unsignedJws(jws.leaf.getEncoded(), intermediate, rsa.root.getEncoded());

            long start = System.nanoTime();
            VerificationException e = assertThrows(
                    VerificationException.class, () -> Checks.signedData(Checks.verifier(rsa.root), token));
            assertFast(start);
            assertEquals(Reason.UNTRUSTED_CHAIN, e.reason(), e.getMessage());
            assertEquals("intermediate certificate is not signed by a pinned Apple root", e.getMessage());
        }
    }

    @Test
    void aJwsLeafLabelledRsaPssWithAHugeSaltIsRefusedBeforeAnythingIsAllocated() throws Exception {
        // x5c[1] is a genuine RSA intermediate under the pinned root, which
        // anyone can copy, and x5c[0] names it as the issuer: the leaf's
        // signature is checked under the intermediate's key.
        TestPki jws = TestPki.jws();
        TestPki rsa = TestPki.receipt();
        for (long saltLength : new long[] {Integer.MAX_VALUE, NEGATIVE_SALT}) {
            byte[] leaf = certificateShaped(
                            pss(saltLength), subject(rsa.intermediate), new X500Name("CN=x"), key(jws.leaf))
                    .getEncoded(ASN1Encoding.DL);
            String token = unsignedJws(leaf, rsa.intermediate.getEncoded(), rsa.root.getEncoded());

            long start = System.nanoTime();
            VerificationException e = assertThrows(
                    VerificationException.class, () -> Checks.signedData(Checks.verifier(rsa.root), token));
            assertFast(start);
            assertEquals(Reason.UNTRUSTED_CHAIN, e.reason(), e.getMessage());
            assertEquals("leaf certificate is not signed by the intermediate", e.getMessage());
        }
    }

    @Test
    void aSignerInfoWhoseSignedAttributesHoldNestedSetsIsHashedAsSent() throws Exception {
        // A copy of the genuine SignerInfo, ahead of it, with one more signed
        // attribute: a SEQUENCE of SETs nested 30 deep, just under the cap.
        // BouncyCastle hashed the DER encoding of the signed attributes, which
        // sorts every SET, before the copy's signature failed: 2.8 to 3.4 s a
        // call. It now hashes them as sent, and Apple's SignerInfo decides.
        TestPki pki = TestPki.receipt();
        SignedData genuine = signedData(pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16])));
        SignerInfo signer = SignerInfo.getInstance(genuine.getSignerInfos().getObjectAt(0));
        ASN1EncodableVector attributes = signedAttributes(signer);
        attributes.add(new DLSequence(new ASN1Encodable[] {
            new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1"), new DLSet(nestedSets(30, CAP_DER - 16384))
        }));
        acceptedFast(pki, aheadOfGenuine(genuine, signer, attributes, signer.getDigestEncryptionAlgorithm()));
    }

    @Test
    void aSignerInfoWhoseSignatureParametersHoldNestedSetsIsLeftOut() throws Exception {
        // The copy's signatureAlgorithm parameters hold the nested value, and
        // a CMSAlgorithmProtection attribute names the same label, so
        // BouncyCastle compares the two, sorting both. No signature algorithm
        // defines a SET in its parameters, so the copy is left out unbuilt.
        TestPki pki = TestPki.receipt();
        SignedData genuine = signedData(pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16])));
        SignerInfo signer = SignerInfo.getInstance(genuine.getSignerInfos().getObjectAt(0));
        DLSequence label = new DLSequence(
                new ASN1Encodable[] {PKCSObjectIdentifiers.sha256WithRSAEncryption, nestedSets(30, CAP_DER / 2 - 16384)
                });
        ASN1EncodableVector attributes = signedAttributes(signer);
        attributes.add(new DLSequence(new ASN1Encodable[] {
            PKCSObjectIdentifiers.id_aa_cmsAlgorithmProtect,
            new DLSet(new DLSequence(
                    new ASN1Encodable[] {signer.getDigestAlgorithm(), new DLTaggedObject(false, 1, label)}))
        }));
        acceptedFast(pki, aheadOfGenuine(genuine, signer, attributes, label));
    }

    @Test
    void aSignerInfoWhoseSignatureParametersHoldNestedSetsInAnExternalIsLeftOut() throws Exception {
        // The same with the nested value as an EXTERNAL's data value
        // descriptor: 2.9 to 3.0 s, and the receipt verified, while the walk
        // read only the EXTERNAL's content.
        TestPki pki = TestPki.receipt();
        SignedData genuine = signedData(pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16])));
        SignerInfo signer = SignerInfo.getInstance(genuine.getSignerInfos().getObjectAt(0));
        DLSequence label = new DLSequence(new ASN1Encodable[] {
            PKCSObjectIdentifiers.sha256WithRSAEncryption, external(nestedSets(30, CAP_DER / 2 - 16384))
        });
        ASN1EncodableVector attributes = signedAttributes(signer);
        attributes.add(new DLSequence(new ASN1Encodable[] {
            PKCSObjectIdentifiers.id_aa_cmsAlgorithmProtect,
            new DLSet(new DLSequence(
                    new ASN1Encodable[] {signer.getDigestAlgorithm(), new DLTaggedObject(false, 1, label)}))
        }));
        acceptedFast(pki, aheadOfGenuine(genuine, signer, attributes, label));
    }

    /**
     * An EXTERNAL whose data value descriptor is {@code descriptor} and whose
     * content is {@code [0] NULL}: a SEQUENCE of the two, encoded
     * definite-length and retagged EXTERNAL (0x28), then parsed.
     */
    private static ASN1Primitive external(ASN1Encodable descriptor) throws Exception {
        byte[] encoded = new DLSequence(new ASN1Encodable[] {descriptor, new DLTaggedObject(true, 0, DERNull.INSTANCE)})
                .getEncoded(ASN1Encoding.DL);
        encoded[0] = 0x28;
        return ASN1Primitive.fromByteArray(encoded);
    }

    /**
     * {@code signer}'s signed attributes less its CMSAlgorithmProtection one:
     * with two, BouncyCastle refuses the SignerInfo before it compares any
     * parameters, and a sender builds the copy with one.
     */
    private static ASN1EncodableVector signedAttributes(SignerInfo signer) {
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        for (int i = 0; i < signer.getAuthenticatedAttributes().size(); i++) {
            Attribute attribute =
                    Attribute.getInstance(signer.getAuthenticatedAttributes().getObjectAt(i));
            if (!PKCSObjectIdentifiers.id_aa_cmsAlgorithmProtect.equals(attribute.getAttrType())) {
                attributes.add(attribute);
            }
        }
        return attributes;
    }

    /**
     * {@code genuine} with a copy of {@code signer} carrying {@code attributes}
     * and {@code label} ahead of it, built of definite-length types: the copy's
     * signature is the genuine one, over other bytes, so it fails.
     */
    private static byte[] aheadOfGenuine(
            SignedData genuine, SignerInfo signer, ASN1EncodableVector attributes, ASN1Encodable label)
            throws Exception {
        DLSequence copy = new DLSequence(new ASN1Encodable[] {
            new ASN1Integer(1),
            signer.getSID(),
            signer.getDigestAlgorithm(),
            new DLTaggedObject(false, 0, new DLSet(attributes)),
            label,
            signer.getEncryptedDigest()
        });
        return receipt(genuine, genuine.getCertificates(), new DLSet(new ASN1Encodable[] {copy, signer}));
    }

    /** RSASSA-PSS with SHA-256, MGF1 with SHA-256 and {@code saltLength}. */
    private static AlgorithmIdentifier pss(long saltLength) {
        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        return new AlgorithmIdentifier(
                PKCSObjectIdentifiers.id_RSASSA_PSS,
                new RSASSAPSSparams(
                        sha256,
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha256),
                        new ASN1Integer(saltLength),
                        new ASN1Integer(1)));
    }

    /**
     * A certificate-shaped SEQUENCE, valid from yesterday to tomorrow: a TBS
     * with {@code label}, {@code issuer}, {@code subject}, {@code key} and any
     * {@code extensions}, then {@code label} again and 256 zero octets as the
     * signature. Built of definite-length types, so nothing is sorted while
     * the input is built.
     */
    private static DLSequence certificateShaped(
            ASN1Encodable label,
            ASN1Encodable issuer,
            ASN1Encodable subject,
            ASN1Encodable key,
            ASN1Encodable... extensions) {
        long now = System.currentTimeMillis();
        ASN1EncodableVector tbs = new ASN1EncodableVector();
        tbs.add(new DLTaggedObject(true, 0, new ASN1Integer(2)));
        tbs.add(new ASN1Integer(4242));
        tbs.add(label);
        tbs.add(issuer);
        tbs.add(new DLSequence(new ASN1Encodable[] {
            new DERUTCTime(new Date(now - 86_400_000L)), new DERUTCTime(new Date(now + 86_400_000L))
        }));
        tbs.add(subject);
        tbs.add(key);
        if (extensions.length > 0) {
            tbs.add(new DLTaggedObject(true, 3, new DLSequence(extensions)));
        }
        return new DLSequence(new ASN1Encodable[] {new DLSequence(tbs), label, new DERBitString(new byte[256])});
    }

    /** A name of one CN whose value is {@code value}. */
    private static DLSequence cnOf(ASN1Encodable value) {
        return new DLSequence(new DLSet(new DLSequence(new ASN1Encodable[] {BCStyle.CN, value})));
    }

    /**
     * Verifies {@code receipt} twice and asserts it verifies and the faster
     * call fits the bound, as {@link #refusedFast} does for a refusal.
     */
    private static void acceptedFast(TestPki pki, byte[] receipt) throws Exception {
        long best = Long.MAX_VALUE;
        for (int i = 0; i < 2; i++) {
            long start = System.nanoTime();
            Checks.receipt(Checks.verifier(pki), receipt);
            best = Math.min(best, (System.nanoTime() - start) / 1_000_000);
        }
        assertTrue(best < BOUND_MS, "took " + best + " ms");
    }

    /** {@code pki}'s genuine receipt with {@code entry} added to its certificate bag. */
    private static byte[] withBagEntry(TestPki pki, ASN1Encodable entry) throws Exception {
        SignedData genuine = signedData(pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16])));
        ASN1EncodableVector bag = new ASN1EncodableVector();
        for (int i = 0; i < genuine.getCertificates().size(); i++) {
            bag.add(genuine.getCertificates().getObjectAt(i));
        }
        bag.add(entry);
        return receipt(genuine, new DLSet(bag), genuine.getSignerInfos());
    }

    /** A JWS of the three DER certificates, an empty payload and a signature of zeros. */
    private static String unsignedJws(byte[] leaf, byte[] intermediate, byte[] root) {
        String header = "{\"alg\":\"ES256\",\"x5c\":[\"" + TestPki.b64(leaf) + "\",\"" + TestPki.b64(intermediate)
                + "\",\"" + TestPki.b64(root) + "\"]}";
        return TestPki.b64url(header.getBytes(StandardCharsets.UTF_8)) + "."
                + TestPki.b64url("{}".getBytes(StandardCharsets.UTF_8)) + "."
                + TestPki.b64url(new byte[64]);
    }

    private static X500Name subject(java.security.cert.X509Certificate certificate) {
        return X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
    }

    private static SubjectPublicKeyInfo key(java.security.cert.X509Certificate certificate) {
        return SubjectPublicKeyInfo.getInstance(certificate.getPublicKey().getEncoded());
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
