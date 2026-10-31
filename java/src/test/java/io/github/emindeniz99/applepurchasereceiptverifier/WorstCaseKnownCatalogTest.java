package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.Collections;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
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
 * Round three: the known-attack catalog. The smoke suite (structure bombs,
 * signer and bag substitution) and the deep suite (marker forgeries, label
 * bombs, huge keys, validity windows) answered whether crafted receipts are
 * refused. This one walks the catalog of classic CMS and X.509 attacks, old
 * (Bleichenbacher exponent forgeries, weak digests, weak keys, RFC 5280
 * issuance rules) and recent (certificate transplants from genuine receipts,
 * key-issuance abuse, nested and detached signatures), ending in a full chain
 * forged with nothing but crafted PKCS#1 blocks, no private key anywhere.
 */
class WorstCaseKnownCatalogTest {

    private static final long BUDGET_MS = 2000;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final AtomicLong SERIAL = new AtomicLong(1);
    private static final Pattern STATUS = Pattern.compile("\"status\":(\\d+)");

    private static final String SIGNING_LEAF_OID = "1.2.840.113635.100.6.11.1";
    private static final String WWDR_OID = "1.2.840.113635.100.6.2.1";
    private static final X500Name ROOT_NAME = new X500Name("CN=Catalog Fake Apple Root CA");
    private static final X500Name INTER_NAME = new X500Name("CN=Catalog Fake Apple WWDR CA");

    private static PrivateKey rootKey;
    private static PrivateKey interKey;
    private static PrivateKey leafKey;
    private static X509Certificate root;
    private static X509CertificateHolder rootHolder;
    private static X509CertificateHolder interHolder;
    private static X509CertificateHolder leafHolder;
    private static Verifier verifier;
    private static TestPki testPki;
    private static Verifier testPkiVerifier;

    @BeforeAll
    static void mintThePki() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair rootKp = rsa.generateKeyPair();
        KeyPair interKp = rsa.generateKeyPair();
        KeyPair leafKp = rsa.generateKeyPair();
        rootKey = rootKp.getPrivate();
        interKey = interKp.getPrivate();
        leafKey = leafKp.getPrivate();
        rootHolder = cert(ROOT_NAME, rootKp.getPublic(), ROOT_NAME, rootKey, true, null, null, -1);
        interHolder = cert(INTER_NAME, interKp.getPublic(), ROOT_NAME, rootKey, true, WWDR_OID, null, -1);
        leafHolder = cert(
                new X500Name("CN=Catalog Fake Receipt Signer"), leafKp.getPublic(), INTER_NAME, interKey, false,
                SIGNING_LEAF_OID, null, -1);
        root = jca(rootHolder);
        verifier = Verifier.create(Config.builder().roots(Collections.singleton(root)).build());
        testPki = TestPki.receipt();
        testPkiVerifier = Verifier.create(Config.builder().roots(Collections.singleton(testPki.root)).build());
    }

    /** One refusal: expected reason (one of), inside the budget, message printed. */
    private static void refused(String what, String receipt, Reason... expected) {
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(receipt);
        long ms = (System.nanoTime() - start) / 1_000_000;
        Reason actual = result.verified() ? null : result.failure().reason();
        System.out.println("catalog " + what + ": " + ms + " ms, "
                + (result.verified() ? "VERIFIED" : actual + " (" + result.failure().message() + ")"));
        assertFalse(result.verified(), what + " verified");
        assertNotNull(actual);
        assertTrue(Arrays.asList(expected).contains(actual),
                what + " refused as " + actual + ", expected one of " + Arrays.toString(expected));
        assertTrue(ms < BUDGET_MS, what + " took " + ms + " ms");
    }

    private static void verifies(String what, String receipt) {
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(receipt);
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("catalog " + what + ": " + ms + " ms, " + result.verified());
        assertTrue(result.verified(), what + " was refused: " + result.failure());
        assertTrue(ms < BUDGET_MS, what + " took " + ms + " ms");
    }

    private static byte[] payload() throws Exception {
        String now = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
        return TestPki.receiptPayload(
                "com.example.app", "1.0", new byte[] {1, 2, 3, 4}, new byte[] {5, 6, 7, 8}, now,
                Collections.singletonList(TestPki.inAppPurchase(1, "gems.small", "2001", "2001", now, null)));
    }

    private static byte[] sign(byte[] payload, PrivateKey key, String alg, X509CertificateHolder signer,
            List<X509CertificateHolder> chain) throws Exception {
        return sign(payload, true, genuineSigner(key, alg), signer, chain);
    }

    /** The receipt generator of this suite: any ContentSigner, so a crafted one. */
    private static byte[] sign(byte[] payload, boolean encapsulate, ContentSigner signer,
            X509CertificateHolder signerCert, List<X509CertificateHolder> chain) throws Exception {
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addCertificates(new CollectionStore<>(chain));
        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider(TestPki.BC).build()).build(signer, signerCert));
        return generator.generate(new CMSProcessableByteArray(payload), encapsulate)
                .toASN1Structure().getEncoded("DER");
    }

    private static ContentSigner genuineSigner(PrivateKey key, String alg) throws Exception {
        return new JcaContentSignerBuilder(alg).setProvider(TestPki.BC).build(key);
    }

    /**
     * A certificate signed the normal way, with knobs the plain builder leaves
     * out: usage restrictions, a path length, an unknown critical extension.
     */
    private static X509CertificateHolder cert(
            X500Name subject, PublicKey key, X500Name issuer, PrivateKey issuerKey, boolean ca, String marker,
            KeyUsage usage, int pathLen) throws Exception {
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(issuer, serial(), new Date(), yearOut(), subject, key);
        if (ca) {
            builder.addExtension(Extension.basicConstraints, true,
                    pathLen >= 0 ? new BasicConstraints(pathLen) : new BasicConstraints(true));
        }
        if (marker != null) {
            builder.addExtension(new ASN1ObjectIdentifier(marker), false, org.bouncycastle.asn1.ASN1Boolean.TRUE);
        }
        if (usage != null) {
            builder.addExtension(Extension.keyUsage, true, usage);
        }
        return builder.build(genuineSigner(issuerKey, "SHA256withRSA"));
    }

    /** A certificate built on a hand-made SPKI, signed the normal way. */
    private static X509CertificateHolder craftedSubjectCert(
            X500Name subject, SubjectPublicKeyInfo spki, X500Name issuer, PrivateKey issuerKey, boolean ca,
            String marker) throws Exception {
        X509v3CertificateBuilder builder =
                new X509v3CertificateBuilder(issuer, serial(), new Date(), yearOut(), subject, spki);
        if (ca) {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        }
        if (marker != null) {
            builder.addExtension(new ASN1ObjectIdentifier(marker), false, org.bouncycastle.asn1.ASN1Boolean.TRUE);
        }
        return builder.build(genuineSigner(issuerKey, "SHA256withRSA"));
    }

    private static X509Certificate jca(X509CertificateHolder holder) throws Exception {
        return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(holder.getEncoded()));
    }

    private static BigInteger serial() {
        return BigInteger.valueOf(SERIAL.getAndIncrement());
    }

    private static Date yearOut() {
        return new Date(System.currentTimeMillis() + 365L * 86_400_000);
    }

    private static String b64(byte[] der) {
        return Base64.getEncoder().encodeToString(der);
    }

    // ------------------------------------------------------------------
    // The textbook forgery: a whole chain signed with nothing but crafted
    // PKCS#1 blocks, no private key anywhere. With e = 1 the RSA operation is
    // the identity, so a signature IS the padded block itself; with a strict
    // verifier the block must still hold exactly the issuer's digest.
    // ------------------------------------------------------------------

    /** Captures the TBS a certificate builder writes; the signature is garbage. */
    private static final class RecordingSigner implements ContentSigner {
        private final AlgorithmIdentifier label;
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        RecordingSigner(AlgorithmIdentifier label) {
            this.label = label;
        }

        byte[] tbs() {
            return buffer.toByteArray();
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return label;
        }

        @Override
        public OutputStream getOutputStream() {
            return buffer;
        }

        @Override
        public byte[] getSignature() {
            return new byte[256];
        }
    }

    /** Signs nothing: answers a crafted PKCS#1 block over whatever was streamed. */
    private static final class CraftingSigner implements ContentSigner {
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return sha256RsaLabel();
        }

        @Override
        public OutputStream getOutputStream() {
            return buffer;
        }

        @Override
        public byte[] getSignature() {
            return craftPkcs1Block(sha256(buffer.toByteArray()));
        }
    }

    private static AlgorithmIdentifier sha256RsaLabel() {
        return new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"), DERNull.INSTANCE);
    }

    private static byte[] sha256(byte[] content) {
        try {
            return MessageDigest.getInstance("SHA-256", TestPki.BC).digest(content);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A PKCS#1 v1.5 block for a 2048-bit key: 00 01 FF.. 00 DigestInfo. */
    private static byte[] craftPkcs1Block(byte[] digest) {
        ASN1EncodableVector info = new ASN1EncodableVector();
        info.add(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE));
        info.add(new DEROctetString(digest));
        byte[] digestInfo;
        try {
            digestInfo = new DERSequence(info).getEncoded("DER");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        byte[] block = new byte[256];
        block[1] = 1;
        for (int i = 2; i < 254 - digestInfo.length + 1; i++) {
            block[i] = (byte) 0xFF;
        }
        System.arraycopy(digestInfo, 0, block, 256 - digestInfo.length, digestInfo.length);
        return block;
    }

    /** A certificate whose signature is a crafted block, not a key's output. */
    private static X509CertificateHolder forgedCert(X509v3CertificateBuilder builder) {
        RecordingSigner recorder = new RecordingSigner(sha256RsaLabel());
        try {
            builder.build(recorder);
            ASN1EncodableVector cert = new ASN1EncodableVector();
            cert.add(ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(recorder.tbs())));
            cert.add(sha256RsaLabel());
            cert.add(new DERBitString(craftPkcs1Block(sha256(recorder.tbs()))));
            return new X509CertificateHolder(
                    Certificate.getInstance(new DERSequence(cert)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** An SPKI for an RSA key nobody holds: any modulus, any exponent. */
    private static SubjectPublicKeyInfo rawRsaKey(int bits, BigInteger exponent) throws IOException {
        BigInteger modulus = new BigInteger(bits, RANDOM).setBit(bits - 1).setBit(0);
        return new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                new RSAPublicKey(modulus, exponent));
    }

    @Test
    void exponentOneCraftedChainCannotForgeAnything() throws Exception {
        // The strongest forge-without-a-key attack: a CA certificate genuinely
        // signed by the pinned intermediate but carrying an e = 1 key, a
        // marker leaf under it, and a receipt, every signature a crafted
        // block. If any layer refuses, the forgery dies there; if none does,
        // the receipt would verify with no private key at all.
        X509CertificateHolder e1Ca = craftedSubjectCert(
                new X500Name("CN=Exponent One CA"), rawRsaKey(2048, BigInteger.ONE), INTER_NAME, interKey, true,
                WWDR_OID);
        X509v3CertificateBuilder leafBuilder = new X509v3CertificateBuilder(
                new X500Name("CN=Exponent One CA"), serial(), new Date(), yearOut(),
                new X500Name("CN=Exponent One Signer"), rawRsaKey(2048, BigInteger.ONE));
        leafBuilder.addExtension(
                new ASN1ObjectIdentifier(SIGNING_LEAF_OID), false, org.bouncycastle.asn1.ASN1Boolean.TRUE);
        X509CertificateHolder e1Leaf = forgedCert(leafBuilder);
        byte[] receipt = sign(payload(), true, new CraftingSigner(), e1Leaf,
                Arrays.asList(e1Leaf, e1Ca, interHolder, rootHolder));
        refused("exponent-1 crafted chain", b64(receipt),
                Reason.MALFORMED, Reason.INVALID_CERTIFICATE, Reason.UNTRUSTED_CHAIN, Reason.INVALID_SIGNATURE,
                Reason.INVALID_CERTIFICATE_PURPOSE);
    }

    @Test
    void weakDigestLabelsAreAcceptedOnlyUnderAPinnedRoot() throws Exception {
        // MD5 and SHA-1 are not on the refused-digest list: they cost no more
        // than SHA-256, and trust comes from the pinned roots, which Apple has
        // never signed an MD5 certificate under. Our own PKI signing with them
        // verifies; a stranger's certificate claiming the label does not.
        for (String alg : new String[] {"MD5withRSA", "SHA1withRSA", "SHA384withRSA", "SHA512withRSA"}) {
            byte[] receipt = sign(payload(), leafKey, alg, leafHolder,
                    Arrays.asList(leafHolder, interHolder, rootHolder));
            verifies(alg + "-signed genuine receipt", b64(receipt));
        }
        SubjectPublicKeyInfo md5Key = rawRsaKey(2048, BigInteger.valueOf(65537));
        X509CertificateHolder md5Leaf = new X509v3CertificateBuilder(
                INTER_NAME, serial(), new Date(), yearOut(), new X500Name("CN=MD5 Labeled Signer"), md5Key)
                .addExtension(new ASN1ObjectIdentifier(SIGNING_LEAF_OID), false,
                        org.bouncycastle.asn1.ASN1Boolean.TRUE)
                .build(new GarbageSigner(
                        new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"), DERNull.INSTANCE)));
        byte[] asSigner = sign(payload(), leafKey, "SHA256withRSA", md5Leaf,
                Arrays.asList(leafHolder, interHolder, rootHolder, md5Leaf));
        refused("md5-labeled stranger as signer", b64(asSigner), Reason.UNTRUSTED_CHAIN);
        byte[] asJunk = sign(payload(), leafKey, "SHA256withRSA", leafHolder,
                Arrays.asList(leafHolder, interHolder, rootHolder, md5Leaf));
        verifies("md5-labeled stranger as bag junk", b64(asJunk));
    }

    @Test
    void hugePublicExponentsCostIsBoundedEvenVouched() throws Exception {
        // The exponent twin of the huge-modulus bomb: a vouched CA with a
        // 20001-bit exponent turns every verification into a modexp with a
        // 20001-step ladder. Only a leaked WWDR key can vouch such a CA.
        BigInteger hugeE = BigInteger.ONE.shiftLeft(20_001).add(BigInteger.ONE);
        X509CertificateHolder hugeECa = craftedSubjectCert(
                new X500Name("CN=Huge Exponent CA"), rawRsaKey(2048, hugeE), INTER_NAME, interKey, true, WWDR_OID);
        X509CertificateHolder namee = new X509v3CertificateBuilder(
                new X500Name("CN=Huge Exponent CA"), serial(), new Date(), yearOut(),
                new X500Name("CN=Huge Exponent Namee"), rawRsaKey(2048, BigInteger.valueOf(65537)))
                .build(new GarbageSigner(sha256RsaLabel()));
        byte[] receipt = sign(payload(), leafKey, "SHA256withRSA", leafHolder,
                Arrays.asList(leafHolder, interHolder, rootHolder, hugeECa, namee));
        verifies("20001-bit-exponent vouched CA", b64(receipt));
    }

    @Test
    void weakModulusKeysAreHandledSafely() throws Exception {
        SubjectPublicKeyInfo smallKey = rawRsaKey(512, BigInteger.valueOf(65537));
        X509CertificateHolder smallSigner = new X509v3CertificateBuilder(
                INTER_NAME, serial(), new Date(), yearOut(), new X500Name("CN=512-bit Signer"), smallKey)
                .addExtension(new ASN1ObjectIdentifier(SIGNING_LEAF_OID), false,
                        org.bouncycastle.asn1.ASN1Boolean.TRUE)
                .build(new GarbageSigner(sha256RsaLabel()));
        byte[] asSigner = sign(payload(), leafKey, "SHA256withRSA", smallSigner,
                Arrays.asList(leafHolder, interHolder, rootHolder, smallSigner));
        refused("512-bit stranger as signer", b64(asSigner), Reason.UNTRUSTED_CHAIN);

        X509CertificateHolder smallCa = craftedSubjectCert(
                new X500Name("CN=512-bit CA"), smallKey, INTER_NAME, interKey, true, WWDR_OID);
        X509CertificateHolder smallNamee = new X509v3CertificateBuilder(
                new X500Name("CN=512-bit CA"), serial(), new Date(), yearOut(),
                new X500Name("CN=512-bit Namee"), rawRsaKey(2048, BigInteger.valueOf(65537)))
                .build(new GarbageSigner(sha256RsaLabel()));
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(b64(sign(
                payload(), leafKey, "SHA256withRSA", leafHolder,
                Arrays.asList(leafHolder, interHolder, rootHolder, smallCa, smallNamee))));
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("catalog 512-bit vouched CA: " + ms + " ms, " + result.verified()
                + (result.verified() ? "" : " " + result.failure()));
        assertTrue(ms < BUDGET_MS, "the 512-bit vouched CA took " + ms + " ms");
    }

    @Test
    void nonRsaSignerKeysCannotVerifyRsaSignatures() throws Exception {
        // An elliptic-curve certificate, genuinely issued by the pinned
        // intermediate, carried as the signer of a receipt the RSA key
        // actually signed: the chain holds, so the refusal must come at the
        // signature, where an EC key cannot check an RSA-style CMS signature.
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ecKp = ec.generateKeyPair();
        X509CertificateHolder ecSigner = cert(
                new X500Name("CN=Elliptic Signer"), ecKp.getPublic(), INTER_NAME, interKey, false,
                SIGNING_LEAF_OID, null, -1);
        byte[] asSigner = sign(payload(), leafKey, "SHA256withRSA", ecSigner,
                Arrays.asList(ecSigner, interHolder, rootHolder));
        refused("elliptic-curve signer", b64(asSigner),
                Reason.INVALID_CERTIFICATE, Reason.UNTRUSTED_CHAIN, Reason.INVALID_SIGNATURE);
        byte[] asJunk = sign(payload(), leafKey, "SHA256withRSA", leafHolder,
                Arrays.asList(leafHolder, interHolder, rootHolder, ecSigner));
        verifies("elliptic-curve stranger as bag junk", b64(asJunk));
    }

    /** Writes garbage as the signature while announcing any TBS label. */
    private static final class GarbageSigner implements ContentSigner {
        private final AlgorithmIdentifier label;
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        GarbageSigner(AlgorithmIdentifier label) {
            this.label = label;
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return label;
        }

        @Override
        public OutputStream getOutputStream() {
            return buffer;
        }

        @Override
        public byte[] getSignature() {
            return new byte[256];
        }
    }

    // ------------------------------------------------------------------
    // RFC 5280 issuance rules: the walk only treats basicConstraints-CA
    // certificates as issuers, and the PKIX builder enforces keyCertSign,
    // path length and unknown critical extensions on the way to the anchor.
    // ------------------------------------------------------------------

    @Test
    void intermediateWithoutKeyCertSignCannotIssue() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair noCertSignKp = rsa.generateKeyPair();
        KeyPair childKp = rsa.generateKeyPair();
        X509CertificateHolder noCertSignInter = cert(
                new X500Name("CN=WWDR No KeyCertSign"), noCertSignKp.getPublic(), ROOT_NAME, rootKey, true,
                WWDR_OID, new KeyUsage(KeyUsage.digitalSignature), -1);
        X509CertificateHolder child = cert(
                new X500Name("CN=Signer Under No KeyCertSign"), childKp.getPublic(),
                new X500Name("CN=WWDR No KeyCertSign"), noCertSignKp.getPrivate(), false, SIGNING_LEAF_OID,
                null, -1);
        byte[] receipt = sign(payload(), childKp.getPrivate(), "SHA256withRSA", child,
                Arrays.asList(child, noCertSignInter, rootHolder));
        refused("intermediate lacking keyCertSign", b64(receipt),
                Reason.UNTRUSTED_CHAIN, Reason.INVALID_CERTIFICATE);
    }

    @Test
    void pathLenConstraintZeroForbidsAnotherIntermediate() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair inter0Kp = rsa.generateKeyPair();
        KeyPair inter2Kp = rsa.generateKeyPair();
        KeyPair leafKp2 = rsa.generateKeyPair();
        X509CertificateHolder inter0 = cert(
                new X500Name("CN=WWDR PathLen Zero"), inter0Kp.getPublic(), ROOT_NAME, rootKey, true,
                WWDR_OID, null, 0);
        X509CertificateHolder inter2 = cert(
                new X500Name("CN=WWDR Deeper Intermediate"), inter2Kp.getPublic(),
                new X500Name("CN=WWDR PathLen Zero"), inter0Kp.getPrivate(), true, WWDR_OID, null, -1);
        X509CertificateHolder deepLeaf = cert(
                new X500Name("CN=Signer Beyond PathLen"), leafKp2.getPublic(),
                new X500Name("CN=WWDR Deeper Intermediate"), inter2Kp.getPrivate(), false, SIGNING_LEAF_OID,
                null, -1);
        byte[] receipt = sign(payload(), leafKp2.getPrivate(), "SHA256withRSA", deepLeaf,
                Arrays.asList(deepLeaf, inter2, inter0, rootHolder));
        refused("chain exceeding pathLen 0", b64(receipt),
                Reason.UNTRUSTED_CHAIN, Reason.INVALID_CERTIFICATE);
    }

    @Test
    void markerLeafCannotIssueCertificates() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair childKp = rsa.generateKeyPair();
        // The signing marker leaf (no basicConstraints) "issues" a marker cert
        // with its own key. The walk must never let an end-entity certificate
        // act as an issuer, whatever it signs.
        X509CertificateHolder child = cert(
                new X500Name("CN=Signer Issued By A Leaf"), childKp.getPublic(),
                new X500Name("CN=Catalog Fake Receipt Signer"), leafKey, false, SIGNING_LEAF_OID, null, -1);
        byte[] receipt = sign(payload(), childKp.getPrivate(), "SHA256withRSA", child,
                Arrays.asList(child, leafHolder, interHolder, rootHolder));
        refused("certificate issued by a leaf", b64(receipt), Reason.UNTRUSTED_CHAIN);
    }

    @Test
    void leafWithoutDigitalSignatureUsageIsPrintedNotAssumed() throws Exception {
        // End-entity keyUsage is not a PKIX path rule; whatever the verdict,
        // it must be fast and never throw.
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair encKp = rsa.generateKeyPair();
        X509CertificateHolder encLeaf = cert(
                new X500Name("CN=KeyEncipherment Only Signer"), encKp.getPublic(), INTER_NAME, interKey,
                false, SIGNING_LEAF_OID, new KeyUsage(KeyUsage.keyEncipherment), -1);
        byte[] receipt = sign(payload(), encKp.getPrivate(), "SHA256withRSA", encLeaf,
                Arrays.asList(encLeaf, interHolder, rootHolder));
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(b64(receipt));
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("catalog keyEncipherment-only leaf: " + ms + " ms, " + result.verified()
                + (result.verified() ? "" : " " + result.failure()));
        assertTrue(ms < BUDGET_MS, "the keyEncipherment-only leaf took " + ms + " ms");
    }

    @Test
    void unknownCriticalExtensionRefusesTheChain() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair weirdKp = rsa.generateKeyPair();
        KeyPair childKp = rsa.generateKeyPair();
        // An intermediate with an unrecognized critical extension: PKIX must
        // refuse to resolve a path through it, however well it is signed.
        X509CertificateHolder weirdCritical = new JcaX509v3CertificateBuilder(
                ROOT_NAME, serial(), new Date(), yearOut(), new X500Name("CN=WWDR Weird Critical"),
                weirdKp.getPublic())
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                .addExtension(new ASN1ObjectIdentifier(WWDR_OID), false, org.bouncycastle.asn1.ASN1Boolean.TRUE)
                .addExtension(new ASN1ObjectIdentifier("1.2.3.4.99"), true, org.bouncycastle.asn1.ASN1Boolean.TRUE)
                .build(genuineSigner(rootKey, "SHA256withRSA"));
        X509CertificateHolder child = cert(
                new X500Name("CN=Signer Under Weird Critical"), childKp.getPublic(),
                new X500Name("CN=WWDR Weird Critical"), weirdKp.getPrivate(), false, SIGNING_LEAF_OID,
                null, -1);
        byte[] receipt = sign(payload(), childKp.getPrivate(), "SHA256withRSA", child,
                Arrays.asList(child, weirdCritical, rootHolder));
        refused("chain through unknown critical extension", b64(receipt),
                Reason.UNTRUSTED_CHAIN, Reason.INVALID_CERTIFICATE);
        byte[] junkReceipt = sign(payload(), leafKey, "SHA256withRSA", leafHolder,
                Arrays.asList(leafHolder, interHolder, rootHolder, weirdCritical));
        verifies("unknown-critical stranger as bag junk", b64(junkReceipt));
    }

    // ------------------------------------------------------------------
    // CMS shape attacks: BER-reencoded certificates, detached signatures
    // without content, nested signed data, transplanting a genuine signer
    // certificate over an attacker's key.
    // ------------------------------------------------------------------

    @Test
    void berEncodedCertificateInBagIsHandledSafely() throws Exception {
        // BERserk: a re-encoded certificate can hash differently from DER,
        // which broke verifiers that hash the re-encoded form. Here the bag
        // entry just has to decode without throwing; either verdict is fine
        // as long as it is fast.
        byte[] berInter = interHolder.toASN1Structure().getEncoded(ASN1Encoding.BER);
        X509CertificateHolder berHolder = new X509CertificateHolder(
                Certificate.getInstance(ASN1Primitive.fromByteArray(berInter)));
        byte[] asJunk = sign(payload(), leafKey, "SHA256withRSA", leafHolder,
                Arrays.asList(leafHolder, interHolder, rootHolder, berHolder));
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(b64(asJunk));
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("catalog ber-reencoded bag certificate: " + ms + " ms, " + result.verified()
                + (result.verified() ? "" : " " + result.failure()));
        assertTrue(ms < BUDGET_MS, "the BER bag certificate took " + ms + " ms");
    }

    @Test
    void detachedSignatureWithoutContentIsRefused() throws Exception {
        byte[] detached = sign(payload(), false, genuineSigner(leafKey, "SHA256withRSA"), leafHolder,
                Arrays.asList(leafHolder, interHolder, rootHolder));
        refused("detached signature with no content", b64(detached),
                Reason.MALFORMED, Reason.INVALID_SIGNATURE, Reason.UNREADABLE_PAYLOAD);
    }

    @Test
    void nestedSignedDataIsRefused() throws Exception {
        byte[] inner = sign(payload(), leafKey, "SHA256withRSA", leafHolder,
                Arrays.asList(leafHolder, interHolder, rootHolder));
        // The outer signature is genuine, but the payload it signs is another
        // SignedData, not a receipt: the payload walker sees a ContentInfo
        // SEQUENCE where every attribute must be a tagged SET.
        byte[] nested = sign(inner, leafKey, "SHA256withRSA", leafHolder,
                Arrays.asList(leafHolder, interHolder, rootHolder));
        refused("nested signed data", b64(nested), Reason.UNREADABLE_PAYLOAD);
        assertEquals(AppleStatus.INTERNAL_DATA_ACCESS_ERROR, endpointStatusOf(b64(nested)));
    }

    @Test
    void genuineSignerCertTransplantedOntoAnAttackersKey() throws Exception {
        // A stranger lifts the genuine signer certificate out of a real
        // receipt (public data) and presents it as the signer of a receipt
        // signed with the attacker's own key.
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair strangerKp = rsa.generateKeyPair();
        byte[] receipt = sign(payload(), strangerKp.getPrivate(), "SHA256withRSA", leafHolder,
                Arrays.asList(leafHolder, interHolder, rootHolder));
        refused("genuine signer cert on a stranger key", b64(receipt), Reason.INVALID_SIGNATURE);
    }

    @Test
    void undecodableInAppPurchaseAnswersApples21009() throws Exception {
        // AppStoreSignedDataLost: Apple genuinely signed a receipt whose
        // in-app purchase does not decode. The decode is lenient, as Apple's
        // is: the purchase is kept raw and the receipt verifies with an
        // in_app that lacks it. The endpoint refuses exactly that, 21009,
        // rather than answering 0 for a receipt whose in_app silently lost
        // a purchase Apple signed.
        String now = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
        byte[] undecodable = TestPki.receiptPayload(
                "com.example.app", "1.0", new byte[] {1, 2, 3, 4}, new byte[] {5, 6, 7, 8}, now,
                Collections.singletonList(new byte[] {(byte) 0x30, (byte) 0x03, (byte) 0x17, 0x01, (byte) 0xFF}));
        String receipt = b64(testPki.signReceipt(undecodable));
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result = testPkiVerifier.verifyReceipt(receipt);
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("catalog undecodable in-app purchase: " + ms + " ms, " + result.verified());
        assertTrue(result.verified(), "a lenient decode refused the receipt: " + result.failure());
        assertTrue(result.payload().inApp().isEmpty(), "the undecodable purchase parsed anyway");
        assertTrue(result.payload().hasUnknownAttribute(ReceiptDecoder.ATTR_IN_APP),
                "the undecodable purchase was not kept raw");
        assertEquals(AppleStatus.INTERNAL_DATA_ACCESS_ERROR, endpointStatus(receipt));
        assertTrue(ms < BUDGET_MS, "the undecodable in-app purchase took " + ms + " ms");
    }

    @Test
    void garbageAndEmptyCreationDatesAreHandledGracefully() throws Exception {
        // Apple's ASN.1 writes dates as RFC 3339 strings and "not set" as an
        // empty string. A garbage string Apple somehow signed is kept raw
        // and the receipt is judged at the clock; the empty string reads as
        // not set the same way. Neither may throw, and only the in-app
        // attribute's unknowns gate the endpoint's 21009, so both answer 0.
        byte[] garbageDate = TestPki.receiptPayload(
                "com.example.app", "1.0", new byte[] {1, 2, 3, 4}, new byte[] {5, 6, 7, 8}, "not-a-date",
                Collections.singletonList(TestPki.inAppPurchase(1, "gems.small", "2001", "2001", "not-a-date", null)));
        String garbage = b64(testPki.signReceipt(garbageDate));
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result = testPkiVerifier.verifyReceipt(garbage);
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("catalog garbage creation dates: " + ms + " ms, " + result.verified());
        assertTrue(result.verified(), "a garbage creation date refused the receipt: " + result.failure());
        assertTrue(result.payload().receiptCreationDateMs() == null,
                "a garbage creation date was read as a date");
        assertEquals(AppleStatus.OK, endpointStatus(garbage));

        byte[] emptyDate = TestPki.receiptPayload(
                "com.example.app", "1.0", new byte[] {1, 2, 3, 4}, new byte[] {5, 6, 7, 8}, "",
                Collections.singletonList(TestPki.inAppPurchase(1, "gems.small", "2001", "2001", "", null)));
        String empty = b64(testPki.signReceipt(emptyDate));
        start = System.nanoTime();
        result = testPkiVerifier.verifyReceipt(empty);
        ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("catalog empty creation dates: " + ms + " ms, " + result.verified()
                + ", unknown attribute types " + result.payload().unknownAttributes().keySet());
        assertTrue(result.verified(), "an empty creation date refused the receipt: " + result.failure());
        assertTrue(result.payload().receiptCreationDateMs() == null,
                "an empty creation date was read as a date");
        assertFalse(result.payload().hasUnknownAttribute(12), "an empty creation date was kept raw");
        assertFalse(result.payload().hasUnknownAttribute(18), "an empty purchase date was kept raw");
        assertEquals(AppleStatus.OK, endpointStatus(empty));
        assertTrue(ms < BUDGET_MS, "the creation-date battery took " + ms + " ms");
    }

    @Test
    void weirdSerialsAreHandledSafely() throws Exception {
        // RFC 5280 wants positive serials of at most 20 octets. A negative
        // or oversized serial on a stranger certificate must be refused (or
        // passed over) fast, never crash the walk.
        SubjectPublicKeyInfo serialKey = rawRsaKey(2048, BigInteger.valueOf(65537));
        X509CertificateHolder negativeSerial = new X509v3CertificateBuilder(
                INTER_NAME, BigInteger.valueOf(-1), new Date(), yearOut(),
                new X500Name("CN=Negative Serial Signer"), serialKey)
                .addExtension(new ASN1ObjectIdentifier(SIGNING_LEAF_OID), false,
                        org.bouncycastle.asn1.ASN1Boolean.TRUE)
                .build(new GarbageSigner(sha256RsaLabel()));
        byte[] negativeAsSigner = sign(payload(), leafKey, "SHA256withRSA", negativeSerial,
                Arrays.asList(leafHolder, interHolder, rootHolder, negativeSerial));
        refused("negative-serial stranger as signer", b64(negativeAsSigner), Reason.UNTRUSTED_CHAIN);
        byte[] negativeAsJunk = sign(payload(), leafKey, "SHA256withRSA", leafHolder,
                Arrays.asList(leafHolder, interHolder, rootHolder, negativeSerial));
        verifies("negative-serial stranger as bag junk", b64(negativeAsJunk));
    }

    @Test
    void spkiParametersHoldingSetsArePassedOver() throws Exception {
        // The pre-trust screen passes over certificates whose SPKI or
        // signature parameters hold a SET (PCC vs DER divergence class):
        // as a signer that reads as not embedded; as junk it is skipped.
        ASN1ObjectIdentifier rsaOid = PKCSObjectIdentifiers.rsaEncryption;
        SubjectPublicKeyInfo setParams = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(rsaOid, new DERSet(new ASN1ObjectIdentifier("1.2.3.4.5"))),
                new RSAPublicKey(BigInteger.probablePrime(2048, RANDOM), BigInteger.valueOf(65537)));
        X509CertificateHolder setParamsSigner = new X509v3CertificateBuilder(
                INTER_NAME, serial(), new Date(), yearOut(), new X500Name("CN=Set Params Signer"), setParams)
                .addExtension(new ASN1ObjectIdentifier(SIGNING_LEAF_OID), false,
                        org.bouncycastle.asn1.ASN1Boolean.TRUE)
                .build(new GarbageSigner(sha256RsaLabel()));
        byte[] asSigner = sign(payload(), leafKey, "SHA256withRSA", setParamsSigner,
                Arrays.asList(leafHolder, interHolder, rootHolder, setParamsSigner));
        refused("set-params stranger as signer", b64(asSigner), Reason.MALFORMED, Reason.UNTRUSTED_CHAIN);
        byte[] asJunk = sign(payload(), leafKey, "SHA256withRSA", leafHolder,
                Arrays.asList(leafHolder, interHolder, rootHolder, setParamsSigner));
        verifies("set-params stranger as bag junk", b64(asJunk));
    }

    // ------------------------------------------------------------------
    // Endpoint plumbing: the endpoint answers of both pinned verifiers, so
    // statuses stay pinned where Apple has a documented answer.
    // ------------------------------------------------------------------

    private static int endpointStatusOf(String receipt) {
        return statusOf(verifier.verifyReceiptEndpoint(
                Environment.SANDBOX, "{\"receipt-data\":\"" + jsonEscaped(receipt) + "\"}"));
    }

    private static int endpointStatus(String receipt) {
        return statusOf(testPkiVerifier.verifyReceiptEndpoint(
                Environment.SANDBOX, "{\"receipt-data\":\"" + jsonEscaped(receipt) + "\"}"));
    }

    private static int statusOf(String answer) {
        Matcher status = STATUS.matcher(answer);
        assertTrue(status.find(), "the endpoint answered no status: "
                + answer.substring(0, Math.min(100, answer.length())));
        return Integer.parseInt(status.group(1));
    }

    private static String jsonEscaped(String s) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' || c == '"') {
                out.append('\\').append(c);
            } else if (c < 0x20) {
                out.append(String.format("\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
