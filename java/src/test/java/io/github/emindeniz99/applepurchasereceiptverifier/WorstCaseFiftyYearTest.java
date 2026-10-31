package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.Collections;
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
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
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
 * Round four: the fifty-year catalog. The smoke suite (structure bombs,
 * substitution), the deep suite (marker forgeries, label bombs, huge keys,
 * validity windows) and the catalog suite (e=1 identity forgeries, weak
 * digests, RFC 5280 issuance rules, BERserk, transplants) left whole eras
 * unexecuted. This one walks what the other three did not:
 *
 * <p>1970s RSA: the common-modulus attack (two certificates, one modulus)
 * and the Bleichenbacher 2006 cube-root forgery under an exponent-3 key,
 * rebuilt exactly as published -- a vouched CA whose key nobody holds, a
 * leaf whose "signature" is the integer cube root of a PKCS#1 v1.5 block,
 * garbage after the DigestInfo where a lax parser would stop. Also that a
 * genuinely used exponent-3 chain is not refused for its exponent: cost,
 * not exponent value, is the rule.
 *
 * <p>1990s identity tricks: distinguished-name squatters (an intermediate
 * lookalike, a self-signed root lookalike), SignerIdentifier collisions
 * (a stranger certificate with the genuine signer's issuer and serial),
 * and serial-number abuse (33-byte and zero serials, RFC 5280's 20-octet
 * positive rule).
 *
 * <p>2000s mesh abuse: a mutual cross-signing cycle that reaches no pinned
 * root, and an authenticated twin with the intermediate's own DN, which
 * PKIX must keep distinct from the real one.
 *
 * <p>2010s CMS attribute abuse: injected unsigned attributes (covered by
 * nothing, so they must be read by nobody), a signed messageDigest that
 * names another payload's digest, and a direct-content signature with no
 * signed attributes at all.
 *
 * <p>Eras that cannot be executed here, with the reason: timing, fault and
 * side-channel attacks (the verifier holds no secret -- pins are public
 * certificates); the Bleichenbacher 1998 padding oracle (there is no
 * decryption anywhere in receipt verification); MD5/SHA-1 chosen-prefix
 * forgery (it needs Apple's signing key on colliding material -- under a
 * pinned root, acceptance of weak-digest labels was bounded in round
 * three); replay (the verifier is stateless by design; freshness and
 * transaction dedup are the wrapper's, and its own tests'); quantum
 * (out of scope until Apple migrates receipts); Apple's WWDR key
 * compromise (the catastrophic assumption; the leaked-CA gates of the
 * earlier rounds bound what even that buys); and supply chain
 * substitution (pinned BouncyCastle 1.86 and vendored 0.12.0, with the
 * dependency enforcer banning every other BC artifact).
 */
class WorstCaseFiftyYearTest {

    private static final long BUDGET_MS = 2000;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final AtomicLong SERIAL = new AtomicLong(1);
    private static final BigInteger THREE = BigInteger.valueOf(3);

    private static final String SIGNING_LEAF_OID = "1.2.840.113635.100.6.11.1";
    private static final String WWDR_OID = "1.2.840.113635.100.6.2.1";
    private static final X500Name ROOT_NAME = new X500Name("CN=Fifty Year Fake Apple Root CA");
    private static final X500Name INTER_NAME = new X500Name("CN=Fifty Year Fake Apple WWDR CA");

    private static PrivateKey rootKey;
    private static PrivateKey interKey;
    private static PrivateKey leafKey;
    private static X509Certificate root;
    private static X509CertificateHolder rootHolder;
    private static X509CertificateHolder interHolder;
    private static X509CertificateHolder leafHolder;
    private static Verifier verifier;

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
        rootHolder = cert(ROOT_NAME, rootKp.getPublic(), ROOT_NAME, rootKey, true, null);
        interHolder = cert(INTER_NAME, interKp.getPublic(), ROOT_NAME, rootKey, true, WWDR_OID);
        leafHolder = cert(
                new X500Name("CN=Fifty Year Fake Receipt Signer"), leafKp.getPublic(), INTER_NAME, interKey,
                false, SIGNING_LEAF_OID);
        root = jca(rootHolder);
        verifier = Verifier.create(Config.builder().roots(Collections.singleton(root)).build());
    }

    /** One refusal: expected reason (one of), inside the budget, message printed. */
    private static void refused(String what, String receipt, Reason... expected) {
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(receipt);
        long ms = (System.nanoTime() - start) / 1_000_000;
        Reason actual = result.verified() ? null : result.failure().reason();
        System.out.println("fifty " + what + ": " + ms + " ms, "
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
        System.out.println("fifty " + what + ": " + ms + " ms, " + result.verified());
        assertTrue(result.verified(), what + " was refused: " + result.failure());
        assertTrue(ms < BUDGET_MS, what + " took " + ms + " ms");
    }

    private static byte[] payload() throws Exception {
        String now = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
        return TestPki.receiptPayload(
                "com.example.app", "1.0", new byte[] {1, 2, 3, 4}, new byte[] {5, 6, 7, 8}, now,
                Collections.singletonList(TestPki.inAppPurchase(1, "gems.small", "2001", "2001", now, null)));
    }

    private static byte[] sign(byte[] content, PrivateKey key, String alg, X509CertificateHolder signerCert,
            List<X509CertificateHolder> chain) throws Exception {
        return sign(content, genuineSigner(key, alg), signerCert, chain, false, null, null);
    }

    /**
     * The receipt generator of this suite: any signer, with the knobs the
     * attribute-abuse tests need (direct signature, or custom generators for
     * the signed and unsigned attribute tables).
     */
    private static byte[] sign(byte[] content, ContentSigner signer, X509CertificateHolder signerCert,
            List<X509CertificateHolder> chain, boolean direct, CMSAttributeTableGenerator signedGenerator,
            CMSAttributeTableGenerator unsignedGenerator) throws Exception {
        JcaSignerInfoGeneratorBuilder builder =
                new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder()
                        .setProvider(TestPki.BC).build());
        if (direct) {
            builder.setDirectSignature(true);
        }
        if (signedGenerator != null) {
            builder.setSignedAttributeGenerator(signedGenerator);
        }
        if (unsignedGenerator != null) {
            builder.setUnsignedAttributeGenerator(unsignedGenerator);
        }
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addCertificates(new CollectionStore<>(chain));
        generator.addSignerInfoGenerator(builder.build(signer, signerCert));
        return generator.generate(new CMSProcessableByteArray(content), true)
                .toASN1Structure().getEncoded("DER");
    }

    private static ContentSigner genuineSigner(PrivateKey key, String alg) throws Exception {
        return new JcaContentSignerBuilder(alg).setProvider(TestPki.BC).build(key);
    }

    /** A certificate signed the normal way, with or without the CA role and a marker. */
    private static X509CertificateHolder cert(
            X500Name subject, PublicKey key, X500Name issuer, PrivateKey issuerKey, boolean ca, String marker)
            throws Exception {
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(issuer, serial(), new Date(), yearOut(), subject, key);
        if (ca) {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        }
        if (marker != null) {
            builder.addExtension(new ASN1ObjectIdentifier(marker), false, org.bouncycastle.asn1.ASN1Boolean.TRUE);
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
    // The 2006 Bleichenbacher forgery, rebuilt as published: under an
    // exponent-3 key, a "signature" is the integer cube root of a PKCS#1
    // v1.5 block, with garbage where a lax parser would stop. A strict
    // parser reads the DigestInfo to the last byte and refuses it.
    // ------------------------------------------------------------------

    /** Captures the TBS a certificate builder writes; the signature is garbage. */
    private static final class RecordingSigner implements ContentSigner {
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
            return new byte[256];
        }

        byte[] tbs() {
            return buffer.toByteArray();
        }
    }

    /** Writes garbage as the signature while announcing a SHA-256 RSA label. */
    private static final class GarbageSigner implements ContentSigner {
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
            return new byte[256];
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

    /** An SPKI for an RSA key nobody holds: any modulus, any exponent. */
    private static SubjectPublicKeyInfo rawRsaKey(int bits, BigInteger exponent) throws IOException {
        return rawRsaKey(new BigInteger(bits, RANDOM).setBit(bits - 1).setBit(0), exponent);
    }

    /** Same, with the modulus shared with a key someone does hold. */
    private static SubjectPublicKeyInfo rawRsaKey(BigInteger modulus, BigInteger exponent) throws IOException {
        return new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                new RSAPublicKey(modulus, exponent));
    }

    /** The least cube root as a ceiling, by Newton's method on big integers. */
    private static BigInteger ceilCbrt(BigInteger value) {
        BigInteger x = BigInteger.ONE.shiftLeft(value.bitLength() / 3 + 2);
        while (true) {
            BigInteger next = x.shiftLeft(1)
                    .add(value.divide(x.multiply(x)))
                    .divide(THREE);
            if (next.compareTo(x) >= 0) {
                break;
            }
            x = next;
        }
        while (x.pow(3).compareTo(value) < 0) {
            x = x.add(BigInteger.ONE);
        }
        while (x.pow(3).compareTo(value) > 0
                && x.subtract(BigInteger.ONE).pow(3).compareTo(value) >= 0) {
            x = x.subtract(BigInteger.ONE);
        }
        return x;
    }

    /**
     * A certificate whose signature is the cube root of a PKCS#1 v1.5 block:
     * 00 01 FF..FF 00 DigestInfo, with room after the DigestInfo for the
     * garbage a cube root cannot help producing. The prefix must survive
     * cubing, or the forgery is not the published one and the test fails.
     */
    private static X509CertificateHolder cubeRootCert(X509v3CertificateBuilder builder) {
        RecordingSigner recorder = new RecordingSigner();
        try {
            builder.build(recorder);
            byte[] tbs = recorder.tbs();
            ASN1EncodableVector info = new ASN1EncodableVector();
            info.add(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE));
            info.add(new DEROctetString(sha256(tbs)));
            byte[] digestInfo = new DERSequence(info).getEncoded("DER");
            byte[] prefix = new byte[2 + 25 + 1 + digestInfo.length];
            prefix[1] = 1;
            for (int i = 2; i < 27; i++) {
                prefix[i] = (byte) 0xFF;
            }
            System.arraycopy(digestInfo, 0, prefix, 28, digestInfo.length);
            byte[] block = new byte[256];
            System.arraycopy(prefix, 0, block, 0, prefix.length);
            BigInteger target = new BigInteger(1, block);
            BigInteger root = ceilCbrt(target);
            byte[] cube = root.pow(3).toByteArray();
            byte[] asBlock = new byte[256];
            System.arraycopy(cube, Math.max(0, cube.length - 256),
                    asBlock, Math.max(0, 256 - cube.length), Math.min(256, cube.length));
            byte[] check = Arrays.copyOf(asBlock, prefix.length);
            if (!Arrays.equals(check, prefix)) {
                throw new IllegalStateException("the cube root lost the PKCS#1 prefix");
            }
            byte[] signature = new byte[256];
            byte[] rootBytes = root.toByteArray();
            System.arraycopy(rootBytes, Math.max(0, rootBytes.length - 256),
                    signature, Math.max(0, 256 - rootBytes.length), Math.min(256, rootBytes.length));
            ASN1EncodableVector cert = new ASN1EncodableVector();
            cert.add(ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(tbs)));
            cert.add(sha256RsaLabel());
            cert.add(new DERBitString(signature));
            return new X509CertificateHolder(Certificate.getInstance(new DERSequence(cert)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void bleichenbacherCubeRootForgedChainIsRefused() throws Exception {
        // The published shape: a CA certificate genuinely issued by the
        // pinned intermediate but carrying an exponent-3 key nobody holds,
        // a marker leaf under it whose "signature" is the cube root of a
        // PKCS#1 v1.5 block, and a receipt. The walk dies at the leaf,
        // where the strict parser reads the DigestInfo to the last byte
        // and refuses the garbage after it.
        X509CertificateHolder cubeCa = craftedSubjectCert(
                new X500Name("CN=Cube Root CA"), rawRsaKey(2048, THREE), INTER_NAME, interKey, true,
                WWDR_OID);
        X509v3CertificateBuilder leafBuilder = new X509v3CertificateBuilder(
                new X500Name("CN=Cube Root CA"), serial(), new Date(), yearOut(),
                new X500Name("CN=Cube Root Signer"), rawRsaKey(2048, THREE));
        leafBuilder.addExtension(
                new ASN1ObjectIdentifier(SIGNING_LEAF_OID), false, org.bouncycastle.asn1.ASN1Boolean.TRUE);
        X509CertificateHolder cubeLeaf = cubeRootCert(leafBuilder);
        byte[] receipt = sign(payload(), new GarbageSigner(), cubeLeaf,
                Arrays.asList(cubeLeaf, cubeCa, interHolder, rootHolder), false, null, null);
        refused("bleichenbacher cube-root forged chain", b64(receipt),
                Reason.UNTRUSTED_CHAIN, Reason.INVALID_CERTIFICATE, Reason.INVALID_SIGNATURE);
    }

    @Test
    void genuinelyUsedExponentThreeKeysAreNotRefusedForTheirExponent() throws Exception {
        // The rule is cost, not exponent value: a chain every key of which
        // was genuinely generated and used with e = 3 verifies, because
        // two squarings cost nothing and the signature is real.
        KeyPairGenerator eThree = KeyPairGenerator.getInstance("RSA");
        eThree.initialize(new RSAKeyGenParameterSpec(2048, THREE));
        KeyPair caKp = eThree.generateKeyPair();
        KeyPair leafKp = eThree.generateKeyPair();
        X509CertificateHolder eThreeCa = cert(
                new X500Name("CN=Exponent Three CA"), caKp.getPublic(), INTER_NAME, interKey, true, WWDR_OID);
        X509CertificateHolder eThreeLeaf = cert(
                new X500Name("CN=Exponent Three Signer"), leafKp.getPublic(),
                new X500Name("CN=Exponent Three CA"), caKp.getPrivate(), false, SIGNING_LEAF_OID);
        byte[] receipt = sign(payload(), leafKp.getPrivate(), "SHA256withRSA", eThreeLeaf,
                Arrays.asList(eThreeLeaf, eThreeCa, interHolder, rootHolder));
        verifies("genuinely used exponent-3 chain", b64(receipt));
    }

    @Test
    void sharedModulusSiblingsStayDistinct() throws Exception {
        // The 1978 common-modulus shape: two CA certificates over one
        // modulus, one key held, one not. The walk keys off the exact
        // (modulus, exponent) pair: the held key's authority never signs
        // anything its sibling "issued", and the sibling's garbage-issued
        // leaf refuses. Only a leaked private key would fuse them, and
        // Apple shares no modulus.
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair shared = rsa.generateKeyPair();
        BigInteger modulus =
                ((java.security.interfaces.RSAPublicKey) shared.getPublic()).getModulus();
        X509CertificateHolder caOne = craftedSubjectCert(
                new X500Name("CN=Shared Modulus CA"), rawRsaKey(modulus, BigInteger.valueOf(65537)),
                INTER_NAME, interKey, true, WWDR_OID);
        X509CertificateHolder caTwo = craftedSubjectCert(
                new X500Name("CN=Shared Modulus CA"), rawRsaKey(modulus, BigInteger.valueOf(17)),
                INTER_NAME, interKey, true, WWDR_OID);
        KeyPair leafKp = rsa.generateKeyPair();
        X509CertificateHolder leafOne = cert(
                new X500Name("CN=Shared Modulus Signer"), leafKp.getPublic(),
                new X500Name("CN=Shared Modulus CA"), shared.getPrivate(), false, SIGNING_LEAF_OID);
        byte[] genuine = sign(payload(), leafKp.getPrivate(), "SHA256withRSA", leafOne,
                Arrays.asList(leafOne, caOne, caTwo, interHolder, rootHolder));
        verifies("shared-modulus chain with the held key", b64(genuine));

        X509CertificateHolder siblingLeaf = new X509v3CertificateBuilder(
                new X500Name("CN=Shared Modulus CA"), serial(), new Date(), yearOut(),
                new X500Name("CN=Shared Modulus Sibling Signer"), rawRsaKey(modulus, BigInteger.valueOf(17)))
                .addExtension(new ASN1ObjectIdentifier(SIGNING_LEAF_OID), false,
                        org.bouncycastle.asn1.ASN1Boolean.TRUE)
                .build(new GarbageSigner());
        byte[] forged = sign(payload(), leafKey, "SHA256withRSA", siblingLeaf,
                Arrays.asList(siblingLeaf, caOne, caTwo, interHolder, rootHolder));
        refused("shared-modulus sibling's garbage-issued signer", b64(forged), Reason.UNTRUSTED_CHAIN);
    }

    // ------------------------------------------------------------------
    // 1990s identity tricks: a stranger certificate wearing a real CA's
    // name, or a real signer's SignerIdentifier, or an outlaw serial.
    // ------------------------------------------------------------------

    @Test
    void dnSquattersAreInert() throws Exception {
        // A garbage-signed lookalike of the intermediate (root-issued DN)
        // and a garbage self-signed lookalike of the pinned root itself,
        // both riding in the bag of a genuine receipt: the walk signature
        // check kills both, whatever names they wear.
        X509CertificateHolder interSquatter = new X509v3CertificateBuilder(
                ROOT_NAME, serial(), new Date(), yearOut(), INTER_NAME, rawRsaKey(2048, BigInteger.valueOf(65537)))
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                .addExtension(new ASN1ObjectIdentifier(WWDR_OID), false,
                        org.bouncycastle.asn1.ASN1Boolean.TRUE)
                .build(new GarbageSigner());
        X509CertificateHolder rootSquatter = new X509v3CertificateBuilder(
                ROOT_NAME, serial(), new Date(), yearOut(), ROOT_NAME, rawRsaKey(2048, BigInteger.valueOf(65537)))
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                .build(new GarbageSigner());
        byte[] receipt = sign(payload(), leafKey, "SHA256withRSA", leafHolder,
                Arrays.asList(leafHolder, interHolder, rootHolder, interSquatter, rootSquatter));
        verifies("receipt beside intermediate and root squatters", b64(receipt));

        byte[] asSigner = sign(payload(), leafKey, "SHA256withRSA", interSquatter,
                Arrays.asList(leafHolder, interHolder, rootHolder, interSquatter));
        refused("intermediate squatter as signer", b64(asSigner), Reason.UNTRUSTED_CHAIN);
    }

    @Test
    void sidCollisionWithTheGenuineSignerStillVerifies() throws Exception {
        // A stranger certificate with the genuine signer's exact issuer
        // name and serial, but another key and a garbage signature. Beside
        // the genuine signer it is a second match for the same
        // SignerIdentifier: the genuine one verifies and the stranger's own
        // failure does not sink it. Alone it is the only match, and the
        // walk refuses it.
        X509CertificateHolder sidStranger = new X509v3CertificateBuilder(
                INTER_NAME, leafHolder.getSerialNumber(), new Date(), yearOut(),
                new X500Name("CN=Sid Colliding Signer"), rawRsaKey(2048, BigInteger.valueOf(65537)))
                .addExtension(new ASN1ObjectIdentifier(SIGNING_LEAF_OID), false,
                        org.bouncycastle.asn1.ASN1Boolean.TRUE)
                .build(new GarbageSigner());
        byte[] besideGenuine = sign(payload(), leafKey, "SHA256withRSA", leafHolder,
                Arrays.asList(leafHolder, sidStranger, interHolder, rootHolder));
        verifies("genuine signer beside a sid-colliding stranger", b64(besideGenuine));

        byte[] alone = sign(payload(), leafKey, "SHA256withRSA", leafHolder,
                Arrays.asList(sidStranger, interHolder, rootHolder));
        refused("sid-colliding stranger alone", b64(alone),
                Reason.UNTRUSTED_CHAIN, Reason.MALFORMED);
    }

    @Test
    void outlawSerialsAreHandledSafely() throws Exception {
        // RFC 5280 wants a positive serial of at most 20 octets. A
        // 33-octet serial and a zero serial, each on a garbage-signed
        // stranger: inert as bag junk, refused as the signer, never a
        // crash in the walk.
        BigInteger oversized = new BigInteger(263, RANDOM).setBit(262).setBit(0);
        for (BigInteger serial : Arrays.asList(oversized, BigInteger.ZERO)) {
            String what = (serial.signum() == 0 ? "zero" : "33-byte") + "-serial stranger";
            X509CertificateHolder outlaw;
            try {
                outlaw = new X509v3CertificateBuilder(
                        INTER_NAME, serial, new Date(), yearOut(),
                        new X500Name("CN=Outlaw Serial Signer"), rawRsaKey(2048, BigInteger.valueOf(65537)))
                        .addExtension(new ASN1ObjectIdentifier(SIGNING_LEAF_OID), false,
                                org.bouncycastle.asn1.ASN1Boolean.TRUE)
                        .build(new GarbageSigner());
            } catch (IllegalArgumentException e) {
                System.out.println("fifty " + what + ": the certificate builder refused the serial");
                continue;
            }
            byte[] asSigner = sign(payload(), leafKey, "SHA256withRSA", outlaw,
                    Arrays.asList(leafHolder, interHolder, rootHolder, outlaw));
            refused(what + " as signer", b64(asSigner), Reason.UNTRUSTED_CHAIN);
            byte[] asJunk = sign(payload(), leafKey, "SHA256withRSA", leafHolder,
                    Arrays.asList(leafHolder, interHolder, rootHolder, outlaw));
            verifies(what + " as bag junk", b64(asJunk));
        }
    }

    // ------------------------------------------------------------------
    // 2000s mesh abuse: cycles that reach no pinned root, and an
    // authenticated twin of the intermediate's own name.
    // ------------------------------------------------------------------

    @Test
    void cycleMeshesAndNamedTwinsStayBounded() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair meshAKp = rsa.generateKeyPair();
        KeyPair meshBKp = rsa.generateKeyPair();
        // A and B sign each other: a cycle the walk can enter only from a
        // pinned root, which neither touches, so both are inert however
        // genuine their mutual signatures are.
        X509CertificateHolder meshA = cert(
                new X500Name("CN=Mesh A"), meshAKp.getPublic(), new X500Name("CN=Mesh B"),
                meshBKp.getPrivate(), true, WWDR_OID);
        X509CertificateHolder meshB = cert(
                new X500Name("CN=Mesh B"), meshBKp.getPublic(), new X500Name("CN=Mesh A"),
                meshAKp.getPrivate(), true, WWDR_OID);
        // C is genuinely issued by A, which never authenticates, so the
        // genuine signature under a dead CA is as inert as garbage.
        X509CertificateHolder meshC = cert(
                new X500Name("CN=Mesh C"), rsa.generateKeyPair().getPublic(), new X500Name("CN=Mesh A"),
                meshAKp.getPrivate(), false, SIGNING_LEAF_OID);
        // A genuine root-issued twin of the intermediate's own name: the
        // walk authenticates it too, and PKIX must keep it distinct from
        // the real one on the way to the anchor.
        KeyPair twinKp = rsa.generateKeyPair();
        KeyPair twinLeafKp = rsa.generateKeyPair();
        X509CertificateHolder twin = cert(
                INTER_NAME, twinKp.getPublic(), ROOT_NAME, rootKey, true, WWDR_OID);
        X509CertificateHolder twinLeaf = cert(
                new X500Name("CN=Signer Under The Twin"), twinLeafKp.getPublic(), INTER_NAME,
                twinKp.getPrivate(), false, SIGNING_LEAF_OID);
        byte[] receipt = sign(payload(), leafKey, "SHA256withRSA", leafHolder,
                Arrays.asList(leafHolder, interHolder, twin, twinLeaf, meshA, meshB, meshC, rootHolder));
        verifies("receipt beside cycles and a named twin", b64(receipt));

        byte[] underTwin = sign(payload(), twinLeafKp.getPrivate(), "SHA256withRSA", twinLeaf,
                Arrays.asList(twinLeaf, twin, rootHolder));
        // The twin is root-issued and carries the marker, so a genuine leaf
        // under it verifies: the walk and PKIX judged it exactly as they
        // judge the real intermediate, which is a name collision under a
        // pinned root, not a forgery.
        verifies("genuine leaf under the root-issued twin", b64(underTwin));
    }

    // ------------------------------------------------------------------
    // 2010s CMS attribute abuse: unsigned attributes covered by nothing,
    // a signed messageDigest naming another payload, and a direct
    // signature with no signed attributes at all.
    // ------------------------------------------------------------------

    /** Adds one garbage attribute to the unsigned table; covered by nothing. */
    private static final class GarbageUnsignedGenerator implements CMSAttributeTableGenerator {
        @Override
        public AttributeTable getAttributes(Map parameters) {
            return new AttributeTable(new Attribute(
                    new ASN1ObjectIdentifier("1.2.3.4.98"),
                    new DERSet(new DEROctetString(new byte[] {9, 9, 9, 9}))));
        }
    }

    /** A signed table whose messageDigest names another payload's digest. */
    private static final class MistakenDigestGenerator implements CMSAttributeTableGenerator {
        @Override
        public AttributeTable getAttributes(Map parameters) {
            Object contentType = parameters.get(CMSAttributeTableGenerator.CONTENT_TYPE);
            ASN1EncodableVector table = new ASN1EncodableVector();
            table.add(new Attribute(
                    CMSAttributes.contentType, new DERSet((org.bouncycastle.asn1.ASN1Encodable) contentType)));
            table.add(new Attribute(
                    CMSAttributes.messageDigest,
                    new DERSet(new DEROctetString(sha256(new byte[] {1, 1, 2, 3, 5, 8})))));
            return new AttributeTable(new DERSet(table));
        }
    }

    @Test
    void unsignedAttributesAreInert() throws Exception {
        byte[] receipt = sign(payload(), genuineSigner(leafKey, "SHA256withRSA"), leafHolder,
                Arrays.asList(leafHolder, interHolder, rootHolder), false, null,
                new GarbageUnsignedGenerator());
        verifies("genuine receipt with an injected unsigned attribute", b64(receipt));
    }

    @Test
    void messageDigestMismatchIsRefused() throws Exception {
        // The signature is genuine and covers the attributes as sent, but
        // the signed messageDigest names another payload's digest: the
        // recomputed digest disagrees, and the SignerInfo refuses.
        byte[] receipt = sign(payload(), genuineSigner(leafKey, "SHA256withRSA"), leafHolder,
                Arrays.asList(leafHolder, interHolder, rootHolder), false,
                new MistakenDigestGenerator(), null);
        refused("signed messageDigest naming another payload", b64(receipt),
                Reason.INVALID_SIGNATURE, Reason.MALFORMED);
    }

    @Test
    void directSignatureWithoutAttributesPrintsItsVerdict() throws Exception {
        // RFC 5652 allows signing the content directly with no signed
        // attributes; Apple never does. Whatever the verdict here, it must
        // be fast and never throw, and a genuine signature is behind it
        // either way.
        byte[] receipt = sign(payload(), genuineSigner(leafKey, "SHA256withRSA"), leafHolder,
                Arrays.asList(leafHolder, interHolder, rootHolder), true, null, null);
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(b64(receipt));
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("fifty direct-signature receipt: " + ms + " ms, " + result.verified()
                + (result.verified() ? "" : " " + result.failure()));
        assertTrue(ms < BUDGET_MS, "the direct-signature receipt took " + ms + " ms");
        if (!result.verified()) {
            assertTrue(Arrays.asList(Reason.MALFORMED, Reason.INVALID_SIGNATURE, Reason.UNREADABLE_PAYLOAD)
                    .contains(result.failure().reason()),
                    "direct signature refused as " + result.failure().reason());
        }
    }
}
