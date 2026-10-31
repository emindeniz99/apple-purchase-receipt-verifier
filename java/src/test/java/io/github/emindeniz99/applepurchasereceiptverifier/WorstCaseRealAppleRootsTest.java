package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Round five: the same attacks, aimed at Apple's own. Rounds one to four ran
 * every class of forgery against test PKIs minted for the purpose. This one
 * re-aims the classes that target the roots and the walk at the certificates
 * the service actually pins -- {@code Config.defaults()}, the three real
 * Apple Inc. root CAs -- with genuine Apple-signed receipts as the substrate,
 * and reads the verdicts off the verifyReceipt-compatible endpoint.
 *
 * <p>The finding: every class dies before Apple's keys. A signature under a
 * genuine Apple signer certificate is an INVALID_SIGNATURE unless Apple's
 * key made it; a certificate claiming Apple WWDR or Apple root issuance
 * cannot enter the walk at all, because only Apple can vouch under Apple; a
 * stranger CA that vouches a WWDR lookalike -- one with Apple's exact WWDR
 * name -- anchors nothing and is inert junk beside a genuine receipt; and
 * the 2006 Bleichenbacher cube-root forgery has no target among the pins,
 * because Apple's RSA roots all use the exponent 65537 and the third pin is
 * EC, so there is no exponent-3 key to cube a PKCS#1 block into.
 *
 * <p>What the endpoint cannot refuse, and does not try to: a genuine
 * Apple-signed receipt of ANOTHER app. The verifier is app-agnostic by
 * design; bundle id equality, receipt type, transaction and product match
 * and freshness are the wrapper's localOutcome, and each rejection is
 * pinned by the wrapper's own tests
 * ({@code IOSPurchaseServiceLocalVerifyTest}, e.g.
 * {@code otherAppsReceipt_isRejected}).
 */
class WorstCaseRealAppleRootsTest {

    private static final long BUDGET_MS = 2000;
    private static final AtomicLong SERIAL = new AtomicLong(1);
    private static final String SIGNING_LEAF_OID = "1.2.840.113635.100.6.11.1";
    private static final String WWDR_OID = "1.2.840.113635.100.6.2.1";
    private static final String OUR_BUNDLE_ID = "com.example.app";
    private static final Path FIXTURES = TestFixtures.publicReceipts();

    private static Verifier verifier;
    private static CMSSignedData genuine;
    private static X509CertificateHolder genuineSigner;
    private static X509CertificateHolder genuineWwdr;
    private static List<X509CertificateHolder> genuineChain;
    private static final List<X509CertificateHolder> rootHolders = new ArrayList<>();

    private static PrivateKey strangerRootKey;
    private static PrivateKey lookalikeWwdrKey;
    private static PrivateKey strangerLeafKey;
    private static PrivateKey attackerKey;
    private static PublicKey attackerPublic;
    private static X509CertificateHolder strangerRoot;
    private static X509CertificateHolder lookalikeWwdr;
    private static X509CertificateHolder strangerLeaf;

    @BeforeAll
    static void mintTheMaterial() throws Exception {
        // The pins prod uses, and the genuine substrate: a real Apple-signed
        // receipt, its real signer certificate, the WWDR its chain runs
        // through, and the real roots as holders, so every forgery below
        // claims exactly the names Apple actually published.
        verifier = Verifier.create(Config.defaults());
        genuine = new CMSSignedData(Base64.getMimeDecoder().decode(receipt("receipt-sandbox-g5")));
        SignerInformation signerInfo = genuine.getSignerInfos().iterator().next();
        genuineSigner = (X509CertificateHolder) genuine.getCertificates()
                .getMatches(signerInfo.getSID())
                .iterator()
                .next();
        genuineChain = new ArrayList<>(genuine.getCertificates().getMatches(null));
        for (X509Certificate root : AppleRootCerts.roots()) {
            rootHolders.add(new X509CertificateHolder(root.getEncoded()));
        }
        for (X509CertificateHolder holder : genuineChain) {
            for (X509CertificateHolder rootHolder : rootHolders) {
                if (holder.getIssuer().equals(rootHolder.getSubject())
                        && !holder.getSubject().equals(rootHolder.getSubject())) {
                    genuineWwdr = holder;
                }
            }
        }
        assertNotNull(genuineWwdr, "the genuine chain reaches no pinned root");

        // The attacker's PKI: a stranger CA that is not Apple, a WWDR
        // lookalike carrying Apple's exact WWDR name vouched by it, a leaf
        // under the lookalike, and one attacker key that signs receipts and
        // claims Apple's issuance in the other legs.
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair rootKp = rsa.generateKeyPair();
        KeyPair wwdrKp = rsa.generateKeyPair();
        KeyPair leafKp = rsa.generateKeyPair();
        KeyPair attackerKp = rsa.generateKeyPair();
        strangerRootKey = rootKp.getPrivate();
        lookalikeWwdrKey = wwdrKp.getPrivate();
        strangerLeafKey = leafKp.getPrivate();
        attackerKey = attackerKp.getPrivate();
        attackerPublic = attackerKp.getPublic();
        X500Name strangerName = new X500Name("CN=Stranger Root that is not Apple");
        strangerRoot = cert(strangerName, rootKp.getPublic(), strangerName, rootKp.getPrivate(), true, null);
        lookalikeWwdr =
                cert(genuineWwdr.getSubject(), wwdrKp.getPublic(), strangerName, rootKp.getPrivate(), true, WWDR_OID);
        strangerLeaf = cert(
                new X500Name("CN=Stranger Receipt Signer"),
                leafKp.getPublic(),
                genuineWwdr.getSubject(),
                wwdrKp.getPrivate(),
                false,
                SIGNING_LEAF_OID);
    }

    private static String receipt(String name) throws Exception {
        return new String(Files.readAllBytes(FIXTURES.resolve(name + ".b64")), StandardCharsets.US_ASCII).trim();
    }

    /** One refusal: expected reason (one of), inside the budget, message printed. */
    private static void refused(String what, byte[] der, Reason... expected) {
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result =
                verifier.verifyReceipt(Base64.getEncoder().encodeToString(der));
        long ms = (System.nanoTime() - start) / 1_000_000;
        Reason actual = result.verified() ? null : result.failure().reason();
        System.out.println("real " + what + ": " + ms + " ms, "
                + (result.verified()
                        ? "VERIFIED"
                        : actual + " (" + result.failure().message() + ")"));
        assertFalse(result.verified(), what + " verified");
        assertNotNull(actual);
        assertTrue(
                Arrays.asList(expected).contains(actual),
                what + " refused as " + actual + ", expected one of " + Arrays.toString(expected));
        assertTrue(ms < BUDGET_MS, what + " took " + ms + " ms");
    }

    /** One verification against the pins prod uses, inside the budget. */
    private static ReceiptPayload verifies(String what, byte[] der) {
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result =
                verifier.verifyReceipt(Base64.getEncoder().encodeToString(der));
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("real " + what + ": " + ms + " ms, " + result.verified());
        assertTrue(result.verified(), what + " was refused: " + result.failure());
        assertTrue(ms < BUDGET_MS, what + " took " + ms + " ms");
        return result.payload();
    }

    /** The status the verifyReceipt-compatible endpoint answers for this receipt. */
    private static int status(Environment environment, byte[] der) {
        String answer = verifier.verifyReceiptEndpoint(
                environment, "{\"receipt-data\":\"" + Base64.getEncoder().encodeToString(der) + "\"}");
        Matcher found = Pattern.compile("\"status\":(\\d+)").matcher(answer);
        assertTrue(found.find(), "no status in: " + answer.substring(0, Math.min(100, answer.length())));
        return Integer.parseInt(found.group(1));
    }

    /**
     * A payload of another app, created at {@code creationDate}: the instant
     * the chain is judged at.
     */
    private static byte[] payloadAt(String creationDate) throws Exception {
        return TestPki.receiptPayload(
                "com.example.app",
                "1.0",
                new byte[] {1, 2, 3, 4},
                new byte[] {5, 6, 7, 8},
                creationDate,
                Collections.singletonList(TestPki.inAppPurchase(1, "gems.small", "2001", "2001", creationDate, null)));
    }

    private static byte[] payload() throws Exception {
        return payloadAt(Instant.now().truncatedTo(ChronoUnit.SECONDS).toString());
    }

    /**
     * The receipt generator of this suite: a direct-content signature, the
     * form Apple's genuine receipts carry, under any signer certificate the
     * attack wants to claim, with any chain in the bag.
     */
    private static byte[] sign(
            byte[] content, PrivateKey key, X509CertificateHolder signerCert, List<X509CertificateHolder> chain)
            throws Exception {
        JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider(TestPki.BC).build());
        builder.setDirectSignature(true);
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addCertificates(new CollectionStore<>(chain));
        generator.addSignerInfoGenerator(builder.build(genuineSigner(key, "SHA256withRSA"), signerCert));
        return generator
                .generate(new CMSProcessableByteArray(content), true)
                .toASN1Structure()
                .getEncoded("DER");
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
            builder.addExtension(new ASN1ObjectIdentifier(marker), false, ASN1Boolean.TRUE);
        }
        return builder.build(genuineSigner(issuerKey, "SHA256withRSA"));
    }

    /**
     * A certificate claiming an issuance nobody can make: Apple's issuer
     * name, the marker, and garbage where the issuer's signature would be.
     * Whatever claims Apple WWDR or an Apple root issued it has to land in
     * this shape, because Apple's keys are Apple's.
     */
    private static X509CertificateHolder garbageSigned(X500Name subject, PublicKey key, X500Name issuer, String marker)
            throws IOException {
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(issuer, serial(), new Date(), yearOut(), subject, key);
        builder.addExtension(new ASN1ObjectIdentifier(marker), false, ASN1Boolean.TRUE);
        return builder.build(new GarbageSigner());
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

    private static BigInteger serial() {
        return BigInteger.valueOf(SERIAL.getAndIncrement());
    }

    private static Date yearOut() {
        return new Date(System.currentTimeMillis() + 365L * 86_400_000);
    }

    // ------------------------------------------------------------------
    // The baseline: what Apple genuinely signed does, on the pins prod
    // uses, at both endpoints.
    // ------------------------------------------------------------------

    @Test
    void genuineAppStoreReceiptsVerifyAgainstThePinsProdUsesAndMapToApplesEndpointStatuses() throws Exception {
        for (String name : new String[] {"receipt-sandbox-g5", "receipt-sandbox-legacy"}) {
            byte[] der = Base64.getMimeDecoder().decode(receipt(name));
            verifies(name, der);
            assertEquals(AppleStatus.OK, status(Environment.SANDBOX, der), name + " on the sandbox endpoint");
            assertEquals(
                    AppleStatus.SANDBOX_RECEIPT_ON_PRODUCTION,
                    status(Environment.PRODUCTION, der),
                    name + " on the production endpoint");
        }
    }

    @Test
    void applesOwnXcodeSigningChainDoesNotReachThePinsAndIsRefused() throws Exception {
        // The xcode fixture is signed by Apple's own tooling, but it chains
        // to no pinned root: the pins are narrow enough to refuse Apple's
        // own Xcode signing chain, exactly as the fixtures README states
        // the file is there to prove.
        byte[] der = Base64.getMimeDecoder().decode(receipt("receipt-xcode-with-purchases"));
        refused("Apple's own Xcode signing chain", der, Reason.UNTRUSTED_CHAIN);
        assertEquals(AppleStatus.RECEIPT_NOT_AUTHENTICATED, status(Environment.SANDBOX, der));
        assertEquals(AppleStatus.RECEIPT_NOT_AUTHENTICATED, status(Environment.PRODUCTION, der));
    }

    @Test
    void theBleichenbacherCubeRootForgeryHasNoTargetAmongApplesRealPins() {
        // The 2006 forgery needs an exponent-3 RSA key to cube a PKCS#1 v1.5
        // block into. Apple's pins offer it none: every RSA root Apple
        // published uses 65537, and the third pin is not RSA at all.
        boolean sawRsa = false;
        boolean sawEc = false;
        for (X509Certificate root : AppleRootCerts.roots()) {
            PublicKey key = root.getPublicKey();
            if ("EC".equals(key.getAlgorithm())) {
                sawEc = true;
                continue;
            }
            sawRsa = true;
            assertEquals(
                    BigInteger.valueOf(65537),
                    ((RSAPublicKey) key).getPublicExponent(),
                    root.getSubjectX500Principal().getName() + " is an RSA root with an unexpected exponent");
        }
        assertTrue(sawRsa, "expected at least one RSA root among the pins");
        assertTrue(sawEc, "expected the EC root among the pins");
    }

    // ------------------------------------------------------------------
    // Apple's own certificates, an attacker's signature.
    // ------------------------------------------------------------------

    @Test
    void anAttackersSignatureUnderApplesGenuineSignerCertificateIsAnInvalidSignature() throws Exception {
        // The one attack that holds everything real except the key: the
        // genuine signer certificate Apple signed, the genuine WWDR and
        // root in the bag, an honest payload -- and the attacker's own
        // signature where Apple's was. The walk passes over real
        // certificates alone; the signature check ends it. The fixture's
        // genuine leaf expired in August 2026, so the payload's creation
        // date -- the instant the chain is judged at -- sits inside the
        // window Apple signed, or the refusal would come from the window
        // before the signature is even read.
        byte[] transplant = sign(payloadAt("2025-06-01T00:00:00Z"), attackerKey, genuineSigner, genuineChain);
        refused("the genuine signer certificate over an attacker's key", transplant, Reason.INVALID_SIGNATURE);
        assertEquals(AppleStatus.RECEIPT_NOT_AUTHENTICATED, status(Environment.SANDBOX, transplant));
    }

    @Test
    void aLeafForgedUnderApplesRealWwdrIsUntrusted() throws Exception {
        // The strongest forgery against the walk, re-aimed at Apple's real
        // WWDR: a leaf claiming Apple's WWDR issued it, marker and all,
        // with garbage where Apple's signature would be. Only Apple holds
        // the WWDR key, so nothing enters the walk through it.
        X509CertificateHolder forged = garbageSigned(
                new X500Name("CN=Leaf Apple never issued"), attackerPublic, genuineWwdr.getSubject(), SIGNING_LEAF_OID);
        List<X509CertificateHolder> bag = new ArrayList<>();
        bag.add(forged);
        bag.addAll(genuineChain);
        byte[] receipt = sign(payload(), attackerKey, forged, bag);
        refused("a leaf forged under Apple's real WWDR", receipt, Reason.UNTRUSTED_CHAIN);
        assertEquals(AppleStatus.RECEIPT_NOT_AUTHENTICATED, status(Environment.SANDBOX, receipt));
    }

    @Test
    void squattersUnderApplesRealRootDnsAreRefusedByEveryRoot() throws Exception {
        // Every pinned root by name: a signer certificate claiming that
        // root issued it, the receipt signed by the attacker under it.
        // Each leg dies the same way -- nobody can vouch under Apple.
        for (X509CertificateHolder rootHolder : rootHolders) {
            X509CertificateHolder squatter = garbageSigned(
                    new X500Name("CN=Receipt signer Apple never vouched"),
                    attackerPublic,
                    rootHolder.getSubject(),
                    SIGNING_LEAF_OID);
            byte[] receipt = sign(payload(), attackerKey, squatter, Arrays.asList(squatter, rootHolder));
            refused(
                    "a squatter under " + rootHolder.getSubject(),
                    receipt,
                    Reason.UNTRUSTED_CHAIN,
                    Reason.INVALID_CERTIFICATE);
            assertEquals(AppleStatus.RECEIPT_NOT_AUTHENTICATED, status(Environment.SANDBOX, receipt));
        }
    }

    // ------------------------------------------------------------------
    // A stranger CA trying to become an anchor through Apple's names.
    // ------------------------------------------------------------------

    @Test
    void aWwdrLookalikeVouchedByAStrangerRootIsNotAnAnchorAndIsInertJunk() throws Exception {
        // The lookalike carries Apple's exact WWDR name but a stranger
        // CA's vouch, and the leaf under it is genuinely the attacker's.
        // Following the name instead of the signature would anchor the
        // stranger chain; following the signature, as the walk does,
        // leaves it untrusted -- and leaves the lookalike inert junk
        // beside a genuine receipt, whose own chain still verifies.
        byte[] receipt = sign(
                payload(), strangerLeafKey, strangerLeaf, Arrays.asList(strangerLeaf, lookalikeWwdr, strangerRoot));
        refused("a WWDR lookalike vouched by a stranger root", receipt, Reason.UNTRUSTED_CHAIN);
        assertEquals(AppleStatus.RECEIPT_NOT_AUTHENTICATED, status(Environment.SANDBOX, receipt));

        List<X509CertificateHolder> bag = new ArrayList<>(genuineChain);
        bag.add(lookalikeWwdr);
        bag.add(strangerRoot);
        byte[] polluted = CMSSignedData.replaceCertificatesAndCRLs(
                        genuine, new CollectionStore<X509CertificateHolder>(bag), null, null)
                .getEncoded();
        verifies("a genuine receipt with the lookalike in the bag", polluted);
        assertEquals(AppleStatus.OK, status(Environment.SANDBOX, polluted));
    }

    @Test
    void appleRootsThemselvesAsBagJunkAreInert() throws Exception {
        // The roots in the bag only add certificates that already pin
        // themselves; a genuine receipt with all three beside its chain
        // verifies exactly as before.
        List<X509CertificateHolder> bag = new ArrayList<>(genuineChain);
        bag.addAll(rootHolders);
        byte[] polluted = CMSSignedData.replaceCertificatesAndCRLs(
                        genuine, new CollectionStore<X509CertificateHolder>(bag), null, null)
                .getEncoded();
        verifies("a genuine receipt with all three real roots in the bag", polluted);
        assertEquals(AppleStatus.OK, status(Environment.SANDBOX, polluted));
    }

    // ------------------------------------------------------------------
    // The genuine substrate, re-aimed at the endpoint.
    // ------------------------------------------------------------------

    @Test
    void oneTamperedByteInAGenuineReceiptIs21003AtTheEndpoint() throws Exception {
        byte[] der = Base64.getMimeDecoder().decode(receipt("receipt-sandbox-g5"));
        byte[] bundleId = "dev.bonzer.weeka.app".getBytes(StandardCharsets.UTF_8);
        int at = TestPki.indexOf(der, bundleId);
        assertTrue(at > 0, "bundle id not found in the receipt");
        byte[] tampered = der.clone();
        tampered[at + bundleId.length - 1] ^= 0x01;
        refused("one byte of a genuine receipt changed", tampered, Reason.INVALID_SIGNATURE);
        assertEquals(AppleStatus.RECEIPT_NOT_AUTHENTICATED, status(Environment.SANDBOX, tampered));
    }

    @Test
    void aCertificateFloodOnAGenuineReceiptIs21002AtTheEndpoint() throws Exception {
        List<X509CertificateHolder> flood = new ArrayList<>();
        while (flood.size() < 64) {
            flood.addAll(genuineChain);
        }
        byte[] flooded = CMSSignedData.replaceCertificatesAndCRLs(
                        genuine, new CollectionStore<X509CertificateHolder>(flood), null, null)
                .getEncoded();
        refused("64 certificates in a genuine receipt's bag", flooded, Reason.MALFORMED);
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, status(Environment.SANDBOX, flooded));
    }

    // ------------------------------------------------------------------
    // The honest boundary: another app's genuine receipt.
    // ------------------------------------------------------------------

    @Test
    void aGenuineReceiptOfAnotherAppVerifiesAndTheWrapperOwnsTheRefusal() throws Exception {
        // This genuine receipt is Apple's signature on ANOTHER app
        // (dev.bonzer.weeka.app), and it answers 0 on the sandbox
        // endpoint, exactly as Apple's own endpoint would. The verifier
        // is app-agnostic by design; refusing another app's genuine
        // receipt is the wrapper's localOutcome -- LocalOutcome.BUNDLE,
        // pinned by IOSPurchaseServiceLocalVerifyTest.otherAppsReceipt_isRejected.
        byte[] der = Base64.getMimeDecoder().decode(receipt("receipt-sandbox-g5"));
        ReceiptPayload payload = verifies("a genuine receipt of another app", der);
        assertEquals("dev.bonzer.weeka.app", payload.bundleId());
        assertNotEquals(OUR_BUNDLE_ID, payload.bundleId());
        assertEquals(AppleStatus.OK, status(Environment.SANDBOX, der));
    }
}
