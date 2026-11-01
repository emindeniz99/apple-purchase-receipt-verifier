package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
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
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
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
import org.junit.jupiter.api.Test;

/**
 * The measured cost envelope of the denial-of-service surface, printed and
 * pinned near today's numbers rather than at the generous bound the attack
 * suites use.
 *
 * <p>{@link UnauthenticatedKeyCostTest} and {@link DigestDenylistCostTest}
 * bound every attack class at 2,000 ms so a slow CI runner does not fail
 * them, which is right for what they guard against — the classes they
 * regress were one to two orders of magnitude slower — but that bound would
 * also pass an input several times slower than anything measured since. This
 * suite pins the two numbers a single-shot bound cannot give: what the
 * longest request we actually serve costs, and that a sustained burst of
 * hostile receipts does not degrade as it runs. Every bound here stays
 * loose enough for a slow CI runner and tight enough to fail an input of
 * the class the attack suites guard against, one to two orders of
 * magnitude slower than anything measured since.</p>
 *
 * <p>The longest request is a genuine receipt at Apple's own cap: 2,359,296
 * bytes of DER, a real receipt with 2,300 real purchases — the most a
 * well-formed input can cost, and the number a capacity plan needs. The
 * worst shape, not the worst size, is the same cap spent on the smallest
 * TLVs DER can build, a tree of SETs nested to the parser's own depth
 * bound: its parse, and nothing cryptographic, is the most a hostile
 * input can still cost. Everything beyond that is refused before the
 * work that used to make it expensive; the historic 14-second huge-key
 * receipt is measured again here beside its genuine chain, and a burst
 * of 200 distinct tampered receipts holds its per-item cost flat from
 * the first fifty to the last.</p>
 */
class WorstCaseDosCostTest {

    private static final String BUNDLE = "com.example.app";

    /** The largest receipt DER whose base64 fits the cap. */
    private static final int CAP_DER = ReceiptCore.MAX_RECEIPT_BYTES / 4 * 3;

    /** Apple's receipt-signing marker, as the genuine chain's signer carries it. */
    private static final String SIGNING_LEAF = "1.2.840.113635.100.6.11.1";

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final BigInteger SMALL_PRIMES = smallPrimes();

    // ------------------------------------------------------------------
    // the envelope
    // ------------------------------------------------------------------

    @Test
    void genuineTrafficVerifiesInMilliseconds() throws Exception {
        Verifier verifier = Checks.verifier(SyntheticReceipts.pki());
        String receipt = SyntheticReceipts.base64();
        ReceiptPayload verified = Checks.receipt(verifier, receipt);
        assertEquals(BUNDLE, verified.bundleId());

        long best = Long.MAX_VALUE;
        for (int i = 0; i < 3; i++) {
            long start = System.nanoTime();
            Checks.receipt(verifier, receipt);
            best = Math.min(best, (System.nanoTime() - start) / 1_000_000);
        }
        System.out.println("genuine receipt verify: " + best + " ms");
        assertTrue(best < 200, "took " + best + " ms");
    }

    /**
     * The longest thing we serve: a genuine, correctly signed receipt whose
     * DER is exactly the cap Apple's own endpoint accepts. Every byte of it
     * is payload a client is owed — 2,300 in-app purchases — so nothing here
     * may be skipped, and the cost is the honest floor any well-formed input
     * can reach. A hostile input cannot cost more: anything larger is
     * refused for its size before a byte of it is parsed.
     */
    @Test
    void theLongestRequestWeServeIsAGenuineReceiptAtTheCapAndItVerifiesQuickly() throws Exception {
        TestPki pki = SyntheticReceipts.pki();
        byte[] der = LargeReceiptFixture.exactSize(pki, "dos-envelope", ReceiptCore.MAX_RECEIPT_BYTES / 4 * 3);
        String receipt = Base64.getEncoder().encodeToString(der);
        assertEquals(ReceiptCore.MAX_RECEIPT_BYTES, receipt.length());
        Verifier verifier = Checks.verifier(pki);

        long best = Long.MAX_VALUE;
        for (int i = 0; i < 2; i++) {
            long start = System.nanoTime();
            assertEquals(BUNDLE, Checks.receipt(verifier, receipt).bundleId());
            best = Math.min(best, (System.nanoTime() - start) / 1_000_000);
        }
        System.out.println("genuine receipt at Apple's cap (2,359,296 B of DER): " + best + " ms");
        assertTrue(best < 2500, "took " + best + " ms");
    }

    @Test
    void anEndpointBodyAtTheCapAnswersNearTheCostOfTheReceiptItCarries() throws Exception {
        Verifier verifier = Checks.verifier(SyntheticReceipts.pki());
        int fixed = requestJson(null).length() + ",\"padding\":\"\"".length();
        String body = requestJson(twoBytePadding(Endpoint.MAX_REQUEST_BYTES - fixed));
        assertEquals(Endpoint.MAX_REQUEST_BYTES, body.getBytes(StandardCharsets.UTF_8).length);

        String expected = verifier.verifyReceiptEndpoint(Environment.SANDBOX, requestJson(null));
        assertTrue(expected.startsWith("{\"status\":0,"), expected);

        long start = System.nanoTime();
        String answer = verifier.verifyReceiptEndpoint(Environment.SANDBOX, body);
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("endpoint body at the 3,145,728-byte cap: " + ms + " ms");
        assertTrue(answer.startsWith("{\"status\":0,"), answer);
        assertTrue(ms < 700, "took " + ms + " ms");
    }

    /**
     * The historic 14-second attack, measured again: eight strangers
     * masquerading as the intermediate, each with a fresh 16,384-bit
     * modulus, embedded beside the genuine chain of the receipt they ride
     * on. Before the fix each key cost over a second of primality testing as
     * it was decoded; now a key is decoded only after a pinned root has
     * vouched for its certificate, so none of the eight is ever decoded and
     * the receipt still verifies, quickly.
     */
    @Test
    void theHistoricFourteenSecondHugeKeyAttackNowVerifiesInMilliseconds() throws Exception {
        TestPki pki = TestPki.receipt();
        KeyPair attacker = rsa2048();
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
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("genuine receipt beside eight 16,384-bit strangers: " + ms + " ms");
        assertEquals(BUNDLE, verified.bundleId());
        assertTrue(ms < 500, "took " + ms + " ms");
    }

    /**
     * The worst shape, not the worst size: the flat cap-sized receipt above
     * is 2,359,296 bytes of a few thousand TLVs; this one is the same
     * 2,359,296 bytes spent on the smallest TLVs DER can build, chains of
     * SETs nested as deep as anything is, tens of thousands of nodes. Every
     * node is walked before the entry is refused as no certificate, and
     * that walk — parse work, nothing cryptographic — is the most a
     * hostile input can still cost. The cost grows linearly in the nesting
     * depth, and BouncyCastle's own parser refuses anything nested deeper
     * than 64 constructed levels (ASN1Exception, sub-millisecond even for
     * a 100,000-deep blob), so the depth a receipt can carry is bounded by
     * the parser itself: a 59-deep chain plus the receipt's own levels
     * around it is the deepest the parser accepts, and this test builds
     * exactly that. The classes this same shape used to reach, the DER
     * re-encode of these SETs at 3.1 s and the 4.1 to 4.7 s subjects they
     * were carried in, are refused before any of that work runs, and the
     * cost suite holds each at its bound; this test prints what the walk
     * itself costs.
     */
    @Test
    void theWorstShapedReceiptRefusesAtTheCostOfItsParse() throws Exception {
        TestPki pki = TestPki.receipt();
        SignedData genuine = signedData(pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16])));
        ASN1EncodableVector bag = new ASN1EncodableVector();
        for (int i = 0; i < genuine.getCertificates().size(); i++) {
            bag.add(genuine.getCertificates().getObjectAt(i));
        }
        bag.add(nestedSets(59, CAP_DER - 16384));
        byte[] receipt = receipt(genuine, new DLSet(bag), genuine.getSignerInfos());

        long best = Long.MAX_VALUE;
        VerificationException refused = null;
        for (int i = 0; i < 2; i++) {
            long start = System.nanoTime();
            refused = assertThrows(VerificationException.class, () -> Checks.receipt(Checks.verifier(pki), receipt));
            best = Math.min(best, (System.nanoTime() - start) / 1_000_000);
        }
        System.out.println("worst shape, the cap in nested SETs (parse floor): " + best + " ms");
        assertEquals(Reason.MALFORMED, refused.reason(), refused.getMessage());
        assertEquals("an embedded certificate is not a valid certificate", refused.getMessage());
        assertTrue(best < 2000, "took " + best + " ms");
    }

    // ------------------------------------------------------------------
    // the real pins
    // ------------------------------------------------------------------

    /**
     * The worst shape under Apple's own pins, the exact set prod verifies
     * against: the genuine g5 chain beside the same cap-sized nested-SET
     * tree as the test above, nested to the parser's own depth bound. The
     * pins change nothing about its cost — the tree is refused as no
     * certificate before any pin's work — but the number belongs with the
     * pins a capacity plan plans for.
     */
    @Test
    void theWorstShapeUnderApplesOwnPinsIsStillTheParseFloor() throws Exception {
        Verifier verifier = Verifier.create(Config.defaults());
        SignedData genuine = signedData(g5Der());
        ASN1EncodableVector bag = new ASN1EncodableVector();
        for (int i = 0; i < genuine.getCertificates().size(); i++) {
            bag.add(genuine.getCertificates().getObjectAt(i));
        }
        bag.add(nestedSets(59, CAP_DER - 16384));
        byte[] receipt = receipt(genuine, new DLSet(bag), genuine.getSignerInfos());

        long best = Long.MAX_VALUE;
        VerificationException refused = null;
        for (int i = 0; i < 2; i++) {
            long start = System.nanoTime();
            refused = assertThrows(VerificationException.class, () -> Checks.receipt(verifier, receipt));
            best = Math.min(best, (System.nanoTime() - start) / 1_000_000);
        }
        System.out.println("worst shape under Apple's own pins: " + best + " ms");
        assertEquals(Reason.MALFORMED, refused.reason(), refused.getMessage());
        assertEquals("an embedded certificate is not a valid certificate", refused.getMessage());
        assertTrue(best < 2000, "took " + best + " ms");
    }

    /**
     * The deepest work an input can reach under Apple's own pins. A
     * SignerInfo's name is public — anyone can copy the genuine one out of
     * any real receipt — and without a count cap a hostile receipt could
     * carry thousands of copies, each digesting the whole cap-sized content
     * before its own failure: seconds. The verifier walks at most
     * {@link ReceiptCore#MAX_SIGNER_INFOS}, and each copy here reaches the
     * full pipeline against the real pins: the real chain built against the
     * pinned anchor at a date the real leaf was valid, Apple's markers
     * checked, the cap-sized content digested and the signature compared
     * under Apple's own key. All four fail on content they were not signed
     * over, in milliseconds.
     */
    @Test
    void fourCopiesOfApplesGenuineSignerAtTheCapCostMillisecondsUnderApplesOwnPins() throws Exception {
        Verifier verifier = Verifier.create(Config.defaults());
        SignedData genuine = signedData(g5Der());
        ASN1Encodable signer = genuine.getSignerInfos().getObjectAt(0);
        StringBuilder productId = new StringBuilder(BUNDLE);
        while (productId.length() < CAP_DER - 16384) {
            productId.append('x');
        }
        byte[] content = TestPki.receiptPayload(
                BUNDLE,
                "1.0",
                new byte[] {1, 2, 3, 4},
                new byte[20],
                "2025-06-01T00:00:00Z",
                Collections.singletonList(TestPki.inAppPurchase(
                        1, productId.toString(), "70000000000001", "70000000000001", "2024-01-15T12:00:00Z", null)));
        ASN1EncodableVector signers = new ASN1EncodableVector();
        for (int i = 0; i < ReceiptCore.MAX_SIGNER_INFOS; i++) {
            signers.add(signer);
        }
        byte[] receipt = receipt(genuine, genuine.getCertificates(), content, new DLSet(signers));

        long best = Long.MAX_VALUE;
        VerificationException refused = null;
        for (int i = 0; i < 2; i++) {
            long start = System.nanoTime();
            refused = assertThrows(VerificationException.class, () -> Checks.receipt(verifier, receipt));
            best = Math.min(best, (System.nanoTime() - start) / 1_000_000);
        }
        System.out.println("four genuine Apple signers over cap-sized content: " + best + " ms");
        assertEquals(Reason.INVALID_SIGNATURE, refused.reason(), refused.getMessage());
        assertTrue(best < 500, "took " + best + " ms");
    }

    // ------------------------------------------------------------------
    // the burst
    // ------------------------------------------------------------------

    /**
     * A sustained attack, not a single shot: 200 distinct tampered receipts,
     * each one a different byte of the same genuine payload changed, so no
     * cache or shortcut can answer for another. Every one is refused only
     * after its content is digested and its signature compared — the most
     * expensive honest refusal — and the cost per item must hold flat from
     * the first fifty to the last: a per-request cost that grows with what
     * ran before it, a leak, an unbounded cache, would show up here as the
     * average of the whole burst rising past the average of its beginning.
     */
    @Test
    void aSustainedBurstOfDistinctTamperedReceiptsStaysFlat() throws Exception {
        Verifier verifier = Checks.verifier(SyntheticReceipts.pki());
        byte[] der = SyntheticReceipts.der();
        byte[] product = (BUNDLE + ".vip").getBytes(StandardCharsets.US_ASCII);

        for (int i = 0; i < 5; i++) {
            final int seed = i;
            assertThrows(VerificationException.class, () -> Checks.receipt(verifier, tampered(der, product, seed)));
        }

        long first = 0;
        long total = 0;
        long worst = 0;
        for (int i = 0; i < 200; i++) {
            String receipt = Base64.getEncoder().encodeToString(tampered(der, product, i));
            long start = System.nanoTime();
            VerificationException e =
                    assertThrows(VerificationException.class, () -> Checks.receipt(verifier, receipt));
            long ms = (System.nanoTime() - start) / 1_000_000;
            assertEquals(Reason.INVALID_SIGNATURE, e.reason(), "item " + i + ": " + e.getMessage());
            if (i < 50) {
                first += ms;
            }
            total += ms;
            worst = Math.max(worst, ms);
        }
        System.out.println("200 distinct tampered receipts: first 50 avg " + first / 50.0 + " ms, all avg "
                + total / 200.0 + " ms, worst " + worst + " ms");
        assertTrue(worst < 600, "an item took " + worst + " ms");
        assertTrue(total / 200 < 250, "the average rose to " + total / 200 + " ms");
        assertTrue(
                total / 200 < 3 * (first / 50) + 100,
                "the burst degraded: first 50 avg " + first / 50 + " ms, all avg " + total / 200 + " ms");
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    /** The genuine receipt with one product-id byte changed, a different one per {@code seed}. */
    private static byte[] tampered(byte[] der, byte[] product, int seed) {
        byte[] hostile = der.clone();
        hostile[TestPki.indexOf(hostile, product) + seed % product.length] ^= (byte) (seed + 1);
        return hostile;
    }

    /** A verifying request body, optionally carrying a padding field to grow it. */
    private static String requestJson(String padding) {
        String base64 = SyntheticReceipts.base64();
        String body = "{\"receipt-data\":\"" + base64 + "\"";
        if (padding != null && !padding.isEmpty()) {
            body = body + ",\"padding\":\"" + padding + "\"";
        }
        return body + "}";
    }

    /** Exactly {@code bytes} UTF-8 bytes of U+00E9, with one ASCII character when the count is odd. */
    private static String twoBytePadding(int bytes) {
        return Checks.repeat('\u00e9', bytes / 2) + (bytes % 2 == 1 ? "a" : "");
    }

    private static String name(X509Certificate certificate) {
        return certificate.getSubjectX500Principal().getName();
    }

    private static KeyPair rsa2048() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        return rsa.generateKeyPair();
    }

    /** The genuine receipt's signer, under {@code pki}'s intermediate, with Apple's marker. */
    private static X509CertificateHolder signerUnder(TestPki pki, KeyPair signerKey) throws Exception {
        return new X509CertificateHolder(TestPki.cert(
                        "CN=Fake Receipt Signing",
                        signerKey,
                        name(pki.intermediate),
                        pki.intermediateKey,
                        false,
                        SIGNING_LEAF,
                        pki.leaf.getNotBefore(),
                        pki.leaf.getNotAfter(),
                        "SHA256withRSA")
                .getEncoded());
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

    private static BigInteger smallPrimes() {
        BigInteger product = BigInteger.ONE;
        for (int i = 3; i < 10000; i += 2) {
            if (BigInteger.valueOf(i).isProbablePrime(30)) {
                product = product.multiply(BigInteger.valueOf(i));
            }
        }
        return product;
    }

    private static SignedData signedData(byte[] receipt) {
        return SignedData.getInstance(ContentInfo.getInstance(receipt).getContent());
    }

    /** The genuine g5 App Store receipt's DER, whose chain and signer are Apple's own. */
    private static byte[] g5Der() throws Exception {
        String text = new String(
                Files.readAllBytes(TestFixtures.publicReceipts().resolve("receipt-sandbox-g5.b64")),
                StandardCharsets.UTF_8);
        return Base64.getDecoder().decode(text.trim());
    }

    /**
     * {@code genuine}'s certificates and signer infos around {@code content}
     * instead of the content it was signed over: every signer's work runs,
     * against content its signature does not cover.
     */
    private static byte[] receipt(SignedData genuine, ASN1Set certificates, byte[] content, ASN1Set signerInfos)
            throws Exception {
        DLSequence signedData = new DLSequence(new ASN1Encodable[] {
            new ASN1Integer(1),
            genuine.getDigestAlgorithms(),
            new ContentInfo(CMSObjectIdentifiers.data, new DEROctetString(content)),
            new DLTaggedObject(false, 0, certificates),
            signerInfos
        });
        byte[] receipt = new DLSequence(
                        new ASN1Encodable[] {CMSObjectIdentifiers.signedData, new DLTaggedObject(true, 0, signedData)})
                .getEncoded(ASN1Encoding.DL);
        assertTrue(receipt.length <= CAP_DER, "the receipt is over the cap: " + receipt.length);
        return receipt;
    }

    /**
     * {@code genuine}'s content in a receipt with {@code certificates} and
     * {@code signerInfos}, encoded definite-length as built: DER would sort
     * the sets, which is the cost the shape used to carry.
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
}
