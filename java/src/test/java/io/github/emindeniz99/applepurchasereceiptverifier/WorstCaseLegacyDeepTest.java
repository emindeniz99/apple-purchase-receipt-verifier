package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The deep red-team suite for the legacy receipt path (verifyReceipt and
 * verifyReceiptEndpoint, which funnel through the same core). Beyond the
 * smoke suite (WorstCaseAttackSurfaceTest), this one mints attacks with an
 * attacker-grade PKI whose shape mirrors Apple's (root, WWDR-marker
 * intermediate, marker leaf) so the holder of every key can craft what a
 * name-only attacker cannot: mislabeled certificates that ARE validly
 * signed, a signer named as the pinned root, historical and future
 * validity windows, and label surgery on genuine receipts.
 */
class WorstCaseLegacyDeepTest {

    private static final long BUDGET_MS = 2000;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final AtomicLong SERIAL = new AtomicLong(1);
    private static final Pattern STATUS = Pattern.compile("\"status\":(\\d+)");

    private static final String SIGNING_LEAF_OID = "1.2.840.113635.100.6.11.1";
    private static final String WWDR_OID = "1.2.840.113635.100.6.2.1";
    private static final String GENERIC_COMPOSITE_OID = "1.3.6.1.4.1.18227.2.1";
    private static final String SHA256_RSA_SIG_OID = "1.2.840.113549.1.1.11";

    private static final X500Name ROOT_NAME = new X500Name("CN=Deep Fake Apple Root CA");
    private static final X500Name INTER_NAME = new X500Name("CN=Deep Fake Apple WWDR CA");

    private static TestPki pki;
    private static Verifier pkiVerifier;
    private static String pkiGenuine;

    private static X509Certificate myRoot;
    private static X509CertificateHolder myRootHolder;
    private static X509CertificateHolder myInterHolder;
    private static X509CertificateHolder myLeafHolder;
    private static PrivateKey myRootKey;
    private static PrivateKey myInterKey;
    private static PrivateKey myLeafKey;
    private static Verifier myVerifier;
    private static String myGenuine;
    private static byte[] myGenuineDer;

    @BeforeAll
    static void mintTheAttackerGradePkiAndGenuineReceipts() throws Exception {
        pki = TestPki.receipt();
        pkiVerifier = Verifier.create(
                Config.builder().roots(Collections.singleton(pki.root)).build());
        pkiGenuine = Base64.getEncoder().encodeToString(pki.signReceipt(payload()));

        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair rootKp = rsa.generateKeyPair();
        KeyPair interKp = rsa.generateKeyPair();
        KeyPair leafKp = rsa.generateKeyPair();
        myRootKey = rootKp.getPrivate();
        myInterKey = interKp.getPrivate();
        myLeafKey = leafKp.getPrivate();
        myRootHolder = cert(ROOT_NAME, rootKp.getPublic(), ROOT_NAME, myRootKey, true, null);
        myInterHolder = cert(INTER_NAME, interKp.getPublic(), ROOT_NAME, myRootKey, true, WWDR_OID);
        myLeafHolder = cert(
                new X500Name("CN=Deep Fake Receipt Signer"),
                leafKp.getPublic(),
                INTER_NAME,
                myInterKey,
                false,
                SIGNING_LEAF_OID);
        myRoot = jca(myRootHolder);
        myVerifier = Verifier.create(
                Config.builder().roots(Collections.singleton(myRoot)).build());
        myGenuineDer = TestPki.signReceiptAs(
                payload(),
                new Date(),
                myLeafKey,
                "SHA256withRSA",
                myLeafHolder,
                Arrays.asList(myLeafHolder, myInterHolder, myRootHolder));
        myGenuine = Base64.getEncoder().encodeToString(myGenuineDer);
    }

    /** One attack receipt: refused with one of {@code expected}, inside the budget. */
    private static void refused(String what, Verifier v, String receipt, Reason... expected) {
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result = v.verifyReceipt(receipt);
        long ms = (System.nanoTime() - start) / 1_000_000;
        Reason actual = result.verified() ? null : result.failure().reason();
        System.out.println("deep " + what + ": " + ms + " ms, "
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

    private static void verifies(String what, Verifier v, String receipt, long budget) {
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result = v.verifyReceipt(receipt);
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("deep " + what + ": " + ms + " ms, " + result.verified());
        assertTrue(result.verified(), what + " was refused: " + result.failure());
        assertTrue(ms < budget, what + " took " + ms + " ms, over the " + budget + " ms budget");
    }

    private static byte[] payload() throws Exception {
        String now = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
        return TestPki.receiptPayload(
                "com.example.app",
                "1.0",
                new byte[] {1, 2, 3, 4},
                new byte[] {5, 6, 7, 8},
                now,
                Collections.singletonList(TestPki.inAppPurchase(1, "gems.small", "2001", "2001", now, null)));
    }

    private static Date iso(String date) {
        return Date.from(Instant.parse(date));
    }

    private static Date yearOut() {
        return new Date(System.currentTimeMillis() + 365L * 86_400_000);
    }

    private static BigInteger nextSerial() {
        return BigInteger.valueOf(SERIAL.getAndIncrement());
    }

    private static X509CertificateHolder cert(
            X500Name subject, PublicKey key, X500Name issuer, PrivateKey issuerKey, boolean ca, String marker)
            throws Exception {
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(issuer, nextSerial(), new Date(), yearOut(), subject, key);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (marker != null) {
            builder.addExtension(new ASN1ObjectIdentifier(marker), false, ASN1Boolean.TRUE);
        }
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(TestPki.BC)
                .build(issuerKey));
    }

    private static X509Certificate jca(X509CertificateHolder holder) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
    }

    /** A hostile certificate: any TBS label, a garbage signature, optionally a huge RSA modulus. */
    private static X509CertificateHolder hostileCert(String subjectCn, AlgorithmIdentifier label, boolean ca) {
        return hostileCert(subjectCn, label, ca, 2048);
    }

    private static X509CertificateHolder hostileCert(
            String subjectCn, AlgorithmIdentifier label, boolean ca, int modulusBits) {
        try {
            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                    INTER_NAME,
                    nextSerial(),
                    new Date(),
                    yearOut(),
                    new X500Name("CN=" + subjectCn),
                    rsaKey(modulusBits));
            if (ca) {
                builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            }
            return builder.build(new GarbageSigner(label));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A hostile certificate that IS validly signed by the WWDR key, but carries the given TBS label. */
    private static X509CertificateHolder mislabeledVouchedCert(String subjectCn, AlgorithmIdentifier label)
            throws Exception {
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                INTER_NAME, nextSerial(), new Date(), yearOut(), new X500Name("CN=" + subjectCn), rsaKey(2048));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        ContentSigner real = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(TestPki.BC)
                .build(myInterKey);
        return builder.build(new MislabelingSigner(real, label));
    }

    private static SubjectPublicKeyInfo rsaKey(int bits) throws Exception {
        BigInteger modulus = new BigInteger(bits, RANDOM).setBit(bits - 1).setBit(0);
        return new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                new RSAPublicKey(modulus, BigInteger.valueOf(65537)));
    }

    /** RSASSA-PSS with a saltLength no RSA key can hold, in BC's untagged form. */
    private static AlgorithmIdentifier hugeSaltPss() {
        ASN1EncodableVector pss = new ASN1EncodableVector();
        pss.add(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE));
        pss.add(new AlgorithmIdentifier(
                PKCSObjectIdentifiers.id_mgf1,
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE)));
        pss.add(new ASN1Integer(100_000));
        pss.add(new ASN1Integer(1));
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, new DERSequence(pss));
    }

    /** RSASSA-PSS with a saltLength no RSA key can hold, in the RFC 8017 tagged form. */
    private static AlgorithmIdentifier taggedPssParams() {
        ASN1EncodableVector pss = new ASN1EncodableVector();
        pss.add(new org.bouncycastle.asn1.DERTaggedObject(
                true, 0, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE)));
        pss.add(new org.bouncycastle.asn1.DERTaggedObject(
                true,
                1,
                new AlgorithmIdentifier(
                        PKCSObjectIdentifiers.id_mgf1,
                        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE))));
        pss.add(new org.bouncycastle.asn1.DERTaggedObject(true, 2, new ASN1Integer(100_000)));
        pss.add(new org.bouncycastle.asn1.DERTaggedObject(true, 3, new ASN1Integer(1)));
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, new DERSequence(pss));
    }

    private static AlgorithmIdentifier md2Label() {
        return new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.2"), DERNull.INSTANCE);
    }

    private static AlgorithmIdentifier compositeLabel() {
        return new AlgorithmIdentifier(new ASN1ObjectIdentifier(GENERIC_COMPOSITE_OID), DERNull.INSTANCE);
    }

    private static AlgorithmIdentifier normalLabel() {
        return new AlgorithmIdentifier(new ASN1ObjectIdentifier(SHA256_RSA_SIG_OID), DERNull.INSTANCE);
    }

    private static String b64(byte[] der) {
        return Base64.getEncoder().encodeToString(der);
    }

    private static byte[] needle(int... bytes) {
        byte[] out = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            out[i] = (byte) bytes[i];
        }
        return out;
    }

    private static int count(byte[] haystack, byte[] needle) {
        int found = 0;
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            if (matchAt(haystack, needle, i)) {
                found++;
            }
        }
        return found;
    }

    private static int lastIndexOf(byte[] haystack, byte[] needle) {
        for (int i = haystack.length - needle.length; i >= 0; i--) {
            if (matchAt(haystack, needle, i)) {
                return i;
            }
        }
        return -1;
    }

    private static boolean matchAt(byte[] haystack, byte[] needle, int at) {
        for (int j = 0; j < needle.length; j++) {
            if (haystack[at + j] != needle[j]) {
                return false;
            }
        }
        return true;
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

    private static int endpointStatus(String body) {
        return statusOf(pkiVerifier.verifyReceiptEndpoint(Environment.SANDBOX, body));
    }

    private static int endpointStatus(Environment environment, String receipt) {
        return statusOf(
                pkiVerifier.verifyReceiptEndpoint(environment, "{\"receipt-data\":\"" + jsonEscaped(receipt) + "\"}"));
    }

    /** The endpoint answer of the same verifier the receipt verifies under. */
    private static int endpointStatusOf(Verifier v, String receipt) {
        return statusOf(
                v.verifyReceiptEndpoint(Environment.SANDBOX, "{\"receipt-data\":\"" + jsonEscaped(receipt) + "\"}"));
    }

    private static int statusOf(String answer) {
        Matcher status = STATUS.matcher(answer);
        assertTrue(
                status.find(),
                "the endpoint answered no status: " + answer.substring(0, Math.min(100, answer.length())));
        return Integer.parseInt(status.group(1));
    }

    @Test
    void controlMyAppleShapedPkiVerifies() {
        verifies("attacker-grade-pki control", myVerifier, myGenuine, BUDGET_MS);
        verifies("upstream-pki control", pkiVerifier, pkiGenuine, BUDGET_MS);
    }

    @Test
    void developerCertWithoutSigningMarkerCannotForge() throws Exception {
        Date past = iso("2026-01-01T00:00:00Z");
        Date future = iso("2027-01-01T00:00:00Z");
        TestPki noLeafMarker = TestPki.receipt(past, future, false, true);
        refused(
                "developer-cert-without-signing-marker",
                Verifier.create(Config.builder()
                        .roots(Collections.singleton(noLeafMarker.root))
                        .build()),
                b64(noLeafMarker.signReceipt(payload())),
                Reason.INVALID_CERTIFICATE_PURPOSE);
        TestPki noInterMarker = TestPki.receipt(past, future, true, false);
        refused(
                "wwdr-intermediate-without-marker",
                Verifier.create(Config.builder()
                        .roots(Collections.singleton(noInterMarker.root))
                        .build()),
                b64(noInterMarker.signReceipt(payload())),
                Reason.INVALID_CERTIFICATE_PURPOSE);
        TestPki noMarkers = TestPki.receipt(past, future, false, false);
        refused(
                "both-markers-missing",
                Verifier.create(Config.builder()
                        .roots(Collections.singleton(noMarkers.root))
                        .build()),
                b64(noMarkers.signReceipt(payload())),
                Reason.INVALID_CERTIFICATE_PURPOSE);
    }

    @Test
    void signerIssuedByTheRootDirectlyIsRefused() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair leafKp = rsa.generateKeyPair();
        X509CertificateHolder leaf2 = cert(
                new X500Name("CN=Deep Fake Root-Issued Signer"),
                leafKp.getPublic(),
                ROOT_NAME,
                myRootKey,
                false,
                SIGNING_LEAF_OID);
        byte[] receipt = TestPki.signReceiptAs(
                payload(), new Date(), leafKp.getPrivate(), "SHA256withRSA", leaf2, Arrays.asList(leaf2, myRootHolder));
        refused("signer-issued-by-root-directly", myVerifier, b64(receipt), Reason.INVALID_CERTIFICATE_PURPOSE);
    }

    @Test
    void receiptEnvironmentMismatchesAnswerApplesStatuses() throws Exception {
        String now = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
        byte[] prodPayload = TestPki.receiptPayload(
                "Production",
                "com.example.app",
                "1.0",
                new byte[] {1, 2, 3, 4},
                new byte[] {5, 6, 7, 8},
                now,
                Collections.singletonList(TestPki.inAppPurchase(1, "gems.small", "2001", "2001", now, null)));
        String prod = b64(pki.signReceipt(prodPayload));
        assertEquals(AppleStatus.OK, endpointStatus(Environment.PRODUCTION, prod));
        assertEquals(AppleStatus.PRODUCTION_RECEIPT_ON_SANDBOX, endpointStatus(Environment.SANDBOX, prod));
        assertEquals(AppleStatus.OK, endpointStatus(Environment.SANDBOX, pkiGenuine));
        assertEquals(AppleStatus.SANDBOX_RECEIPT_ON_PRODUCTION, endpointStatus(Environment.PRODUCTION, pkiGenuine));
        assertTrue(pkiVerifier.verifyReceipt(prod).verified(), "verifyReceipt itself must not check the environment");
    }

    @Test
    void expiredHistoricalReceiptInsideItsValidityStillVerifies() throws Exception {
        TestPki expired = TestPki.receipt(iso("2020-01-01T00:00:00Z"), iso("2020-12-31T00:00:00Z"));
        byte[] historicalPayload = TestPki.receiptPayload(
                "com.example.app",
                "1.0",
                new byte[] {1, 2, 3, 4},
                new byte[] {5, 6, 7, 8},
                "2020-06-15T12:00:00Z",
                Collections.singletonList(
                        TestPki.inAppPurchase(1, "gems.small", "2001", "2001", "2020-06-15T12:00:00Z", null)));
        byte[] historical = expired.signReceipt(historicalPayload, iso("2020-06-15T12:00:00Z"));
        Verifier v = Verifier.create(
                Config.builder().roots(Collections.singleton(expired.root)).build());
        verifies("expired-chain-historical-date (documented policy)", v, b64(historical), BUDGET_MS);
    }

    @Test
    void expiredChainWithoutACreationDateIsJudgedAtTheClockAndRefused() throws Exception {
        TestPki expired = TestPki.receipt(iso("2020-01-01T00:00:00Z"), iso("2020-12-31T00:00:00Z"));
        byte[] noDatePayload = TestPki.receiptPayload(
                "ProductionSandbox",
                "com.example.app",
                "1.0",
                new byte[] {1, 2, 3, 4},
                new byte[] {5, 6, 7, 8},
                "2020-06-15T12:00:00Z",
                Collections.singletonList(
                        TestPki.inAppPurchase(1, "gems.small", "2001", "2001", "2020-06-15T12:00:00Z", null)),
                false,
                null,
                null);
        Verifier v = Verifier.create(
                Config.builder().roots(Collections.singleton(expired.root)).build());
        refused(
                "expired-chain-no-creation-date",
                v,
                b64(expired.signReceipt(noDatePayload)),
                Reason.INVALID_CERTIFICATE,
                Reason.UNTRUSTED_CHAIN);
    }

    @Test
    void notYetValidChainIsRefused() throws Exception {
        TestPki future = TestPki.receipt(iso("2027-01-01T00:00:00Z"), iso("2030-01-01T00:00:00Z"));
        Verifier v = Verifier.create(
                Config.builder().roots(Collections.singleton(future.root)).build());
        refused(
                "not-yet-valid-chain",
                v,
                b64(future.signReceipt(payload())),
                Reason.INVALID_CERTIFICATE,
                Reason.UNTRUSTED_CHAIN);
    }

    @Test
    void digestLabelSurgeryToSha384FailsTheSignatureFast() {
        byte[] sha256Oid = needle(0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01);
        // Three appear: the SignedData digest-set, the SignerInfo's own digest
        // algorithm, and the signed CMSAlgorithmProtection copy of it. Only the
        // SignerInfo's is what verification hashes with; the set is advisory
        // and the protection copy is checked for consistency as sent.
        int second = nthIndexOf(myGenuineDer, sha256Oid, 2);
        assertTrue(second > 0, "the SHA-256 digest OID should appear at least twice");
        byte[] patched = myGenuineDer.clone();
        patched[second + sha256Oid.length - 1] = 0x02;
        refused("digest-label-sha384-surgery", myVerifier, b64(patched), Reason.INVALID_SIGNATURE);
    }

    private static int nthIndexOf(byte[] haystack, byte[] needle, int nth) {
        int seen = 0;
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            if (matchAt(haystack, needle, i) && ++seen == nth) {
                return i;
            }
        }
        return -1;
    }

    @Test
    void signatureLabelSurgeryToPssWithNullParamsIsRefusedFast() {
        // The signer writes the combined sha256WithRSAEncryption label; the
        // last one in the DER belongs to the SignerInfo, which sits after the
        // certificate bag. Changing its last byte turns it into RSA-PSS with
        // the NULL parameters carried as sent.
        byte[] combinedOid = needle(0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B);
        int at = lastIndexOf(myGenuineDer, combinedOid);
        assertTrue(at > 0, "the receipt carries no sha256WithRSAEncryption label");
        byte[] patched = myGenuineDer.clone();
        patched[at + combinedOid.length - 1] = 0x0A;
        refused(
                "signature-label-pss-null-params-surgery",
                myVerifier,
                b64(patched),
                Reason.INVALID_SIGNATURE,
                Reason.MALFORMED);

        // The rsaEncryption OID lives only inside the certificates; the last
        // one is an embedded certificate's outer label, which pins no trust,
        // so the receipt still verifies.
        byte[] rsaOid = needle(0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01);
        int inert = lastIndexOf(myGenuineDer, rsaOid);
        assertTrue(inert > 0, "the certificates carry no rsaEncryption label");
        byte[] patchedOuter = myGenuineDer.clone();
        patchedOuter[inert + rsaOid.length - 1] = 0x0A;
        verifies("certificate-outer-label-surgery-is-inert", myVerifier, b64(patchedOuter), BUDGET_MS);
    }

    @Test
    void hostileCertificateLabelsAreRefusedBeforeAnyWork() throws Exception {
        String[] names = {"pss-huge-salt", "md2-digest", "generic-composite"};
        AlgorithmIdentifier[] labelIds = {taggedPssParams(), md2Label(), compositeLabel()};
        for (int i = 0; i < labelIds.length; i++) {
            X509CertificateHolder hostile = hostileCert("Hostile " + names[i] + " signer", labelIds[i], false);
            byte[] asSigner = TestPki.signReceiptAs(
                    payload(),
                    new Date(),
                    myLeafKey,
                    "SHA256withRSA",
                    hostile,
                    Arrays.asList(myLeafHolder, myInterHolder, myRootHolder, hostile));
            refused(
                    "label-bomb-" + names[i] + "-as-signer",
                    myVerifier,
                    b64(asSigner),
                    Reason.UNTRUSTED_CHAIN,
                    Reason.MALFORMED);
            byte[] asJunk = TestPki.signReceiptAs(
                    payload(),
                    new Date(),
                    myLeafKey,
                    "SHA256withRSA",
                    myLeafHolder,
                    Arrays.asList(myLeafHolder, myInterHolder, myRootHolder, hostile));
            verifies("label-bomb-" + names[i] + "-as-bag-junk", myVerifier, b64(asJunk), BUDGET_MS);
        }
    }

    @Test
    void nonstandardPssParameterFormsAreRefusedCleanlyAtTheBagDecode() throws Exception {
        // A PSS label whose parameters use BC's untagged SEQUENCE form crashes
        // BouncyCastle's own certificate converter; the vendored decode catches
        // it and refuses the whole receipt as MALFORMED, quickly, so the crash
        // neither escapes as INTERNAL nor costs anything.
        X509CertificateHolder untagged = hostileCert("Untagged PSS pretender", hugeSaltPss(), false);
        byte[] asJunk = TestPki.signReceiptAs(
                payload(),
                new Date(),
                myLeafKey,
                "SHA256withRSA",
                myLeafHolder,
                Arrays.asList(myLeafHolder, myInterHolder, myRootHolder, untagged));
        refused("untagged-pss-params-as-bag-junk", myVerifier, b64(asJunk), Reason.MALFORMED);
        byte[] asSigner = TestPki.signReceiptAs(
                payload(),
                new Date(),
                myLeafKey,
                "SHA256withRSA",
                untagged,
                Arrays.asList(myLeafHolder, myInterHolder, myRootHolder, untagged));
        refused("untagged-pss-params-as-signer", myVerifier, b64(asSigner), Reason.MALFORMED);
    }

    @Test
    void mislabeledCertificatesSignedByTheCaKeyStillRefuseBeforeWork() throws Exception {
        // The leaked-WWDR-key scenario: certificates that ARE validly signed by the vouched
        // intermediate but carry a work-bomb label. The label is read before any salt is
        // allocated or digest run, so even this certificate minter costs milliseconds.
        String[] names = {"pss-huge-salt", "md2-digest", "generic-composite"};
        AlgorithmIdentifier[] labelIds = {taggedPssParams(), md2Label(), compositeLabel()};
        for (int i = 0; i < labelIds.length; i++) {
            X509CertificateHolder vouched = mislabeledVouchedCert("Vouched " + names[i], labelIds[i]);
            X509CertificateHolder namee = new X509v3CertificateBuilder(
                            new X500Name("CN=Vouched " + names[i]),
                            nextSerial(),
                            new Date(),
                            yearOut(),
                            new X500Name("CN=Namee of " + names[i]),
                            rsaKey(2048))
                    .build(new GarbageSigner(normalLabel()));
            byte[] receipt = TestPki.signReceiptAs(
                    payload(),
                    new Date(),
                    myLeafKey,
                    "SHA256withRSA",
                    myLeafHolder,
                    Arrays.asList(myLeafHolder, myInterHolder, myRootHolder, vouched, namee));
            verifies("leaked-key-mislabeled-" + names[i] + "-cannot-bomb", myVerifier, b64(receipt), BUDGET_MS);
        }
    }

    @Test
    void hugeModulusPretendersAreNeverDecoded() throws Exception {
        X509CertificateHolder pretender = hostileCert("Huge Modulus Pretender", normalLabel(), false, 16384);
        byte[] withPretender = TestPki.signReceiptAs(
                payload(),
                new Date(),
                myLeafKey,
                "SHA256withRSA",
                myLeafHolder,
                Arrays.asList(myLeafHolder, myInterHolder, myRootHolder, pretender));
        verifies("16384-bit-pretender-never-decoded", myVerifier, b64(withPretender), BUDGET_MS);

        X509CertificateHolder intermediateClone = new X509v3CertificateBuilder(
                        INTER_NAME, nextSerial(), new Date(), yearOut(), INTER_NAME, rsaKey(16384))
                .build(new GarbageSigner(normalLabel()));
        byte[] withClone = TestPki.signReceiptAs(
                payload(),
                new Date(),
                myLeafKey,
                "SHA256withRSA",
                myLeafHolder,
                Arrays.asList(myLeafHolder, myInterHolder, myRootHolder, intermediateClone));
        verifies("16384-bit-intermediate-name-clone-never-decoded", myVerifier, b64(withClone), BUDGET_MS);
    }

    @Test
    void vouchedHugeKeysCostBoundedSecondsOnlyWithALeakedCaKey() throws Exception {
        // Unreachable in production without Apple's WWDR key: certificates validly signed
        // by a vouched CA, with a 16384-bit key, that something names as its issuer. The
        // decode cost is paid once per such key; this bounds the leaked-key worst case.
        X509CertificateHolder vouched1 = vouchedHugeCa("Vouched Huge 1");
        X509CertificateHolder vouched2 = vouchedHugeCa("Vouched Huge 2");
        X509CertificateHolder namee1 = new X509v3CertificateBuilder(
                        new X500Name("CN=Vouched Huge 1"),
                        nextSerial(),
                        new Date(),
                        yearOut(),
                        new X500Name("CN=Namee 1"),
                        rsaKey(2048))
                .build(new GarbageSigner(normalLabel()));
        X509CertificateHolder namee2 = new X509v3CertificateBuilder(
                        new X500Name("CN=Vouched Huge 2"),
                        nextSerial(),
                        new Date(),
                        yearOut(),
                        new X500Name("CN=Namee 2"),
                        rsaKey(2048))
                .build(new GarbageSigner(normalLabel()));
        byte[] receipt = TestPki.signReceiptAs(
                payload(),
                new Date(),
                myLeafKey,
                "SHA256withRSA",
                myLeafHolder,
                Arrays.asList(myLeafHolder, myInterHolder, myRootHolder, vouched1, namee1, vouched2, namee2));
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result = myVerifier.verifyReceipt(b64(receipt));
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("deep leaked-ca-key two 16384-bit vouched keys: " + ms + " ms, " + result.verified());
        assertTrue(result.verified(), "the genuine receipt should still verify: " + result.failure());
        assertTrue(ms < 30_000, "the leaked-CA-key worst case cost " + ms + " ms, over the 30 s bound");
    }

    private static X509CertificateHolder vouchedHugeCa(String subjectCn) throws Exception {
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                INTER_NAME, nextSerial(), new Date(), yearOut(), new X500Name("CN=" + subjectCn), rsaKey(16384));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(TestPki.BC)
                .build(myInterKey));
    }

    @Test
    void injectedJunkSignersCannotShadowAGenuineOne() throws Exception {
        TestPki otherPki = TestPki.receipt();
        byte[] injected = TestPki.signReceiptByEach(payload(), Arrays.asList(otherPki, pki));
        verifies("attacker-signer-injected-first", pkiVerifier, b64(injected), BUDGET_MS);

        X509CertificateHolder junk = hostileCert("Junk Signer", normalLabel(), false);
        byte[] junkFirst = TestPki.signReceiptAs(
                payload(),
                new Date(),
                myLeafKey,
                "SHA256withRSA",
                Arrays.asList(junk, myLeafHolder),
                Arrays.asList(myLeafHolder, myInterHolder, myRootHolder, junk));
        verifies("junk-signer-injected-beside-genuine", myVerifier, b64(junkFirst), BUDGET_MS);
    }

    @Test
    void signerNamedAsThePinnedRootIsRefused() throws Exception {
        byte[] receipt = TestPki.signReceiptAs(
                payload(),
                new Date(),
                myLeafKey,
                "SHA256withRSA",
                myRootHolder,
                Arrays.asList(myLeafHolder, myInterHolder, myRootHolder));
        refused(
                "signer-named-as-the-pinned-root",
                myVerifier,
                b64(receipt),
                Reason.INVALID_CERTIFICATE_PURPOSE,
                Reason.UNTRUSTED_CHAIN);
    }

    @Test
    void undecodableBagEntriesAreRefused() throws Exception {
        byte[] undecodable = pki.signReceiptWithUndecodablePadding(payload(), 5);
        refused("undecodable-bag-entries", pkiVerifier, b64(undecodable), Reason.INVALID_CERTIFICATE, Reason.MALFORMED);
    }

    @Test
    void tamperedMessageDigestAttributeFailsTheSignature() {
        byte[] mdOid = needle(0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04);
        assertEquals(1, count(myGenuineDer, mdOid), "the messageDigest OID should appear exactly once");
        byte[] patched = myGenuineDer.clone();
        int at = TestPki.indexOf(patched, mdOid) + mdOid.length;
        assertEquals(0x31, patched[at] & 0xFF, "expected the attribute value SET tag");
        assertEquals(0x04, patched[at + 2] & 0xFF, "expected the digest OCTET STRING tag");
        assertEquals(0x20, patched[at + 3] & 0xFF, "expected a 32-byte SHA-256 digest");
        patched[at + 4] ^= 0x01;
        refused("tampered-messageDigest-attribute", myVerifier, b64(patched), Reason.INVALID_SIGNATURE);
    }

    @Test
    void tamperedPayloadFailsTheSignature() {
        byte[] bundleId = "com.example.app".getBytes();
        assertEquals(1, count(myGenuineDer, bundleId), "the bundle id should appear exactly once");
        byte[] patched = myGenuineDer.clone();
        patched[TestPki.indexOf(patched, bundleId)] ^= 0x01;
        refused("tampered-payload", myVerifier, b64(patched), Reason.INVALID_SIGNATURE);
    }

    @Test
    void tamperedIntermediateBreaksTheChain() throws Exception {
        byte[] intermediate = myInterHolder.getEncoded();
        assertEquals(1, count(myGenuineDer, intermediate), "the intermediate should appear exactly once");
        byte[] patched = myGenuineDer.clone();
        int at = TestPki.indexOf(patched, intermediate);
        patched[at + intermediate.length / 2] ^= 0x01;
        refused(
                "tampered-intermediate-certificate",
                myVerifier,
                b64(patched),
                Reason.UNTRUSTED_CHAIN,
                Reason.INVALID_CERTIFICATE,
                Reason.MALFORMED);
    }

    @Test
    void malformedDerShapesAreRefusedFast() throws Exception {
        ContentInfo dataTyped = new ContentInfo(PKCSObjectIdentifiers.data, new DEROctetString(payload()));
        refused("content-typed-as-plain-data", myVerifier, b64(dataTyped.getEncoded()), Reason.MALFORMED);

        ContentInfo inner = new ContentInfo(PKCSObjectIdentifiers.data, new DEROctetString(payload()));
        SignedData noSigners = new SignedData(new DERSet(), inner, null, null, new DERSet());
        refused(
                "signed-data-with-no-signers",
                myVerifier,
                b64(new ContentInfo(CMSObjectIdentifiers.signedData, noSigners).getEncoded()),
                Reason.MALFORMED);

        SignedData garbageDigest = new SignedData(
                new DERSet(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4.5"), DERNull.INSTANCE)),
                inner,
                null,
                null,
                new DERSet());
        refused(
                "garbage-digest-algorithm-set",
                myVerifier,
                b64(new ContentInfo(CMSObjectIdentifiers.signedData, garbageDigest).getEncoded()),
                Reason.MALFORMED);

        refused(
                "huge-der-length-claim",
                myVerifier,
                b64(needle(0x30, (byte) 0x84, 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x02, 0x01, 0x01)),
                Reason.MALFORMED);

        refused(
                "high-tag-continuation-bytes",
                myVerifier,
                b64(needle(0x1F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x7F)),
                Reason.MALFORMED);

        for (int fraction : new int[] {25, 50, 75, 99}) {
            byte[] truncated = Arrays.copyOf(myGenuineDer, myGenuineDer.length * fraction / 100);
            refused("truncated-at-" + fraction + "-percent", myVerifier, b64(truncated), Reason.MALFORMED);
        }
    }

    @Test
    void sizeCapBoundaryIsEnforcedExactly() {
        StringBuilder atCap = new StringBuilder(3_145_728);
        for (int i = 0; i < 3_145_728; i++) {
            atCap.append('A');
        }
        refused("receipt-at-exactly-the-cap", myVerifier, atCap.toString(), Reason.MALFORMED);
        refused("receipt-one-char-over-the-cap", myVerifier, atCap.append('A').toString(), Reason.TOO_LARGE);
    }

    @Test
    void looseBase64VariantsAreRefusedStrictly() {
        StringBuilder mime = new StringBuilder();
        for (int i = 0; i < myGenuine.length(); i++) {
            if (i > 0 && i % 76 == 0) {
                mime.append('\n');
            }
            mime.append(myGenuine.charAt(i));
        }
        refused("mime-base64-with-line-breaks", myVerifier, mime.toString(), Reason.MALFORMED);
        refused("trailing-whitespace", myVerifier, myGenuine + " ", Reason.MALFORMED);
        refused(
                "nul-character-inside",
                myVerifier,
                myGenuine.substring(0, 100) + "\0" + myGenuine.substring(100),
                Reason.MALFORMED);

        String unpadded = myGenuine.substring(0, myGenuine.length() - 2);
        VerificationResult<ReceiptPayload> unpaddedResult = myVerifier.verifyReceipt(unpadded);
        System.out.println("deep unpadded-standard-base64: " + unpaddedResult.verified()
                + (unpaddedResult.verified()
                        ? ""
                        : " " + unpaddedResult.failure().reason()));

        String urlSafe = myGenuine.replace('+', '-').replace('/', '_').replaceAll("=+$", "");
        VerificationResult<ReceiptPayload> urlSafeResult = myVerifier.verifyReceipt(urlSafe);
        System.out.println("deep base64url-of-a-receipt: " + urlSafeResult.verified()
                + (urlSafeResult.verified() ? "" : " " + urlSafeResult.failure().reason()));
    }

    @Test
    void berIndefiniteLengthReceiptIsHandledWithoutThrowing() {
        int bodyStart = (myGenuineDer[1] & 0x80) == 0 ? 2 : 2 + (myGenuineDer[1] & 0x7F);
        byte[] wrapped = new byte[myGenuineDer.length - bodyStart + 4];
        wrapped[0] = 0x30;
        wrapped[1] = (byte) 0x80;
        System.arraycopy(myGenuineDer, bodyStart, wrapped, 2, myGenuineDer.length - bodyStart);
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result = myVerifier.verifyReceipt(b64(wrapped));
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("deep ber-indefinite-length-wrap: " + ms + " ms, " + result.verified()
                + (result.verified() ? "" : " " + result.failure().reason()));
        assertTrue(ms < BUDGET_MS, "the BER wrap took " + ms + " ms");
    }

    @Test
    void endpointAnswersOnlyMappedStatusesUnderStructuredAbuse() {
        long start = System.nanoTime();
        assertEquals(AppleStatus.OK, endpointStatus("{\"receipt-data\":\"" + pkiGenuine + "\"}"));
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, endpointStatus("{\"receipt-data\":12345}"));
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, endpointStatus("{\"receipt-data\":null}"));
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, endpointStatus("{\"receipt-data\":[\"x\"]}"));
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, endpointStatus("{\"receipt-data\":{\"x\":1}}"));
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, endpointStatus("{\"receipt-data\":true}"));
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, endpointStatus("{\"receipt-data\":\"\"}"));
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, endpointStatus("{}"));
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, endpointStatus("[1,2,3]"));
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, endpointStatus("42"));
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, endpointStatus("{\"receipt-data\":\"AAAA\",}"));
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, endpointStatus("{'receipt-data':'AAAA'}"));
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, endpointStatus("{\"receipt-data\":NaN}"));
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, endpointStatus("\uFEFF{\"receipt-data\":\"AAAA\"}"));
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, endpointStatus(null));
        assertEquals(
                AppleStatus.OK, endpointStatus("{\"receipt-data\":\"AAAA\",\"receipt-data\":\"" + pkiGenuine + "\"}"));
        // The reader hands over top-level members only, so the last duplicate
        // wins and "@@@" is read as the receipt: refused as not base64.
        assertEquals(
                AppleStatus.MALFORMED_RECEIPT_DATA,
                endpointStatus("{\"receipt-data\":\"" + pkiGenuine + "\",\"receipt-data\":\"@@@\"}"));
        long ms = (System.nanoTime() - start) / 1_000_000;
        assertTrue(ms < BUDGET_MS, "the structured endpoint battery took " + ms + " ms");
    }

    @Test
    void endpointDeepAndOversizedBodiesAreBounded() {
        StringBuilder deep = new StringBuilder();
        for (int i = 0; i < 2000; i++) {
            deep.append("{\"a\":");
        }
        deep.append("{\"receipt-data\":\"AAAA\"}");
        for (int i = 0; i < 2000; i++) {
            deep.append("}");
        }
        long start = System.nanoTime();
        int deepStatus = endpointStatus(deep.toString());
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("deep 2000-deep-json-body: " + ms + " ms, status " + deepStatus);
        assertTrue(deepStatus == AppleStatus.MALFORMED_RECEIPT_DATA
                || deepStatus == AppleStatus.RECEIPT_NOT_AUTHENTICATED);
        assertTrue(ms < BUDGET_MS, "the deep body took " + ms + " ms");

        StringBuilder okDeep = new StringBuilder();
        for (int i = 0; i < 900; i++) {
            okDeep.append("{\"a\":");
        }
        okDeep.append("{\"receipt-data\":\"").append(pkiGenuine).append("\"}");
        for (int i = 0; i < 900; i++) {
            okDeep.append("}");
        }
        // The reader hands over top-level members only and skips nested
        // values, so a receipt-data buried nine hundred levels deep is not
        // read at all, and skipping that deep still costs milliseconds.
        start = System.nanoTime();
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, endpointStatus(okDeep.toString()));
        ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("deep 900-deep-buried-receipt-data: " + ms + " ms");
        assertTrue(ms < BUDGET_MS, "the buried receipt body took " + ms + " ms");

        StringBuilder huge = new StringBuilder(3_500_000);
        for (int i = 0; i < 3_500_000; i++) {
            huge.append(' ');
        }
        huge.insert(0, "{\"receipt-data\":\"").append("\"}");
        start = System.nanoTime();
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, endpointStatus(huge.toString()));
        ms = (System.nanoTime() - start) / 1_000_000;
        assertTrue(ms < BUDGET_MS, "the oversized body took " + ms + " ms");

        StringBuilder nearCap = new StringBuilder(3_200_000);
        nearCap.append("{\"receipt-data\":\"");
        for (int i = 0; i < 3_140_000; i++) {
            nearCap.append('A');
        }
        nearCap.append("\"}");
        start = System.nanoTime();
        assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, endpointStatus(nearCap.toString()));
        ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("deep near-cap-body-full-pipeline: " + ms + " ms");
        assertTrue(ms < BUDGET_MS, "the near-cap body took " + ms + " ms");
    }

    @Test
    void endpointAgreesWithVerifyReceiptOnEveryVerdict() throws Exception {
        List<String> receipts = new ArrayList<>();
        receipts.add(pkiGenuine);
        receipts.add(myGenuine);
        receipts.add(b64(TestPki.corruptSignatures(myGenuineDer, 1)));
        receipts.add("AAAA");
        receipts.add("");
        for (int i = 0; i < 20; i++) {
            byte[] bytes = new byte[RANDOM.nextInt(50_000)];
            RANDOM.nextBytes(bytes);
            receipts.add(b64(bytes));
        }
        StringBuilder atCap = new StringBuilder();
        for (int i = 0; i < 3_145_729; i++) {
            atCap.append('A');
        }
        receipts.add(atCap.toString());
        for (String receipt : receipts) {
            VerificationResult<ReceiptPayload> result = pkiVerifier.verifyReceipt(receipt);
            int status = endpointStatus(Environment.SANDBOX, receipt);
            if (result.verified()) {
                assertEquals(AppleStatus.OK, status, "a verified receipt answered " + status);
            } else {
                assertTrue(status != AppleStatus.OK, "a refused receipt answered 0");
                assertTrue(
                        status != AppleStatus.INTERNAL_DATA_ACCESS_ERROR,
                        "a refused receipt answered 21009: " + result.failure().reason());
                Reason reason = result.failure().reason();
                if (reason == Reason.MALFORMED || reason == Reason.TOO_LARGE) {
                    assertEquals(AppleStatus.MALFORMED_RECEIPT_DATA, status);
                } else if (reason == Reason.INVALID_SIGNATURE
                        || reason == Reason.UNTRUSTED_CHAIN
                        || reason == Reason.INVALID_CERTIFICATE
                        || reason == Reason.INVALID_CERTIFICATE_PURPOSE) {
                    assertEquals(AppleStatus.RECEIPT_NOT_AUTHENTICATED, status);
                }
            }
        }
    }

    @Test
    void sharedVerifierIsThreadSafeUnderMixedLoad() throws Exception {
        List<Object[]> pool = new ArrayList<>();
        pool.add(new Object[] {myVerifier, myGenuine, Boolean.TRUE, null});
        pool.add(new Object[] {pkiVerifier, pkiGenuine, Boolean.TRUE, null});
        pool.add(new Object[] {
            myVerifier, b64(TestPki.corruptSignatures(myGenuineDer, 1)), Boolean.FALSE, Reason.INVALID_SIGNATURE
        });
        pool.add(new Object[] {myVerifier, "AAAA", Boolean.FALSE, Reason.MALFORMED});
        pool.add(new Object[] {
            myVerifier, myGenuine.substring(0, myGenuine.length() / 2), Boolean.FALSE, Reason.MALFORMED
        });
        ExecutorService threads = Executors.newFixedThreadPool(12);
        List<Callable<Boolean>> jobs = new ArrayList<>();
        long start = System.nanoTime();
        for (int t = 0; t < 12; t++) {
            final int seed = t;
            jobs.add(() -> {
                for (int round = 0; round < 25; round++) {
                    for (int i = 0; i < pool.size(); i++) {
                        Object[] item = pool.get((i + seed) % pool.size());
                        Verifier v = (Verifier) item[0];
                        String receipt = (String) item[1];
                        boolean expectVerified = (Boolean) item[2];
                        Reason expectReason = (Reason) item[3];
                        VerificationResult<ReceiptPayload> result = v.verifyReceipt(receipt);
                        if (result.verified() != expectVerified) {
                            return false;
                        }
                        if (!expectVerified && result.failure().reason() != expectReason) {
                            return false;
                        }
                        if (result.verified() != (endpointStatusOf(v, receipt) == AppleStatus.OK)) {
                            return false;
                        }
                    }
                }
                return true;
            });
        }
        List<Future<Boolean>> results = threads.invokeAll(jobs);
        threads.shutdown();
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println(
                "deep concurrency: " + 12 * 25 * pool.size() * 2 + " mixed ops on shared verifiers in " + ms + " ms");
        for (Future<Boolean> result : results) {
            assertTrue(result.get(), "a worker saw a cross-contaminated verdict");
        }
    }

    @Test
    void deepRandomFuzzNeverVerifiesNeverThrows() {
        long worst = 0;
        for (int i = 0; i < 300; i++) {
            int size = i < 50 ? 3_000_000 + RANDOM.nextInt(100_000) : RANDOM.nextInt(1_000_000);
            byte[] bytes = new byte[size];
            RANDOM.nextBytes(bytes);
            String receipt = i % 10 == 0 ? new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1) : b64(bytes);
            long start = System.nanoTime();
            VerificationResult<ReceiptPayload> result = myVerifier.verifyReceipt(receipt);
            long ms = (System.nanoTime() - start) / 1_000_000;
            worst = Math.max(worst, ms);
            assertFalse(result.verified(), "random input " + i + " verified");
            assertNotNull(result.failure());
            assertTrue(
                    result.failure().reason() != Reason.INTERNAL_ERROR,
                    "random input " + i + " answered INTERNAL_ERROR");
        }
        System.out.println("deep 300 random inputs (up to 3.1 MB): worst " + worst + " ms");
        assertTrue(worst < BUDGET_MS, "a random input took " + worst + " ms");
    }

    /** Writes garbage as the signature while announcing any TBS label the caller wants. */
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

    /** Signs for real (SHA256withRSA) while announcing a different TBS label. */
    private static final class MislabelingSigner implements ContentSigner {
        private final ContentSigner real;
        private final AlgorithmIdentifier label;

        MislabelingSigner(ContentSigner real, AlgorithmIdentifier label) {
            this.real = real;
            this.label = label;
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return label;
        }

        @Override
        public OutputStream getOutputStream() {
            return real.getOutputStream();
        }

        @Override
        public byte[] getSignature() {
            return real.getSignature();
        }
    }
}
