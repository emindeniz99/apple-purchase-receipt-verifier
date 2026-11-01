package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Red-team smoke over the attack shapes a hostile receipt reaches. Every case is a real attack
 * (not upstream's fixtures): each must be refused, refused fast, and never throw, and the never-throws
 * invariant is re-checked on random and mutated input. The wall-clock budget is upstream's per-case
 * figure (2000 ms): no hostile shape may cost seconds.
 */
class WorstCaseAttackSurfaceTest {

    private static final long BUDGET_MS = 2000;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern STATUS = Pattern.compile("\"status\":(\\d+)");

    private static TestPki pki;
    private static TestPki otherPki;
    private static TestPki deepPki;
    private static Verifier verifier;
    private static Verifier deepVerifier;
    private static String genuine;

    @BeforeAll
    static void mintPkiAndGenuineReceipt() throws Exception {
        pki = TestPki.receipt();
        otherPki = TestPki.receipt();
        // 7 intermediates + 1 self-issued tail: 10 embedded certificates (the cap), a path of 9 below the anchor (the
        // builder's bound is 7).
        deepPki = TestPki.deepReceipt(7, 1);
        verifier = Verifier.create(
                Config.builder().roots(Collections.singleton(pki.root)).build());
        deepVerifier = Verifier.create(
                Config.builder().roots(Collections.singleton(deepPki.root)).build());
        genuine = Base64.getEncoder().encodeToString(pki.signReceipt(payload()));
    }

    private static byte[] payload() throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        return TestPki.receiptPayload(
                "com.example.app",
                "1.0",
                new byte[] {1, 2, 3, 4},
                new byte[] {5, 6, 7, 8},
                now.toString(),
                Collections.singletonList(
                        TestPki.inAppPurchase(1, "gems.small", "2001", "2001", now.toString(), null)));
    }

    /** One attack receipt: never verifies, refuses as {@code expected}, inside the budget; prints the cost. */
    private static void refused(String what, Verifier v, String receipt, Reason expected) {
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result = v.verifyReceipt(receipt);
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("worstCase " + what + ": " + ms + " ms, "
                + (result.verified() ? "VERIFIED" : result.failure().reason()));
        assertFalse(result.verified(), what + " verified");
        assertEquals(expected, result.failure().reason(), what + " refused as the wrong reason after " + ms + " ms");
        assertTrue(ms < BUDGET_MS, what + " took " + ms + " ms, over the " + BUDGET_MS + " ms budget");
    }

    @Test
    void controlGenuineReceiptVerifiesUnderThePinnedRoot() {
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(genuine);
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("worstCase genuine control: " + ms + " ms, " + result.verified());
        assertTrue(result.verified(), "the genuine control receipt did not verify: " + result.failure());
        assertEquals("com.example.app", result.payload().bundleId());
        assertTrue(ms < BUDGET_MS, "the genuine control took " + ms + " ms");
    }

    @Test
    void asn1NestedFiveHundredDeepIsRefusedAsMalformedFast() throws Exception {
        ASN1Encodable nested = new ASN1Integer(0);
        for (int i = 0; i < 500; i++) {
            nested = new DERSequence(nested);
        }
        refused(
                "nesting-500-deep",
                verifier,
                Base64.getEncoder().encodeToString(nested.toASN1Primitive().getEncoded()),
                Reason.MALFORMED);
    }

    @Test
    void receiptOverTheSizeCapIsRefusedBeforeAnythingIsDecoded() {
        StringBuilder oversized = new StringBuilder(4 * 1024 * 1024);
        for (int i = 0; i < 4 * 1024 * 1024; i++) {
            oversized.append('A');
        }
        refused("oversized-4mib", verifier, oversized.toString(), Reason.TOO_LARGE);
    }

    @Test
    void nonCanonicalBase64IsRefusedAsMalformed() {
        refused("non-canonical-base64", verifier, genuine.substring(0, genuine.length() - 2) + "!!", Reason.MALFORMED);
        refused("empty-receipt", verifier, "", Reason.MALFORMED);
    }

    @Test
    void certificateBagPaddingIsRefusedOnTheCount() throws Exception {
        refused("bag-padded-203-certs", verifier, b64(pki.signReceiptWithPadding(payload(), 200)), Reason.MALFORMED);
        refused(
                "bag-hundred-leaf-copies",
                verifier,
                b64(pki.signReceiptWithLeafCopies(payload(), 100)),
                Reason.MALFORMED);
    }

    @Test
    void receiptOmittingTheSignerCertificateIsRefusedAsMalformed() throws Exception {
        refused("signer-omitted", verifier, b64(pki.signReceiptOmittingSigner(payload(), 20)), Reason.MALFORMED);
    }

    @Test
    void crossSignedMeshWithNoPathToTheAnchorIsRefusedFast() throws Exception {
        // 3 layers of 3 equally valid issuers each: 27 combinations for a builder that explores before it bounds.
        refused(
                "cross-signed-mesh-27-combos",
                verifier,
                b64(pki.signReceiptWithCrossSignedMesh(payload(), 3, 3)),
                Reason.UNTRUSTED_CHAIN);
    }

    @Test
    void chainDeeperThanTheBuildersBoundIsRefusedFast() throws Exception {
        refused("chain-9-deep", deepVerifier, b64(deepPki.signReceipt(payload())), Reason.UNTRUSTED_CHAIN);
    }

    @Test
    void signerInfoCountOverTheCapIsRefusedAsMalformed() throws Exception {
        List<TestPki> five = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            five.add(TestPki.receipt());
        }
        refused("five-signer-infos", verifier, b64(TestPki.signReceiptByEach(payload(), five)), Reason.MALFORMED);
    }

    @Test
    void twinCertCloningTheSignersIdentityIsRejected() throws Exception {
        // An attacker key whose certificate clones the genuine leaf's issuer, serial and subject, embedded first.
        refused(
                "twin-cert-identity-clone",
                verifier,
                b64(pki.signReceiptWithTwinCert(payload())),
                Reason.UNTRUSTED_CHAIN);
    }

    @Test
    void twinIntheBagDoesNotBreakAGenuineSignature() throws Exception {
        // Genuine signature, an attacker's twin ahead of the signer in the bag: the receipt must still verify.
        long start = System.nanoTime();
        VerificationResult<ReceiptPayload> result =
                verifier.verifyReceipt(b64(pki.signReceiptWithTwinAheadOfSigner(payload())));
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("worstCase twin-ahead control: " + ms + " ms, " + result.verified());
        assertTrue(result.verified(), "a genuine receipt with a twin in the bag was refused: " + result.failure());
        assertTrue(ms < BUDGET_MS);
    }

    @Test
    void validlySignedReceiptFromAnotherRootIsRefusedAsUntrusted() throws Exception {
        refused("wrong-root-pki", verifier, b64(otherPki.signReceipt(payload())), Reason.UNTRUSTED_CHAIN);
    }

    @Test
    void randomInputNeverThrowsNeverVerifiesAndIsNeverInternalError() {
        long worst = 0;
        for (int i = 0; i < 300; i++) {
            byte[] bytes = new byte[RANDOM.nextInt(100_000)];
            RANDOM.nextBytes(bytes);
            String receipt = i % 10 == 0
                    ? new String(bytes, StandardCharsets.ISO_8859_1)
                    : Base64.getEncoder().encodeToString(bytes);
            long start = System.nanoTime();
            VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(receipt);
            long ms = (System.nanoTime() - start) / 1_000_000;
            worst = Math.max(worst, ms);
            assertFalse(result.verified(), "random input " + i + " verified");
            assertNotNull(result.failure());
            assertTrue(
                    result.failure().reason() != Reason.INTERNAL_ERROR,
                    "random input " + i + " answered INTERNAL_ERROR");
        }
        System.out.println("worstCase 300 random inputs: worst " + worst + " ms");
        assertTrue(worst < BUDGET_MS, "a random input took " + worst + " ms");
    }

    @Test
    void bitFlippedGenuineReceiptsNeverVerifyADifferentPayload() throws Exception {
        // A flip may still verify when it lands in bytes no signature covers: the embedded copy
        // of the pinned root (its key comes from Config, not the bag), the outer contentType and
        // version, the digestAlgorithms SET, or the case of the signer's issuer name. Such a flip
        // must yield the genuine payload unchanged; every flip that would change it must refuse.
        // The flipped offsets depend on the receipt's length, which TestPki's JVM-wide serial
        // counter makes depend on the test classes that ran before this one.
        byte[] der = Base64.getDecoder().decode(genuine);
        ReceiptPayload genuinePayload = verifier.verifyReceipt(genuine).payload();
        assertNotNull(genuinePayload, "the genuine control receipt did not verify");
        Random random = new Random(20261015L);
        long worst = 0;
        int tolerated = 0;
        for (int i = 0; i < 300; i++) {
            byte[] mutated = der.clone();
            int index = random.nextInt(mutated.length);
            mutated[index] ^= 1 << random.nextInt(8);
            long start = System.nanoTime();
            VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(b64(mutated));
            long ms = (System.nanoTime() - start) / 1_000_000;
            worst = Math.max(worst, ms);
            if (result.verified()) {
                tolerated++;
                assertEquals(
                        genuinePayload,
                        result.payload(),
                        "a flip at byte " + index + " verified a different payload (" + i + ")");
            } else {
                assertTrue(
                        result.failure().reason() != Reason.INTERNAL_ERROR,
                        "a bit-flipped receipt answered INTERNAL_ERROR (" + i + ")");
            }
        }
        System.out.println("worstCase 300 bit flips: " + tolerated + " tolerated (all with the genuine payload) of "
                + der.length + " bytes, worst " + worst + " ms");
        assertTrue(worst < BUDGET_MS, "a bit-flipped receipt took " + worst + " ms");
    }

    @Test
    void endpointNeverAnswersTheAlertStatusOnHostileRequests() {
        long worst = 0;
        for (int i = 0; i < 200; i++) {
            byte[] bytes = new byte[RANDOM.nextInt(50_000)];
            RANDOM.nextBytes(bytes);
            String receiptData = i % 10 == 0
                    ? new String(bytes, StandardCharsets.ISO_8859_1)
                    : Base64.getEncoder().encodeToString(bytes);
            String body = "{\"receipt-data\":\"" + receiptData + "\"}";
            long start = System.nanoTime();
            String answer = verifier.verifyReceiptEndpoint(Environment.PRODUCTION, body);
            long ms = (System.nanoTime() - start) / 1_000_000;
            worst = Math.max(worst, ms);
            Matcher status = STATUS.matcher(answer);
            assertTrue(
                    status.find(),
                    "the endpoint answered no status: " + answer.substring(0, Math.min(100, answer.length())));
            int code = Integer.parseInt(status.group(1));
            assertTrue(code != 21009, "the endpoint answered the alert status 21009 on hostile input " + i);
        }
        System.out.println("worstCase 200 hostile endpoint calls: worst " + worst + " ms");
        assertTrue(worst < BUDGET_MS, "a hostile endpoint call took " + worst + " ms");
    }

    private static String b64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
