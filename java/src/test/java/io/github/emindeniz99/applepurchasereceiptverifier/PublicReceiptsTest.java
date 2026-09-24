package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.CollectionStore;
import org.junit.jupiter.api.Test;

/**
 * The strongest fixture tier: genuine Apple-signed receipts (vendored from
 * MIT-licensed public test suites — see fixtures/public-receipts/README.md)
 * verified against the REAL pinned Apple Inc. Root CA.
 *
 * <p>The verdicts on these receipts are pinned in {@code fixtures/cases.json}
 * and asserted by {@link ConformanceCasesTest}. What is left here is the one
 * thing a language-neutral vector cannot express: a bound read back out of the
 * rejection message it produces.</p>
 */
class PublicReceiptsTest {

    private static final Path FIXTURES = TestFixtures.publicReceipts();

    private static String receipt(String name) throws Exception {
        return new String(Files.readAllBytes(FIXTURES.resolve(name + ".b64")), StandardCharsets.US_ASCII).trim();
    }

    @Test
    void theEmbeddedCertificateBoundClearsEveryGenuineChain() throws Exception {
        // The bound is only safe if it sits above the largest chain Apple
        // actually ships, and MAXIMUM_EMBEDDED_CERTIFICATES is private to
        // another package, so its value is read where the implementation
        // states it: out of the rejection it raises. That takes making the
        // bound fire — a genuine receipt re-packed with copies of its own
        // certificates, which is rejected on the count while the payload,
        // signature and chain stay the genuine ones.
        //
        // Fails if the bound stops firing (nothing is thrown, the receipt
        // verifies) and if it is tightened to 3 or below (the ceiling it
        // reports no longer clears sandbox-g5's three-certificate chain).
        // It does NOT check that the rejection happens before the embedded
        // certificates are decoded — that is
        // ReceiptVerifierTest#countsEmbeddedCertificatesBeforeDecodingAnyOfThem.
        int largestGenuine = 0;
        for (String name :
                new String[] {"receipt-sandbox-g5", "receipt-sandbox-legacy", "receipt-xcode-with-purchases"}) {
            int embedded = new CMSSignedData(Base64.getMimeDecoder().decode(receipt(name)))
                    .getCertificates()
                    .getMatches(null)
                    .size();
            largestGenuine = Math.max(largestGenuine, embedded);
        }

        CMSSignedData genuine = new CMSSignedData(Base64.getMimeDecoder().decode(receipt("receipt-sandbox-g5")));
        // 64 copies: far above any ceiling that could still clear a genuine
        // three-certificate chain, so the bound fires wherever it is set.
        List<X509CertificateHolder> flood = new ArrayList<X509CertificateHolder>();
        while (flood.size() < 64) {
            flood.addAll(genuine.getCertificates().getMatches(null));
        }
        final byte[] flooded = CMSSignedData.replaceCertificatesAndCRLs(
                        genuine, new CollectionStore<X509CertificateHolder>(flood), null, null)
                .getEncoded();

        ReceiptVerifier verifier = new ReceiptVerifier(AppleRootCerts.receiptRoots(), "dev.bonzer.weeka.app");
        VerificationException e = assertThrows(VerificationException.class, () -> verifier.verify(flooded));
        Matcher reported = Pattern.compile("more than the maximum of (\\d+)").matcher(e.getMessage());
        assertTrue(reported.find(), e.getMessage());
        assertTrue(
                Integer.parseInt(reported.group(1)) > largestGenuine,
                "bound of " + reported.group(1) + " does not clear the largest genuine chain, " + "which embeds "
                        + largestGenuine + " certificates");
    }

    /**
     * Genuine Apple receipts carry no CMS signed attributes, unlike every
     * receipt the test PKI builds, so the RSA check here runs over the
     * content itself. One byte of the bundle id changed inside a genuine
     * receipt must fail that check, with the chain and the creation date
     * left exactly as Apple signed them.
     */
    @Test
    void aGenuineReceiptWithOneContentByteChangedIsAnInvalidSignature() throws Exception {
        byte[] genuine = Base64.getMimeDecoder().decode(receipt("receipt-sandbox-g5"));
        ReceiptVerifier verifier = new ReceiptVerifier(AppleRootCerts.receiptRoots(), "dev.bonzer.weeka.app");
        verifier.verify(genuine);

        byte[] bundleId = "dev.bonzer.weeka.app".getBytes(StandardCharsets.UTF_8);
        int at = indexOf(genuine, bundleId);
        assertTrue(at > 0, "bundle id not found in the receipt");
        final byte[] tampered = genuine.clone();
        tampered[at + bundleId.length - 1] ^= 0x01;

        VerificationException e = assertThrows(VerificationException.class, () -> verifier.verify(tampered));
        assertEquals(VerificationException.Reason.INVALID_SIGNATURE, e.reason(), e.getMessage());
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
}
