package io.github.emindeniz99.applepurchasereceiptverifier;

import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.EnumSet;

/**
 * The child JVM of {@link ChainAlgorithmsTest}: run under a host policy, it
 * prints what each constructor and verification did, one line each.
 */
public final class HostPolicyProbe {

    private HostPolicyProbe() {}

    public static void main(String[] args) throws Exception {
        try {
            new ReceiptVerifier(AppleRootCerts.receiptRoots(), "com.example.app");
            System.out.println("default: constructed");
        } catch (IllegalStateException e) {
            System.out.println("default: IllegalStateException " + e.getMessage());
        }

        EnumSet<SignatureAlgorithm> withoutSha1 = EnumSet.of(SignatureAlgorithm.SHA256_WITH_RSA);
        ReceiptVerifier.verifyReceiptCore(receipt("receipt-sandbox-g5"), AppleRootCerts.receiptRoots(), withoutSha1);
        System.out.println("without SHA-1: current receipt verifies");
        try {
            ReceiptVerifier.verifyReceiptCore(
                    receipt("receipt-sandbox-legacy"), AppleRootCerts.receiptRoots(), withoutSha1);
            System.out.println("without SHA-1: legacy receipt verified");
        } catch (VerificationException e) {
            System.out.println("without SHA-1: legacy receipt " + e.reason());
        }

        new JwsVerifier(AppleRootCerts.jwsRoots(), "com.example.app", EnumSet.of(Environment.SANDBOX));
        System.out.println("jws default: constructed");
    }

    private static byte[] receipt(String name) throws Exception {
        return Base64.getMimeDecoder()
                .decode(new String(
                        Files.readAllBytes(Paths.get("..", "fixtures", "public-receipts", name + ".b64")),
                        StandardCharsets.US_ASCII));
    }
}
