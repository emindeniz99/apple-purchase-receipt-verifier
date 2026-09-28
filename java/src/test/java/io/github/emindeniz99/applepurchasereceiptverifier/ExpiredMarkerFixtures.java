package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Date;

/**
 * Writes the inputs of the shared cases that pin validity before the marker
 * check, into the directory given as the first argument (default
 * {@code fixtures/generated-0.7}). Every file is prefixed
 * {@code expired-marker-}.
 *
 * <p>Each input is signed genuinely under its own chain, valid only from
 * 2020-01-01 to 2021-01-01, while the receipt or JWS is dated 2024-08-06, so
 * the chain instant is outside validity. The one other defect is a missing
 * Apple marker OID: on the leaf, or on the intermediate. Each chain's root is
 * written beside its input as {@code <input>-root.der}.</p>
 *
 * <p>Run it the way {@link ReviewParityFixtures} documents. Each run mints
 * fresh keys.</p>
 */
public final class ExpiredMarkerFixtures {

    private static final String BUNDLE = "com.example.app";
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";

    private final Date nb = new Date(1577836800000L); // 2020-01-01
    private final Date na = new Date(1609459200000L); // 2021-01-01
    private Path out;

    private ExpiredMarkerFixtures() {}

    public static void main(String[] args) throws Exception {
        ExpiredMarkerFixtures generator = new ExpiredMarkerFixtures();
        generator.out =
                args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(generator.out);
        generator.run();
    }

    private void run() throws Exception {
        byte[] payload = TestPki.receiptPayload(
                BUNDLE, "1.2.3", new byte[] {1, 2, 3, 4}, new byte[20], CREATION_DATE, Collections.<byte[]>emptyList());
        receipt("expired-marker-receipt-signer-without-marker", TestPki.receipt(nb, na, false, true), payload);
        receipt("expired-marker-receipt-intermediate-without-marker", TestPki.receipt(nb, na, true, false), payload);
        jws("expired-marker-jws-leaf-without-marker", TestPki.jws(false, true, nb, na));
        jws("expired-marker-jws-intermediate-without-marker", TestPki.jws(true, false, nb, na));
    }

    private void receipt(String name, TestPki pki, byte[] payload) throws Exception {
        write(name + "-root.der", pki.root.getEncoded());
        write(name + ".der", pki.signReceipt(payload, new Date(SIGNED_DATE)));
    }

    private void jws(String name, TestPki pki) throws Exception {
        write(name + "-root.der", pki.root.getEncoded());
        String jws = pki.signJws(TestPki.claims(
                "bundleId",
                BUNDLE,
                "environment",
                "Sandbox",
                "signedDate",
                SIGNED_DATE,
                "productId",
                BUNDLE + ".pro",
                "transactionId",
                "2000000000000001"));
        write(name + ".jws", jws.getBytes(StandardCharsets.US_ASCII));
    }

    private void write(String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
