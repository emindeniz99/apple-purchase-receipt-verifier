package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.List;

/**
 * Writes the inputs of the shared cases for the date a JWS's chain is judged
 * at when the payload states no {@code signedDate} (owner Q67, 2026-10-06)
 * into the directory given as the first argument (default
 * {@code fixtures/generated-0.7}). Every file is prefixed
 * {@code creation-date-}, and {@code creation-date-jws-root.der} is the root
 * they chain to.
 *
 * <p>An app transaction carries {@code receiptCreationDate}, and Apple's App
 * Store Server Library judges its chain there when {@code signedDate} is
 * absent. The chain is valid from 2020-01-01 to 2021-01-01, so the config
 * clock (2025-01-01) is outside it and only a date from the payload can make
 * a JWS verify. Run it the way {@link ReviewParityFixtures} documents. Each
 * run mints fresh keys, so regenerating changes the bytes of every file and
 * every {@code contentSha256} that records them.</p>
 */
public final class CreationDateFixtures {

    private static final long NOT_BEFORE = 1577836800000L; // 2020-01-01
    private static final long NOT_AFTER = 1609459200000L; // 2021-01-01
    private static final long INSIDE = 1590969600000L; // 2020-06-01
    private static final long OUTSIDE = 1722945600000L; // 2024-08-06T12:00:00Z

    private Path out;

    private CreationDateFixtures() {}

    public static void main(String[] args) throws Exception {
        CreationDateFixtures generator = new CreationDateFixtures();
        generator.out =
                args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(generator.out);
        generator.run();
    }

    private void run() throws Exception {
        TestPki pki = TestPki.jws(true, true, new Date(NOT_BEFORE), new Date(NOT_AFTER));
        write("creation-date-jws-root.der", pki.root.getEncoded());
        String header = header(pki);

        write("creation-date-inside-the-chain.jws", pki.signJwsWithHeader(header, appTransaction(INSIDE, "")));
        write("creation-date-outside-the-chain.jws", pki.signJwsWithHeader(header, appTransaction(OUTSIDE, "")));
        // Both dates: signedDate, the moment Apple signed, decides.
        write(
                "creation-date-signed-date-wins.jws",
                pki.signJwsWithHeader(header, appTransaction(OUTSIDE, ",\"signedDate\":" + INSIDE)));
    }

    private static String appTransaction(long receiptCreationDate, String extra) {
        return "{\"receiptType\":\"Sandbox\",\"appAppleId\":1234567890,\"bundleId\":\"com.example.app\","
                + "\"applicationVersion\":\"1\",\"versionExternalIdentifier\":0,\"receiptCreationDate\":"
                + receiptCreationDate + ",\"originalPurchaseDate\":" + NOT_BEFORE
                + ",\"originalApplicationVersion\":\"1\",\"deviceVerification\":\"AAAA\","
                + "\"deviceVerificationNonce\":\"00000000-0000-4000-8000-000000000000\","
                + "\"appTransactionId\":\"704289572311950000\",\"originalPlatform\":\"iOS\""
                + extra + "}";
    }

    private static String header(TestPki pki) throws Exception {
        List<String> x5c = pki.x5c();
        return "{\"alg\":\"ES256\",\"x5c\":[\"" + x5c.get(0) + "\",\"" + x5c.get(1) + "\",\"" + x5c.get(2) + "\"]}";
    }

    private void write(String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }

    private void write(String name, String text) throws Exception {
        write(name, text.getBytes(StandardCharsets.US_ASCII));
    }
}
