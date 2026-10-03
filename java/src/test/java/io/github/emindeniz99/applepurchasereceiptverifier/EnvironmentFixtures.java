package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.List;

/**
 * Writes the inputs of the shared cases for where a JWS states its
 * environment (docs/rust-core/DECISIONS.md R42) into the directory given as
 * the first argument (default {@code fixtures/generated-0.7}). Every file
 * is prefixed {@code environment-}, and {@code environment-jws-root.der} is
 * the root they chain to.
 *
 * <p>The core and this implementation read the environment from the first
 * of three places Apple documents that is present: the top-level
 * {@code environment} (a transaction, renewal info), {@code data.environment}
 * (an App Store Server Notification V2) and {@code summary.environment} (a
 * summary notification). Apple's own test notification in
 * {@code fixtures/apple-official} covers {@code data} with {@code Sandbox};
 * these cover {@code Production} at each place, and a payload whose first
 * place names neither environment while a later one does.</p>
 *
 * <p>The chain is valid from 2024-01-01 to 2050-01-01 and every payload is
 * signed on 2024-08-06. Run it the way {@link ReviewParityFixtures}
 * documents. Each run mints fresh keys, so regenerating changes the bytes of
 * every file and every {@code contentSha256} that records them.</p>
 */
public final class EnvironmentFixtures {

    private static final String BUNDLE = "com.example.app";
    private static final long NOT_BEFORE = 1704067200000L; // 2024-01-01
    private static final long NOT_AFTER = 2524608000000L; // 2050-01-01
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z

    private Path out;

    private EnvironmentFixtures() {}

    public static void main(String[] args) throws Exception {
        EnvironmentFixtures generator = new EnvironmentFixtures();
        generator.out =
                args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(generator.out);
        generator.run();
    }

    private void run() throws Exception {
        TestPki pki = TestPki.jws(true, true, new Date(NOT_BEFORE), new Date(NOT_AFTER));
        write("environment-jws-root.der", pki.root.getEncoded());
        String header = header(pki);

        // A transaction: the top-level claim.
        write(
                "environment-transaction-production.jws",
                pki.signJwsWithHeader(
                        header,
                        "{\"transactionId\":\"2000000000000002\",\"originalTransactionId\":\"2000000000000002\","
                                + "\"bundleId\":\"" + BUNDLE + "\",\"productId\":\"" + BUNDLE + ".pro\","
                                + "\"purchaseDate\":1722945000000,\"originalPurchaseDate\":1722945000000,"
                                + "\"quantity\":1,\"type\":\"Auto-Renewable Subscription\","
                                + "\"inAppOwnershipType\":\"PURCHASED\",\"signedDate\":" + SIGNED_DATE
                                + ",\"environment\":\"Production\"}"));

        // An App Store Server Notification V2: data.environment.
        write(
                "environment-notification-production.jws",
                pki.signJwsWithHeader(
                        header,
                        "{\"notificationType\":\"DID_RENEW\",\"notificationUUID\":"
                                + "\"5b9e3c1a-6f0d-4a52-9d3e-2c7a1b8e4f60\",\"version\":\"2.0\",\"signedDate\":"
                                + SIGNED_DATE + ",\"data\":{\"appAppleId\":1234567890,\"bundleId\":\"" + BUNDLE
                                + "\",\"bundleVersion\":\"1.0\",\"environment\":\"Production\",\"status\":1}}"));

        // A summary notification (RENEWAL_EXTENSION, SUMMARY): summary.environment.
        write(
                "environment-summary-notification.jws",
                pki.signJwsWithHeader(
                        header,
                        "{\"notificationType\":\"RENEWAL_EXTENSION\",\"subtype\":\"SUMMARY\",\"notificationUUID\":"
                                + "\"0f4b2d6e-8a1c-4e3f-b5d7-9c2e6a1f3b84\",\"version\":\"2.0\",\"signedDate\":"
                                + SIGNED_DATE + ",\"summary\":{\"requestIdentifier\":"
                                + "\"b3c1e2d4-5f6a-4b7c-8d9e-0a1b2c3d4e5f\",\"environment\":\"Production\","
                                + "\"appAppleId\":1234567890,\"bundleId\":\"" + BUNDLE + "\",\"productId\":\""
                                + BUNDLE + ".pro\",\"storefrontCountryCodes\":[\"USA\"],"
                                + "\"succeededCount\":5,\"failedCount\":0}}"));

        // The first place present decides: a top-level environment that
        // names neither environment wins over data.environment.
        write(
                "environment-first-present-wins.jws",
                pki.signJwsWithHeader(
                        header,
                        "{\"notificationType\":\"TEST\",\"notificationUUID\":"
                                + "\"9d8c7b6a-5e4f-4a3b-8c2d-1e0f9a8b7c6d\",\"version\":\"2.0\",\"signedDate\":"
                                + SIGNED_DATE + ",\"environment\":\"Xcode\",\"data\":{\"bundleId\":\"" + BUNDLE
                                + "\",\"environment\":\"Sandbox\"}}"));
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
