package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Date;

/**
 * Writes the receipt string that holds the base64 receipt cap from the
 * accepting side: {@code fixtures/limits/receipt-b64-at-cap.txt}, canonical
 * standard base64 of exactly 3,145,728 characters, and the root it verifies
 * under, {@code fixtures/generated/receipt-b64-cap-root.der}.
 *
 * <p>The cap counts the string a client sends, and the string must be
 * canonical base64 with nothing around it, so the only way to reach the cap
 * with a string that verifies is a genuinely signed receipt of exactly
 * 2,359,296 bytes of DER: 3,145,728 / 4 * 3, no padding. It is the
 * {@link LargeReceiptFixture} byte-floor shape grown to that size, the same
 * way that class grows it to the DER cap.</p>
 *
 * <p>A {@code main} for the same reason as the other generators. Regenerate
 * with (note the argument is {@code fixtures/}, not {@code fixtures/generated}):</p>
 *
 * <pre>
 * mvn -B -q -f java/pom.xml test-compile
 * mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
 * java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
 *      io.github.emindeniz99.applepurchasereceiptverifier.ReceiptBase64CapFixture \
 *      fixtures
 * node tools/generate-limit-fixtures.mjs   # the over-cap twin is built from this file
 * node tools/lint-cases.mjs                # re-hash: every contentSha256 must be updated
 * </pre>
 *
 * <p>Each run mints fresh keys, so regenerating changes every byte of both
 * files.</p>
 */
public final class ReceiptBase64CapFixture {

    private static final long CHAIN_NOT_BEFORE = 1704067200000L; // 2024-01-01
    private static final long CHAIN_NOT_AFTER = 2524608000000L; // 2050-01-01

    /** The receipt cap every port enforces on the base64 string. */
    private static final int STRING_CAP = 3 * 1024 * 1024;

    private ReceiptBase64CapFixture() {}

    public static void main(String[] args) throws Exception {
        Path fixtures = args.length > 0 ? Paths.get(args[0]) : TestFixtures.root();
        TestPki pki = TestPki.receipt(new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        byte[] der = LargeReceiptFixture.exactSize(pki, "receipt-b64-at-cap", STRING_CAP / 4 * 3);
        byte[] text = Base64.getEncoder().encode(der);
        if (text.length != STRING_CAP) {
            throw new IllegalStateException("built " + text.length + " characters, wanted " + STRING_CAP);
        }
        write(fixtures.resolve("generated"), "receipt-b64-cap-root.der", pki.root.getEncoded());
        write(fixtures.resolve("limits"), "receipt-b64-at-cap.txt", text);
    }

    private static void write(Path dir, String name, byte[] bytes) throws Exception {
        Files.createDirectories(dir);
        Files.write(dir.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
