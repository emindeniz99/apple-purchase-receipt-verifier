package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Date;

/**
 * Writes the inputs of the shared case on which embedded certificate a
 * SignerInfo resolves to, into the directory given as the first argument
 * (default {@code fixtures/generated-0.7}). Every file is prefixed
 * {@code lookup-}.
 *
 * <p>{@code lookup-receipt-twin-ahead-of-signer.der} is a genuine receipt,
 * signed by the genuine leaf, whose unsigned certificate bag carries a twin
 * of the leaf (same issuer, serial and subject, another key, self-signed)
 * ahead of it. It verifies under {@code lookup-receipt-root.der}. The chain
 * is valid from 2024-01-01 to 2050-01-01 and the receipt states the creation
 * date 2024-08-06.</p>
 *
 * <p>Run it the way {@link ReviewParityFixtures} documents. Each run mints
 * fresh keys, so regenerating changes every file and its
 * {@code contentSha256}.</p>
 */
public final class SignerLookupFixtures {

    private static final String BUNDLE = "com.example.app";
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";

    private SignerLookupFixtures() {}

    public static void main(String[] args) throws Exception {
        Path out = args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(out);
        TestPki pki = TestPki.receipt(new Date(1704067200000L), new Date(2524608000000L));
        byte[] payload = TestPki.receiptPayload(
                BUNDLE, "1.2.3", new byte[] {1, 2, 3, 4}, new byte[20], CREATION_DATE, Collections.<byte[]>emptyList());
        write(out, "lookup-receipt-root.der", pki.root.getEncoded());
        write(out, "lookup-receipt-twin-ahead-of-signer.der", pki.signReceiptWithTwinAheadOfSigner(payload));
    }

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
