package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSet;

/**
 * Generates synthetic in-app attribute 1720 receipts. No production data.
 * Run after test-compile with the test dependency classpath, passing the output directory.
 * Each run mints fresh signing keys; refresh fixture hashes after regenerating.
 */
public final class CancellationReasonFixtures {

    private static final String BUNDLE = "com.example.app";

    // The same fixed instants the other receipt generators use.
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";
    private static final long CHAIN_NOT_BEFORE = 1704067200000L; // 2024-01-01
    private static final long CHAIN_NOT_AFTER = 2524608000000L; // 2050-01-01

    private static final byte[] GUID = {
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        (byte) 0x88,
        (byte) 0x99,
        (byte) 0xaa,
        (byte) 0xbb,
        (byte) 0xcc,
        (byte) 0xdd,
        (byte) 0xee,
        (byte) 0xff,
        0x00
    };
    private static final byte[] OPAQUE = {1, 2, 3, 4, 5, 6, 7, 8};

    private CancellationReasonFixtures() {}

    public static void main(String[] args) throws Exception {
        Path out = args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(out);

        TestPki pki = TestPki.receipt(new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        write(out, "cancellation-reason-root.der", pki.root.getEncoded());

        for (String shape : Arrays.asList("zero", "one", "absent", "malformed", "duplicate")) {
            List<ASN1Encodable> extras = new ArrayList<>();
            if ("zero".equals(shape)) extras.add(integerAttribute(1720, 0));
            if ("one".equals(shape) || "duplicate".equals(shape)) extras.add(integerAttribute(1720, 1));
            if ("malformed".equals(shape))
                extras.add(TestPki.attribute(1720, new DERUTF8String("invalid").getEncoded()));
            if ("duplicate".equals(shape)) extras.add(integerAttribute(1720, 0));
            byte[] purchase = TestPki.inAppPurchase(
                    1, "com.example.app.test", "70000000000501", "70000000000501", "2024-01-15T12:00:00Z", null);
            ASN1Set original = ASN1Set.getInstance(purchase);
            ASN1EncodableVector values = new ASN1EncodableVector();
            for (ASN1Encodable value : original) values.add(value);
            for (ASN1Encodable value : extras) values.add(value);
            byte[] changed = new DLSet(values).getEncoded();
            byte[] payload = TestPki.receiptPayload(
                    "ProductionSandbox",
                    BUNDLE,
                    "1.2.3",
                    OPAQUE,
                    TestPki.deviceHash(GUID, OPAQUE, BUNDLE),
                    CREATION_DATE,
                    Collections.singletonList(changed),
                    true,
                    null,
                    new byte[] {1, 2, 3},
                    Collections.emptyList());
            write(out, "cancellation-reason-" + shape + ".der", pki.signReceipt(payload, new Date(SIGNED_DATE)));
        }
    }

    private static ASN1Encodable integerAttribute(int type, long value) throws Exception {
        return TestPki.attribute(type, new ASN1Integer(value).getEncoded());
    }

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
