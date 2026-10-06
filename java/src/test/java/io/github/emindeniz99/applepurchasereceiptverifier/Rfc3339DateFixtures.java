package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Writes the inputs of the shared cases for the owner decision that a
 * receipt date is an RFC 3339 {@code date-time} (Q68, 2026-10-06) into the
 * directory given as the first argument (default
 * {@code fixtures/generated-0.7}). Every file is prefixed {@code q68-}, and
 * {@code q68-receipt-root.der} is the root they chain to.
 *
 * <p>The chain is valid from 2020-01-01 to 2021-01-01, so it has expired:
 * a creation date that reads puts the chain instant inside or outside that
 * window, and one that does not leaves it to the clock. Every receipt is
 * signed on 2020-06-01. {@code OwnerDecisionFixtures}' date-grammar receipt
 * already carries a lowercase {@code t} and {@code z}, a {@code .5}
 * fraction, a {@code +03:00} offset and second 60; this adds the rest.</p>
 *
 * <p>Run it the way {@link ReviewParityFixtures} documents. Each run mints
 * fresh keys, so regenerating changes the bytes of every file and every
 * {@code contentSha256} that records them.</p>
 */
public final class Rfc3339DateFixtures {

    private static final String BUNDLE = "com.example.app";
    private static final long NOT_BEFORE = 1577836800000L; // 2020-01-01
    private static final long NOT_AFTER = 1609459200000L; // 2021-01-01
    private static final long SIGNED_DATE = 1591012800000L; // 2020-06-01T12:00:00Z

    /** Purchase dates, one in-app purchase each, keyed by transaction id suffix. */
    private static final String[][] PURCHASE_DATES = {
        {"301", "2024-08-06T12:00:00.123456789012Z"},
        {"302", "2024-08-06T12:00:00.9999Z"},
        {"303", "2024-08-06T01:00:00+03:00"},
        {"304", "2024-08-06T12:00:00-05:30"},
        {"305", "2024-08-06T12:00:00-00:00"},
        {"306", "2016-12-31T15:59:60.5-08:00"},
        {"307", "0000-01-01T00:00:00.5Z"},
        {"308", "9999-12-31T23:59:59.999Z"},
        {"311", "2024-08-06T12:00:00.Z"},
        {"312", "2024-08-06T12:00:00,5Z"},
        {"313", "2024-08-06T12:00:00+24:00"},
        {"314", "2024-08-06T12:00:00+0300"},
        {"315", "2024-08-06T12:00:61Z"},
        {"316", "2024-08-06 12:00:00Z"},
        {"317", "2024-08-06T12:00Z"},
        {"318", "9999-12-31T23:59:59-00:01"},
        {"319", "0000-01-01T00:00:00+00:01"},
    };

    private Path out;
    private TestPki pki;

    private Rfc3339DateFixtures() {}

    public static void main(String[] args) throws Exception {
        Rfc3339DateFixtures generator = new Rfc3339DateFixtures();
        generator.out =
                args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(generator.out);
        generator.run();
    }

    private void run() throws Exception {
        pki = TestPki.receipt(new Date(NOT_BEFORE), new Date(NOT_AFTER));
        write("q68-receipt-root.der", pki.root.getEncoded());

        // Every date attribute in an RFC 3339 form: the two top-level ones,
        // the four in-app ones on purchase 300, and one purchase date per
        // vector on the purchases after it.
        ASN1EncodableVector receipt = header("2020-06-01T12:00:00Z");
        receipt.add(TestPki.attribute(18, ia5("2013-08-01t00:00:00.25-07:00")));
        receipt.add(TestPki.attribute(21, ia5("4001-01-01T00:00:00+00:00")));
        ASN1EncodableVector every = purchase("300", "2024-08-06T12:00:00.5+01:00");
        every.add(TestPki.attribute(1706, ia5("2024-08-01t12:00:00z")));
        every.add(TestPki.attribute(1708, ia5("2024-09-06T12:00:00.001-00:00")));
        every.add(TestPki.attribute(1712, ia5("2024-08-07T00:00:00+12:00")));
        receipt.add(TestPki.attribute(17, new DERSet(every).getEncoded()));
        for (String[] vector : PURCHASE_DATES) {
            receipt.add(TestPki.attribute(17, new DERSet(purchase(vector[0], vector[1])).getEncoded()));
        }
        write("q68-receipt-date-forms.der", sign(receipt));

        // The creation date in each new form, inside the chain's window, and
        // a fraction and an offset that each move it past the window's end.
        write("q68-receipt-creation-date-fraction.der", sign(header("2020-06-01T12:00:00.123Z")));
        write("q68-receipt-creation-date-offset.der", sign(header("2020-06-01T15:00:00+03:00")));
        write("q68-receipt-creation-date-lowercase.der", sign(header("2020-06-01t12:00:00z")));
        write("q68-receipt-creation-date-fraction-past-not-after.der", sign(header("2021-01-01T00:00:00.001Z")));
        write("q68-receipt-creation-date-offset-past-not-after.der", sign(header("2020-12-31T23:30:00-01:00")));
    }

    /** Receipt type, bundle id and creation date. */
    private static ASN1EncodableVector header(String creationDate) throws Exception {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(TestPki.attribute(0, new DERUTF8String("ProductionSandbox").getEncoded()));
        vector.add(TestPki.attribute(2, new DERUTF8String(BUNDLE).getEncoded()));
        vector.add(TestPki.attribute(12, ia5(creationDate)));
        return vector;
    }

    private static ASN1EncodableVector purchase(String suffix, String purchaseDate) throws Exception {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(TestPki.attribute(1701, new ASN1Integer(1).getEncoded()));
        vector.add(TestPki.attribute(1702, new DERUTF8String(BUNDLE + ".coins").getEncoded()));
        vector.add(TestPki.attribute(1703, new DERUTF8String("70000000000" + suffix).getEncoded()));
        vector.add(TestPki.attribute(1704, ia5(purchaseDate)));
        return vector;
    }

    private static byte[] ia5(String s) throws Exception {
        return new DERIA5String(s).getEncoded();
    }

    private byte[] sign(ASN1EncodableVector attributes) throws Exception {
        return pki.signReceipt(new DERSet(attributes).getEncoded(), new Date(SIGNED_DATE));
    }

    private void write(String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
