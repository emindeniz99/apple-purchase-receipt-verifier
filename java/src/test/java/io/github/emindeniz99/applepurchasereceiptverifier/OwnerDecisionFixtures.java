package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;

/**
 * Writes the inputs of the shared cases for the owner decisions of
 * 2026-09-27 (chain before markers on the JWS path, validity before
 * signature, IA5String high bytes, the ASN.1 depth bound, malformed receipt
 * INTEGERs, the receipt date grammar, and the JSON name and number length
 * bounds) into the directory given as the first argument (default
 * {@code fixtures/generated-0.7}). Every file is prefixed {@code owner-}.
 *
 * <p>The synthetic chains are valid from 2024-01-01 to 2050-01-01 and every
 * receipt states the creation date 2024-08-06 unless a case says otherwise.
 * Roots are emitted beside the inputs: {@code owner-receipt-root.der} and
 * {@code owner-jws-root.der}.</p>
 *
 * <p>Two inputs are derived from committed files rather than minted: the
 * expired-chain twins with a broken signature flip one signature bit of
 * {@code receipt-expired-fresh.der} (in this directory) and of
 * {@code ../generated/expired-cert-fresh.jws}, so they keep the roots
 * {@code receipt-expired-root} and {@code jws-expired-root}.</p>
 *
 * <p>Run it the way {@link ReviewParityFixtures} documents. Each run mints
 * fresh keys, so regenerating changes the bytes of every minted file and
 * every {@code contentSha256} that records them.</p>
 */
public final class OwnerDecisionFixtures {

    private static final String BUNDLE = "com.example.app";
    private static final long NOT_BEFORE = 1704067200000L; // 2024-01-01
    private static final long NOT_AFTER = 2524608000000L; // 2050-01-01
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";

    /** Receipt date vectors, one per in-app purchase, keyed by transaction id suffix. */
    private static final String[][] DATE_VECTORS = {
        {"201", "0000-01-01T00:00:00Z"},
        {"202", "9999-12-31T23:59:59Z"},
        {"203", "2024-02-29T12:00:00Z"},
        {"204", "2000-02-29T12:00:00Z"},
        {"205", "2024-08-06T23:59:59Z"},
        {"211", "2024-08-06t12:00:00Z"},
        {"212", "2024-08-06T12:00:00z"},
        {"213", "2024-08-06T12:00:00.5Z"},
        {"214", "2024-08-06T12:00:00+03:00"},
        {"215", "2024-08-06T12:00:60Z"},
        {"216", "2023-02-29T12:00:00Z"},
        {"217", "1900-02-29T12:00:00Z"},
        {"218", "12024-08-06T12:00:00Z"},
        {"219", "2024-08-06T12:00:00"},
        {"220", "2024-08-06T24:00:00Z"},
    };

    private final Date nb = new Date(NOT_BEFORE);
    private final Date na = new Date(NOT_AFTER);
    private Path out;

    private OwnerDecisionFixtures() {}

    public static void main(String[] args) throws Exception {
        OwnerDecisionFixtures generator = new OwnerDecisionFixtures();
        generator.out =
                args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(generator.out);
        generator.run();
    }

    private void run() throws Exception {
        TestPki receipts = TestPki.receipt(nb, na);
        write("owner-receipt-root.der", receipts.root.getEncoded());
        TestPki jws = TestPki.jws(true, true, nb, na);
        write("owner-jws-root.der", jws.root.getEncoded());

        writeOrder(jws);
        writeDecodeRules(receipts);
        writeDepth(receipts);
        writeJsonBounds(jws);
    }

    // --- verification order ------------------------------------------------

    private void writeOrder(TestPki pinned) throws Exception {
        // A chain under a root nobody pins, with neither Apple marker: the
        // chain is judged before the markers.
        TestPki foreign = TestPki.jws(false, false, nb, na);
        write("owner-jws-foreign-chain-without-markers.jws", foreign.signJwsWithHeader(header(foreign), claims()));

        // Expired chains with a broken signature: validity is judged first.
        write(
                "owner-receipt-expired-bad-signature.der",
                TestPki.corruptSignatures(read("receipt-expired-fresh.der"), 1));
        String expired = new String(
                        Files.readAllBytes(out.resolveSibling("generated").resolve("expired-cert-fresh.jws")),
                        StandardCharsets.US_ASCII)
                .trim();
        String[] parts = expired.split("\\.", -1);
        byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
        signature[10] ^= 0x01;
        write("owner-jws-expired-bad-signature.jws", parts[0] + "." + parts[1] + "." + TestPki.b64url(signature));
    }

    // --- decode rules ------------------------------------------------------

    private void writeDecodeRules(TestPki pki) throws Exception {
        // IA5String values with a byte at or above 0x80. Each high byte is an
        // ASCII character with its top bit set, so a reader that masks the
        // top bit sees a well-formed value.
        byte[] version = "1.2.3".getBytes(StandardCharsets.US_ASCII);
        version[4] |= (byte) 0x80;
        byte[] date = CREATION_DATE.getBytes(StandardCharsets.US_ASCII);
        date[10] |= (byte) 0x80;
        byte[] product = (BUNDLE + ".coins").getBytes(StandardCharsets.US_ASCII);
        product[product.length - 1] |= (byte) 0x80;
        byte[] purchase = "2024-01-15T12:00:00Z".getBytes(StandardCharsets.US_ASCII);
        purchase[10] |= (byte) 0x80;
        ASN1EncodableVector iap = new ASN1EncodableVector();
        iap.add(TestPki.attribute(1701, integer(1)));
        iap.add(TestPki.attribute(1702, rawIa5(product)));
        iap.add(TestPki.attribute(1703, utf8("70000000000301")));
        iap.add(TestPki.attribute(1704, rawIa5(purchase)));
        write(
                "owner-receipt-ia5-high-bytes.der",
                sign(
                        pki,
                        attributes(
                                TestPki.attribute(0, utf8("ProductionSandbox")),
                                TestPki.attribute(2, utf8(BUNDLE)),
                                TestPki.attribute(3, rawIa5(version)),
                                TestPki.attribute(12, ia5(CREATION_DATE)),
                                TestPki.attribute(17, new DERSet(iap).getEncoded()),
                                TestPki.attribute(18, rawIa5(date)))));

        // INTEGER values that are not DER: non-minimal and empty.
        ASN1EncodableVector badIap = new ASN1EncodableVector();
        badIap.add(TestPki.attribute(1701, new byte[] {0x02, 0x02, (byte) 0xff, (byte) 0xff}));
        badIap.add(TestPki.attribute(1702, utf8(BUNDLE + ".coins")));
        badIap.add(TestPki.attribute(1703, utf8("70000000000302")));
        badIap.add(TestPki.attribute(1713, new byte[] {0x02, 0x00}));
        write(
                "owner-receipt-malformed-integers.der",
                sign(
                        pki,
                        attributes(
                                TestPki.attribute(0, utf8("ProductionSandbox")),
                                TestPki.attribute(1, new byte[] {0x02, 0x02, 0x00, 0x05}),
                                TestPki.attribute(2, utf8(BUNDLE)),
                                TestPki.attribute(12, ia5(CREATION_DATE)),
                                TestPki.attribute(15, new byte[] {0x02, 0x00}),
                                TestPki.attribute(17, new DERSet(badIap).getEncoded()))));

        // The date grammar: one in-app purchase per vector, its purchase date.
        ASN1EncodableVector grammar = new ASN1EncodableVector();
        grammar.add(TestPki.attribute(0, utf8("ProductionSandbox")));
        grammar.add(TestPki.attribute(2, utf8(BUNDLE)));
        grammar.add(TestPki.attribute(12, ia5(CREATION_DATE)));
        for (String[] vector : DATE_VECTORS) {
            ASN1EncodableVector purchaseSet = new ASN1EncodableVector();
            purchaseSet.add(TestPki.attribute(1701, integer(1)));
            purchaseSet.add(TestPki.attribute(1702, utf8(BUNDLE + ".coins")));
            purchaseSet.add(TestPki.attribute(1703, utf8("70000000000" + vector[0])));
            purchaseSet.add(TestPki.attribute(1704, ia5(vector[1])));
            grammar.add(TestPki.attribute(17, new DERSet(purchaseSet).getEncoded()));
        }
        write("owner-receipt-date-grammar.der", sign(pki, new DERSet(grammar).getEncoded()));

        // A creation date outside the grammar, naming an instant before the
        // chain's window: the clock decides the chain instead.
        write(
                "owner-receipt-creation-date-lowercase-t.der",
                sign(
                        pki,
                        attributes(
                                TestPki.attribute(0, utf8("ProductionSandbox")),
                                TestPki.attribute(2, utf8(BUNDLE)),
                                TestPki.attribute(12, ia5("2020-01-01t00:00:00Z")))));
    }

    // --- ASN.1 depth -------------------------------------------------------

    private void writeDepth(TestPki pki) throws Exception {
        // Signed content: payload SET (1) > attribute SEQUENCE (2) > a fourth
        // attribute field nesting SEQUENCEs from depth 3 down.
        write("owner-receipt-content-depth-64.der", sign(pki, deepPayload(62)));
        write("owner-receipt-content-depth-65.der", sign(pki, deepPayload(63)));

        // Envelope: ContentInfo (1) > [0] (2) > SignedData (3) > SignerInfos
        // (4) > SignerInfo (5) > unsignedAttrs [1] (6) > Attribute (7) >
        // attrValues SET (8) > SEQUENCEs from depth 9 down.
        byte[] genuine = sign(pki, standardPayload());
        write("owner-receipt-envelope-depth-64.der", withDeepUnsignedAttribute(genuine, 56));
        write("owner-receipt-envelope-depth-65.der", withDeepUnsignedAttribute(genuine, 57));
    }

    private static byte[] deepPayload(int levels) throws Exception {
        ASN1EncodableVector deepAttribute = new ASN1EncodableVector();
        deepAttribute.add(new ASN1Integer(9000));
        deepAttribute.add(new ASN1Integer(1));
        deepAttribute.add(new DEROctetString(integer(1)));
        deepAttribute.add(nest(levels));
        return attributes(
                TestPki.attribute(0, utf8("ProductionSandbox")),
                TestPki.attribute(2, utf8(BUNDLE)),
                TestPki.attribute(12, ia5(CREATION_DATE)),
                new DERSequence(deepAttribute));
    }

    private static byte[] withDeepUnsignedAttribute(byte[] cms, int levels) throws Exception {
        SignedData data = SignedData.getInstance(
                ContentInfo.getInstance(ASN1Primitive.fromByteArray(cms)).getContent());
        SignerInfo original = SignerInfo.getInstance(data.getSignerInfos().getObjectAt(0));
        Attribute deep = new Attribute(new ASN1ObjectIdentifier("1.2.3.4.5"), new DERSet(nest(levels)));
        SignerInfo withUnsigned = new SignerInfo(
                original.getSID(),
                original.getDigestAlgorithm(),
                original.getAuthenticatedAttributes(),
                original.getDigestEncryptionAlgorithm(),
                original.getEncryptedDigest(),
                new DERSet(deep));
        SignedData replaced = new SignedData(
                data.getDigestAlgorithms(),
                data.getEncapContentInfo(),
                data.getCertificates(),
                (ASN1Set) null,
                new DLSet(withUnsigned));
        return new ContentInfo(CMSObjectIdentifiers.signedData, replaced).getEncoded();
    }

    /** {@code levels} SEQUENCEs, each holding the next; the innermost is empty. */
    private static ASN1Encodable nest(int levels) {
        ASN1Encodable inner = new DERSequence();
        for (int i = 1; i < levels; i++) {
            inner = new DERSequence(inner);
        }
        return inner;
    }

    // --- JSON bounds -------------------------------------------------------

    private void writeJsonBounds(TestPki jws) throws Exception {
        String claims = claims();
        write(
                "owner-jws-header-name-50000.jws",
                jws.signJwsWithHeader(withMember(header(jws), repeat('n', 50000), "1"), claims));
        write(
                "owner-jws-header-name-50001.jws",
                jws.signJwsWithHeader(withMember(header(jws), repeat('n', 50001), "1"), claims));
        write(
                "owner-jws-header-number-1000.jws",
                jws.signJwsWithHeader(withMember(header(jws), "n", "1" + repeat('0', 999)), claims));
        write(
                "owner-jws-header-number-1001.jws",
                jws.signJwsWithHeader(withMember(header(jws), "n", "1" + repeat('0', 1000)), claims));
    }

    // --- helpers -----------------------------------------------------------

    private static String header(TestPki pki) throws Exception {
        List<String> x5c = pki.x5c();
        return "{\"alg\":\"ES256\",\"x5c\":[\"" + x5c.get(0) + "\",\"" + x5c.get(1) + "\",\"" + x5c.get(2) + "\"]}";
    }

    private static String claims() {
        return "{\"bundleId\":\"" + BUNDLE + "\",\"environment\":\"Sandbox\",\"signedDate\":" + SIGNED_DATE
                + ",\"productId\":\"" + BUNDLE + ".pro\",\"transactionId\":\"2000000000000001\"}";
    }

    private static String withMember(String object, String name, String value) {
        return object.substring(0, object.length() - 1) + ",\"" + name + "\":" + value + "}";
    }

    private static String repeat(char c, int count) {
        StringBuilder sb = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            sb.append(c);
        }
        return sb.toString();
    }

    private static byte[] standardPayload() throws Exception {
        return attributes(
                TestPki.attribute(0, utf8("ProductionSandbox")),
                TestPki.attribute(2, utf8(BUNDLE)),
                TestPki.attribute(12, ia5(CREATION_DATE)));
    }

    private static byte[] sign(TestPki pki, byte[] payload) throws Exception {
        return pki.signReceipt(payload, new Date(SIGNED_DATE));
    }

    /** A payload SET of the given attributes, DER-sorted as a receipt is. */
    private static byte[] attributes(ASN1Encodable... entries) throws Exception {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        for (ASN1Encodable entry : entries) {
            vector.add(entry);
        }
        return new DERSet(vector).getEncoded();
    }

    private static byte[] utf8(String s) throws Exception {
        return new DERUTF8String(s).getEncoded();
    }

    private static byte[] ia5(String s) throws Exception {
        return new DERIA5String(s).getEncoded();
    }

    private static byte[] integer(long value) throws Exception {
        return new ASN1Integer(value).getEncoded();
    }

    /** An IA5String TLV around {@code content} verbatim, high bytes included. */
    private static byte[] rawIa5(byte[] content) {
        byte[] out = new byte[content.length + 2];
        out[0] = 0x16;
        out[1] = (byte) content.length;
        System.arraycopy(content, 0, out, 2, content.length);
        return out;
    }

    private byte[] read(String name) throws Exception {
        return Files.readAllBytes(out.resolve(name));
    }

    private void write(String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }

    private void write(String name, String text) throws Exception {
        write(name, text.getBytes(StandardCharsets.US_ASCII));
    }
}
