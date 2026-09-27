package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * Writes the synthetic inputs the 0.7 shared cases add (docs/design/0.7-api.md,
 * "Testing"), into the directory given as the first argument:
 *
 * <ul>
 *   <li>{@code receipt-signers-one-broken.der}: two SignerInfos, both under
 *       trusted receipt-signing certificates. The one that sorts first in the
 *       DER SET is signed with a key that is not its certificate's, so its
 *       signature fails; the other is genuine. 0.7 accepts a receipt when at
 *       least one signer verifies.</li>
 *   <li>{@code receipt-signers-both-broken.der}: the same two signers, both
 *       signed with the wrong key: {@code INVALID_SIGNATURE}.</li>
 *   <li>{@code receipt-signers-four.der} and {@code receipt-signers-five.der}:
 *       four and five genuine signers. Four is the cap and verifies; the fifth
 *       is the only defect of the other and fails as {@code MALFORMED}.</li>
 *   <li>{@code receipt-content-not-asn1.der}: a well-formed CMS whose
 *       encapsulated content is not ASN.1, genuinely signed:
 *       {@code UNREADABLE_PAYLOAD}. {@code receipt-content-not-asn1-bad-signature.der}
 *       is the same content signed with the wrong key: {@code INVALID_SIGNATURE}.</li>
 *   <li>{@code receipt-intermediate-without-wwdr-oid.der}: a genuine receipt
 *       whose intermediate lacks the Apple WWDR marker OID, with its own root
 *       {@code api-receipt-no-wwdr-oid-root.der}: {@code INVALID_CERTIFICATE_PURPOSE}.</li>
 *   <li>{@code receipt-web-order-zero.der}: two in-app purchases, one with
 *       attribute 1711 equal to 0, which the endpoint omits.</li>
 *   <li>{@code receipt-non-ascii-product-id.der}: one in-app purchase whose
 *       product id holds non-ASCII characters and a slash, for the canonical
 *       {@code toJson} vector.</li>
 *   <li>{@code receipt-escapes-product-id.der}: a product id holding every
 *       JSON short escape, U+001F and U+2028, for the canonical escape vector.</li>
 *   <li>{@code receipt-creation-date-twice-first-wins.der}: attribute 12 twice
 *       under {@code api-receipt-expired-root.der} (valid 2020 to 2021); the
 *       first, 2020-06-01, lies inside the window and the second does not.</li>
 *   <li>{@code receipt-in-app-oddities.der}: one purchase with attribute 1702
 *       twice, one with a quantity that is not an INTEGER and a purchase date
 *       that does not parse.</li>
 *   <li>{@code receipt-b64-at-cap-trailing-zeros.txt},
 *       {@code receipt-b64-over-cap-two-byte-char.txt} and
 *       {@code receipt-b64-over-cap-signed.txt}: base64 strings of exactly the
 *       3,145,728-byte cap, one UTF-8 byte over it, and a genuinely signed
 *       receipt four characters over it.</li>
 *   <li>{@code jws-payload-json-array-signed.jws} and
 *       {@code jws-payload-empty-signed.jws}: a genuine header over a payload
 *       that is not a JSON object, genuinely signed: {@code UNREADABLE_PAYLOAD}.
 *       Their unsigned twins are {@code jws-payload-json-array.jws} and
 *       {@code jws-payload-empty.jws} from {@link JwsSegmentFixtures}.</li>
 * </ul>
 *
 * <p>Every receipt here except the no-WWDR one and the creation-date-twice
 * one is anchored to {@code api-receipt-root.der}; both JWS to
 * {@code api-jws-root.der}. Those chains are valid from 2024-01-01 to
 * 2050-01-01.</p>
 *
 * <p>A {@code main} like the other generators. Regenerate with:</p>
 *
 * <pre>
 * mvn -B -q -f java/pom.xml test-compile
 * mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
 * java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
 *      io.github.emindeniz99.applepurchasereceiptverifier.VerifierApiFixtures \
 *      fixtures/generated-0.7
 * </pre>
 *
 * <p>Each run mints fresh keys, so regenerating changes every byte of these
 * files and every {@code contentSha256} in fixtures/cases.json that
 * records them.</p>
 */
public final class VerifierApiFixtures {

    private static final String BUNDLE = "com.example.app";
    private static final String SIGNER_OID = "1.2.840.113635.100.6.11.1";
    private static final String RSA = "SHA256withRSA";

    private static final long CHAIN_NOT_BEFORE = 1704067200000L; // 2024-01-01
    private static final long CHAIN_NOT_AFTER = 2524608000000L; // 2050-01-01
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";
    private static final long OLD_NOT_BEFORE = 1577836800000L; // 2020-01-01
    private static final long OLD_NOT_AFTER = 1609459200000L; // 2021-01-01
    private static final long OLD_SIGNED_DATE = 1590969600000L; // 2020-06-01
    private static final String OLD_CREATION_DATE = "2020-06-01T00:00:00Z";

    /** The receipt cap on the base64 string, in UTF-8 bytes. */
    private static final int STRING_CAP = 3 * 1024 * 1024;

    /** Every JSON short escape, one control character without one, and U+2028. */
    static final String ESCAPES_PRODUCT_ID = "com.example.app.esc\"\\\b\f\n\r\t" + (char) 0x1f + (char) 0x2028 + "end";

    /** Two-, three- and four-byte UTF-8 sequences, and a slash no encoder may escape. */
    static final String NON_ASCII_PRODUCT_ID = "com.example.app.café/€/𝄞";

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

    private VerifierApiFixtures() {}

    public static void main(String[] args) throws Exception {
        Path out = args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(out);
        Date notBefore = new Date(CHAIN_NOT_BEFORE);
        Date notAfter = new Date(CHAIN_NOT_AFTER);

        TestPki pki = TestPki.receipt(notBefore, notAfter);
        write(out, "api-receipt-root.der", pki.root.getEncoded());

        // Five receipt-signing leaves under the trusted intermediate, minted
        // in order so their serials, and so their SignerInfos in the sorted
        // DER SET, come out in this order.
        List<X509Certificate> leaves = new ArrayList<X509Certificate>();
        List<KeyPair> keys = new ArrayList<KeyPair>();
        for (int i = 1; i <= 5; i++) {
            KeyPair kp = rsaKeyPair();
            keys.add(kp);
            leaves.add(TestPki.cert(
                    "CN=Fake Receipt Signing " + i,
                    kp,
                    "CN=Fake WWDR CA",
                    pki.intermediateKey,
                    false,
                    SIGNER_OID,
                    notBefore,
                    notAfter,
                    RSA));
        }
        PrivateKey stranger = rsaKeyPair().getPrivate();
        byte[] payload = standardPayload();

        write(
                out,
                "receipt-signers-one-broken.der",
                signers(
                        payload,
                        pki,
                        leaves.subList(0, 2),
                        Arrays.asList(stranger, keys.get(1).getPrivate())));
        write(
                out,
                "receipt-signers-both-broken.der",
                signers(payload, pki, leaves.subList(0, 2), Arrays.asList(stranger, stranger)));
        write(out, "receipt-signers-four.der", signers(payload, pki, leaves.subList(0, 4), privates(keys, 4)));
        write(out, "receipt-signers-five.der", signers(payload, pki, leaves, privates(keys, 5)));

        byte[] notAsn1 = "this is not an attribute set".getBytes(StandardCharsets.US_ASCII);
        write(
                out,
                "receipt-content-not-asn1.der",
                signers(
                        notAsn1,
                        pki,
                        leaves.subList(0, 1),
                        Collections.singletonList(keys.get(0).getPrivate())));
        write(
                out,
                "receipt-content-not-asn1-bad-signature.der",
                signers(notAsn1, pki, leaves.subList(0, 1), Collections.singletonList(stranger)));

        TestPki noWwdr = TestPki.receipt(notBefore, notAfter, true, false);
        write(out, "api-receipt-no-wwdr-oid-root.der", noWwdr.root.getEncoded());
        write(out, "receipt-intermediate-without-wwdr-oid.der", noWwdr.signReceipt(payload, new Date(SIGNED_DATE)));

        byte[] webOrderZero = TestPki.receiptPayload(
                "ProductionSandbox",
                BUNDLE,
                "1.2.3",
                OPAQUE,
                TestPki.deviceHash(GUID, OPAQUE, BUNDLE),
                CREATION_DATE,
                Arrays.asList(
                        consumableWithWebOrderZero(),
                        TestPki.inAppPurchase(
                                1,
                                BUNDLE + ".vip",
                                "70000000000032",
                                "70000000000032",
                                "2024-02-01T09:30:00Z",
                                "2030-02-01T09:30:00Z")));
        write(out, "receipt-web-order-zero.der", pki.signReceipt(webOrderZero, new Date(SIGNED_DATE)));

        byte[] nonAscii = TestPki.receiptPayload(
                "ProductionSandbox",
                BUNDLE,
                "1.2.3",
                OPAQUE,
                TestPki.deviceHash(GUID, OPAQUE, BUNDLE),
                CREATION_DATE,
                Collections.singletonList(TestPki.inAppPurchase(
                        1, NON_ASCII_PRODUCT_ID, "70000000000041", "70000000000041", "2024-01-15T12:00:00Z", null)));
        write(out, "receipt-non-ascii-product-id.der", pki.signReceipt(nonAscii, new Date(SIGNED_DATE)));

        byte[] hash = TestPki.deviceHash(GUID, OPAQUE, BUNDLE);
        byte[] escapes = TestPki.receiptPayload(
                "ProductionSandbox",
                BUNDLE,
                "1.2.3",
                OPAQUE,
                hash,
                CREATION_DATE,
                Collections.singletonList(TestPki.inAppPurchase(
                        1, ESCAPES_PRODUCT_ID, "70000000000051", "70000000000051", "2024-01-15T12:00:00Z", null)));
        write(out, "receipt-escapes-product-id.der", pki.signReceipt(escapes, new Date(SIGNED_DATE)));

        // Attribute 12 twice under a chain valid 2020 to 2021. The DER SET
        // sorts the 2020 date first; only a port that takes the FIRST
        // occurrence judges the chain inside its window.
        TestPki expired = TestPki.receipt(new Date(OLD_NOT_BEFORE), new Date(OLD_NOT_AFTER));
        write(out, "api-receipt-expired-root.der", expired.root.getEncoded());
        byte[] twice = TestPki.receiptPayload(
                "ProductionSandbox",
                BUNDLE,
                "1.2.3",
                OPAQUE,
                hash,
                OLD_CREATION_DATE,
                Collections.<byte[]>emptyList(),
                false,
                null,
                new byte[0],
                Arrays.asList(date(12, CREATION_DATE), date(12, OLD_CREATION_DATE)));
        write(out, "receipt-creation-date-twice-first-wins.der", expired.signReceipt(twice, new Date(OLD_SIGNED_DATE)));

        // One purchase naming its product id twice, one whose quantity is not
        // an INTEGER and whose purchase date does not parse.
        byte[] inAppOddities = TestPki.receiptPayload(
                "ProductionSandbox",
                BUNDLE,
                "1.2.3",
                OPAQUE,
                hash,
                CREATION_DATE,
                Arrays.asList(purchaseWithProductIdTwice(), purchaseWithUnparseableFields()));
        write(out, "receipt-in-app-oddities.der", pki.signReceipt(inAppOddities, new Date(SIGNED_DATE)));

        // Base64 length boundary. A standard receipt padded with zero bytes to
        // 2,359,296 bytes is canonical base64 of exactly the 3,145,728-byte
        // cap: the size check passes and the trailing bytes answer. The same
        // text with its first character replaced by U+00E9 is 3,145,728
        // characters but 3,145,729 UTF-8 bytes. A genuinely signed receipt of
        // 2,359,299 bytes is canonical base64 of 3,145,732 characters.
        byte[] padded = Arrays.copyOf(pki.signReceipt(payload, new Date(SIGNED_DATE)), STRING_CAP / 4 * 3);
        String atCap = Base64.getEncoder().encodeToString(padded);
        write(out, "receipt-b64-at-cap-trailing-zeros.txt", atCap.getBytes(StandardCharsets.US_ASCII));
        write(
                out,
                "receipt-b64-over-cap-two-byte-char.txt",
                ("\u00e9" + atCap.substring(1)).getBytes(StandardCharsets.UTF_8));
        write(
                out,
                "receipt-b64-over-cap-signed.txt",
                Base64.getEncoder()
                        .encode(LargeReceiptFixture.exactSize(
                                pki, "receipt-b64-over-cap-signed", STRING_CAP / 4 * 3 + 3)));

        TestPki jws = TestPki.jws(true, true, notBefore, notAfter);
        write(out, "api-jws-root.der", jws.root.getEncoded());
        String header = header(jws.x5c());
        write(out, "jws-payload-json-array-signed.jws", ascii(jws.signJwsWithHeader(header, "[1,2,3]")));
        write(out, "jws-payload-empty-signed.jws", ascii(jws.signJwsWithHeader(header, "")));
    }

    private static ASN1Encodable date(int type, String text) throws Exception {
        return TestPki.attribute(type, new DERIA5String(text).getEncoded());
    }

    private static byte[] purchaseWithProductIdTwice() throws Exception {
        ASN1EncodableVector attrs = new ASN1EncodableVector();
        attrs.add(TestPki.attribute(1701, new ASN1Integer(1).getEncoded()));
        attrs.add(TestPki.attribute(1702, new DERUTF8String(BUNDLE + ".a").getEncoded()));
        attrs.add(TestPki.attribute(1702, new DERUTF8String(BUNDLE + ".b").getEncoded()));
        attrs.add(TestPki.attribute(1703, new DERUTF8String("70000000000061").getEncoded()));
        attrs.add(TestPki.attribute(1705, new DERUTF8String("70000000000061").getEncoded()));
        attrs.add(date(1704, "2024-01-15T12:00:00Z"));
        attrs.add(date(1706, "2024-01-15T12:00:00Z"));
        attrs.add(TestPki.attribute(1711, new ASN1Integer(42).getEncoded()));
        return new DERSet(attrs).getEncoded();
    }

    private static byte[] purchaseWithUnparseableFields() throws Exception {
        ASN1EncodableVector attrs = new ASN1EncodableVector();
        attrs.add(TestPki.attribute(1701, new DERUTF8String("1").getEncoded()));
        attrs.add(TestPki.attribute(1702, new DERUTF8String(BUNDLE + ".coins100").getEncoded()));
        attrs.add(TestPki.attribute(1703, new DERUTF8String("70000000000062").getEncoded()));
        attrs.add(TestPki.attribute(1705, new DERUTF8String("70000000000062").getEncoded()));
        attrs.add(date(1704, "not-a-date"));
        attrs.add(date(1706, "2024-01-15T12:00:00Z"));
        attrs.add(TestPki.attribute(1711, new ASN1Integer(42).getEncoded()));
        return new DERSet(attrs).getEncoded();
    }

    /** The standard synthetic payload: no in-app purchases, attribute 9999 unknown. */
    private static byte[] standardPayload() throws Exception {
        return TestPki.receiptPayload(
                BUNDLE,
                "1.2.3",
                OPAQUE,
                TestPki.deviceHash(GUID, OPAQUE, BUNDLE),
                CREATION_DATE,
                Collections.<byte[]>emptyList());
    }

    /** A consumable purchase whose attribute 1711 is 0, as Apple writes it. */
    private static byte[] consumableWithWebOrderZero() throws Exception {
        ASN1EncodableVector attrs = new ASN1EncodableVector();
        attrs.add(TestPki.attribute(1701, new ASN1Integer(1).getEncoded()));
        attrs.add(TestPki.attribute(1702, new DERUTF8String(BUNDLE + ".coins100").getEncoded()));
        attrs.add(TestPki.attribute(1703, new DERUTF8String("70000000000031").getEncoded()));
        attrs.add(TestPki.attribute(1705, new DERUTF8String("70000000000031").getEncoded()));
        attrs.add(TestPki.attribute(1704, new DERIA5String("2024-01-15T12:00:00Z").getEncoded()));
        attrs.add(TestPki.attribute(1706, new DERIA5String("2024-01-15T12:00:00Z").getEncoded()));
        attrs.add(TestPki.attribute(1711, new ASN1Integer(0).getEncoded()));
        return new DERSet(attrs).getEncoded();
    }

    /**
     * A CMS over {@code payload} with one SignerInfo per leaf, each signed
     * with the matching entry of {@code signingKeys}. A key that is not the
     * leaf's own yields a well-formed SignerInfo whose signature fails.
     */
    private static byte[] signers(
            byte[] payload, TestPki pki, List<X509Certificate> leaves, List<PrivateKey> signingKeys) throws Exception {
        ASN1EncodableVector baseAttrs = new ASN1EncodableVector();
        baseAttrs.add(new org.bouncycastle.asn1.cms.Attribute(
                CMSAttributes.signingTime, new DERSet(new Time(new Date(SIGNED_DATE)))));
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        for (int i = 0; i < leaves.size(); i++) {
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder()
                            .setProvider(TestPki.BC)
                            .build())
                    .setSignedAttributeGenerator(
                            new DefaultSignedAttributeTableGenerator(new AttributeTable(baseAttrs)))
                    .build(new JcaContentSignerBuilder(RSA).build(signingKeys.get(i)), leaves.get(i)));
        }
        List<X509Certificate> bag = new ArrayList<X509Certificate>(leaves);
        bag.add(pki.intermediate);
        bag.add(pki.root);
        gen.addCertificates(new JcaCertStore(bag));
        return gen.generate(new CMSProcessableByteArray(payload), true).getEncoded();
    }

    private static List<PrivateKey> privates(List<KeyPair> keys, int count) {
        List<PrivateKey> out = new ArrayList<PrivateKey>();
        for (int i = 0; i < count; i++) {
            out.add(keys.get(i).getPrivate());
        }
        return out;
    }

    private static String header(List<String> x5c) {
        StringBuilder sb = new StringBuilder("{\"alg\":\"ES256\",\"x5c\":[");
        for (int i = 0; i < x5c.size(); i++) {
            sb.append(i == 0 ? "\"" : ",\"").append(x5c.get(i)).append('"');
        }
        return sb.append("]}").toString();
    }

    private static byte[] ascii(String text) {
        return text.getBytes(StandardCharsets.US_ASCII);
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
