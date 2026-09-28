package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
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
 * Writes the inputs of the shared cases for the ASN.1 depth bound (32
 * constructed values, the outermost included; owner, 2026-09-27) into the
 * directory given as the first argument (default
 * {@code fixtures/generated-0.7}). Every file is prefixed {@code depth-}.
 *
 * <p>The bound was first 64 and its cases came from
 * {@link OwnerDecisionFixtures}. Lowering it re-signs the signed-content
 * inputs, so they live here under their own root,
 * {@code depth-receipt-root.der}: regenerating them re-keys nothing else.
 * The chain is valid from 2024-01-01 to 2050-01-01 and every receipt states
 * the creation date 2024-08-06.</p>
 *
 * <p>Run it the way {@link ReviewParityFixtures} documents. Each run mints
 * fresh keys, so regenerating changes every file and its
 * {@code contentSha256}.</p>
 */
public final class Asn1DepthFixtures {

    private static final String BUNDLE = "com.example.app";
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";

    private Asn1DepthFixtures() {}

    public static void main(String[] args) throws Exception {
        Path out = args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(out);
        TestPki pki = TestPki.receipt(new Date(1704067200000L), new Date(2524608000000L));
        write(out, "depth-receipt-root.der", pki.root.getEncoded());

        // Signed content: payload SET (1) > attribute SEQUENCE (2) > a fourth
        // attribute field nesting SEQUENCEs from depth 3 down.
        write(out, "depth-receipt-content-32.der", sign(pki, deepPayload(30)));
        write(out, "depth-receipt-content-33.der", sign(pki, deepPayload(31)));

        // Envelope: ContentInfo (1) > [0] (2) > SignedData (3) > SignerInfos
        // (4) > SignerInfo (5) > unsignedAttrs [1] (6) > Attribute (7) >
        // attrValues SET (8) > SEQUENCEs from depth 9 down.
        byte[] genuine = sign(
                pki,
                attributes(
                        TestPki.attribute(0, utf8("ProductionSandbox")),
                        TestPki.attribute(2, utf8(BUNDLE)),
                        TestPki.attribute(12, ia5(CREATION_DATE))));
        write(out, "depth-receipt-envelope-32.der", withDeepUnsignedAttribute(genuine, 24));
        write(out, "depth-receipt-envelope-33.der", withDeepUnsignedAttribute(genuine, 25));
    }

    private static byte[] deepPayload(int levels) throws Exception {
        ASN1EncodableVector deepAttribute = new ASN1EncodableVector();
        deepAttribute.add(new ASN1Integer(9000));
        deepAttribute.add(new ASN1Integer(1));
        deepAttribute.add(new DEROctetString(new ASN1Integer(1).getEncoded()));
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

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
