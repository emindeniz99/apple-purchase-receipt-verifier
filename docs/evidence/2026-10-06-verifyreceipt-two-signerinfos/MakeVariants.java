import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Writes variants of one genuine receipt that differ only in their
 * SignerInfos (and two controls that break the signature), each as the
 * base64 a client sends. Usage: MakeVariants <receipt.b64> <out dir>.
 */
public class MakeVariants {
    public static void main(String[] args) throws Exception {
        byte[] der = Base64.getDecoder().decode(new String(Files.readAllBytes(Paths.get(args[0]))).trim());
        Path out = Paths.get(args[1]);
        Files.createDirectories(out);
        ContentInfo ci = ContentInfo.getInstance(ASN1Primitive.fromByteArray(der));
        SignedData sd = SignedData.getInstance(ci.getContent());
        SignerInfo genuine = SignerInfo.getInstance(sd.getSignerInfos().getObjectAt(0));

        // The genuine SignerInfo with a digest algorithm nobody implements.
        SignerInfo unknownDigest = new SignerInfo(genuine.getSID(),
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4")),
                genuine.getAuthenticatedAttributes(), genuine.getDigestEncryptionAlgorithm(),
                genuine.getEncryptedDigest(), genuine.getUnauthenticatedAttributes());
        // The genuine SignerInfo with one bit of its signature flipped.
        byte[] sig = genuine.getEncryptedDigest().getOctets();
        sig[sig.length - 1] ^= 1;
        SignerInfo badSignature = new SignerInfo(genuine.getSID(), genuine.getDigestAlgorithm(),
                genuine.getAuthenticatedAttributes(), genuine.getDigestEncryptionAlgorithm(),
                new DEROctetString(sig), genuine.getUnauthenticatedAttributes());

        write(out, "c0-original", der);
        write(out, "c1-reencoded-one-genuine", rebuild(ci, sd, sd.getEncapContentInfo(), genuine));
        write(out, "c2-payload-byte-flipped", rebuild(ci, sd, flipPayload(sd.getEncapContentInfo()), genuine));
        write(out, "c3-signature-bit-flipped", rebuild(ci, sd, sd.getEncapContentInfo(), badSignature));
        write(out, "c4-unknown-digest-alone", rebuild(ci, sd, sd.getEncapContentInfo(), unknownDigest));
        write(out, "v1-unknown-digest-then-genuine", rebuild(ci, sd, sd.getEncapContentInfo(), unknownDigest, genuine));
        write(out, "v2-genuine-then-unknown-digest", rebuild(ci, sd, sd.getEncapContentInfo(), genuine, unknownDigest));
        write(out, "v3-genuine-twice", rebuild(ci, sd, sd.getEncapContentInfo(), genuine, genuine));
        write(out, "v4-bad-signature-then-genuine", rebuild(ci, sd, sd.getEncapContentInfo(), badSignature, genuine));
        write(out, "v5-genuine-then-bad-signature", rebuild(ci, sd, sd.getEncapContentInfo(), genuine, badSignature));
    }

    /** The same envelope with the given SignerInfos, in this order, definite lengths throughout. */
    static byte[] rebuild(ContentInfo ci, SignedData sd, ContentInfo encap, ASN1Encodable... signerInfos)
            throws Exception {
        SignedData rebuilt = new SignedData(sd.getDigestAlgorithms(), encap, sd.getCertificates(), sd.getCRLs(),
                new DLSet(signerInfos));
        return new ContentInfo(ci.getContentType(), rebuilt).getEncoded(ASN1Encoding.DL);
    }

    /** The encapsulated content with its last octet changed, so its messageDigest no longer matches. */
    static ContentInfo flipPayload(ContentInfo encap) {
        byte[] payload = ASN1OctetString.getInstance(encap.getContent()).getOctets();
        payload[payload.length - 1] ^= 1;
        return new ContentInfo(encap.getContentType(), new DEROctetString(payload));
    }

    static void write(Path out, String name, byte[] der) throws Exception {
        Files.write(out.resolve(name + ".b64"), Base64.getEncoder().encodeToString(der).getBytes("US-ASCII"));
    }
}
