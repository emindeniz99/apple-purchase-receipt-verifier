package io.github.emindeniz99.applepurchasereceiptverifier;

import static io.github.emindeniz99.applepurchasereceiptverifier.CertificateDerFixtures.children;
import static io.github.emindeniz99.applepurchasereceiptverifier.CertificateDerFixtures.concat;
import static io.github.emindeniz99.applepurchasereceiptverifier.CertificateDerFixtures.contentInfo;
import static io.github.emindeniz99.applepurchasereceiptverifier.CertificateDerFixtures.der;
import static io.github.emindeniz99.applepurchasereceiptverifier.CertificateDerFixtures.signedDataFields;
import static io.github.emindeniz99.applepurchasereceiptverifier.CertificateDerFixtures.tlv;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Writes the inputs of the shared case on a signedAttrs attribute whose type
 * carries the OBJECT IDENTIFIER tag but does not decode as one, into the
 * directory given as the first argument (default
 * {@code fixtures/generated-0.7}). Every file is prefixed
 * {@code signed-attrs-}.
 *
 * <p>{@code signed-attrs-receipt-type-empty-oid.der} is a genuine receipt
 * whose one SignerInfo carries, beside its own contentType, signingTime and
 * messageDigest attributes, one more attribute of type {@code 06 00}: an
 * empty OBJECT IDENTIFIER. The SignerInfo is re-signed over the resulting
 * set, so the signature is genuine and that attribute type is the only
 * defect; without it the receipt verifies under
 * {@code signed-attrs-receipt-root.der}. The shape is the one the Node
 * {@code parse-cms} fuzz target reduced a crasher to. BouncyCastle cannot
 * encode an empty OID, so the attribute is written byte by byte.</p>
 *
 * <p>The chain is valid from 2024-01-01 to 2050-01-01 and the receipt states
 * the creation date 2024-08-06. Run it the way {@link ReviewParityFixtures}
 * documents. Each run mints fresh keys, so regenerating changes every file
 * and its {@code contentSha256}.</p>
 */
public final class SignedAttrsTypeFixtures {

    private static final String BUNDLE = "com.example.app";
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";
    private static final long SIGNING_TIME = 1722945600000L; // 2024-08-06T12:00:00Z

    private SignedAttrsTypeFixtures() {}

    public static void main(String[] args) throws Exception {
        Path out = args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(out);
        Date notBefore = new Date(1704067200000L); // 2024-01-01
        Date notAfter = new Date(2524608000000L); // 2050-01-01
        KeyPair rootKeys = rsaKeys();
        KeyPair interKeys = rsaKeys();
        KeyPair leafKeys = rsaKeys();
        X509Certificate root = TestPki.cert(
                "CN=Signed Attrs Root",
                rootKeys,
                "CN=Signed Attrs Root",
                rootKeys.getPrivate(),
                true,
                null,
                notBefore,
                notAfter,
                "SHA256withRSA");
        X509Certificate inter = TestPki.cert(
                "CN=Signed Attrs WWDR",
                interKeys,
                "CN=Signed Attrs Root",
                rootKeys.getPrivate(),
                true,
                "1.2.840.113635.100.6.2.1",
                notBefore,
                notAfter,
                "SHA256withRSA");
        X509Certificate leaf = TestPki.cert(
                "CN=Signed Attrs Signer",
                leafKeys,
                "CN=Signed Attrs WWDR",
                interKeys.getPrivate(),
                false,
                "1.2.840.113635.100.6.11.1",
                notBefore,
                notAfter,
                "SHA256withRSA");
        byte[] payload = TestPki.receiptPayload(
                BUNDLE, "1.2.3", new byte[] {1, 2, 3, 4}, new byte[20], CREATION_DATE, Collections.<byte[]>emptyList());
        byte[] genuine = der(TestPki.signReceiptAs(
                payload,
                new Date(SIGNING_TIME),
                leafKeys.getPrivate(),
                "SHA256withRSA",
                holder(leaf),
                Arrays.asList(holder(leaf), holder(inter), holder(root))));

        // SEQUENCE { OBJECT IDENTIFIER (empty), SET { NULL } }
        byte[] emptyOidAttribute =
                tlv(0x30, concat(Arrays.asList(tlv(0x06, new byte[0]), tlv(0x31, tlv(0x05, new byte[0])))));

        write(out, "signed-attrs-receipt-root.der", root.getEncoded());
        write(
                out,
                "signed-attrs-receipt-type-empty-oid.der",
                withExtraSignedAttribute(genuine, leafKeys, emptyOidAttribute));
    }

    /**
     * {@code cms} with {@code attribute} added to its one SignerInfo's
     * signedAttrs, in DER SET OF order, and the SignerInfo re-signed over
     * the result.
     */
    private static byte[] withExtraSignedAttribute(byte[] cms, KeyPair signer, byte[] attribute) throws Exception {
        List<byte[]> fields = signedDataFields(cms);
        byte[] signerInfo = children(fields.get(fields.size() - 1)).get(0);
        List<byte[]> parts = new ArrayList<byte[]>(children(signerInfo));
        int signedAttrsAt = -1;
        for (int i = 0; i < parts.size(); i++) {
            if ((parts.get(i)[0] & 0xff) == 0xa0) {
                signedAttrsAt = i;
            }
        }
        List<byte[]> attributes = new ArrayList<byte[]>(children(parts.get(signedAttrsAt)));
        attributes.add(attribute);
        attributes.sort(SignedAttrsTypeFixtures::derOrder);
        byte[] body = concat(attributes);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(signer.getPrivate());
        signature.update(tlv(0x31, body));
        parts.set(signedAttrsAt, tlv(0xa0, body));
        parts.set(parts.size() - 1, tlv(0x04, signature.sign()));

        fields.set(fields.size() - 1, tlv(0x31, tlv(0x30, concat(parts))));
        return contentInfo(fields);
    }

    /** X.690 §11.6: SET OF elements ascend as octet strings, a prefix first. */
    private static int derOrder(byte[] a, byte[] b) {
        for (int i = 0; i < Math.min(a.length, b.length); i++) {
            int diff = (a[i] & 0xff) - (b[i] & 0xff);
            if (diff != 0) {
                return diff;
            }
        }
        return a.length - b.length;
    }

    private static KeyPair rsaKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509CertificateHolder holder(X509Certificate certificate) throws Exception {
        return new X509CertificateHolder(certificate.getEncoded());
    }

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
