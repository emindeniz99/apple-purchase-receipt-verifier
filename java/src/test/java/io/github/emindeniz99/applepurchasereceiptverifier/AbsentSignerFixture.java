package io.github.emindeniz99.applepurchasereceiptverifier;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Writes the receipt that separates "the signer is not in the bag" from
 * "something in the bag is not a certificate" into {@code fixtures/generated/}.
 *
 * <p>Its SignerInfo names an issuer and serial no embedded entry carries: the
 * signing certificate really exists and really did sign the payload, it is
 * simply not embedded. Beside the genuine intermediate and root the bag also
 * holds one entry that is not a certificate — a SEQUENCE that stops after the
 * identity fields, so it carries a legible issuer and serial of its own and no
 * X.509 decoder will accept it.</p>
 *
 * <p>Two independent defects, and a port that reports the wrong one is
 * guessing. Node, Swift and Go resolve the SignerInfo's issuer and serial
 * against every entry's raw DER before judging any entry, so the malformed
 * stranger cannot be mistaken for the absent signer and the verdict is
 * {@code INVALID_RECEIPT_FORMAT} — a defect of the receipt. Python, Rust,
 * Java, PHP and Ruby used to answer {@code INVALID_CERTIFICATE} here, which
 * says the signer was found and was bad. The stranger's identity is legible
 * on purpose: a port cannot pass this by failing to read identities at all,
 * only by reading them and comparing.</p>
 *
 * <p>A {@code main} rather than a {@code @Test} for the same reason as the
 * other generators: a generation-gated test is a permanently skipped test.
 * Regenerate with:</p>
 *
 * <pre>
 * mvn -B -q -f java/pom.xml test-compile
 * mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
 * java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
 *      io.github.emindeniz99.applepurchasereceiptverifier.AbsentSignerFixture \
 *      fixtures/generated
 * node tools/lint-cases.mjs   # re-hash: every contentSha256 must be updated
 * </pre>
 *
 * <p>Each run mints fresh keys, so regenerating changes every byte of the
 * receipt and the {@code contentSha256} that records it. The root is emitted
 * beside it and the private keys are not kept.</p>
 */
public final class AbsentSignerFixture {

    private static final String BUNDLE = "com.example.app";

    /** Apple marker OID: a leaf certificate used for receipt signing. */
    private static final String SIGNER_OID = "1.2.840.113635.100.6.11.1";

    /** The subject the receipt PKI's intermediate carries, as its issuer name. */
    private static final String INTERMEDIATE_NAME = "CN=Fake WWDR CA";

    /** {@code sha256WithRSAEncryption}, so the stranger looks like a certificate as far as it goes. */
    private static final String SHA256_WITH_RSA = "1.2.840.113549.1.1.11";

    /** Nothing in this PKI issues under that name, and nothing shares that serial. */
    private static final String STRANGER_NAME = "CN=Fake Unrelated Stranger";

    private static final BigInteger STRANGER_SERIAL = BigInteger.valueOf(0x5eed);

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

    private AbsentSignerFixture() {}

    public static void main(String[] args) throws Exception {
        Path out = Paths.get(args.length > 0 ? args[0] : "../fixtures/generated");
        Files.createDirectories(out);

        Date notBefore = new Date(CHAIN_NOT_BEFORE);
        Date notAfter = new Date(CHAIN_NOT_AFTER);
        TestPki pki = TestPki.receipt(notBefore, notAfter);
        write(out, "receipt-signer-absent-root.der", pki.root.getEncoded());

        byte[] payload = TestPki.receiptPayload(
                "ProductionSandbox",
                BUNDLE,
                "1.2.3",
                OPAQUE,
                TestPki.deviceHash(GUID, OPAQUE, BUNDLE),
                CREATION_DATE,
                Arrays.<byte[]>asList());

        // A real receipt-signing leaf under the real intermediate, which
        // really signs the payload — and is then left out of the bag. That is
        // the whole defect on the receipt's side: nothing about the signer is
        // wrong, it is absent.
        KeyPair signerKey = rsaKeyPair();
        X509Certificate signer = TestPki.cert(
                "CN=Fake Receipt Signing",
                signerKey,
                INTERMEDIATE_NAME,
                pki.intermediateKey,
                false,
                SIGNER_OID,
                notBefore,
                notAfter,
                "SHA256withRSA");
        byte[] cms = TestPki.signReceiptAs(
                payload,
                new Date(SIGNED_DATE),
                signerKey.getPrivate(),
                "SHA256withRSA",
                new X509CertificateHolder(signer.getEncoded()),
                Arrays.asList(
                        new X509CertificateHolder(pki.intermediate.getEncoded()),
                        new X509CertificateHolder(pki.root.getEncoded())));
        if (contains(cms, signer.getEncoded())) {
            throw new IllegalStateException("the signer certificate is embedded after all");
        }

        byte[] receipt = withExtraBagEntry(cms, malformedStranger());
        write(out, "receipt-signer-absent.der", receipt);
    }

    /**
     * An entry that is not a certificate but does carry an identity: a
     * {@code SEQUENCE} holding a TBS that stops after issuer, so there is no
     * validity, no subject, no public key and no signature.
     *
     * <p>Everything a decoder needs is missing and every X.509 decoder refuses
     * it; everything the SignerInfo is matched against — the version tag, the
     * serial and the issuer Name — is intact and belongs to nobody in this
     * PKI. That is what makes the vector discriminating: resolving the signer
     * means comparing identities, not counting the entries that would not
     * decode.</p>
     */
    private static byte[] malformedStranger() throws Exception {
        ASN1Sequence tbs = new DERSequence(new ASN1Encodable[] {
            new DERTaggedObject(true, 0, new ASN1Integer(2)),
            new ASN1Integer(STRANGER_SERIAL),
            new DERSequence(new ASN1Encodable[] {new ASN1ObjectIdentifier(SHA256_WITH_RSA), DERNull.INSTANCE}),
            new X500Name(STRANGER_NAME).toASN1Primitive()
        });
        return new DERSequence(tbs).getEncoded("DER");
    }

    /**
     * Re-encodes {@code cms} with one more entry in the SignedData certificate
     * bag. The bag is re-encoded rather than patched because the entry is new
     * rather than a same-length replacement, and every enclosing length has to
     * be recomputed; the SignerInfo signature covers the payload, not the bag,
     * so it stays valid.
     */
    private static byte[] withExtraBagEntry(byte[] cms, byte[] entry) throws Exception {
        ASN1Sequence contentInfo = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(cms));
        ASN1Sequence signedData =
                ASN1Sequence.getInstance(ASN1TaggedObject.getInstance(contentInfo.getObjectAt(1)), true);
        ASN1EncodableVector fields = new ASN1EncodableVector();
        boolean extended = false;
        for (int i = 0; i < signedData.size(); i++) {
            ASN1Encodable field = signedData.getObjectAt(i);
            if (!(field instanceof ASN1TaggedObject) || ((ASN1TaggedObject) field).getTagNo() != 0) {
                fields.add(field);
                continue;
            }
            ASN1Set certificates = ASN1Set.getInstance((ASN1TaggedObject) field, false);
            ASN1EncodableVector rebuilt = new ASN1EncodableVector();
            for (int j = 0; j < certificates.size(); j++) {
                rebuilt.add(certificates.getObjectAt(j));
            }
            rebuilt.add(ASN1Primitive.fromByteArray(entry));
            fields.add(new DERTaggedObject(false, 0, new DERSet(rebuilt)));
            extended = true;
        }
        if (!extended) {
            throw new IllegalStateException("the CMS carries no certificate bag");
        }
        return new DERSequence(new ASN1Encodable[] {
                    contentInfo.getObjectAt(0), new DERTaggedObject(true, 0, new DERSequence(fields))
                })
                .getEncoded("DER");
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            boolean matches = true;
            for (int j = 0; matches && j < needle.length; j++) {
                matches = haystack[i + j] == needle[j];
            }
            if (matches) {
                return true;
            }
        }
        return false;
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
