package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Writes the four receipts whose single defect sits in the CMS structure
 * itself — two chain shapes, an empty signature and an empty payload — into
 * {@code fixtures/generated/}.
 *
 * <p>They come from the 2026-09-22 audit of the {@code tikhop/TPInAppReceipt}
 * test suite recorded in PLAN.md's prior-art table. That suite exercises the
 * shapes a receipt takes when an attacker rearranges the CMS rather than the
 * receipt payload, and nothing here covered them: every existing negative
 * receipt vector either mutates a certificate, mutates the payload or points
 * the verifier at the wrong root.</p>
 *
 * <ul>
 *   <li><b>{@code receipt-leaf-as-intermediate.der}</b> — the signer is issued
 *       by the receipt-signing LEAF, which then sits where the intermediate
 *       belongs. Every signature and every name link in the path is genuine
 *       and every window covers the receipt's creation date; the one thing
 *       wrong is that the certificate in the issuer position is an end entity
 *       rather than a CA. A port that chains on issuer names and signatures
 *       alone accepts it, which would let any receipt-signing leaf mint
 *       signers of its own.</li>
 *   <li><b>{@code receipt-missing-intermediate.der}</b> — the same genuine
 *       signer, with the intermediate simply left out of the certificate bag,
 *       so the path cannot be built at all. The pair separates "the issuer is
 *       the wrong KIND of certificate" from "the issuer is not there".</li>
 *   <li><b>{@code receipt-empty-signature.der}</b> — a genuine receipt whose
 *       SignerInfo signature is rewritten to an OCTET STRING of zero bytes.
 *       The signature is a length-prefixed string in DER, so an empty one is
 *       well-formed ASN.1: a port has to reach the verification step and get a
 *       negative answer from it rather than fail to parse.</li>
 *   <li><b>{@code receipt-empty-content.der}</b> — a CMS signed over zero
 *       bytes of encapsulated content. The chain, the signer purpose and the
 *       signature are all genuine — the receipt really was signed over
 *       nothing — so the empty payload is the only thing left to object
 *       to.</li>
 * </ul>
 *
 * <p>All four share one root, emitted beside them.</p>
 *
 * <p>A {@code main} rather than a {@code @Test} for the same reason as the
 * other generators: a generation-gated test is a permanently skipped test.
 * Regenerate with:</p>
 *
 * <pre>
 * mvn -B -q -f java/pom.xml test-compile
 * mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
 * java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
 *      io.github.emindeniz99.applepurchasereceiptverifier.ReceiptCmsDefectFixtures \
 *      fixtures/generated
 * node tools/lint-cases.mjs   # re-hash: every contentSha256 must be updated
 * </pre>
 *
 * <p>Each run mints fresh keys, so regenerating changes every byte of these
 * files and every {@code contentSha256} that records them. The private keys
 * are not kept.</p>
 */
public final class ReceiptCmsDefectFixtures {

    private static final String BUNDLE = "com.example.app";

    /** Apple marker OID: a leaf certificate used for receipt signing. */
    private static final String SIGNER_OID = "1.2.840.113635.100.6.11.1";

    /** The subjects this generator's own receipt PKI carries. */
    private static final String ROOT_NAME = "CN=Fake Apple Inc Root";

    private static final String INTERMEDIATE_NAME = "CN=Fake WWDR CA";

    private static final String LEAF_NAME = "CN=Fake Receipt Signing";

    /** The signature algorithm every certificate and every CMS here uses. */
    private static final String RSA = "SHA256withRSA";

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

    private ReceiptCmsDefectFixtures() {}

    public static void main(String[] args) throws Exception {
        Path out = args.length > 0 ? Paths.get(args[0]) : TestFixtures.generated();
        Files.createDirectories(out);

        Date notBefore = new Date(CHAIN_NOT_BEFORE);
        Date notAfter = new Date(CHAIN_NOT_AFTER);

        // The PKI is minted here rather than taken from TestPki.receipt()
        // because one of these fixtures needs the LEAF's private key to issue
        // a certificate, and TestPki keeps that key to itself.
        KeyPair rootKey = rsaKeyPair();
        X509Certificate root =
                TestPki.cert(ROOT_NAME, rootKey, ROOT_NAME, rootKey.getPrivate(), true, null, notBefore, notAfter, RSA);
        KeyPair intermediateKey = rsaKeyPair();
        X509Certificate intermediate = TestPki.cert(
                INTERMEDIATE_NAME,
                intermediateKey,
                ROOT_NAME,
                rootKey.getPrivate(),
                true,
                null,
                notBefore,
                notAfter,
                RSA);
        KeyPair leafKey = rsaKeyPair();
        X509Certificate leaf = TestPki.cert(
                LEAF_NAME,
                leafKey,
                INTERMEDIATE_NAME,
                intermediateKey.getPrivate(),
                false,
                SIGNER_OID,
                notBefore,
                notAfter,
                RSA);
        write(out, "receipt-cms-root.der", root.getEncoded());

        byte[] payload = TestPki.receiptPayload(
                "ProductionSandbox",
                BUNDLE,
                "1.2.3",
                OPAQUE,
                TestPki.deviceHash(GUID, OPAQUE, BUNDLE),
                CREATION_DATE,
                Arrays.<byte[]>asList());

        // --- 1. the leaf standing in for the intermediate ----------------
        // A second receipt-signing certificate, issued by the first. Nothing
        // is forged: the sub-signer's issuer name is the leaf's subject name
        // and the leaf's key really signed it. Only basicConstraints says the
        // leaf may not do that.
        KeyPair subSignerKey = rsaKeyPair();
        X509Certificate subSigner = TestPki.cert(
                "CN=Fake Receipt Signing Sub",
                subSignerKey,
                LEAF_NAME,
                leafKey.getPrivate(),
                false,
                SIGNER_OID,
                notBefore,
                notAfter,
                RSA);
        write(
                out,
                "receipt-leaf-as-intermediate.der",
                TestPki.signReceiptAs(
                        payload,
                        new Date(SIGNED_DATE),
                        subSignerKey.getPrivate(),
                        RSA,
                        new X509CertificateHolder(subSigner.getEncoded()),
                        holders(subSigner, leaf, intermediate, root)));

        // --- 2. the intermediate left out of the bag ---------------------
        // The genuine signer under the genuine intermediate, with the
        // intermediate absent. The receipt names an issuer the bag cannot
        // supply, so no path reaches the pinned root.
        write(
                out,
                "receipt-missing-intermediate.der",
                TestPki.signReceiptAs(
                        payload,
                        new Date(SIGNED_DATE),
                        leafKey.getPrivate(),
                        RSA,
                        new X509CertificateHolder(leaf.getEncoded()),
                        holders(leaf, root)));

        // --- 3. a SignerInfo signature of zero bytes ---------------------
        byte[] genuine = TestPki.signReceiptAs(
                payload,
                new Date(SIGNED_DATE),
                leafKey.getPrivate(),
                RSA,
                new X509CertificateHolder(leaf.getEncoded()),
                holders(leaf, intermediate, root));
        write(out, "receipt-empty-signature.der", withEmptySignature(genuine));

        // --- 4. zero bytes of encapsulated content -----------------------
        // Signed over the empty payload rather than patched to it, so the
        // signature is genuine and a port cannot answer about the signature
        // instead of about the payload.
        write(
                out,
                "receipt-empty-content.der",
                TestPki.signReceiptAs(
                        new byte[0],
                        new Date(SIGNED_DATE),
                        leafKey.getPrivate(),
                        RSA,
                        new X509CertificateHolder(leaf.getEncoded()),
                        holders(leaf, intermediate, root)));
    }

    /**
     * Rewrites the SignerInfo's {@code signature} to an OCTET STRING of zero
     * bytes.
     *
     * <p>The CMS is re-encoded rather than patched because the replacement is
     * shorter than what it replaces and every enclosing length has to be
     * recomputed. The signature is the last field of the SignerInfo here:
     * BouncyCastle emits no {@code unsignedAttrs}, and the generator asserts
     * the field it is about to replace really is an OCTET STRING rather than
     * trusting the position.</p>
     */
    private static byte[] withEmptySignature(byte[] cms) throws Exception {
        ASN1Sequence contentInfo = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(cms));
        ASN1Sequence signedData =
                ASN1Sequence.getInstance(ASN1TaggedObject.getInstance(contentInfo.getObjectAt(1)), true);
        ASN1EncodableVector fields = new ASN1EncodableVector();
        boolean emptied = false;
        for (int i = 0; i < signedData.size(); i++) {
            ASN1Encodable field = signedData.getObjectAt(i);
            if (i != signedData.size() - 1) {
                fields.add(field);
                continue;
            }
            ASN1Set signerInfos = ASN1Set.getInstance(field);
            ASN1EncodableVector rebuiltInfos = new ASN1EncodableVector();
            for (int j = 0; j < signerInfos.size(); j++) {
                ASN1Sequence info = ASN1Sequence.getInstance(signerInfos.getObjectAt(j));
                ASN1EncodableVector members = new ASN1EncodableVector();
                for (int k = 0; k < info.size(); k++) {
                    ASN1Encodable member = info.getObjectAt(k);
                    if (k == info.size() - 1) {
                        if (!(member instanceof ASN1OctetString)) {
                            throw new IllegalStateException("the last SignerInfo field is not the signature");
                        }
                        members.add(new DEROctetString(new byte[0]));
                        emptied = true;
                    } else {
                        members.add(member);
                    }
                }
                rebuiltInfos.add(new DERSequence(members));
            }
            fields.add(new DERSet(rebuiltInfos));
        }
        if (!emptied) {
            throw new IllegalStateException("the CMS carries no SignerInfo");
        }
        return new DERSequence(new ASN1Encodable[] {
                    contentInfo.getObjectAt(0), new DERTaggedObject(true, 0, new DERSequence(fields))
                })
                .getEncoded("DER");
    }

    private static List<X509CertificateHolder> holders(X509Certificate... certs) throws Exception {
        List<X509CertificateHolder> out = new ArrayList<X509CertificateHolder>();
        for (X509Certificate cert : certs) {
            out.add(new X509CertificateHolder(cert.getEncoded()));
        }
        return out;
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
