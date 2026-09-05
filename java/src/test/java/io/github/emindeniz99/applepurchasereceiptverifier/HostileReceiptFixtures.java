package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Writes the four defective-signer receipts into {@code fixtures/generated/} —
 * the receipt-path twins of the {@code x5c} certificate mutations
 * {@link HostileJwsFixtures} builds.
 *
 * <p>The JWS vectors pinned X.509 version 11, a duplicated extension, an
 * unimplemented EC curve and a corrupt extension for a certificate carried in
 * a JWS header. Four ports answered them from checks that sit on the JWS path
 * only (node, python, ruby, dotnet), so the same four mutations on the
 * certificate a legacy PKCS#7 receipt is signed by were unanswered. These are
 * those, and the reason is the one the JWS twins pinned:
 * {@code INVALID_CERTIFICATE}.</p>
 *
 * <p>Each receipt is genuine in every other respect — real chain, real CMS
 * signature, real bundle id and creation date, a signer re-signed by the
 * intermediate wherever the mutation touched its TBS — so the defective
 * certificate is the only thing a port can object to. The unimplemented-curve
 * receipt is the one where the signer's KEY is the mutation: it is signed with
 * a real P-256 key whose certificate then names an unassigned curve, so a port
 * has to refuse the certificate before it can reach the signature at all.</p>
 *
 * <p>A {@code main} rather than a {@code @Test} for the same reason as the
 * other two generators: a generation-gated test is a permanently skipped test.
 * Regenerate with:</p>
 *
 * <pre>
 * mvn -B -q -f java/pom.xml test-compile
 * mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
 * java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
 *      io.github.emindeniz99.applepurchasereceiptverifier.HostileReceiptFixtures \
 *      fixtures/generated
 * node tools/lint-cases.mjs   # re-hash: every contentSha256 must be updated
 * </pre>
 *
 * <p>Each run mints fresh keys, so regenerating changes every byte of these
 * files and every {@code contentSha256} that records them. All four share one
 * root, emitted beside them; the private keys are not kept.</p>
 */
public final class HostileReceiptFixtures {

    private static final String BUNDLE = "com.example.app";

    /** Apple marker OID: a leaf certificate used for receipt signing. */
    private static final String SIGNER_OID = "1.2.840.113635.100.6.11.1";

    /** The subject the receipt PKI's intermediate carries, as its issuer name. */
    private static final String INTERMEDIATE_NAME = "CN=Fake WWDR CA";

    /** {@code OBJECT IDENTIFIER 2.5.29.19} — basicConstraints. */
    private static final byte[] BASIC_CONSTRAINTS_OID = {0x06, 0x03, 0x55, 0x1d, 0x13};

    // The same fixed instants the other two generators use.
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

    private HostileReceiptFixtures() {}

    public static void main(String[] args) throws Exception {
        Path out = Paths.get(args.length > 0 ? args[0] : "../fixtures/generated");
        Files.createDirectories(out);

        Date notBefore = new Date(CHAIN_NOT_BEFORE);
        Date notAfter = new Date(CHAIN_NOT_AFTER);
        TestPki pki = TestPki.receipt(notBefore, notAfter);
        write(out, "receipt-signer-root.der", pki.root.getEncoded());

        byte[] payload = TestPki.receiptPayload(
                "ProductionSandbox",
                BUNDLE,
                "1.2.3",
                OPAQUE,
                TestPki.deviceHash(GUID, OPAQUE, BUNDLE),
                CREATION_DATE,
                Arrays.<byte[]>asList());

        // --- 1. a signer claiming X.509 version 11 -----------------------
        // Re-signed by the intermediate, so a port without a version check
        // finds nothing else wrong with it: the marker OID is there, the
        // validity window covers the creation date, and it really did sign
        // this receipt.
        KeyPair versionKey = rsaKeyPair();
        byte[] versionSigner = signerCert(versionKey, pki, notBefore, notAfter).getEncoded();
        write(
                out,
                "receipt-signer-version-11.der",
                patchedReceipt(
                        payload,
                        pki,
                        versionKey.getPrivate(),
                        "SHA256withRSA",
                        versionSigner,
                        HostileJwsFixtures.resign(
                                HostileJwsFixtures.version(versionSigner, 11), pki.intermediateKey, "SHA256withRSA")));

        // --- 2. a signer carrying basicConstraints twice -----------------
        // Also re-signed by the intermediate. RFC 5280 4.2 forbids a second
        // instance of any extension, and a reader that allows one has to pick
        // which copy the certificate means — including for the marker OID
        // lookup that happens on this path.
        KeyPair duplicateKey = rsaKeyPair();
        byte[] duplicateSigner =
                signerCert(duplicateKey, pki, notBefore, notAfter).getEncoded();
        write(
                out,
                "receipt-signer-duplicate-extension.der",
                rebuiltReceipt(
                        payload,
                        pki,
                        duplicateKey.getPrivate(),
                        duplicateSigner,
                        HostileJwsFixtures.resign(
                                HostileJwsFixtures.duplicateBasicConstraints(duplicateSigner),
                                pki.intermediateKey,
                                "SHA256withRSA")));

        // --- 3. a signer key on a curve nobody implements ----------------
        // Here the KEY is the mutation. The receipt is signed with a real
        // P-256 key, and the certificate that key sits in then names
        // 1.2.840.10045.3.1.10, which is unassigned — so the public key that
        // would check this signature cannot be built, and a port has to
        // refuse the certificate before it reaches the signature at all.
        // Its TBS is re-signed by the intermediate, as the other two are.
        KeyPair curveKey = ecKeyPair();
        byte[] curveSigner = signerCert(curveKey, pki, notBefore, notAfter).getEncoded();
        write(
                out,
                "receipt-signer-unimplemented-curve.der",
                patchedReceipt(
                        payload,
                        pki,
                        curveKey.getPrivate(),
                        "SHA256withECDSA",
                        curveSigner,
                        HostileJwsFixtures.resign(
                                HostileJwsFixtures.unimplementedCurve(curveSigner),
                                pki.intermediateKey,
                                "SHA256withRSA")));

        // --- 4. a signer that stops decoding inside an extension VALUE ---
        // One byte, and deliberately one byte further in than the JWS twin
        // changes. That one rewrites the extnValue OCTET STRING's own length,
        // which breaks the DER of everything containing it — harmless in a
        // JWS header, where the certificate is a base64 string of its own,
        // but inside a CMS it would break the receipt's DER and every port
        // that walks the whole blob would answer INVALID_RECEIPT_FORMAT about
        // the receipt instead of INVALID_CERTIFICATE about the certificate.
        // So the corruption goes INSIDE the OCTET STRING, where a generic
        // reader sees an opaque primitive of the length it declares: the
        // BasicConstraints SEQUENCE it holds is left claiming 127 content
        // bytes in a two-byte value. The receipt still parses; the signer's
        // extension block does not. There is no TBS left to re-sign and no
        // verifier can reach the certificate's signature to notice.
        KeyPair corruptKey = rsaKeyPair();
        byte[] corruptSigner = signerCert(corruptKey, pki, notBefore, notAfter).getEncoded();
        write(
                out,
                "receipt-signer-corrupt-extension.der",
                patchedReceipt(
                        payload,
                        pki,
                        corruptKey.getPrivate(),
                        "SHA256withRSA",
                        corruptSigner,
                        corruptBasicConstraintsValue(corruptSigner)));
    }

    /**
     * Rewrites the length octet of the {@code BasicConstraints} SEQUENCE that
     * sits INSIDE the basicConstraints extnValue, leaving it claiming 127
     * content bytes in a value that holds none.
     *
     * <p>The extnValue OCTET STRING keeps its own tag and length, so a reader
     * walking the certificate — or the CMS around it — as generic ASN.1 sees
     * a well-formed primitive and never looks inside. Only a reader that
     * decodes the extension finds the defect, which is exactly the difference
     * this vector exists to observe.</p>
     */
    private static byte[] corruptBasicConstraintsValue(byte[] der) {
        int cursor = HostileJwsFixtures.indexOf(der, BASIC_CONSTRAINTS_OID) + BASIC_CONSTRAINTS_OID.length;
        if (der[cursor] == 0x01) {
            cursor += 3; // the critical BOOLEAN
        }
        if (der[cursor] != 0x04 || der[cursor + 2] != 0x30) {
            throw new IllegalStateException("basicConstraints does not hold a SEQUENCE in an OCTET STRING");
        }
        byte[] mutated = der.clone();
        mutated[cursor + 3] = 0x7f;
        return mutated;
    }

    /** A receipt-signing leaf under {@code pki}'s intermediate, marker OID and all. */
    private static X509Certificate signerCert(KeyPair keyPair, TestPki pki, Date notBefore, Date notAfter)
            throws Exception {
        return TestPki.cert(
                "CN=Fake Receipt Signing",
                keyPair,
                INTERMEDIATE_NAME,
                pki.intermediateKey,
                false,
                SIGNER_OID,
                notBefore,
                notAfter,
                "SHA256withRSA");
    }

    /**
     * CMS over {@code payload} signed by {@code intactDer}'s key, with the
     * signer's bytes replaced by {@code mutatedDer} afterwards.
     *
     * <p>Three of the four mutations are length-preserving, and this is the
     * only way to embed them: BouncyCastle's own certificate reader refuses a
     * version it does not recognise and cannot decode a certificate that stops
     * decoding inside its extensions, so the CMS has to be generated around
     * the intact certificate and patched. Every enclosing ASN.1 length stays
     * correct because the replacement is the same length, and the CMS
     * signature covers the payload rather than the certificate bag.</p>
     */
    private static byte[] patchedReceipt(
            byte[] payload, TestPki pki, PrivateKey signingKey, String sigAlg, byte[] intactDer, byte[] mutatedDer)
            throws Exception {
        return replaceOnce(receipt(payload, pki, signingKey, sigAlg, intactDer), intactDer, mutatedDer);
    }

    /**
     * Same, for the one mutation that makes the certificate LONGER: the CMS
     * is re-encoded around the replacement rather than patched, so every
     * enclosing length is recomputed. It is the second-choice mechanism
     * because re-encoding the certificate SET can reorder it, and because it
     * needs the replacement to be readable as ASN.1 — which the corrupt-
     * extension certificate deliberately is not.
     */
    private static byte[] rebuiltReceipt(
            byte[] payload, TestPki pki, PrivateKey signingKey, byte[] intactDer, byte[] mutatedDer) throws Exception {
        byte[] cms = receipt(payload, pki, signingKey, "SHA256withRSA", intactDer);
        ASN1Sequence contentInfo = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(cms));
        ASN1Sequence signedData =
                ASN1Sequence.getInstance(ASN1TaggedObject.getInstance(contentInfo.getObjectAt(1)), true);
        ASN1EncodableVector fields = new ASN1EncodableVector();
        boolean replaced = false;
        for (int i = 0; i < signedData.size(); i++) {
            ASN1Encodable field = signedData.getObjectAt(i);
            if (!(field instanceof ASN1TaggedObject) || ((ASN1TaggedObject) field).getTagNo() != 0) {
                fields.add(field);
                continue;
            }
            ASN1Set certificates = ASN1Set.getInstance((ASN1TaggedObject) field, false);
            ASN1EncodableVector rebuilt = new ASN1EncodableVector();
            for (int j = 0; j < certificates.size(); j++) {
                ASN1Encodable entry = certificates.getObjectAt(j);
                if (Arrays.equals(entry.toASN1Primitive().getEncoded("DER"), intactDer)) {
                    rebuilt.add(ASN1Primitive.fromByteArray(mutatedDer));
                    replaced = true;
                } else {
                    rebuilt.add(entry);
                }
            }
            fields.add(new DERTaggedObject(false, 0, new DERSet(rebuilt)));
        }
        if (!replaced) {
            throw new IllegalStateException("the signer certificate is not embedded in the CMS");
        }
        return new DERSequence(new ASN1Encodable[] {
                    contentInfo.getObjectAt(0), new DERTaggedObject(true, 0, new DERSequence(fields))
                })
                .getEncoded("DER");
    }

    /** CMS over {@code payload}, embedding {@code signerDer} plus the real CA chain. */
    private static byte[] receipt(byte[] payload, TestPki pki, PrivateKey signingKey, String sigAlg, byte[] signerDer)
            throws Exception {
        X509CertificateHolder signer = new X509CertificateHolder(signerDer);
        List<X509CertificateHolder> embedded = Arrays.asList(
                signer,
                new X509CertificateHolder(pki.intermediate.getEncoded()),
                new X509CertificateHolder(pki.root.getEncoded()));
        return TestPki.signReceiptAs(payload, new Date(SIGNED_DATE), signingKey, sigAlg, signer, embedded);
    }

    /**
     * Replaces the single occurrence of {@code from} in {@code haystack} with
     * {@code to}. Both must be the same length, so every enclosing ASN.1
     * length in the CMS stays correct, and {@code from} must occur exactly
     * once — each run mints fresh keys, and a coincidental second occurrence
     * would silently patch the wrong bytes.
     */
    private static byte[] replaceOnce(byte[] haystack, byte[] from, byte[] to) {
        if (from.length != to.length) {
            throw new IllegalStateException("the mutation changed the certificate's length");
        }
        int at = -1;
        for (int i = 0; i + from.length <= haystack.length; i++) {
            boolean matches = true;
            for (int j = 0; matches && j < from.length; j++) {
                matches = haystack[i + j] == from[j];
            }
            if (!matches) {
                continue;
            }
            if (at >= 0) {
                throw new IllegalStateException("the signer certificate occurs more than once in the CMS");
            }
            at = i;
        }
        if (at < 0) {
            throw new IllegalStateException("the signer certificate is not embedded in the CMS");
        }
        byte[] patched = haystack.clone();
        System.arraycopy(to, 0, patched, at, to.length);
        return patched;
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static KeyPair ecKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
