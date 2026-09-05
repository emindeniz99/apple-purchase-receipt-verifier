package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * Writes the eight hostile-JWS fixtures into {@code fixtures/generated/} —
 * the inputs Python's coverage-guided fuzzing found escaping the library as
 * bare exceptions (ROADMAP "Before 1.0" item 3), plus the {@code x5c[2]}
 * vector that closed the last parser differential, turned into shared
 * vectors so all nine ports have to answer them the same way.
 *
 * <p>Same technique as {@link PortDivergenceFixtures}: a fake Apple PKI from
 * {@link TestPki}, fixed epoch instants so nothing depends on generation
 * time, bytes written under {@code fixtures/generated/} and registered in
 * {@code fixtures/cases.json} with the SHA-256 of their decoded content. A
 * {@code main} rather than a {@code @Test} for the same reason: a
 * generation-gated test is a permanently skipped test. Regenerate with:</p>
 *
 * <pre>
 * mvn -B -q -f java/pom.xml test-compile
 * mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
 * java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
 *      io.github.emindeniz99.applepurchasereceiptverifier.HostileJwsFixtures \
 *      fixtures/generated
 * node tools/lint-cases.mjs   # re-hash: every contentSha256 must be updated
 * </pre>
 *
 * <p>Seven of the eight carry exactly ONE defect each; the remaining one
 * carries none and must verify, because it is the boundary of what the
 * second one refuses. Six of the seven put that
 * defect in the JWS header or in an {@code x5c} certificate, which is signed
 * material in neither case — the header is covered by the ES256 signature but
 * an attacker writes it, and the certificates are covered by their own
 * issuer's signature. So the header is signed in its hostile state, and a
 * mutated certificate is re-signed by the issuing key ({@link #resign}) so a
 * broken issuer signature can never be the thing a port objects to first. The
 * one exception is the corrupt-extension fixture, whose certificate cannot be
 * decoded at all: there is no TBS left to re-sign, and no verifier can reach
 * the signature to notice.</p>
 *
 * <p>Each run mints fresh keys, so regenerating changes every byte of these
 * files and every {@code contentSha256} that records them. The root is
 * emitted beside them and the private keys are not kept.</p>
 */
public final class HostileJwsFixtures {

    private static final String BUNDLE = "com.example.app";

    // The same fixed instants the other two generators use.
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final long CHAIN_NOT_BEFORE = 1704067200000L; // 2024-01-01
    private static final long CHAIN_NOT_AFTER = 2524608000000L; // 2050-01-01

    /**
     * The DER of {@code id-ecPublicKey}'s namedCurve parameter for
     * secp256r1 (1.2.840.10045.3.1.7) — what every certificate in the JWS
     * PKI carries, and what {@link #unimplementedCurve} rewrites.
     */
    private static final byte[] SECP256R1_OID = {
        0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07
    };

    /** {@code [0] EXPLICIT INTEGER 2} — the X.509 v3 version field. */
    private static final byte[] VERSION_V3 = {(byte) 0xa0, 0x03, 0x02, 0x01, 0x02};

    /** {@code OBJECT IDENTIFIER 2.5.29.19} — basicConstraints. */
    private static final byte[] BASIC_CONSTRAINTS_OID = {0x06, 0x03, 0x55, 0x1d, 0x13};

    /** The same OID as an object, for the extension list rebuild. */
    private static final ASN1ObjectIdentifier BASIC_CONSTRAINTS = new ASN1ObjectIdentifier("2.5.29.19");

    /** {@code [3] EXPLICIT Extensions} — the last TBSCertificate field. */
    private static final int EXTENSIONS_TAG = 3;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private HostileJwsFixtures() {}

    public static void main(String[] args) throws Exception {
        Path out = Paths.get(args.length > 0 ? args[0] : "../fixtures/generated");
        Files.createDirectories(out);

        TestPki pki = TestPki.jws(true, true, new Date(CHAIN_NOT_BEFORE), new Date(CHAIN_NOT_AFTER));
        write(out, "hostile-jws-root.der", pki.root.getEncoded());

        Map<String, Object> transaction = TestPki.claims(
                "bundleId",
                BUNDLE,
                "environment",
                "Sandbox",
                "signedDate",
                SIGNED_DATE,
                "purchaseDate",
                SIGNED_DATE,
                "originalPurchaseDate",
                SIGNED_DATE,
                "productId",
                BUNDLE + ".pro",
                "transactionId",
                "2000000000000001",
                "originalTransactionId",
                "2000000000000001",
                "quantity",
                1,
                "type",
                "Non-Consumable",
                "inAppOwnershipType",
                "PURCHASED");
        String claimsJson = MAPPER.writeValueAsString(transaction);

        // --- 1. x5c entries that are not strings -------------------------
        // The header is signed in this state, so the ES256 signature covers
        // exactly the bytes served and the JSON types are the only defect.
        write(
                out,
                "transaction-x5c-entry-not-a-string.jws",
                pki.signJwsWithHeader("{\"alg\":\"ES256\",\"x5c\":[1,2,3]}", claimsJson)
                        .getBytes(StandardCharsets.US_ASCII));

        // --- 2. a signedDate no calendar can express ---------------------
        // 1e300 ms is about 10^289 years. NaN and Infinity reach the same
        // place in the ports whose JSON parser accepts them, but most reject
        // both outright, so the vector is the huge-but-valid JSON number.
        Map<String, Object> farFuture = new LinkedHashMap<String, Object>(transaction);
        farFuture.put("signedDate", Double.valueOf(1e300));
        write(
                out,
                "transaction-signed-date-out-of-range.jws",
                pki.signJws(farFuture).getBytes(StandardCharsets.US_ASCII));

        // --- 3. one corrupt extension in x5c[1] --------------------------
        // The intermediate's basicConstraints extnValue is left claiming 127
        // content bytes inside a 15-byte extension, so the certificate stops
        // being decodable partway through a region a port only reaches if it
        // parses the whole certificate rather than scanning it for marker
        // OIDs. Nothing else about the JWS is touched.
        byte[] corruptExtension = corruptBasicConstraintsLength(pki.intermediate.getEncoded());
        write(
                out,
                "transaction-x5c-corrupt-extension.jws",
                pki.signJwsWithHeader(header(replacing(pki.x5c(), 1, corruptExtension)), claimsJson)
                        .getBytes(StandardCharsets.US_ASCII));

        // --- 4. an EC curve no port implements ---------------------------
        // The intermediate's namedCurve becomes 1.2.840.10045.3.1.10, which
        // is unassigned, and the TBS is re-signed by the root so the
        // certificate is otherwise genuine. Verifying that the leaf was
        // issued by this intermediate needs its public key, and there is no
        // such key to build.
        byte[] unimplementedCurve = resign(unimplementedCurve(pki.intermediate.getEncoded()), pki.rootKey);
        write(
                out,
                "transaction-x5c-unimplemented-curve.jws",
                pki.signJwsWithHeader(header(replacing(pki.x5c(), 1, unimplementedCurve)), claimsJson)
                        .getBytes(StandardCharsets.US_ASCII));

        // --- 5. a certificate claiming version 11 ------------------------
        // X.509 defines v1, v2 and v3 only. Re-signed by the root, so a port
        // that does not check the version finds nothing else wrong with it.
        byte[] version11 = resign(version(pki.intermediate.getEncoded(), 11), pki.rootKey);
        write(
                out,
                "transaction-x5c-certificate-version-11.jws",
                pki.signJwsWithHeader(header(replacing(pki.x5c(), 1, version11)), claimsJson)
                        .getBytes(StandardCharsets.US_ASCII));

        // --- 6. the leaf carries basicConstraints twice -------------------
        // The extension list of x5c[0] holds a byte-identical second copy of
        // its basicConstraints, and the TBS is re-signed by the intermediate
        // so the certificate is genuine in every other respect. RFC 5280
        // 4.2 forbids a second instance of any extension, and a parser that
        // allows one has to decide which copy wins — so this never becomes a
        // verdict about basicConstraints, it is a certificate the library
        // cannot be said to have read. It is x5c[0] because that is where
        // the marker-OID lookup touches an extension block first.
        byte[] duplicateExtension = resign(duplicateBasicConstraints(pki.leaf.getEncoded()), pki.intermediateKey);
        write(
                out,
                "transaction-x5c-duplicate-extension.jws",
                pki.signJwsWithHeader(header(replacing(pki.x5c(), 0, duplicateExtension)), claimsJson)
                        .getBytes(StandardCharsets.US_ASCII));

        // --- 7. the same signedDate, written with a decimal point ---------
        // The one input here that must be ACCEPTED, and it belongs beside the
        // other six because it is the boundary of the rule they set: a port
        // that answers transaction/reject-signed-date-out-of-range by
        // refusing every number that is not a bare integer passes that vector
        // and fails this one. JSON draws no line between 1722945600000 and
        // 1722945600000.0, and reading only the integer spelling fails OPEN —
        // the date reads as absent, certificate validity falls back to the
        // current time and the staleness rule stops applying at all.
        // BigDecimal rather than double so the literal is written out as it
        // is spelled here.
        Map<String, Object> decimalDate = new LinkedHashMap<String, Object>(transaction);
        decimalDate.put("signedDate", new BigDecimal("1722945600000.0"));
        write(
                out,
                "transaction-signed-date-decimal.jws",
                pki.signJws(decimalDate).getBytes(StandardCharsets.US_ASCII));

        // --- 8. x5c[2] is not a certificate ------------------------------
        // The third entry holds base64 of the ASCII text "not a
        // certificate" — the index twin of
        // transaction/reject-x5c-leaf-that-is-not-a-certificate, which
        // deliberately sits on x5c[0] because the ports disagreed about
        // x5c[2]. Java parsed all three entries and rejected this; the other
        // eight never touched the third and verified the JWS. Pinning the
        // majority would have made java DROP a rejection it already makes,
        // so the vector pins java's answer and the other eight parse the
        // entry — without trusting it, which nothing here changes.
        List<String> brokenRoot = replacing(pki.x5c(), 2, "not a certificate".getBytes(StandardCharsets.US_ASCII));
        write(
                out,
                "transaction-x5c-root-not-a-certificate.jws",
                pki.signJwsWithHeader(header(brokenRoot), claimsJson).getBytes(StandardCharsets.US_ASCII));
    }

    /** {@code {"alg":"ES256","x5c":[...]}} — the header the last three use. */
    private static String header(List<String> x5c) throws Exception {
        Map<String, Object> header = new LinkedHashMap<String, Object>();
        header.put("alg", "ES256");
        header.put("x5c", x5c);
        return MAPPER.writeValueAsString(header);
    }

    private static List<String> replacing(List<String> x5c, int index, byte[] der) {
        List<String> copy = new ArrayList<String>(x5c);
        copy.set(index, TestPki.b64(der));
        return copy;
    }

    /**
     * Rewrites the basicConstraints extnValue length octet to 0x7f. The
     * extension SEQUENCE still declares its original 15 content bytes, so the
     * OCTET STRING now claims more than its parent holds and every
     * bounds-checking DER reader has to stop there. The length octet is the
     * one byte that breaks decoding without changing the file's shape.
     */
    static byte[] corruptBasicConstraintsLength(byte[] der) {
        int oid = indexOf(der, BASIC_CONSTRAINTS_OID);
        int cursor = oid + BASIC_CONSTRAINTS_OID.length;
        if (der[cursor] == 0x01) {
            cursor += 3; // the critical BOOLEAN
        }
        if (der[cursor] != 0x04) {
            throw new IllegalStateException("basicConstraints extnValue is not an OCTET STRING");
        }
        byte[] mutated = der.clone();
        mutated[cursor + 1] = 0x7f;
        return mutated;
    }

    /**
     * Appends a byte-identical second copy of the basicConstraints extension
     * to the certificate's extension list. Rebuilt through the ASN.1 types
     * rather than spliced, because every enclosing length — the extension
     * list, the {@code [3]} wrapper and the TBS itself — grows with it. The
     * signature the certificate still carries is stale afterwards, which
     * {@link #resign} repairs.
     */
    static byte[] duplicateBasicConstraints(byte[] der) throws Exception {
        ASN1Sequence certificate = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(der));
        ASN1Sequence tbs = ASN1Sequence.getInstance(certificate.getObjectAt(0));
        ASN1EncodableVector fields = new ASN1EncodableVector();
        boolean duplicated = false;
        for (int i = 0; i < tbs.size(); i++) {
            ASN1Encodable field = tbs.getObjectAt(i);
            if (!(field instanceof ASN1TaggedObject) || ((ASN1TaggedObject) field).getTagNo() != EXTENSIONS_TAG) {
                fields.add(field);
                continue;
            }
            ASN1Sequence extensions = ASN1Sequence.getInstance((ASN1TaggedObject) field, true);
            ASN1EncodableVector rebuilt = new ASN1EncodableVector();
            for (int j = 0; j < extensions.size(); j++) {
                ASN1Sequence extension = ASN1Sequence.getInstance(extensions.getObjectAt(j));
                rebuilt.add(extension);
                if (BASIC_CONSTRAINTS.equals(ASN1ObjectIdentifier.getInstance(extension.getObjectAt(0)))) {
                    rebuilt.add(extension);
                    duplicated = true;
                }
            }
            fields.add(new DERTaggedObject(true, EXTENSIONS_TAG, new DERSequence(rebuilt)));
        }
        if (!duplicated) {
            throw new IllegalStateException("certificate carries no basicConstraints to duplicate");
        }
        return new DERSequence(new ASN1Encodable[] {
                    new DERSequence(fields), certificate.getObjectAt(1), certificate.getObjectAt(2)
                })
                .getEncoded("DER");
    }

    /** Rewrites the namedCurve OID to the unassigned 1.2.840.10045.3.1.10. */
    static byte[] unimplementedCurve(byte[] der) {
        int at = indexOf(der, SECP256R1_OID);
        byte[] mutated = der.clone();
        mutated[at + SECP256R1_OID.length - 1] = 0x0a;
        return mutated;
    }

    /** Rewrites the X.509 version INTEGER, which DER holds in one byte here. */
    static byte[] version(byte[] der, int version) {
        int at = indexOf(der, VERSION_V3);
        byte[] mutated = der.clone();
        mutated[at + VERSION_V3.length - 1] = (byte) version;
        return mutated;
    }

    /**
     * Re-signs a certificate whose TBS was mutated, so the issuer's signature
     * covers the bytes served. Keeps the certificate's own
     * signatureAlgorithm field, which the mutations never touch.
     */
    private static byte[] resign(byte[] der, PrivateKey issuerKey) throws Exception {
        return resign(der, issuerKey, "SHA256withECDSA");
    }

    /** Same, for an issuer whose key is not EC — the receipt PKI's is RSA. */
    static byte[] resign(byte[] der, PrivateKey issuerKey, String sigAlg) throws Exception {
        ASN1Sequence certificate = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(der));
        byte[] tbs = certificate.getObjectAt(0).toASN1Primitive().getEncoded("DER");
        Signature signer = Signature.getInstance(sigAlg);
        signer.initSign(issuerKey);
        signer.update(tbs);
        return new DERSequence(new ASN1Encodable[] {
                    ASN1Primitive.fromByteArray(tbs), certificate.getObjectAt(1), new DERBitString(signer.sign())
                })
                .getEncoded("DER");
    }

    /** The single occurrence of {@code needle}; more than one is an error. */
    static int indexOf(byte[] haystack, byte[] needle) {
        int at = -1;
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            boolean matches = true;
            for (int j = 0; matches && j < needle.length; j++) {
                matches = haystack[i + j] == needle[j];
            }
            if (!matches) {
                continue;
            }
            if (at >= 0) {
                throw new IllegalStateException("pattern occurs more than once");
            }
            at = i;
        }
        if (at < 0) {
            throw new IllegalStateException("pattern not found");
        }
        return at;
    }

    private static void write(Path out, String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
