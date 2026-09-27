package io.github.emindeniz99.applepurchasereceiptverifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.CollectionStore;

/**
 * Writes the inputs of the port-neutral cases the 2026-09-27 Java/Rust
 * cross-review moved into fixtures/cases-0.7.json, into the directory given as
 * the first argument (default {@code fixtures/generated-0.7}). Every file is
 * prefixed {@code review-}.
 *
 * <p>All synthetic chains here are valid from 2024-01-01 to 2050-01-01 and
 * every receipt states the creation date 2024-08-06, so the verdicts do not
 * move with the clock except where a case pins one. Roots are emitted beside
 * the inputs: {@code review-receipt-root.der}, {@code review-deep-root.der},
 * {@code review-deep7-root.der}, {@code review-deep-self-issued-root.der},
 * {@code review-shallow-root.der} and {@code review-jws-root.der}.</p>
 *
 * <p>Two inputs are derived from files already committed rather than minted:
 * the SHA-384 and RSA-PSS tampered twins flip one content byte of
 * {@code receipt-signer-sha384.der} and {@code receipt-signer-rsa-pss.der},
 * and the stranger-with-unreadable-key receipt borrows the certificate bag of
 * {@code receipt-signer-unimplemented-curve.der}. Run this after
 * {@link HardeningParityFixtures} and the base generators.</p>
 *
 * <p>A {@code main} like the other generators. Regenerate with:</p>
 *
 * <pre>
 * mvn -B -q -f java/pom.xml test-compile
 * mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
 * java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
 *      io.github.emindeniz99.applepurchasereceiptverifier.ReviewParityFixtures \
 *      fixtures/generated-0.7
 * </pre>
 *
 * <p>Each run mints fresh keys, so regenerating changes the bytes of every
 * minted file and every {@code contentSha256} that records them.</p>
 */
public final class ReviewParityFixtures {

    private static final String BUNDLE = "com.example.app";
    private static final String LEAF_OID = "1.2.840.113635.100.6.11.1";
    private static final String WWDR_OID = "1.2.840.113635.100.6.2.1";
    private static final String RSA = "SHA256withRSA";

    private static final long NOT_BEFORE = 1704067200000L; // 2024-01-01
    private static final long NOT_AFTER = 2524608000000L; // 2050-01-01
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";

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

    /** Invalid UTF-8: a lone continuation byte and a truncated two-byte sequence. */
    private static final byte[] NOT_UTF8 = {'b', 'a', 'd', (byte) 0x80, (byte) 0xC3};

    private final Date nb = new Date(NOT_BEFORE);
    private final Date na = new Date(NOT_AFTER);
    private Path out;

    private ReviewParityFixtures() {}

    public static void main(String[] args) throws Exception {
        ReviewParityFixtures generator = new ReviewParityFixtures();
        generator.out =
                args.length > 0 ? Paths.get(args[0]) : TestFixtures.root().resolve("generated-0.7");
        Files.createDirectories(generator.out);
        generator.run();
    }

    private void run() throws Exception {
        TestPki pki = TestPki.receipt(nb, na);
        write("review-receipt-root.der", pki.root.getEncoded());
        byte[] payload = standardPayload();
        byte[] genuine = pki.signReceipt(payload, new Date(SIGNED_DATE));

        writeBounds(pki, payload, genuine);
        writeDecodeRules(pki);
        writeSigners(pki, payload, genuine);
        writeCertificateDecode(pki, genuine);
        writeJws();
        writeEndpointBodies(genuine);
    }

    // --- bounds ------------------------------------------------------------

    private void writeBounds(TestPki pki, byte[] payload, byte[] genuine) throws Exception {
        write("review-receipt-ten-certificates.der", pki.signReceiptWithPadding(payload, 7));
        write("review-receipt-eleven-certificates.der", pki.signReceiptWithPadding(payload, 8));
        write("review-receipt-cross-signed-mesh.der", pki.signReceiptWithCrossSignedMesh(payload, 14, 2));
        deep("review-deep-root.der", "review-receipt-path-six.der", 5, 0, payload);
        deep("review-deep7-root.der", "review-receipt-path-seven.der", 6, 0, payload);
        deep("review-deep-self-issued-root.der", "review-receipt-path-seven-self-issued.der", 5, 1, payload);
        deep("review-shallow-root.der", "review-receipt-signer-issued-by-root.der", 0, 0, payload);
        write("review-receipt-signer-sha384-tampered.der", tamper(read("receipt-signer-sha384.der")));
        write("review-receipt-signer-rsa-pss-tampered.der", tamper(read("receipt-signer-rsa-pss.der")));
    }

    /**
     * A receipt chain of {@code intermediates} CAs and {@code selfIssuedTail}
     * self-issued CAs between the leaf and the root, every CA carrying the WWDR
     * marker, all valid 2024 to 2050. The path below the anchor is
     * {@code intermediates + selfIssuedTail + 1} certificates long.
     */
    private void deep(String rootName, String receiptName, int intermediates, int selfIssuedTail, byte[] payload)
            throws Exception {
        KeyPair rootKp = rsa();
        X509Certificate root = TestPki.cert(
                "CN=Review Deep Root", rootKp, "CN=Review Deep Root", rootKp.getPrivate(), true, null, nb, na, RSA);
        List<X509Certificate> cas = new ArrayList<X509Certificate>();
        String issuer = "CN=Review Deep Root";
        PrivateKey issuerKey = rootKp.getPrivate();
        for (int i = 1; i <= intermediates; i++) {
            String subject = "CN=Review Deep CA " + i;
            KeyPair kp = rsa();
            cas.add(TestPki.cert(subject, kp, issuer, issuerKey, true, WWDR_OID, nb, na, RSA));
            issuer = subject;
            issuerKey = kp.getPrivate();
        }
        for (int i = 0; i < selfIssuedTail; i++) {
            KeyPair kp = rsa();
            cas.add(TestPki.cert(issuer, kp, issuer, issuerKey, true, WWDR_OID, nb, na, RSA));
            issuerKey = kp.getPrivate();
        }
        KeyPair leafKp = rsa();
        X509Certificate leaf =
                TestPki.cert("CN=Review Deep Receipt Signing", leafKp, issuer, issuerKey, false, LEAF_OID, nb, na, RSA);
        List<X509CertificateHolder> embedded = new ArrayList<X509CertificateHolder>();
        embedded.add(holder(leaf));
        for (X509Certificate ca : cas) {
            embedded.add(holder(ca));
        }
        embedded.add(holder(root));
        write(rootName, root.getEncoded());
        write(
                receiptName,
                TestPki.signReceiptAs(
                        payload, new Date(SIGNED_DATE), leafKp.getPrivate(), RSA, holder(leaf), embedded));
    }

    // --- decode rules ------------------------------------------------------

    private void writeDecodeRules(TestPki pki) throws Exception {
        byte[] hash = TestPki.deviceHash(GUID, OPAQUE, BUNDLE);

        // Attribute 18 an expanded-year date whose epoch milliseconds overflow
        // a signed 64-bit value: not a date any port can hold.
        write(
                "review-receipt-date-beyond-epoch-ms.der",
                sign(
                        pki,
                        attributes(
                                TestPki.attribute(0, utf8("ProductionSandbox")),
                                TestPki.attribute(2, utf8(BUNDLE)),
                                TestPki.attribute(12, ia5(CREATION_DATE)),
                                TestPki.attribute(18, ia5("+1000000000-01-01T00:00:00Z")))));

        // An unknown attribute whose type is 2^31 - 1, the largest that fits.
        write(
                "review-receipt-attribute-type-int32-max.der",
                sign(
                        pki,
                        TestPki.receiptPayload(
                                "ProductionSandbox",
                                BUNDLE,
                                "1.2.3",
                                OPAQUE,
                                hash,
                                CREATION_DATE,
                                Collections.<byte[]>emptyList(),
                                true,
                                BigInteger.valueOf(Integer.MAX_VALUE),
                                new byte[] {1, 2, 3})));

        // The bundle id and the application version as PrintableString.
        write(
                "review-receipt-printable-string-attributes.der",
                sign(
                        pki,
                        attributes(
                                TestPki.attribute(0, utf8("ProductionSandbox")),
                                TestPki.attribute(2, new DERPrintableString(BUNDLE).getEncoded()),
                                TestPki.attribute(3, new DERPrintableString("1.2.3").getEncoded()),
                                TestPki.attribute(12, ia5(CREATION_DATE)))));

        // Integers at the 64-bit edge, a negative quantity, non-zero flags.
        ASN1EncodableVector iap = new ASN1EncodableVector();
        iap.add(TestPki.attribute(1701, integer(BigInteger.valueOf(-1))));
        iap.add(TestPki.attribute(1702, utf8(BUNDLE + ".coins100")));
        iap.add(TestPki.attribute(1703, utf8("70000000000071")));
        iap.add(TestPki.attribute(1713, integer(BigInteger.valueOf(2))));
        iap.add(TestPki.attribute(1719, integer(BigInteger.valueOf(-1))));
        write(
                "review-receipt-integer-edges.der",
                sign(
                        pki,
                        attributes(
                                TestPki.attribute(0, utf8("ProductionSandbox")),
                                TestPki.attribute(1, integer(BigInteger.valueOf(Long.MAX_VALUE))),
                                TestPki.attribute(2, utf8(BUNDLE)),
                                TestPki.attribute(12, ia5(CREATION_DATE)),
                                TestPki.attribute(15, integer(BigInteger.valueOf(Long.MIN_VALUE))),
                                TestPki.attribute(16, integer(BigInteger.ONE.shiftLeft(63))),
                                TestPki.attribute(17, new DERSet(iap).getEncoded()))));

        // Invalid UTF-8 inside UTF8Strings: bundle id, 19, 21 and in-app 1702.
        ASN1EncodableVector badIap = new ASN1EncodableVector();
        badIap.add(TestPki.attribute(1701, integer(BigInteger.ONE)));
        badIap.add(TestPki.attribute(1702, rawUtf8String(NOT_UTF8)));
        badIap.add(TestPki.attribute(1703, utf8("70000000000081")));
        write(
                "review-receipt-invalid-utf8-strings.der",
                sign(
                        pki,
                        attributes(
                                TestPki.attribute(0, utf8("ProductionSandbox")),
                                TestPki.attribute(2, rawUtf8String(NOT_UTF8)),
                                TestPki.attribute(12, ia5(CREATION_DATE)),
                                TestPki.attribute(17, new DERSet(badIap).getEncoded()),
                                TestPki.attribute(19, rawUtf8String(NOT_UTF8)),
                                TestPki.attribute(21, rawUtf8String(NOT_UTF8)))));

        // Canonical escapes: < > & (no HTML escaping), DEL, U+0000, U+2029.
        String productId = "com.example.app.<>&" + (char) 0x7f + (char) 0x0000 + (char) 0x2029 + "end";
        write(
                "review-receipt-escapes-html-and-separators.der",
                sign(
                        pki,
                        TestPki.receiptPayload(
                                "ProductionSandbox",
                                BUNDLE,
                                "1.2.3",
                                OPAQUE,
                                hash,
                                CREATION_DATE,
                                Collections.singletonList(TestPki.inAppPurchase(
                                        1,
                                        productId,
                                        "70000000000091",
                                        "70000000000091",
                                        "2024-01-15T12:00:00Z",
                                        null)))));
    }

    // --- signers -----------------------------------------------------------

    private void writeSigners(TestPki pki, byte[] payload, byte[] genuine) throws Exception {
        write("review-receipt-twin-certificate.der", pki.signReceiptWithTwinCert(payload));
        write("review-receipt-corrupted-signature.der", TestPki.corruptSignatures(genuine, 1));

        KeyPair sha512Key = rsa();
        X509Certificate sha512Signer = signerUnder(pki, sha512Key, "CN=Review SHA-512 Signing");
        write("review-receipt-signer-sha512.der", signAs(pki, payload, sha512Key, "SHA512withRSA", sha512Signer));

        // A SignerInfo whose digest is SHA-1 and whose signature algorithm is
        // md5WithRSAEncryption, carrying a genuine MD5 signature over its
        // signed attributes: the label contradicts the digest.
        KeyPair relabelKey = rsa();
        X509Certificate relabelSigner = signerUnder(pki, relabelKey, "CN=Review Relabel Signing");
        SignedData sha1 = signedData(signAs(pki, payload, relabelKey, "SHA1withRSA", relabelSigner));
        SignerInfo original = SignerInfo.getInstance(sha1.getSignerInfos().getObjectAt(0));
        Signature md5 = Signature.getInstance("MD5withRSA");
        md5.initSign(relabelKey.getPrivate());
        md5.update(original.getAuthenticatedAttributes().getEncoded(ASN1Encoding.DER));
        SignerInfo relabelled = new SignerInfo(
                original.getSID(),
                original.getDigestAlgorithm(),
                original.getAuthenticatedAttributes(),
                new AlgorithmIdentifier(PKCSObjectIdentifiers.md5WithRSAEncryption, DERNull.INSTANCE),
                new DEROctetString(md5.sign()),
                original.getUnauthenticatedAttributes());
        write("review-receipt-relabelled-signature-algorithm.der", withSignerInfos(sha1, new DLSet(relabelled)));

        // No SignerInfo at all.
        write("review-receipt-zero-signer-infos.der", withSignerInfos(signedData(genuine), new DLSet()));

        // Two failing signers, in both orders: a stranger that chains to no
        // pinned root (UNTRUSTED_CHAIN) and a genuine signer whose signature
        // is corrupted (INVALID_SIGNATURE). The SET is written in the order
        // given, so the first SignerInfo's failure is the verdict.
        KeyPair genuineKey = rsa();
        X509Certificate genuineSigner = signerUnder(pki, genuineKey, "CN=Review Genuine Signing");
        KeyPair strangerKey = rsa();
        X509Certificate stranger = TestPki.cert(
                "CN=Review Stranger",
                strangerKey,
                "CN=Review Stranger",
                strangerKey.getPrivate(),
                false,
                LEAF_OID,
                nb,
                na,
                RSA);
        byte[] brokenGenuine = TestPki.corruptSignatures(signAs(pki, payload, genuineKey, RSA, genuineSigner), 1);
        byte[] fromStranger = signAs(pki, payload, strangerKey, RSA, stranger);
        write("review-receipt-failing-signers-stranger-first.der", inOrder(fromStranger, brokenGenuine, genuineSigner));
        write("review-receipt-failing-signers-broken-first.der", inOrder(brokenGenuine, fromStranger, stranger));

        // Malformed signedAttrs in either position, beside a valid signer: the
        // [0] field holds an INTEGER where Attributes belong.
        KeyPair okKey = rsa();
        X509Certificate okSigner = signerUnder(pki, okKey, "CN=Review Valid Signing");
        byte[] valid = signAs(pki, payload, okKey, RSA, okSigner);
        KeyPair badKey = rsa();
        X509Certificate badSigner = signerUnder(pki, badKey, "CN=Review Malformed Attrs Signing");
        byte[] malformed = withMalformedSignedAttrs(signAs(pki, payload, badKey, RSA, badSigner));
        write("review-receipt-malformed-signed-attrs-first.der", inOrder(malformed, valid, okSigner));
        write("review-receipt-malformed-signed-attrs-second.der", inOrder(valid, malformed, badSigner));
    }

    // --- certificate decode ------------------------------------------------

    private void writeCertificateDecode(TestPki pki, byte[] genuine) throws Exception {
        CMSSignedData withBadKey = new CMSSignedData(read("receipt-signer-unimplemented-curve.der"));
        write(
                "review-receipt-stranger-unreadable-key.der",
                withExtraCertificates(genuine, withBadKey.getCertificates().getMatches(null)));
        write(
                "review-receipt-stranger-unaligned-signature.der",
                withExtraCertificates(
                        genuine,
                        Collections.singletonList(new X509CertificateHolder(unaligned(pki.root.getEncoded())))));
    }

    // --- JWS ---------------------------------------------------------------

    private void writeJws() throws Exception {
        TestPki jws = TestPki.jws(true, true, nb, na);
        write("review-jws-root.der", jws.root.getEncoded());
        String header = header("ES256", jws.x5c());
        Map<String, Object> claims = claims(SIGNED_DATE);
        String payload = json(claims);

        // Nesting, counting the outer object: 64 passes, 65 is refused.
        write("review-jws-header-nested-64.jws", jws.signJwsWithHeader(withNest(header, 63), payload));
        write("review-jws-header-nested-65.jws", jws.signJwsWithHeader(withNest(header, 64), payload));
        write("review-jws-payload-nested-64.jws", jws.signJwsWithHeader(header, withNest(payload, 63)));
        write("review-jws-payload-nested-65-signed.jws", jws.signJwsWithHeader(header, withNest(payload, 64)));
        String[] genuine = jws.signJwsWithHeader(header, payload).split("\\.", -1);
        write(
                "review-jws-payload-nested-65-unsigned.jws",
                genuine[0] + "." + TestPki.b64url(withNest(payload, 64).getBytes(StandardCharsets.UTF_8)) + "."
                        + genuine[2]);

        // alg carrying CR, LF, NEL, LINE SEPARATOR and a bidi override.
        String hostileAlg = "ES256\r\n\u0085 ‮";
        write("review-jws-alg-control-characters.jws", jws.signJwsWithHeader(header(hostileAlg, jws.x5c()), payload));
        write("review-jws-alg-rs256.jws", jws.signJwsWithHeader(header("RS256", jws.x5c()), payload));
        write(
                "review-jws-two-certificate-x5c.jws",
                jws.signJwsWithHeader(header("ES256", jws.x5c().subList(0, 2)), payload));

        // A payload that is not UTF-8, signed.
        byte[] notUtf8 = {'{', '"', 'a', '"', ':', '"', (byte) 0xC3, '"', '}'};
        write(
                "review-jws-payload-not-utf8.jws",
                jws.signCompact(
                        TestPki.b64url(header.getBytes(StandardCharsets.UTF_8)) + "." + TestPki.b64url(notUtf8)));

        // Non-ASCII claims.
        Map<String, Object> nonAscii = claims(SIGNED_DATE);
        nonAscii.put("productId", "com.example.app.é€中");
        nonAscii.put("offerIdentifier", "über-€-中文-😀");
        write("review-jws-non-ascii-claims.jws", jws.signJwsWithHeader(header, json(nonAscii)));

        // Duplicate members: the last one wins, in the header and the payload.
        String duplicateHeader =
                "{\"alg\":\"RS256\",\"x5c\":[\"AAAA\"],\"alg\":\"ES256\",\"x5c\":" + x5cArray(jws.x5c()) + "}";
        write("review-jws-duplicate-header-members.jws", jws.signJwsWithHeader(duplicateHeader, payload));
        String duplicateDate = "{\"signedDate\":1590969600000," + payload.substring(1, payload.length() - 1)
                + ",\"signedDate\":" + SIGNED_DATE + "}";
        write("review-jws-duplicate-signed-date.jws", jws.signJwsWithHeader(header, duplicateDate));

        // Trailing content after the header object, and after the payload object.
        write("review-jws-header-trailing-content.jws", jws.signJwsWithHeader(header + "x", payload));
        write("review-jws-payload-trailing-content.jws", jws.signJwsWithHeader(header, payload + "xyz"));

        // A header in UTF-16 (big-endian, no BOM) and a UTF-8 header behind a BOM.
        write(
                "review-jws-header-utf16.jws",
                jws.signCompact(TestPki.b64url(header.getBytes(StandardCharsets.UTF_16BE)) + "."
                        + TestPki.b64url(payload.getBytes(StandardCharsets.UTF_8))));
        write("review-jws-header-bom.jws", jws.signJwsWithHeader("﻿" + header, payload));

        // signedDate edges.
        write(
                "review-jws-signed-date-9e15.jws",
                jws.signJwsWithHeader(header, withSignedDate(payload, "9000000000000000")));
        write("review-jws-signed-date-negative.jws", jws.signJwsWithHeader(header, withSignedDate(payload, "-1000")));
        write(
                "review-jws-signed-date-fractional.jws",
                jws.signJwsWithHeader(header, withSignedDate(payload, "1722945600000.5")));

        // An x5c leaf whose signature BIT STRING declares one unused bit, the
        // header re-signed so the certificate is the only defect.
        List<String> x5c = new ArrayList<String>(jws.x5c());
        x5c.set(
                0,
                Base64.getEncoder().encodeToString(unaligned(Base64.getDecoder().decode(x5c.get(0)))));
        write("review-jws-x5c-leaf-unaligned-signature.jws", jws.signJwsWithHeader(header("ES256", x5c), payload));
    }

    // --- endpoint bodies ---------------------------------------------------

    private void writeEndpointBodies(byte[] genuine) throws Exception {
        String receipt = Base64.getEncoder().encodeToString(genuine);
        text("review-body-array.json", "[]");
        text("review-body-null.json", "null");
        text("review-body-scalar.json", "42");
        text("review-body-receipt-data-missing.json", "{}");
        text("review-body-receipt-data-not-a-string.json", "{\"receipt-data\":42}");
        text(
                "review-body-duplicate-receipt-data.json",
                "{\"receipt-data\":\"AAAA\",\"receipt-data\":\"" + receipt + "\"}");
        text(
                "review-body-password-and-exclude-old.json",
                "{\"receipt-data\":\"" + receipt
                        + "\",\"password\":\"shared-secret\",\"exclude-old-transactions\":true}");
    }

    // --- helpers -----------------------------------------------------------

    private byte[] standardPayload() throws Exception {
        return TestPki.receiptPayload(
                BUNDLE,
                "1.2.3",
                OPAQUE,
                TestPki.deviceHash(GUID, OPAQUE, BUNDLE),
                CREATION_DATE,
                Collections.<byte[]>emptyList());
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

    private static byte[] integer(BigInteger value) throws Exception {
        return new ASN1Integer(value).getEncoded();
    }

    /** A UTF8String TLV around {@code content} verbatim, valid UTF-8 or not. */
    private static byte[] rawUtf8String(byte[] content) {
        byte[] out = new byte[content.length + 2];
        out[0] = 0x0c;
        out[1] = (byte) content.length;
        System.arraycopy(content, 0, out, 2, content.length);
        return out;
    }

    private X509Certificate signerUnder(TestPki pki, KeyPair key, String subject) throws Exception {
        return TestPki.cert(subject, key, name(pki.intermediate), pki.intermediateKey, false, LEAF_OID, nb, na, RSA);
    }

    private static byte[] signAs(TestPki pki, byte[] payload, KeyPair key, String sigAlg, X509Certificate signer)
            throws Exception {
        List<X509CertificateHolder> embedded =
                Arrays.asList(holder(signer), holder(pki.intermediate), holder(pki.root));
        return TestPki.signReceiptAs(
                payload, new Date(SIGNED_DATE), key.getPrivate(), sigAlg, embedded.get(0), embedded);
    }

    private static SignedData signedData(byte[] cms) throws Exception {
        return SignedData.getInstance(
                ContentInfo.getInstance(ASN1Primitive.fromByteArray(cms)).getContent());
    }

    private static byte[] withSignerInfos(SignedData original, ASN1Set signerInfos) throws Exception {
        SignedData replaced = new SignedData(
                original.getDigestAlgorithms(),
                original.getEncapContentInfo(),
                original.getCertificates(),
                (ASN1Set) null,
                signerInfos);
        return new ContentInfo(CMSObjectIdentifiers.signedData, replaced).getEncoded();
    }

    /**
     * {@code first}'s SignedData with {@code second}'s SignerInfo appended in
     * that order (a DL SET, which DER would sort) and {@code extra} added to
     * the certificates.
     */
    private static byte[] inOrder(byte[] first, byte[] second, X509Certificate extra) throws Exception {
        SignedData a = signedData(first);
        SignedData b = signedData(second);
        ASN1EncodableVector infos = new ASN1EncodableVector();
        infos.add(a.getSignerInfos().getObjectAt(0));
        infos.add(b.getSignerInfos().getObjectAt(0));
        ASN1EncodableVector certificates = new ASN1EncodableVector();
        for (ASN1Encodable certificate : a.getCertificates()) {
            certificates.add(certificate);
        }
        certificates.add(holder(extra).toASN1Structure());
        SignedData combined = new SignedData(
                a.getDigestAlgorithms(),
                a.getEncapContentInfo(),
                new DLSet(certificates),
                (ASN1Set) null,
                new DLSet(infos));
        return new ContentInfo(CMSObjectIdentifiers.signedData, combined).getEncoded();
    }

    /** The single SignerInfo of {@code cms} with its signedAttrs replaced by [0] { INTEGER 7 }. */
    private static byte[] withMalformedSignedAttrs(byte[] cms) throws Exception {
        SignedData data = signedData(cms);
        SignerInfo original = SignerInfo.getInstance(data.getSignerInfos().getObjectAt(0));
        SignerInfo broken = new SignerInfo(
                original.getSID(),
                original.getDigestAlgorithm(),
                new DERSet(new ASN1Integer(7)),
                original.getDigestEncryptionAlgorithm(),
                original.getEncryptedDigest(),
                original.getUnauthenticatedAttributes());
        return withSignerInfos(data, new DLSet(broken));
    }

    private static byte[] withExtraCertificates(byte[] genuine, java.util.Collection<X509CertificateHolder> extra)
            throws Exception {
        CMSSignedData cms = new CMSSignedData(genuine);
        List<X509CertificateHolder> bag =
                new ArrayList<X509CertificateHolder>(cms.getCertificates().getMatches(null));
        bag.addAll(extra);
        return CMSSignedData.replaceCertificatesAndCRLs(
                        cms, new CollectionStore<X509CertificateHolder>(bag), null, null)
                .getEncoded();
    }

    /** {@code der} re-encoded with its signature BIT STRING declaring one unused bit. */
    private static byte[] unaligned(byte[] der) throws Exception {
        ASN1Sequence certificate = ASN1Sequence.getInstance(der);
        byte[] signature = DERBitString.getInstance(certificate.getObjectAt(2)).getBytes();
        ASN1EncodableVector fields = new ASN1EncodableVector();
        fields.add(certificate.getObjectAt(0));
        fields.add(certificate.getObjectAt(1));
        fields.add(new DERBitString(signature, 1));
        return new DERSequence(fields).getEncoded();
    }

    /** Flips one byte of the bundle id inside the encapsulated content. */
    private static byte[] tamper(byte[] der) {
        byte[] needle = BUNDLE.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i + needle.length <= der.length; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length && match; j++) {
                match = der[i + j] == needle[j];
            }
            if (match) {
                byte[] copy = der.clone();
                copy[i + needle.length - 1] ^= 0x01;
                return copy;
            }
        }
        throw new IllegalStateException("bundle id not found");
    }

    private static Map<String, Object> claims(long signedDate) {
        Map<String, Object> claims = new LinkedHashMap<String, Object>();
        claims.put("bundleId", BUNDLE);
        claims.put("environment", "Sandbox");
        claims.put("signedDate", signedDate);
        claims.put("productId", BUNDLE + ".pro");
        claims.put("transactionId", "2000000000000001");
        return claims;
    }

    /** Compact JSON for the flat string/number maps used here. */
    private static String json(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        for (Map.Entry<String, Object> e : map.entrySet()) {
            if (sb.length() > 1) {
                sb.append(',');
            }
            sb.append('"').append(e.getKey()).append("\":");
            Object v = e.getValue();
            sb.append(v instanceof String ? "\"" + v + "\"" : String.valueOf(v));
        }
        return sb.append('}').toString();
    }

    private static String header(String alg, List<String> x5c) {
        return "{\"alg\":\"" + escape(alg) + "\",\"x5c\":" + x5cArray(x5c) + "}";
    }

    private static String x5cArray(List<String> x5c) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < x5c.size(); i++) {
            sb.append(i == 0 ? "\"" : ",\"").append(x5c.get(i)).append('"');
        }
        return sb.append(']').toString();
    }

    /** JSON string escaping for the control characters the hostile alg carries. */
    private static String escape(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c < 0x20) {
                sb.append(String.format("\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** {@code object} with a member "n" nesting {@code arrays} arrays, appended before its closing brace. */
    private static String withNest(String object, int arrays) {
        StringBuilder nest = new StringBuilder();
        for (int i = 0; i < arrays; i++) {
            nest.append('[');
        }
        for (int i = 0; i < arrays; i++) {
            nest.append(']');
        }
        return object.substring(0, object.length() - 1) + ",\"n\":" + nest + "}";
    }

    private static String withSignedDate(String payload, String literal) {
        return payload.replace("\"signedDate\":" + SIGNED_DATE, "\"signedDate\":" + literal);
    }

    private static X509CertificateHolder holder(X509Certificate certificate) throws Exception {
        return new X509CertificateHolder(certificate.getEncoded());
    }

    private static String name(X509Certificate certificate) {
        return certificate.getSubjectX500Principal().getName();
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
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

    private void text(String name, String body) throws Exception {
        write(name, body.getBytes(StandardCharsets.UTF_8));
    }
}
