package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Generates a fake "Apple" PKI (root → intermediate → leaf) and signs JWS
 * payloads / CMS receipts with it — the same fixture technique Apple's own
 * libraries use, so no real Apple key material is ever needed. Also proves
 * anchor pinning: chains from a second TestPki instance must be rejected.
 *
 * <p>Kept Java 8-compatible (like main sources) so the suite can run on a
 * real JDK 8 in a CI matrix — hence the DER→P1363 signature conversion
 * instead of the Java 9+ {@code SHA256withECDSAinP1363Format} algorithm.</p>
 */
final class TestPki {

    private static final AtomicLong SERIAL = new AtomicLong(1);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    static final BouncyCastleProvider BC = new BouncyCastleProvider();

    final X509Certificate root;
    final X509Certificate intermediate;
    final X509Certificate leaf;
    private final PrivateKey leafKey;

    private TestPki(X509Certificate root, X509Certificate intermediate,
                    X509Certificate leaf, PrivateKey leafKey) {
        this.root = root;
        this.intermediate = intermediate;
        this.leaf = leaf;
        this.leafKey = leafKey;
    }

    /** EC P-256 chain with both Apple marker OIDs — for JWS fixtures. */
    static TestPki jws() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 86_400_000L);
        return jws(true, true, notBefore, notAfter);
    }

    /** EC chain with configurable marker OIDs and validity window. */
    static TestPki jws(boolean leafOid, boolean intermediateOid, Date notBefore, Date notAfter)
            throws Exception {
        KeyPair rootKp = ecKeyPair();
        KeyPair interKp = ecKeyPair();
        KeyPair leafKp = ecKeyPair();
        X509Certificate rootCert = cert("CN=Fake Apple Root CA", rootKp, "CN=Fake Apple Root CA",
                rootKp.getPrivate(), true, null, notBefore, notAfter, "SHA256withECDSA");
        X509Certificate interCert = cert("CN=Fake Apple WWDR CA", interKp, "CN=Fake Apple Root CA",
                rootKp.getPrivate(), true,
                intermediateOid ? "1.2.840.113635.100.6.2.1" : null,
                notBefore, notAfter, "SHA256withECDSA");
        X509Certificate leafCert = cert("CN=Fake App Store Signing", leafKp, "CN=Fake Apple WWDR CA",
                interKp.getPrivate(), false,
                leafOid ? "1.2.840.113635.100.6.11.1" : null,
                notBefore, notAfter, "SHA256withECDSA");
        return new TestPki(rootCert, interCert, leafCert, leafKp.getPrivate());
    }

    /** RSA chain (no marker OIDs — receipts don't require them) — for CMS receipts. */
    static TestPki receipt() throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 86_400_000L);
        return receipt(notBefore, notAfter);
    }

    static TestPki receipt(Date notBefore, Date notAfter) throws Exception {
        return receipt(notBefore, notAfter, true);
    }

    /** RSA receipt chain; {@code signerOid} stamps the Apple receipt-signing marker on the leaf. */
    static TestPki receipt(Date notBefore, Date notAfter, boolean signerOid) throws Exception {
        KeyPair rootKp = rsaKeyPair();
        KeyPair interKp = rsaKeyPair();
        KeyPair signerKp = rsaKeyPair();
        X509Certificate rootCert = cert("CN=Fake Apple Inc Root", rootKp, "CN=Fake Apple Inc Root",
                rootKp.getPrivate(), true, null, notBefore, notAfter, "SHA256withRSA");
        X509Certificate interCert = cert("CN=Fake WWDR CA", interKp, "CN=Fake Apple Inc Root",
                rootKp.getPrivate(), true, null, notBefore, notAfter, "SHA256withRSA");
        X509Certificate signerCert = cert("CN=Fake Receipt Signing", signerKp, "CN=Fake WWDR CA",
                interKp.getPrivate(), false,
                signerOid ? "1.2.840.113635.100.6.11.1" : null,
                notBefore, notAfter, "SHA256withRSA");
        return new TestPki(rootCert, interCert, signerCert, signerKp.getPrivate());
    }

    /** Varargs {@code key, value, key, value…} claims helper (insertion-ordered). */
    static Map<String, Object> claims(Object... kv) {
        Map<String, Object> map = new LinkedHashMap<String, Object>();
        for (int i = 0; i < kv.length; i += 2) {
            map.put((String) kv[i], kv[i + 1]);
        }
        return map;
    }

    // --- JWS -------------------------------------------------------------

    /** Signs claims as an ES256 compact JWS carrying this chain in x5c. */
    String signJws(Map<String, ?> claims) throws Exception {
        Map<String, Object> header = new LinkedHashMap<String, Object>();
        header.put("alg", "ES256");
        header.put("x5c", Arrays.asList(b64(leaf.getEncoded()),
                b64(intermediate.getEncoded()), b64(root.getEncoded())));
        return signJwsWithHeader(MAPPER.writeValueAsString(header),
                MAPPER.writeValueAsString(claims));
    }

    /** Same, but with a caller-controlled header (for malformed-header tests). */
    String signJwsWithHeader(String headerJson, String payloadJson) throws Exception {
        String input = b64url(headerJson.getBytes(StandardCharsets.UTF_8))
                + "." + b64url(payloadJson.getBytes(StandardCharsets.UTF_8));
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(leafKey);
        sig.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + b64url(derToP1363(sig.sign()));
    }

    List<String> x5c() throws Exception {
        return Arrays.asList(b64(leaf.getEncoded()), b64(intermediate.getEncoded()),
                b64(root.getEncoded()));
    }

    /** JCA emits DER ECDSA signatures; JWS wants raw 64-byte r ‖ s. */
    private static byte[] derToP1363(byte[] der) throws Exception {
        ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(der);
        BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
        BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
        byte[] out = new byte[64];
        copyPadded(r, out, 0);
        copyPadded(s, out, 32);
        return out;
    }

    private static void copyPadded(BigInteger value, byte[] out, int offset) {
        byte[] bytes = value.toByteArray();
        int start = bytes.length > 32 ? bytes.length - 32 : 0;
        int length = bytes.length - start;
        System.arraycopy(bytes, start, out, offset + 32 - length, length);
    }

    // --- Receipts --------------------------------------------------------

    /** CMS-signs a receipt payload (encapsulated), embedding the full chain. */
    byte[] signReceipt(byte[] payload) throws Exception {
        return signReceipt(payload, new Date());
    }

    /**
     * Same, with an explicit CMS signingTime — needed for historical-receipt
     * fixtures, where signingTime must fall inside the (now expired) signer
     * cert's validity window like a genuine old receipt's would.
     */
    byte[] signReceipt(byte[] payload, Date signingTime) throws Exception {
        ASN1EncodableVector baseAttrs = new ASN1EncodableVector();
        baseAttrs.add(new org.bouncycastle.asn1.cms.Attribute(CMSAttributes.signingTime,
                new DERSet(new Time(signingTime))));
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(leafKey);
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider(BC).build())
                .setSignedAttributeGenerator(
                        new DefaultSignedAttributeTableGenerator(new AttributeTable(baseAttrs)))
                .build(cs, leaf));
        gen.addCertificates(new JcaCertStore(Arrays.asList(leaf, intermediate, root)));
        CMSSignedData signed = gen.generate(new CMSProcessableByteArray(payload), true);
        return signed.getEncoded();
    }

    /** Builds a receipt payload SET; each entry of {@code inAppSets} becomes an attr-17. */
    static byte[] receiptPayload(String bundleId, String appVersion, byte[] opaque,
                                 byte[] sha1Hash, String creationDate,
                                 List<byte[]> inAppSets) throws Exception {
        return receiptPayload("ProductionSandbox", bundleId, appVersion, opaque, sha1Hash,
                creationDate, inAppSets);
    }

    /** Same, with an explicit receipt_type (attr 0); {@code null} omits the attribute. */
    static byte[] receiptPayload(String receiptType, String bundleId, String appVersion,
                                 byte[] opaque, byte[] sha1Hash, String creationDate,
                                 List<byte[]> inAppSets) throws Exception {
        ASN1EncodableVector attrs = new ASN1EncodableVector();
        if (receiptType != null) {
            attrs.add(attr(0, new DERUTF8String(receiptType).getEncoded()));
        }
        attrs.add(attr(2, new DERUTF8String(bundleId).getEncoded()));
        attrs.add(attr(3, new DERUTF8String(appVersion).getEncoded()));
        attrs.add(attr(18, new DERIA5String(creationDate).getEncoded()));
        attrs.add(attr(4, opaque));
        attrs.add(attr(5, sha1Hash));
        attrs.add(attr(12, new DERIA5String(creationDate).getEncoded()));
        attrs.add(attr(19, new DERUTF8String("1.0").getEncoded()));
        attrs.add(attr(9999, new byte[]{1, 2, 3}));  // unknown attr for D10 tests
        for (byte[] inApp : inAppSets) {
            attrs.add(attr(17, inApp));
        }
        return new DERSet(attrs).getEncoded();
    }

    /** Builds one in-app purchase attribute SET (the value of an attr-17). */
    static byte[] inAppPurchase(long quantity, String productId, String transactionId,
                                String originalTransactionId, String purchaseDate,
                                String expiresDate) throws Exception {
        ASN1EncodableVector attrs = new ASN1EncodableVector();
        attrs.add(attr(1701, new ASN1Integer(quantity).getEncoded()));
        attrs.add(attr(1702, new DERUTF8String(productId).getEncoded()));
        attrs.add(attr(1703, new DERUTF8String(transactionId).getEncoded()));
        attrs.add(attr(1705, new DERUTF8String(originalTransactionId).getEncoded()));
        attrs.add(attr(1704, new DERIA5String(purchaseDate).getEncoded()));
        attrs.add(attr(1706, new DERIA5String(purchaseDate).getEncoded()));
        if (expiresDate != null) {
            attrs.add(attr(1708, new DERIA5String(expiresDate).getEncoded()));
        }
        attrs.add(attr(1711, new ASN1Integer(42).getEncoded()));
        return new DERSet(attrs).getEncoded();
    }

    /** Xcode-style double wrap: the payload SET inside an extra OCTET STRING. */
    static byte[] doubleWrap(byte[] payload) throws Exception {
        return new DEROctetString(payload).getEncoded();
    }

    /** The device hash a genuine receipt would carry for this GUID (PLAN §2.2 step 5). */
    static byte[] deviceHash(byte[] guid, byte[] opaque, String bundleId) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(guid);
        sha1.update(opaque);
        sha1.update(new DERUTF8String(bundleId).getEncoded());
        return sha1.digest();
    }

    private static ASN1Encodable attr(int type, byte[] valueOctets) {
        return new DERSequence(new ASN1Encodable[]{
                new ASN1Integer(type), new ASN1Integer(1), new DEROctetString(valueOctets)});
    }

    // --- plumbing --------------------------------------------------------

    private static KeyPair ecKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate cert(String subject, KeyPair subjectKp, String issuer,
                                        PrivateKey issuerKey, boolean ca, String markerOid,
                                        Date notBefore, Date notAfter, String sigAlg)
            throws Exception {
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(issuer), BigInteger.valueOf(SERIAL.getAndIncrement()),
                notBefore, notAfter, new X500Name(subject), subjectKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (markerOid != null) {
            builder.addExtension(new ASN1ObjectIdentifier(markerOid), false, DERNull.INSTANCE);
        }
        ContentSigner cs = new JcaContentSignerBuilder(sigAlg).build(issuerKey);
        return new JcaX509CertificateConverter().getCertificate(builder.build(cs));
    }

    static String b64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    static String b64url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
