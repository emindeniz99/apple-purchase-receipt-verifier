package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;

/**
 * Which bytes each implementation verifies signed attributes over when they
 * are not in DER order. A receipt signed by a fresh key whose certificate the
 * test intermediate issued (with the receipt-signing marker), its signed
 * attributes sent out of DER order in one of two places, and signed either
 * over the bytes as sent or over their DER encoding:
 *
 * <ul>
 *   <li>{@code top-as-sent}, {@code top-sorted}: the SET of attributes, a
 *       private attribute ahead of contentType and messageDigest;</li>
 *   <li>{@code values-as-sent}, {@code values-sorted}: one private attribute
 *       holding two values, the longer first, the attributes in DER
 *       order.</li>
 * </ul>
 *
 * <p>Prints the verdict of each, or with -Ddump=DIR writes each receipt and
 * its root for core_shapes.rs.
 */
public class SignedAttrsOrderProbe {
    public static void main(String[] a) throws Exception {
        TestPki pki = TestPki.receipt();
        Set<TrustAnchor> anchors = AppleTrust.anchors(Collections.singleton(pki.root));
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair key = rsa.generateKeyPair();
        X509Certificate signer = TestPki.cert(
                "CN=Order Probe Signer",
                key,
                pki.intermediate.getSubjectX500Principal().getName(),
                pki.intermediateKey,
                false,
                AppleTrust.SIGNING_LEAF_OID,
                pki.leaf.getNotBefore(),
                pki.leaf.getNotAfter(),
                "SHA256withRSA");
        byte[] payload = TestPki.singleAttributePayload(9999, new byte[16]);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(payload);
        ASN1Encodable contentType = attribute(CMSAttributes.contentType, CMSObjectIdentifiers.data);
        ASN1Encodable messageDigest = attribute(CMSAttributes.messageDigest, new DEROctetString(digest));
        ASN1ObjectIdentifier privateType = new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.2");
        // DER orders a SET OF by its members' encodings, so the length octet
        // decides: the longer UTF8String after the shorter, and an attribute
        // longer than messageDigest's after it and contentType. Each mode
        // breaks the order in one place only: in the values modes the
        // attributes themselves are in DER order.
        ASN1Encodable one = attribute(privateType, new DERUTF8String(new String(new char[60]).replace('\0', 'a')));
        ASN1Encodable two = new DLSequence(new ASN1Encodable[] {
            privateType,
            new DLSet(new ASN1Encodable[] {
                new DERUTF8String(new String(new char[40]).replace('\0', 'b')), new DERUTF8String("a")})});
        for (String mode : new String[] {"top-as-sent", "top-sorted", "values-as-sent", "values-sorted"}) {
            DLSet sent = mode.startsWith("top")
                    ? new DLSet(new ASN1Encodable[] {one, contentType, messageDigest})
                    : new DLSet(new ASN1Encodable[] {contentType, messageDigest, two});
            byte[] signed = mode.endsWith("as-sent") ? sent.getEncoded("DL") : derOf(sent);
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(key.getPrivate());
            signature.update(signed);
            byte[] der = receipt(pki, signer, payload, sent, signature.sign());
            if (System.getProperty("dump") != null) {
                java.nio.file.Files.write(java.nio.file.Paths.get(System.getProperty("dump"), "order-" + mode + ".der"), der);
                java.nio.file.Files.write(
                        java.nio.file.Paths.get(System.getProperty("dump"), "order-" + mode + ".root.der"),
                        pki.root.getEncoded());
                continue;
            }
            String verdict;
            try {
                ReceiptCore.verifyDer(der, anchors, System.currentTimeMillis());
                verdict = "ACCEPTED";
            } catch (VerificationException e) {
                verdict = e.reason() + ": " + e.getMessage();
            }
            System.out.printf("order %s der=%d sentIsDer=%s topIsDer=%s [%s]%n", mode, der.length,
                    java.util.Arrays.equals(sent.getEncoded("DL"), derOf(sent)),
                    java.util.Arrays.equals(new DERSet(sent.toArray()).toArray(), sent.toArray()), verdict);
        }
    }

    /** The DER encoding of {@code set}, every level sorted. */
    static byte[] derOf(DLSet set) throws Exception {
        return set.getEncoded("DER");
    }

    static ASN1Encodable attribute(ASN1ObjectIdentifier type, ASN1Encodable value) {
        return new DLSequence(new ASN1Encodable[] {type, new DLSet(value)});
    }

    static byte[] receipt(TestPki pki, X509Certificate signer, byte[] payload, DLSet attributes, byte[] signature)
            throws Exception {
        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        Certificate signerCert = Certificate.getInstance(signer.getEncoded());
        DLSequence signerInfo = new DLSequence(new ASN1Encodable[] {
            new ASN1Integer(1),
            new DLSequence(new ASN1Encodable[] {
                signerCert.getIssuer(), new ASN1Integer(signer.getSerialNumber())}),
            sha256,
            new DLTaggedObject(false, 0, attributes),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE),
            new DEROctetString(signature)});
        ASN1EncodableVector body = new ASN1EncodableVector();
        body.add(new ASN1Integer(1));
        body.add(new DERSet(sha256));
        body.add(new DLSequence(new ASN1Encodable[] {
            CMSObjectIdentifiers.data, new DLTaggedObject(true, 0, new DEROctetString(payload))}));
        body.add(new DLTaggedObject(false, 0, new DLSet(new ASN1Encodable[] {
            signerCert, Certificate.getInstance(pki.intermediate.getEncoded())})));
        body.add(new DLSet(signerInfo));
        return new DLSequence(new ASN1Encodable[] {CMSObjectIdentifiers.signedData,
            new DLTaggedObject(true, 0, new DLSequence(body))}).getEncoded("DL");
    }
}
