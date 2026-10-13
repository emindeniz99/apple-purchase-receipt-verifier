package io.github.emindeniz99.applepurchasereceiptverifier;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.Date;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Unsigned receipts whose attacker-chosen ASN.1 BouncyCastle DER-re-encodes
 * before any trust decision. Mode "sid": the SignerInfo's issuer name holds
 * one RDN whose value is a SEQUENCE of nested-SET chains; ten embedded
 * copies of a self-made certificate share the SignerInfo's serial and RDN
 * shape. Mode "cert": the certificate bag holds one entry that is the same
 * SEQUENCE. Mode "plain": no nesting, same size (a flat SEQUENCE of
 * INTEGERs). Mode "string" (added for the fix): the issuer value is one
 * UTF8String of targetBytes. Args: mode depth targetBytes copies
 */
public class NestedValueProbe {
    public static void main(String[] a) throws Exception {
        String mode = a[0];
        int depth = Integer.parseInt(a[1]);
        int target = Integer.parseInt(a[2]);
        int copies = a.length > 3 ? Integer.parseInt(a[3]) : 10;
        TestPki pki = TestPki.receipt();
        Set<TrustAnchor> anchors = AppleTrust.anchors(Collections.singleton(pki.root));
        byte[] genuine = pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16]));
        SignedData sd = SignedData.getInstance(ContentInfo.getInstance(genuine).getContent());
        SignerInfo si = SignerInfo.getInstance(sd.getSignerInfos().getObjectAt(0));

        ASN1Encodable node = new ASN1Integer(7);
        for (int i = 0; i < depth; i++) {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(node);
            v.add(new ASN1Integer(1));
            node = new DLSet(v);
        }
        int one = node.toASN1Primitive().getEncoded("DL").length;
        ASN1EncodableVector all = new ASN1EncodableVector();
        if (mode.equals("plain")) {
            for (int i = 0; i < target / 3; i++) all.add(new ASN1Integer(1));
        } else {
            for (int i = 0; i < target / one; i++) all.add(node);
        }
        ASN1Encodable bulk = mode.equals("string")
                ? new org.bouncycastle.asn1.DERUTF8String(new String(new char[target]).replace('\0', 'a'))
                : new DLSequence(all);

        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", BouncyCastle.PROVIDER);
        g.initialize(1024);
        KeyPair kp = g.generateKeyPair();
        BigInteger serial = BigInteger.valueOf(4242);
        X509CertificateHolder junk = new JcaX509v3CertificateBuilder(new X500Name("CN=x"), serial,
                new Date(System.currentTimeMillis() - 86400000L), new Date(System.currentTimeMillis() + 86400000L),
                new X500Name("CN=y"), kp.getPublic()).build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate()));

        ASN1Set certs;
        SignerInfo signer;
        if (mode.equals("cert")) {
            ASN1EncodableVector c = new ASN1EncodableVector();
            for (int i = 0; i < sd.getCertificates().size(); i++) c.add(sd.getCertificates().getObjectAt(i));
            c.add(bulk);
            certs = new DLSet(c);
            signer = si;
        } else {
            ASN1EncodableVector c = new ASN1EncodableVector();
            for (int i = 0; i < copies; i++) c.add(junk.toASN1Structure());
            certs = new DLSet(c);
            X500Name issuer = new X500Name(new RDN[] {new RDN(new AttributeTypeAndValue(BCStyle.CN, bulk))});
            signer = new SignerInfo(new SignerIdentifier(new IssuerAndSerialNumber(issuer, serial)),
                    si.getDigestAlgorithm(), si.getAuthenticatedAttributes(), si.getDigestEncryptionAlgorithm(),
                    si.getEncryptedDigest(), (ASN1Set) null);
        }
        ASN1EncodableVector body = new ASN1EncodableVector();
        body.add(new ASN1Integer(1));
        body.add(sd.getDigestAlgorithms());
        body.add(sd.getEncapContentInfo());
        body.add(new DLTaggedObject(false, 0, certs));
        body.add(new DLSet(signer));
        byte[] der = new DLSequence(new ASN1Encodable[] {CMSObjectIdentifiers.signedData,
            new DLTaggedObject(true, 0, new DLSequence(body))}).getEncoded("DL");
        if (System.getProperty("dump") != null) {
            // For the core: the receipt and its test root, then no timing.
            java.nio.file.Files.write(java.nio.file.Paths.get(System.getProperty("dump") + ".der"), der);
            java.nio.file.Files.write(java.nio.file.Paths.get(System.getProperty("dump") + ".root.der"), pki.root.getEncoded());
            return;
        }
        System.out.printf("mode=%s depth=%d chain=%dB der=%d base64=%d (cap 3145728)%n", mode, depth, one, der.length, (der.length + 2) / 3 * 4);
        for (int r = 0; r < 3; r++) {
            long t = System.nanoTime();
            String verdict;
            try {
                ReceiptCore.verifyDer(der, anchors, System.currentTimeMillis());
                verdict = "ACCEPTED";
            } catch (VerificationException e) {
                verdict = e.reason() + ": " + e.getMessage();
            }
            System.out.printf("  run %d: %d ms [%s]%n", r, (System.nanoTime() - t) / 1_000_000, verdict);
        }
    }
}
