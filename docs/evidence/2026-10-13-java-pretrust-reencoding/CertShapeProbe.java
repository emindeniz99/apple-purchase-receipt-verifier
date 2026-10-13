package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.Date;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Certificate;

/**
 * A genuine test-PKI receipt whose unsigned certificate bag gains one
 * entry shaped like a certificate (TBSCertificate, AlgorithmIdentifier,
 * BIT STRING) that carries a sender-chosen ASN.1 value of about
 * targetBytes, built of depth-nested SETs (depth 0: a flat SEQUENCE of
 * INTEGERs). Modes put that value where a certificate allows any ASN.1:
 * "issuer" and "subject" (the value of a CN attribute; for "subject" the
 * issuer is the test root's subject, so signedByAny reaches verify),
 * "spki" (the key's AlgorithmIdentifier parameters) and "sigalg" (the
 * outer signatureAlgorithm parameters). Also mode "bag": the value itself
 * is the bag entry (NestedValueProbe's "cert").
 * Args: mode depth targetBytes
 */
public class CertShapeProbe {
    public static void main(String[] a) throws Exception {
        String mode = a[0];
        int depth = Integer.parseInt(a[1]);
        int target = Integer.parseInt(a[2]);
        TestPki pki = TestPki.receipt();
        Set<TrustAnchor> anchors = AppleTrust.anchors(Collections.singleton(pki.root));
        byte[] genuine = pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16]));
        SignedData sd = SignedData.getInstance(ContentInfo.getInstance(genuine).getContent());

        DLSequence bulk = bulk(depth, target);
        Certificate rootCert = Certificate.getInstance(pki.root.getEncoded());
        ASN1Encodable rootName = rootCert.getSubject().toASN1Primitive();
        ASN1Encodable hostileName = new DLSequence(new DLSet(new DLSequence(new ASN1Encodable[] {BCStyle.CN, bulk})));
        ASN1Encodable smallName = new DLSequence(new DLSet(new DLSequence(new ASN1Encodable[] {
            BCStyle.CN, new org.bouncycastle.asn1.DERUTF8String("x")})));
        ASN1Sequence leafTbs = ASN1Sequence.getInstance(Certificate.getInstance(pki.leaf.getEncoded())
                .getTBSCertificate().toASN1Primitive());
        ASN1Sequence leafSpki = ASN1Sequence.getInstance(leafTbs.getObjectAt(6));
        ASN1Encodable rsaSha256 = new DLSequence(PKCSObjectIdentifiers.sha256WithRSAEncryption);
        ASN1Encodable spki = leafSpki;
        ASN1Encodable sigAlg = rsaSha256;
        ASN1Encodable issuer = rootName;
        ASN1Encodable subject = smallName;
        if (mode.equals("issuer")) {
            issuer = hostileName;
        } else if (mode.equals("subject")) {
            subject = hostileName;
        } else if (mode.equals("spki")) {
            spki = new DLSequence(new ASN1Encodable[] {
                new DLSequence(new ASN1Encodable[] {PKCSObjectIdentifiers.rsaEncryption, bulk}),
                leafSpki.getObjectAt(1)});
        } else if (mode.equals("sigalg")) {
            sigAlg = new DLSequence(new ASN1Encodable[] {PKCSObjectIdentifiers.sha256WithRSAEncryption, bulk});
        }
        long now = System.currentTimeMillis();
        DLSequence tbs = new DLSequence(new ASN1Encodable[] {
            new DLTaggedObject(true, 0, new ASN1Integer(2)),
            new ASN1Integer(4242),
            rsaSha256,
            issuer,
            new DLSequence(new ASN1Encodable[] {
                new DERUTCTime(new Date(now - 86400000L)), new DERUTCTime(new Date(now + 86400000L))}),
            subject,
            spki});
        ASN1Encodable entry = mode.equals("bag")
                ? bulk
                : new DLSequence(new ASN1Encodable[] {tbs, sigAlg, new DERBitString(new byte[256])});

        ASN1EncodableVector c = new ASN1EncodableVector();
        for (int i = 0; i < sd.getCertificates().size(); i++) c.add(sd.getCertificates().getObjectAt(i));
        c.add(entry);
        ASN1EncodableVector body = new ASN1EncodableVector();
        body.add(new ASN1Integer(1));
        body.add(sd.getDigestAlgorithms());
        body.add(sd.getEncapContentInfo());
        body.add(new DLTaggedObject(false, 0, new DLSet(c)));
        body.add(sd.getSignerInfos());
        byte[] der = new DLSequence(new ASN1Encodable[] {CMSObjectIdentifiers.signedData,
            new DLTaggedObject(true, 0, new DLSequence(body))}).getEncoded("DL");
        if (System.getProperty("dump") != null) {
            // For the core: the receipt and its test root, then no timing.
            java.nio.file.Files.write(java.nio.file.Paths.get(System.getProperty("dump") + ".der"), der);
            java.nio.file.Files.write(java.nio.file.Paths.get(System.getProperty("dump") + ".root.der"), pki.root.getEncoded());
            return;
        }
        System.out.printf("mode=%s depth=%d der=%d base64=%d (cap 3145728)%n", mode, depth, der.length, (der.length + 2) / 3 * 4);
        for (int r = 0; r < 4; r++) {
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

    /** A SEQUENCE of nested-SET chains of {@code depth}, about {@code target} bytes; depth 0: flat INTEGERs. */
    static DLSequence bulk(int depth, int target) throws Exception {
        ASN1Encodable node = new ASN1Integer(7);
        for (int i = 0; i < depth; i++) {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(node);
            v.add(new ASN1Integer(1));
            node = new DLSet(v);
        }
        int one = node.toASN1Primitive().getEncoded("DL").length;
        ASN1EncodableVector all = new ASN1EncodableVector();
        for (int i = 0; i < target / one; i++) all.add(node);
        return new DLSequence(all);
    }
}
