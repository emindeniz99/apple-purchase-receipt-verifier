package io.github.emindeniz99.applepurchasereceiptverifier;

import java.math.BigInteger;
import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.Date;
import java.util.Set;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;

/**
 * Like ShapeProbe "issuer", but the extra bag entry carries the genuine
 * signer's serial and an issuer with the signer issuer's RDN count and first
 * type, so ReceiptCertificates.signers compares it (BCStrictStyle.areEqual ->
 * canonicalString of the nested value). Args: depth targetBytes signerInfos matchSerial(0|1)
 * With signerInfos k > 1, the first k-1 are the genuine SignerInfo with a broken signature.
 */
public class SidIssuerProbe {
    public static void main(String[] a) throws Exception {
        int depth = Integer.parseInt(a[0]);
        int target = Integer.parseInt(a[1]);
        int k = Integer.parseInt(a[2]);
        boolean matchSerial = a[3].equals("1");
        TestPki pki = TestPki.receipt();
        Set<TrustAnchor> anchors = AppleTrust.anchors(Collections.singleton(pki.root));
        byte[] genuine = pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16]));
        SignedData sd = SignedData.getInstance(ContentInfo.getInstance(genuine).getContent());
        SignerInfo si = SignerInfo.getInstance(sd.getSignerInfos().getObjectAt(0));
        IssuerAndSerialNumber ias = IssuerAndSerialNumber.getInstance(si.getSID().getId());
        RDN[] rdns = ias.getName().getRDNs();
        DLSequence bulk = ShapeProbe.bulk(depth, target);
        ASN1EncodableVector nameV = new ASN1EncodableVector();
        for (int i = 0; i < rdns.length; i++) {
            if (i == 0) {
                nameV.add(new DLSet(new DLSequence(new ASN1Encodable[] {rdns[0].getFirst().getType(), bulk})));
            } else {
                nameV.add(rdns[i].toASN1Primitive());
            }
        }
        Certificate rootCert = Certificate.getInstance(pki.root.getEncoded());
        ASN1Sequence leafTbs = ASN1Sequence.getInstance(Certificate.getInstance(pki.leaf.getEncoded())
                .getTBSCertificate().toASN1Primitive());
        ASN1Encodable rsaSha256 = new DLSequence(PKCSObjectIdentifiers.sha256WithRSAEncryption);
        long now = System.currentTimeMillis();
        DLSequence tbs = new DLSequence(new ASN1Encodable[] {
            new DLTaggedObject(true, 0, new ASN1Integer(2)),
            matchSerial ? ias.getSerialNumber() : new ASN1Integer(4242),
            rsaSha256,
            new DLSequence(nameV),
            new DLSequence(new ASN1Encodable[] {
                new DERUTCTime(new Date(now - 86400000L)), new DERUTCTime(new Date(now + 86400000L))}),
            new DLSequence(new DLSet(new DLSequence(new ASN1Encodable[] {
                org.bouncycastle.asn1.x500.style.BCStyle.CN, new DERUTF8String("x")}))),
            leafTbs.getObjectAt(6)});
        ASN1Encodable entry = new DLSequence(new ASN1Encodable[] {tbs, rsaSha256, new DERBitString(new byte[256])});
        ASN1EncodableVector c = new ASN1EncodableVector();
        for (int i = 0; i < sd.getCertificates().size(); i++) c.add(sd.getCertificates().getObjectAt(i));
        c.add(entry);
        ASN1EncodableVector sis = new ASN1EncodableVector();
        byte[] sig = si.getEncryptedDigest().getOctets().clone();
        sig[sig.length - 1] ^= 1;
        SignerInfo broken = new SignerInfo(si.getSID(), si.getDigestAlgorithm(), si.getAuthenticatedAttributes(),
                si.getDigestEncryptionAlgorithm(), new DEROctetString(sig), si.getUnauthenticatedAttributes());
        for (int i = 0; i < k - 1; i++) sis.add(broken);
        sis.add(si);
        ASN1EncodableVector body = new ASN1EncodableVector();
        body.add(new ASN1Integer(1));
        body.add(sd.getDigestAlgorithms());
        body.add(sd.getEncapContentInfo());
        body.add(new DLTaggedObject(false, 0, new DLSet(c)));
        body.add(new DLSet(sis));
        byte[] der = new DLSequence(new ASN1Encodable[] {CMSObjectIdentifiers.signedData,
            new DLTaggedObject(true, 0, new DLSequence(body))}).getEncoded("DL");
        System.out.printf("depth=%d k=%d matchSerial=%s der=%d base64=%d (cap 3145728)%n", depth, k, matchSerial, der.length, (der.length + 2) / 3 * 4);
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
}
