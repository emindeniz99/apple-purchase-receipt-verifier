package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.Date;
import java.util.Set;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;

/**
 * The genuine test-PKI receipt plus one bag entry shaped as a certificate
 * issued by the root (issuer = root subject, so signedByAny reaches
 * verify), signature labelled RSASSA-PSS (SHA-256, MGF1 SHA-256) with the
 * given saltLength, inner and outer. Args: saltLength
 */
public class BagPssProbe {
    public static void main(String[] a) throws Exception {
        int salt = Integer.parseInt(a[0]);
        TestPki pki = TestPki.receipt();
        Set<TrustAnchor> anchors = AppleTrust.anchors(Collections.singleton(pki.root));
        byte[] genuine = pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16]));
        SignedData sd = SignedData.getInstance(ContentInfo.getInstance(genuine).getContent());
        Certificate rootCert = Certificate.getInstance(pki.root.getEncoded());
        ASN1Sequence leafTbs = ASN1Sequence.getInstance(Certificate.getInstance(pki.leaf.getEncoded())
                .getTBSCertificate().toASN1Primitive());
        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        ASN1Encodable pss = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, new RSASSAPSSparams(
                sha256, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha256),
                new ASN1Integer(salt), new ASN1Integer(1)));
        long now = System.currentTimeMillis();
        DLSequence tbs = new DLSequence(new ASN1Encodable[] {
            new DLTaggedObject(true, 0, new ASN1Integer(2)),
            new ASN1Integer(4242),
            pss,
            rootCert.getSubject(),
            new DLSequence(new ASN1Encodable[] {
                new DERUTCTime(new Date(now - 86400000L)), new DERUTCTime(new Date(now + 86400000L))}),
            new DLSequence(new DLSet(new DLSequence(new ASN1Encodable[] {
                org.bouncycastle.asn1.x500.style.BCStyle.CN, new DERUTF8String("x")}))),
            leafTbs.getObjectAt(6)});
        ASN1Encodable entry = new DLSequence(new ASN1Encodable[] {tbs, pss, new DERBitString(new byte[256])});
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
        System.out.printf("salt=%d der=%d%n", salt, der.length);
        for (int r = 0; r < 3; r++) {
            long t = System.nanoTime();
            String verdict;
            try {
                ReceiptCore.verifyDer(der, anchors, System.currentTimeMillis());
                verdict = "ACCEPTED";
            } catch (VerificationException e) {
                verdict = e.reason() + ": " + e.getMessage();
            } catch (Throwable e) {
                verdict = "THROWN " + e;
            }
            System.out.printf("  run %d: %d ms [%s]%n", r, (System.nanoTime() - t) / 1_000_000, verdict);
        }
    }
}
