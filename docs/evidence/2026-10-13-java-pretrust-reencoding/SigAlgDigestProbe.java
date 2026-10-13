package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.Set;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Review round 4, opus. The SignerInfo's signatureAlgorithm label, not only
 * its digestAlgorithm, picks a digest BouncyCastle runs before any signature
 * is checked: with signed attributes, SignerInformation.doVerify writes the
 * DER of the signed attributes into the content verifier's Signature engine,
 * whose digest comes from the signatureAlgorithm OID (md2WithRSAEncryption
 * gives MD2withRSA). REFUSED_DIGESTS checks digestAlgorithm only.
 *
 * Args: padBytes sigAlgOid[,sigAlgOid...] [signerInfos]
 * Synthetic PKI only; the signer is a genuine (test-root) leaf whose
 * signature no longer matches, so every input here is not signed.
 */
public class SigAlgDigestProbe {
    public static void main(String[] a) throws Exception {
        int pad = Integer.parseInt(a[0]);
        int count = a.length > 2 ? Integer.parseInt(a[2]) : 1;
        int contentBytes = a.length > 3 ? Integer.parseInt(a[3]) : 16;
        String digestOid = a.length > 4 ? a[4] : null;
        TestPki pki = TestPki.receipt();
        Set<TrustAnchor> anchors = AppleTrust.anchors(Collections.singleton(pki.root));
        byte[] genuine = pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[contentBytes]));
        ContentInfo ci = ContentInfo.getInstance(genuine);
        SignedData sd = SignedData.getInstance(ci.getContent());
        SignerInfo si = SignerInfo.getInstance(sd.getSignerInfos().getObjectAt(0));
        for (String oid : a[1].split(",")) {
            ASN1EncodableVector signers = new ASN1EncodableVector();
            for (int s = 0; s < count; s++) {
                ASN1EncodableVector attrs = new ASN1EncodableVector();
                for (int i = 0; i < si.getAuthenticatedAttributes().size(); i++) {
                    attrs.add(si.getAuthenticatedAttributes().getObjectAt(i));
                }
                // An attribute of an unregistered type carrying the padding,
                // split so each SignerInfo differs (a SET keeps them all).
                attrs.add(new Attribute(
                        new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1"),
                        new DERSet(new DEROctetString(new byte[pad / count + s]))));
                signers.add(new SignerInfo(
                        si.getSID(),
                        digestOid == null ? si.getDigestAlgorithm() : new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestOid), DERNull.INSTANCE),
                        new DERSet(attrs),
                        new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid), DERNull.INSTANCE),
                        si.getEncryptedDigest(),
                        (ASN1Set) null));
            }
            SignedData forged = new SignedData(
                    sd.getDigestAlgorithms(), sd.getEncapContentInfo(), sd.getCertificates(), sd.getCRLs(),
                    new DERSet(signers));
            byte[] der = new ContentInfo(CMSObjectIdentifiers.signedData, forged).getEncoded("DER");
            if (System.getProperty("dump") != null) {
                // For the core: the receipt and its test root, then no timing.
                String base = System.getProperty("dump") + "-" + oid + "-" + count;
                java.nio.file.Files.write(java.nio.file.Paths.get(base + ".der"), der);
                java.nio.file.Files.write(java.nio.file.Paths.get(base + ".root.der"), pki.root.getEncoded());
                continue;
            }
            String verdict = "";
            for (int i = 0; i < 3; i++) {
                try {
                    ReceiptCore.verifyDer(der, anchors, System.currentTimeMillis());
                    verdict = "ACCEPTED";
                } catch (VerificationException e) {
                    verdict = e.reason() + ": " + e.getMessage()
                            + (e.getCause() != null ? " / " + e.getCause().getMessage() : "");
                }
            }
            int n = 7;
            long best = Long.MAX_VALUE;
            for (int i = 0; i < n; i++) {
                long t = System.nanoTime();
                try {
                    ReceiptCore.verifyDer(der, anchors, System.currentTimeMillis());
                } catch (VerificationException e) {
                    // expected
                }
                best = Math.min(best, System.nanoTime() - t);
            }
            System.out.printf("digest=%s content=%d %-24s signerInfos=%d der=%d base64=%d best=%d ms [%s]%n",
                    digestOid, contentBytes, oid, count, der.length, (der.length + 2) / 3 * 4, best / 1_000_000, verdict);
        }
    }
}
