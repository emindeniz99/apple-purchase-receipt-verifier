package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.cert.TrustAnchor;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Set;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;

/** x5c[1] issued "by" the root, labelled RSASSA-PSS with the given saltLength. Args: saltLength */
public class JwsPssRsaProbe {
    public static void main(String[] a) throws Exception {
        int salt = Integer.parseInt(a[0]);
        TestPki pki = TestPki.jws(); TestPki rsa = TestPki.receipt();
        Set<TrustAnchor> anchors = AppleTrust.anchors(Collections.singleton(rsa.root));
        Certificate rootCert = Certificate.getInstance(rsa.root.getEncoded());
        ASN1Sequence leafTbs = ASN1Sequence.getInstance(Certificate.getInstance(pki.leaf.getEncoded())
                .getTBSCertificate().toASN1Primitive());
        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        ASN1Encodable pss = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, new RSASSAPSSparams(
                sha256, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha256),
                new ASN1Integer(salt), new ASN1Integer(1)));
        long now = System.currentTimeMillis();
        DLSequence tbs = new DLSequence(new ASN1Encodable[] {
            new DLTaggedObject(true, 0, new ASN1Integer(2)), new ASN1Integer(4242), pss, rootCert.getSubject(),
            new DLSequence(new ASN1Encodable[] {
                new DERUTCTime(new Date(now - 86400000L)), new DERUTCTime(new Date(now + 86400000L))}),
            new DLSequence(new DLSet(new DLSequence(new ASN1Encodable[] {
                org.bouncycastle.asn1.x500.style.BCStyle.CN, new DERUTF8String("x")}))),
            leafTbs.getObjectAt(6)});
        byte[] hostile = new DLSequence(new ASN1Encodable[] {tbs, pss, new DERBitString(new byte[256])}).getEncoded("DL");
        Base64.Encoder b = Base64.getEncoder();
        String header = "{\"alg\":\"ES256\",\"x5c\":[\"" + b.encodeToString(pki.leaf.getEncoded()) + "\",\""
                + b.encodeToString(hostile) + "\",\"" + b.encodeToString(pki.root.getEncoded()) + "\"]}";
        Base64.Encoder u = Base64.getUrlEncoder().withoutPadding();
        String jws = u.encodeToString(header.getBytes("UTF-8")) + ".e30." + u.encodeToString(new byte[64]);
        System.out.printf("salt=%d jws=%d%n", salt, jws.length());
        for (int r = 0; r < 3; r++) {
            long t = System.nanoTime();
            String verdict;
            try {
                JwsCore.verify(jws, anchors, now);
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
