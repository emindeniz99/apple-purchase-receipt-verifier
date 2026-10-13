package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.Date;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;

/**
 * One sender-chosen shape added to a genuine test-PKI receipt (or JWS), just
 * under the input cap, then ReceiptCore.verifyDer (JwsCore.verify) four times
 * in one JVM. The nested value is CertShapeProbe's: a SEQUENCE of chains of
 * two-member SETs {@code depth} deep (depth 0: a flat SEQUENCE of INTEGERs).
 *
 * <p>Modes, each a bag entry shaped as a certificate the root issued unless
 * noted: {@code subject}, {@code issuer} (the value as the one CN; for
 * {@code issuer} the entry names no root), {@code spki} and {@code sigalg}
 * (the value as the key's, or the outer signature's, AlgorithmIdentifier
 * parameters), {@code san} (the value as the CN of a directoryName in a
 * subjectAltName extension), {@code widerdn} (the subject is one RDN of
 * {@code depth} thousand UTF8String values in descending order),
 * {@code signedattrs} (no bag entry: a copy of the genuine SignerInfo,
 * ahead of it, with one more signed attribute holding the value),
 * {@code signerparams} (the same copy with half the value as its
 * signatureAlgorithm parameters and a CMSAlgorithmProtection attribute naming
 * that label), and {@code jws} (a JWS at the 256 KiB cap
 * whose x5c[2] is the {@code subject} entry). -Ddump=PREFIX writes the
 * receipt and its root for core_shapes.rs and times nothing.
 *
 * <p>Args: mode depth targetBytes
 */
public class ShapeProbe {
    public static void main(String[] a) throws Exception {
        String mode = a[0];
        int depth = Integer.parseInt(a[1]);
        int target = Integer.parseInt(a[2]);
        if (mode.equals("jws")) {
            jws(depth, target);
            return;
        }
        TestPki pki = TestPki.receipt();
        Set<TrustAnchor> anchors = AppleTrust.anchors(Collections.singleton(pki.root));
        byte[] genuine = pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16]));
        SignedData sd = SignedData.getInstance(ContentInfo.getInstance(genuine).getContent());
        ASN1EncodableVector bag = new ASN1EncodableVector();
        for (int i = 0; i < sd.getCertificates().size(); i++) bag.add(sd.getCertificates().getObjectAt(i));
        ASN1EncodableVector signers = new ASN1EncodableVector();
        SignerInfo si = SignerInfo.getInstance(sd.getSignerInfos().getObjectAt(0));
        if (mode.equals("signedattrs") || mode.equals("signerparams")) {
            ASN1EncodableVector attributes = new ASN1EncodableVector();
            for (int i = 0; i < si.getAuthenticatedAttributes().size(); i++) {
                attributes.add(si.getAuthenticatedAttributes().getObjectAt(i));
            }
            ASN1Encodable label = si.getDigestEncryptionAlgorithm();
            if (mode.equals("signedattrs")) {
                attributes.add(new DLSequence(new ASN1Encodable[] {
                    new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1"), new DLSet(bulk(depth, target))}));
            } else {
                // The label's parameters hold the value, and a
                // CMSAlgorithmProtection attribute names the same label, so
                // BouncyCastle compares the two.
                label = new DLSequence(new ASN1Encodable[] {
                    PKCSObjectIdentifiers.sha256WithRSAEncryption, bulk(depth, target / 2)});
                attributes.add(new DLSequence(new ASN1Encodable[] {
                    PKCSObjectIdentifiers.id_aa_cmsAlgorithmProtect,
                    new DLSet(new DLSequence(new ASN1Encodable[] {
                        si.getDigestAlgorithm(), new DLTaggedObject(false, 1, label)}))}));
            }
            // Built of definite-length types: BouncyCastle's SignerInfo encodes as DER.
            signers.add(new DLSequence(new ASN1Encodable[] {
                new ASN1Integer(1), si.getSID(), si.getDigestAlgorithm(),
                new DLTaggedObject(false, 0, new DLSet(attributes)), label, si.getEncryptedDigest()}));
        } else {
            bag.add(entry(mode, depth, target, pki));
        }
        signers.add(si);
        ASN1EncodableVector body = new ASN1EncodableVector();
        body.add(new ASN1Integer(1));
        body.add(sd.getDigestAlgorithms());
        body.add(sd.getEncapContentInfo());
        body.add(new DLTaggedObject(false, 0, new DLSet(bag)));
        body.add(new DLSet(signers));
        byte[] der = new DLSequence(new ASN1Encodable[] {CMSObjectIdentifiers.signedData,
            new DLTaggedObject(true, 0, new DLSequence(body))}).getEncoded("DL");
        if (System.getProperty("dump") != null) {
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
            } catch (Throwable e) {
                verdict = "THROWN " + e;
            }
            System.out.printf("  run %d: %d ms [%s]%n", r, (System.nanoTime() - t) / 1_000_000, verdict);
        }
    }

    /** The bag entry of {@code mode}: a certificate-shaped SEQUENCE, the root as its issuer unless mode is issuer. */
    static ASN1Encodable entry(String mode, int depth, int target, TestPki pki) throws Exception {
        Certificate rootCert = Certificate.getInstance(pki.root.getEncoded());
        ASN1Sequence leafTbs = ASN1Sequence.getInstance(Certificate.getInstance(pki.leaf.getEncoded())
                .getTBSCertificate().toASN1Primitive());
        ASN1Sequence leafSpki = ASN1Sequence.getInstance(leafTbs.getObjectAt(6));
        ASN1Encodable rsaSha256 = new DLSequence(PKCSObjectIdentifiers.sha256WithRSAEncryption);
        ASN1Encodable spki = leafSpki;
        ASN1Encodable sigAlg = rsaSha256;
        ASN1Encodable issuer = rootCert.getSubject().toASN1Primitive();
        ASN1Encodable subject = cn(new DERUTF8String("x"));
        ASN1Encodable extensions = null;
        if (mode.equals("issuer")) {
            issuer = cn(bulk(depth, target));
        } else if (mode.equals("subject")) {
            subject = cn(bulk(depth, target));
        } else if (mode.equals("spki")) {
            spki = new DLSequence(new ASN1Encodable[] {
                new DLSequence(new ASN1Encodable[] {PKCSObjectIdentifiers.rsaEncryption, bulk(depth, target)}),
                leafSpki.getObjectAt(1)});
        } else if (mode.equals("sigalg")) {
            sigAlg = new DLSequence(new ASN1Encodable[] {PKCSObjectIdentifiers.sha256WithRSAEncryption, bulk(depth, target)});
        } else if (mode.equals("san")) {
            byte[] names = new DLSequence(new DLTaggedObject(true, 4, cn(bulk(depth, target)))).getEncoded("DL");
            extensions = new DLTaggedObject(true, 3, new DLSequence(new DLSequence(new ASN1Encodable[] {
                Extension.subjectAlternativeName, new DEROctetString(names)})));
        } else if (mode.equals("widerdn")) {
            ASN1EncodableVector values = new ASN1EncodableVector();
            for (int i = depth * 1000; i > 0; i--) {
                values.add(new DLSequence(new ASN1Encodable[] {BCStyle.CN, new DERUTF8String(String.format("%06d", i))}));
            }
            subject = new DLSequence(new DLSet(values));
        } else {
            throw new IllegalArgumentException(mode);
        }
        long now = System.currentTimeMillis();
        ASN1EncodableVector tbs = new ASN1EncodableVector();
        tbs.add(new DLTaggedObject(true, 0, new ASN1Integer(2)));
        tbs.add(new ASN1Integer(4242));
        tbs.add(rsaSha256);
        tbs.add(issuer);
        tbs.add(new DLSequence(new ASN1Encodable[] {
            new DERUTCTime(new Date(now - 86400000L)), new DERUTCTime(new Date(now + 86400000L))}));
        tbs.add(subject);
        tbs.add(spki);
        if (extensions != null) tbs.add(extensions);
        return new DLSequence(new ASN1Encodable[] {new DLSequence(tbs), sigAlg, new DERBitString(new byte[256])});
    }

    /** A genuine test-PKI JWS whose x5c[2] is the subject entry, sized so the JWS is just under its cap. */
    static void jws(int depth, int target) throws Exception {
        TestPki pki = TestPki.jws();
        Set<TrustAnchor> anchors = AppleTrust.anchors(Collections.singleton(pki.root));
        String leaf = TestPki.b64(pki.leaf.getEncoded());
        String intermediate = TestPki.b64(pki.intermediate.getEncoded());
        String root = TestPki.b64(entry("subject", depth, target, pki).toASN1Primitive().getEncoded("DL"));
        String jws = pki.signJwsWithHeader(
                "{\"alg\":\"ES256\",\"x5c\":[\"" + leaf + "\",\"" + intermediate + "\",\"" + root + "\"]}", "{}");
        System.out.printf("mode=jws depth=%d jws=%d (cap %d)%n", depth, jws.length(), JwsCore.MAX_JWS_BYTES);
        for (int r = 0; r < 4; r++) {
            long t = System.nanoTime();
            String verdict;
            try {
                JwsCore.verify(jws, anchors, System.currentTimeMillis());
                verdict = "ACCEPTED";
            } catch (VerificationException e) {
                verdict = e.reason() + ": " + e.getMessage();
            } catch (Throwable e) {
                verdict = "THROWN " + e;
            }
            System.out.printf("  run %d: %d ms [%s]%n", r, (System.nanoTime() - t) / 1_000_000, verdict);
        }
    }

    static DLSequence cn(ASN1Encodable value) {
        return new DLSequence(new DLSet(new DLSequence(new ASN1Encodable[] {BCStyle.CN, value})));
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
