package io.github.emindeniz99.applepurchasereceiptverifier;

import java.math.BigInteger;
import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.Set;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;

/**
 * Q144 a: what the generic composite label (id-alg-composite,
 * 1.3.6.1.4.1.18227.2.1) costs one ReceiptCore.verifyDer call on a genuine
 * test-PKI receipt.
 *
 * <p>{@code signer parts payloadBytes}: the review's construction. The one
 * SignerInfo is the genuine one with no signed attributes, labelled
 * id-alg-composite with parts parts of sha256WithRSAEncryption, over a
 * payload with one attribute of payloadBytes octets.
 *
 * <p>{@code cert parts kind}: the genuine receipt plus one bag entry naming
 * the RSA root as its issuer, labelled id-alg-composite with parts parts of
 * kind (rsa: sha256WithRSAEncryption, ecdsa: ecdsa-with-SHA256, ed25519:
 * Ed25519, unknown: an OID no provider names) and a signature that is a SEQUENCE of parts empty
 * BIT STRINGs. This is the certificate path (AppleTrust.signedBy), which
 * does not go through the SignerInfo's content verifier provider.
 */
public class CompositeLabelProbe {
    public static void main(String[] a) throws Exception {
        String mode = a[0];
        int parts = Integer.parseInt(a[1]);
        TestPki pki = TestPki.receipt();
        Set<TrustAnchor> anchors = AppleTrust.anchors(Collections.singleton(pki.root));
        byte[] der;
        if (mode.equals("signer")) {
            int payloadBytes = Integer.parseInt(a[2]);
            SignedData sd = SignedData.getInstance(ContentInfo.getInstance(
                            pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[payloadBytes])))
                    .getContent());
            SignerInfo si = SignerInfo.getInstance(sd.getSignerInfos().getObjectAt(0));
            AlgorithmIdentifier label = composite(parts,
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE));
            SignerInfo relabelled = new SignerInfo(si.getSID(), si.getDigestAlgorithm(), (ASN1Set) null, label,
                    new DEROctetString(new byte[256]), (ASN1Set) null);
            der = new ContentInfo(CMSObjectIdentifiers.signedData, new SignedData(sd.getDigestAlgorithms(),
                            sd.getEncapContentInfo(), sd.getCertificates(), sd.getCRLs(), new DERSet(relabelled)))
                    .getEncoded("DER");
            System.out.printf("signer composite parts=%d payload=%d der=%d%n", parts, payloadBytes, der.length);
        } else if (mode.equals("cert")) {
            String kind = a[2];
            AlgorithmIdentifier part;
            if (kind.equals("rsa")) {
                part = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);
            } else if (kind.equals("ecdsa")) {
                part = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
            } else if (kind.equals("ed25519")) {
                part = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.101.112"));
            } else if (kind.equals("unknown")) {
                part = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1"));
            } else {
                throw new IllegalArgumentException("kind: rsa, ecdsa, ed25519 or unknown");
            }
            AlgorithmIdentifier label = composite(parts, part);
            ASN1EncodableVector sigs = new ASN1EncodableVector();
            for (int i = 0; i < parts; i++) {
                sigs.add(new DERBitString(new byte[0]));
            }
            byte[] signature = new DERSequence(sigs).getEncoded("DER");
            ContentSigner signer = new ContentSigner() {
                public AlgorithmIdentifier getAlgorithmIdentifier() {
                    return label;
                }

                public java.io.OutputStream getOutputStream() {
                    return new java.io.ByteArrayOutputStream();
                }

                public byte[] getSignature() {
                    return signature;
                }
            };
            byte[] stranger = new X509v3CertificateBuilder(
                            X500Name.getInstance(pki.root.getSubjectX500Principal().getEncoded()),
                            BigInteger.valueOf(4243),
                            pki.leaf.getNotBefore(),
                            pki.leaf.getNotAfter(),
                            new X500Name("CN=Stranger"),
                            SubjectPublicKeyInfo.getInstance(pki.leaf.getPublicKey().getEncoded()))
                    .build(signer)
                    .getEncoded();
            SignedData sd = SignedData.getInstance(ContentInfo.getInstance(
                            pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16])))
                    .getContent());
            ASN1EncodableVector bag = new ASN1EncodableVector();
            for (int i = 0; i < sd.getCertificates().size(); i++) {
                bag.add(sd.getCertificates().getObjectAt(i));
            }
            bag.add(ASN1Primitive.fromByteArray(stranger));
            der = new ContentInfo(CMSObjectIdentifiers.signedData, new SignedData(sd.getDigestAlgorithms(),
                            sd.getEncapContentInfo(), new DLSet(bag), sd.getCRLs(), sd.getSignerInfos()))
                    .getEncoded("DER");
            System.out.printf("cert composite parts=%d kind=%s der=%d%n", parts, kind, der.length);
        } else {
            throw new IllegalArgumentException("mode: signer or cert");
        }
        for (int r = 0; r < 3; r++) {
            long t = System.nanoTime();
            String verdict;
            try {
                ReceiptCore.verifyDer(der, anchors, System.currentTimeMillis());
                verdict = "ACCEPTED";
            } catch (VerificationException e) {
                verdict = e.reason() + ": " + e.getMessage();
            } catch (Throwable e) {
                verdict = "THREW " + e;
            }
            System.out.printf("  run %d: %d ms [%s]%n", r, (System.nanoTime() - t) / 1_000_000, verdict);
        }
    }

    private static AlgorithmIdentifier composite(int parts, AlgorithmIdentifier part) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < parts; i++) {
            v.add(part);
        }
        return new AlgorithmIdentifier(MiscObjectIdentifiers.id_alg_composite, new DERSequence(v));
    }
}
