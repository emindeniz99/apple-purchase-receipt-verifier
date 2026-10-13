package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.Set;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * A genuine test-PKI receipt whose signerInfos SignerInfos are copies of the
 * genuine one relabelled RSASSA-PSS (SHA-256, MGF1 with SHA-256) with a
 * saltLength of saltLength; the signature is the genuine PKCS#1 v1.5 one, so
 * nothing here verifies. Times ReceiptCore.verifyDer, catching Throwable so
 * an OutOfMemoryError is printed rather than ending the run.
 * Args: saltLength [signerInfos [label]]. Added for Q142 a: label is pss
 * (the default), eac-sha256 or eac-sha1 (id-TA-RSA-PSS-SHA-256 or -SHA-1
 * carrying the same parameters), or composite (id-alg-composite whose one
 * part is the PSS identifier).
 */
public class PssSaltProbe {
    public static void main(String[] a) throws Exception {
        long salt = Long.parseLong(a[0]);
        int count = a.length > 1 ? Integer.parseInt(a[1]) : 1;
        TestPki pki = TestPki.receipt();
        Set<TrustAnchor> anchors = AppleTrust.anchors(Collections.singleton(pki.root));
        SignedData sd = SignedData.getInstance(ContentInfo.getInstance(
                        pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16])))
                .getContent());
        SignerInfo si = SignerInfo.getInstance(sd.getSignerInfos().getObjectAt(0));
        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        AlgorithmIdentifier pss = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, new RSASSAPSSparams(
                sha256, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha256), new ASN1Integer(salt),
                new ASN1Integer(1)));
        String label = a.length > 2 ? a[2] : "pss";
        if (label.equals("eac-sha256")) {
            pss = new AlgorithmIdentifier(
                    org.bouncycastle.asn1.eac.EACObjectIdentifiers.id_TA_RSA_PSS_SHA_256, pss.getParameters());
        } else if (label.equals("eac-sha1")) {
            pss = new AlgorithmIdentifier(
                    org.bouncycastle.asn1.eac.EACObjectIdentifiers.id_TA_RSA_PSS_SHA_1, pss.getParameters());
        } else if (label.equals("composite")) {
            pss = new AlgorithmIdentifier(org.bouncycastle.asn1.misc.MiscObjectIdentifiers.id_alg_composite,
                    new org.bouncycastle.asn1.DERSequence(pss));
        } else if (!label.equals("pss")) {
            throw new IllegalArgumentException("label: pss, eac-sha256, eac-sha1 or composite");
        }
        ASN1EncodableVector signers = new ASN1EncodableVector();
        for (int i = 0; i < count; i++) {
            // Distinct copies: the SignerInfos SET would keep only one of equal ones.
            signers.add(new SignerInfo(si.getSID(), si.getDigestAlgorithm(), si.getAuthenticatedAttributes(), pss,
                    new org.bouncycastle.asn1.DEROctetString(
                            org.bouncycastle.util.Arrays.append(si.getEncryptedDigest().getOctets(), (byte) i)),
                    (ASN1Set) null));
        }
        byte[] der = new ContentInfo(CMSObjectIdentifiers.signedData, new SignedData(sd.getDigestAlgorithms(),
                        sd.getEncapContentInfo(), sd.getCertificates(), sd.getCRLs(), new DERSet(signers)))
                .getEncoded("DER");
        if (System.getProperty("dump") != null) {
            // For the core: the receipt and its test root, then no timing.
            java.nio.file.Files.write(java.nio.file.Paths.get(System.getProperty("dump") + ".der"), der);
            java.nio.file.Files.write(java.nio.file.Paths.get(System.getProperty("dump") + ".root.der"), pki.root.getEncoded());
            return;
        }
        System.out.printf("label=%s saltLength=%d signerInfos=%d der=%d maxHeapMB=%d%n", label, salt, count, der.length,
                Runtime.getRuntime().maxMemory() >> 20);
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
}
