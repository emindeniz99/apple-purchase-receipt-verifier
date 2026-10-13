package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.Date;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;

/**
 * Review 5's probe for the EXTERNAL gap: the genuine test-PKI receipt plus
 * one bag entry shaped as a certificate the root issued, whose key
 * parameters, or whose signature label (TBS and outer, half the value
 * each), hold SETs nested {@code depth} deep inside an EXTERNAL's data
 * value descriptor, {@code EXTERNAL { descriptor, [0] NULL }}. The control
 * puts the same value directly in the key parameters. Each shape is
 * verified three times in one JVM, the first cold.
 *
 * <p>The other review probes in this folder reuse its helpers.
 *
 * <p>Args: [depth], default 30
 */
public class ExternalDescriptorProbe {
    static final int CAP_DER = ReceiptCore.MAX_RECEIPT_BYTES / 4 * 3;
    static final AlgorithmIdentifier SHA256_WITH_RSA =
            new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);

    public static void main(String[] a) throws Exception {
        TestPki pki = TestPki.receipt();
        X500Name rootName = X500Name.getInstance(pki.root.getSubjectX500Principal().getEncoded());
        SubjectPublicKeyInfo key = SubjectPublicKeyInfo.getInstance(pki.leaf.getPublicKey().getEncoded());
        int depth = Integer.parseInt(a.length > 0 ? a[0] : "30");
        int bytes = CAP_DER - 16384;

        AlgorithmIdentifier label = new AlgorithmIdentifier(
                PKCSObjectIdentifiers.sha256WithRSAEncryption, external(nestedSets(depth, bytes / 2 - 8192)));
        time("external-in-label depth=" + depth, pki,
                withBagEntry(pki, certificateShaped(label, rootName, new X500Name("CN=x"), key)));

        SubjectPublicKeyInfo externalKey = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, external(nestedSets(depth, bytes))),
                key.getPublicKeyData().getBytes());
        time("external-in-key depth=" + depth, pki,
                withBagEntry(pki, certificateShaped(SHA256_WITH_RSA, rootName, new X500Name("CN=x"), externalKey)));

        SubjectPublicKeyInfo directKey = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, nestedSets(depth, bytes)),
                key.getPublicKeyData().getBytes());
        time("direct-set-in-key depth=" + depth, pki,
                withBagEntry(pki, certificateShaped(SHA256_WITH_RSA, rootName, new X500Name("CN=x"), directKey)));
    }

    /** A SEQUENCE of chains of two-member SETs {@code depth} deep, of about {@code bytes}. */
    static DLSequence nestedSets(int depth, int bytes) throws Exception {
        ASN1Encodable chain = new ASN1Integer(7);
        for (int i = 0; i < depth; i++) {
            chain = new DLSet(new ASN1Encodable[] {chain, new ASN1Integer(1)});
        }
        int chainBytes = chain.toASN1Primitive().getEncoded(ASN1Encoding.DL).length;
        ASN1EncodableVector chains = new ASN1EncodableVector();
        for (int i = 0; i < bytes / chainBytes; i++) {
            chains.add(chain);
        }
        return new DLSequence(chains);
    }

    /** {@code EXTERNAL { descriptor, [0] NULL }}: a definite-length SEQUENCE retagged 0x28, then parsed. */
    static ASN1Primitive external(ASN1Encodable descriptor) throws Exception {
        byte[] b = new DLSequence(new ASN1Encodable[] {descriptor, new DLTaggedObject(true, 0, DERNull.INSTANCE)})
                .getEncoded(ASN1Encoding.DL);
        b[0] = 0x28;
        return ASN1Primitive.fromByteArray(b);
    }

    /** A certificate-shaped SEQUENCE valid from yesterday to tomorrow, with 256 zero octets as its signature. */
    static DLSequence certificateShaped(
            ASN1Encodable label, ASN1Encodable issuer, ASN1Encodable subject, ASN1Encodable key,
            ASN1Encodable... extensions) {
        long now = System.currentTimeMillis();
        ASN1EncodableVector tbs = new ASN1EncodableVector();
        tbs.add(new DLTaggedObject(true, 0, new ASN1Integer(2)));
        tbs.add(new ASN1Integer(4242));
        tbs.add(label);
        tbs.add(issuer);
        tbs.add(new DLSequence(new ASN1Encodable[] {
            new DERUTCTime(new Date(now - 86_400_000L)), new DERUTCTime(new Date(now + 86_400_000L))
        }));
        tbs.add(subject);
        tbs.add(key);
        if (extensions.length > 0) {
            tbs.add(new DLTaggedObject(true, 3, new DLSequence(extensions)));
        }
        return new DLSequence(new ASN1Encodable[] {new DLSequence(tbs), label, new DERBitString(new byte[256])});
    }

    static SignedData signedData(byte[] receipt) {
        return SignedData.getInstance(ContentInfo.getInstance(receipt).getContent());
    }

    /** {@code genuine}'s content with {@code certificates} and {@code signerInfos}, encoded definite-length. */
    static byte[] receipt(SignedData genuine, ASN1Set certificates, ASN1Set signerInfos) throws Exception {
        DLSequence signedData = new DLSequence(new ASN1Encodable[] {
            new ASN1Integer(1),
            genuine.getDigestAlgorithms(),
            genuine.getEncapContentInfo(),
            new DLTaggedObject(false, 0, certificates),
            signerInfos
        });
        return new DLSequence(
                        new ASN1Encodable[] {CMSObjectIdentifiers.signedData, new DLTaggedObject(true, 0, signedData)})
                .getEncoded(ASN1Encoding.DL);
    }

    /** {@code pki}'s genuine receipt with {@code entry} added to its certificate bag. */
    static byte[] withBagEntry(TestPki pki, ASN1Encodable entry) throws Exception {
        SignedData genuine = signedData(pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16])));
        ASN1EncodableVector bag = new ASN1EncodableVector();
        for (int i = 0; i < genuine.getCertificates().size(); i++) {
            bag.add(genuine.getCertificates().getObjectAt(i));
        }
        bag.add(entry);
        return receipt(genuine, new DLSet(bag), genuine.getSignerInfos());
    }

    /** Verifies {@code receipt} three times under {@code pki}'s root and prints each call. */
    static void time(String name, TestPki pki, byte[] receipt) {
        System.out.printf("%s der=%d%n", name, receipt.length);
        for (int r = 0; r < 3; r++) {
            long t = System.nanoTime();
            String verdict;
            try {
                Checks.receipt(Checks.verifier(pki), receipt);
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
