package io.github.emindeniz99.applepurchasereceiptverifier;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;

/**
 * Review 5's probe for the residual cost with no SET: the genuine test-PKI
 * receipt plus one bag entry shaped as a certificate the root issued, whose
 * key parameters ({@code key}) or signature label ({@code label}, TBS and
 * outer) hold SEQUENCEs nested {@code depth} deep, each level with
 * {@code fan} INTEGER siblings. The shape rule passes it, and BouncyCastle
 * DER-encodes it as it builds and verifies the certificate. Verified three
 * times in one JVM, the first cold.
 *
 * <p>Args: depth fan key|label
 */
public class NestedSequenceProbe {
    public static void main(String[] a) throws Exception {
        int depth = Integer.parseInt(a[0]);
        int fan = Integer.parseInt(a[1]);
        String where = a[2];
        TestPki pki = TestPki.receipt();
        X500Name rootName = X500Name.getInstance(pki.root.getSubjectX500Principal().getEncoded());
        SubjectPublicKeyInfo key = SubjectPublicKeyInfo.getInstance(pki.leaf.getPublicKey().getEncoded());
        ASN1Encodable nested = nestedSequences(depth, fan);
        int size = nested.toASN1Primitive().getEncoded(ASN1Encoding.DL).length;
        AlgorithmIdentifier label = ExternalDescriptorProbe.SHA256_WITH_RSA;
        if (where.equals("label")) {
            label = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, nested);
        } else {
            key = new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, nested),
                    key.getPublicKeyData().getBytes());
        }
        byte[] receipt = ExternalDescriptorProbe.withBagEntry(
                pki, ExternalDescriptorProbe.certificateShaped(label, rootName, new X500Name("CN=x"), key));
        ExternalDescriptorProbe.time(
                "nested-sequences depth=" + depth + " fan=" + fan + " in=" + where + " params=" + size, pki, receipt);
    }

    /** {@code depth} levels of SEQUENCE, each the level below and {@code fan} INTEGERs. */
    static ASN1Encodable nestedSequences(int depth, int fan) {
        ASN1Encodable current = new ASN1Integer(7);
        for (int i = 0; i < depth; i++) {
            ASN1Encodable[] members = new ASN1Encodable[fan + 1];
            members[0] = current;
            for (int j = 1; j <= fan; j++) {
                members[j] = new ASN1Integer(1);
            }
            current = new DLSequence(members);
        }
        return current;
    }
}
