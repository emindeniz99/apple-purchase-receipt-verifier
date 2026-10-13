package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.Arrays;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;

/**
 * Review 5's probe for costs without nesting: the genuine test-PKI receipt
 * plus one bag entry shaped as a certificate the root issued (for
 * {@code issuer-rdns}, naming no root) with one large flat part:
 * {@code subject-rdns} and {@code issuer-rdns} (150,000 one-value RDNs),
 * {@code bigstring} (one CN of 2,200,000 characters), {@code keyusage} (a
 * keyUsage extension whose BIT STRING is 2,200,000 octets, which
 * BouncyCastle expands to a boolean per bit) and {@code manyext} (100,000
 * one-octet extensions). Verified three times in one JVM, the first cold.
 *
 * <p>Args: subject-rdns|issuer-rdns|bigstring|keyusage|manyext
 */
public class FlatCostProbe {
    public static void main(String[] a) throws Exception {
        String mode = a[0];
        TestPki pki = TestPki.receipt();
        X500Name rootName = X500Name.getInstance(pki.root.getSubjectX500Principal().getEncoded());
        SubjectPublicKeyInfo key = SubjectPublicKeyInfo.getInstance(pki.leaf.getPublicKey().getEncoded());
        AlgorithmIdentifier label = ExternalDescriptorProbe.SHA256_WITH_RSA;
        DLSequence entry;
        if (mode.equals("subject-rdns")) {
            entry = ExternalDescriptorProbe.certificateShaped(label, rootName, manyRdns(150_000), key);
        } else if (mode.equals("issuer-rdns")) {
            entry = ExternalDescriptorProbe.certificateShaped(label, manyRdns(150_000), new X500Name("CN=x"), key);
        } else if (mode.equals("bigstring")) {
            char[] text = new char[2_200_000];
            Arrays.fill(text, 'a');
            DLSequence subject = new DLSequence(new DLSet(
                    new DLSequence(new ASN1Encodable[] {BCStyle.CN, new DERUTF8String(new String(text))})));
            entry = ExternalDescriptorProbe.certificateShaped(label, rootName, subject, key);
        } else if (mode.equals("keyusage")) {
            byte[] keyUsage = new DERBitString(new byte[2_200_000]).getEncoded(ASN1Encoding.DL);
            entry = ExternalDescriptorProbe.certificateShaped(label, rootName, new X500Name("CN=x"), key,
                    new DLSequence(new ASN1Encodable[] {Extension.keyUsage, new DEROctetString(keyUsage)}));
        } else if (mode.equals("manyext")) {
            ASN1Encodable[] extensions = new ASN1Encodable[100_000];
            for (int i = 0; i < extensions.length; i++) {
                extensions[i] = new DLSequence(new ASN1Encodable[] {
                    new ASN1ObjectIdentifier("1.3.6.1.4.1.99999." + (i + 1)), new DEROctetString(new byte[1])
                });
            }
            entry = ExternalDescriptorProbe.certificateShaped(label, rootName, new X500Name("CN=x"), key, extensions);
        } else {
            throw new IllegalArgumentException(mode);
        }
        ExternalDescriptorProbe.time("flat " + mode, pki, ExternalDescriptorProbe.withBagEntry(pki, entry));
    }

    /** A name of {@code n} RDNs, each one CN of "a". */
    static DLSequence manyRdns(int n) {
        ASN1Encodable[] rdns = new ASN1Encodable[n];
        for (int i = 0; i < n; i++) {
            rdns[i] = new DLSet(new DLSequence(new ASN1Encodable[] {BCStyle.CN, new DERUTF8String("a")}));
        }
        return new DLSequence(rdns);
    }
}
