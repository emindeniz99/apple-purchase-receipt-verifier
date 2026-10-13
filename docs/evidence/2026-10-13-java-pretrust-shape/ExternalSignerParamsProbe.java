package io.github.emindeniz99.applepurchasereceiptverifier;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * Review 5's probe for the SignerInfo side of the EXTERNAL gap: a copy of
 * the genuine SignerInfo, ahead of it, whose signatureAlgorithm parameters
 * are NULL ({@code none}), SETs nested 30 deep ({@code direct-set}) or the
 * same SETs inside an EXTERNAL's data value descriptor ({@code external}),
 * with one CMSAlgorithmProtection attribute naming that label. The genuine
 * CMSAlgorithmProtection attribute is dropped from the copy: with two,
 * BouncyCastle refuses the SignerInfo before it compares any parameters.
 * Each shape is verified three times in one JVM, the first cold.
 *
 * <p>Args: none
 */
public class ExternalSignerParamsProbe {
    public static void main(String[] a) throws Exception {
        TestPki pki = TestPki.receipt();
        SignedData genuine = ExternalDescriptorProbe.signedData(
                pki.signReceipt(TestPki.singleAttributePayload(9999, new byte[16])));
        SignerInfo signer = SignerInfo.getInstance(genuine.getSignerInfos().getObjectAt(0));

        for (String mode : new String[] {"none", "direct-set", "external"}) {
            ASN1Encodable nested = mode.equals("none")
                    ? DERNull.INSTANCE
                    : ExternalDescriptorProbe.nestedSets(30, ExternalDescriptorProbe.CAP_DER / 2 - 16384);
            if (mode.equals("external")) {
                nested = ExternalDescriptorProbe.external(nested);
            }
            DLSequence label =
                    new DLSequence(new ASN1Encodable[] {PKCSObjectIdentifiers.sha256WithRSAEncryption, nested});
            ASN1EncodableVector attributes = new ASN1EncodableVector();
            for (int i = 0; i < signer.getAuthenticatedAttributes().size(); i++) {
                Attribute attribute = Attribute.getInstance(signer.getAuthenticatedAttributes().getObjectAt(i));
                if (!PKCSObjectIdentifiers.id_aa_cmsAlgorithmProtect.equals(attribute.getAttrType())) {
                    attributes.add(attribute);
                }
            }
            attributes.add(new DLSequence(new ASN1Encodable[] {
                PKCSObjectIdentifiers.id_aa_cmsAlgorithmProtect,
                new DLSet(new DLSequence(
                        new ASN1Encodable[] {signer.getDigestAlgorithm(), new DLTaggedObject(false, 1, label)}))
            }));
            DLSequence copy = new DLSequence(new ASN1Encodable[] {
                new ASN1Integer(1),
                signer.getSID(),
                signer.getDigestAlgorithm(),
                new DLTaggedObject(false, 0, new DLSet(attributes)),
                label,
                signer.getEncryptedDigest()
            });
            byte[] receipt = ExternalDescriptorProbe.receipt(
                    genuine, genuine.getCertificates(), new DLSet(new ASN1Encodable[] {copy, signer}));
            ExternalDescriptorProbe.time("signerinfo-params-" + mode, pki, receipt);
        }
    }
}
