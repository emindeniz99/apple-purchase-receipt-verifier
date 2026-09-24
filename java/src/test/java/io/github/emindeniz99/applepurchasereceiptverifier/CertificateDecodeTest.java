package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.CollectionStore;
import org.junit.jupiter.api.Test;

/**
 * Certificate content BouncyCastle decodes lazily.
 *
 * <p>BouncyCastle reads a certificate's public key and its signature BIT
 * STRING only when something first asks for them, and reports a value it
 * cannot use with an unchecked exception from wherever that is, often inside
 * the path builder or validator. Both verifiers read both right after parsing
 * every certificate, so such a certificate gets the verdict for an unreadable
 * certificate in its position, and never an exception outside
 * {@link VerificationException}. On the JWS path that is INVALID_CERTIFICATE,
 * as the shared suite pins for {@code transaction/reject-x5c-unimplemented-curve};
 * the JWS case below is the input java-fuzz found. On the receipt path it is
 * INVALID_CERTIFICATE for the signer
 * ({@code receipt/reject-signer-on-an-unimplemented-curve}) and
 * INVALID_RECEIPT_FORMAT for any other entry, exactly as for an entry whose
 * X.509 structure does not parse: the bag is unsigned, so what cannot be read
 * there is a defect of the receipt.</p>
 *
 * <p>The receipt cases add a certificate that is not the signer to the CMS
 * certificate bag, which the signature does not cover, so the receipt is
 * genuine in every other way; the test first shows it verifies untouched.</p>
 */
class CertificateDecodeTest {

    private static final Path GENERATED = TestFixtures.generated();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static X509Certificate root(String name) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(GENERATED.resolve(name))));
    }

    /** {@code der} re-encoded with its signature BIT STRING declaring one unused bit. */
    private static byte[] withUnalignedSignature(byte[] der) throws Exception {
        ASN1Sequence certificate = ASN1Sequence.getInstance(der);
        byte[] signature = DERBitString.getInstance(certificate.getObjectAt(2)).getBytes();
        ASN1EncodableVector fields = new ASN1EncodableVector();
        fields.add(certificate.getObjectAt(0));
        fields.add(certificate.getObjectAt(1));
        fields.add(new DERBitString(signature, 1));
        return new DERSequence(fields).getEncoded();
    }

    private static byte[] receiptWithExtraCertificates(byte[] genuine, Collection<X509CertificateHolder> extra)
            throws Exception {
        CMSSignedData cms = new CMSSignedData(genuine);
        List<X509CertificateHolder> bag =
                new ArrayList<X509CertificateHolder>(cms.getCertificates().getMatches(null));
        bag.addAll(extra);
        return CMSSignedData.replaceCertificatesAndCRLs(
                        cms, new CollectionStore<X509CertificateHolder>(bag), null, null)
                .getEncoded();
    }

    @Test
    void aNonSignerCertificateWithAnUnreadableKeyIsInvalidReceiptFormat() throws Exception {
        byte[] genuine = Files.readAllBytes(GENERATED.resolve("receipt.der"));
        X509Certificate receiptRoot = root("receipt-root.der");
        assertNotNull(ReceiptVerifier.verifyReceiptCore(genuine, Collections.singleton(receiptRoot)));

        CMSSignedData withBadKey =
                new CMSSignedData(Files.readAllBytes(GENERATED.resolve("receipt-signer-unimplemented-curve.der")));
        byte[] tampered = receiptWithExtraCertificates(
                genuine, withBadKey.getCertificates().getMatches(null));

        VerificationException e = assertThrows(
                VerificationException.class,
                () -> ReceiptVerifier.verifyReceiptCore(tampered, Collections.singleton(receiptRoot)));
        assertEquals(Reason.INVALID_RECEIPT_FORMAT, e.reason(), e.getMessage());
    }

    @Test
    void aNonSignerCertificateWithAnUnalignedSignatureIsInvalidReceiptFormat() throws Exception {
        byte[] genuine = Files.readAllBytes(GENERATED.resolve("receipt.der"));
        X509Certificate receiptRoot = root("receipt-root.der");
        byte[] tampered = receiptWithExtraCertificates(
                genuine,
                Collections.singletonList(new X509CertificateHolder(withUnalignedSignature(receiptRoot.getEncoded()))));

        VerificationException e = assertThrows(
                VerificationException.class,
                () -> ReceiptVerifier.verifyReceiptCore(tampered, Collections.singleton(receiptRoot)));
        assertEquals(Reason.INVALID_RECEIPT_FORMAT, e.reason(), e.getMessage());
    }

    @Test
    void anX5cLeafWithAnUnalignedSignatureIsInvalidCertificate() throws Exception {
        String jws =
                new String(Files.readAllBytes(GENERATED.resolve("transaction.jws")), StandardCharsets.US_ASCII).trim();
        JwsVerifier verifier = new JwsVerifier(
                Collections.singleton(root("jws-root.der")), "com.example.app", EnumSet.of(Environment.SANDBOX));
        assertNotNull(verifier.verifyTransaction(jws));

        String[] parts = jws.split("\\.");
        ObjectNode header = (ObjectNode) MAPPER.readTree(Base64.getUrlDecoder().decode(parts[0]));
        ArrayNode x5c = (ArrayNode) header.get("x5c");
        byte[] leaf = Base64.getDecoder().decode(x5c.get(0).asText());
        x5c.set(0, Base64.getEncoder().encodeToString(withUnalignedSignature(leaf)));
        String tampered = Base64.getUrlEncoder().withoutPadding().encodeToString(MAPPER.writeValueAsBytes(header)) + "."
                + parts[1] + "." + parts[2];

        VerificationException e = assertThrows(VerificationException.class, () -> verifier.verifyTransaction(tampered));
        assertEquals(Reason.INVALID_CERTIFICATE, e.reason(), e.getMessage());
    }
}
