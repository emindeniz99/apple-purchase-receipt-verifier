package io.github.emindeniz99.applepurchasereceiptverifier;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

/**
 * Walks one receipt through the steps of ReceiptCore.verifySignature and
 * prints what each step sees, for java/WALKTHROUGH.md §6.3. It calls the
 * library's own classes (the private ReceiptCore methods by reflection), so
 * it must be compiled into the library's package against the main and
 * shared sources. Argument: a base64 receipt file.
 */
public final class Trace {

    public static void main(String[] args) throws Exception {
        String b64 = new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.US_ASCII).trim();
        long now = System.currentTimeMillis();
        Set<TrustAnchor> anchors = AppleTrust.anchors(AppleRootCerts.roots());
        System.out.println("clock " + Instant.ofEpochMilli(now));

        System.out.println("2 base64 chars=" + b64.length()
                + " over cap=" + Utf8Length.exceeds(b64, ReceiptCore.MAX_RECEIPT_BYTES));
        byte[] der = StrictBase64.decode(b64, Reason.MALFORMED, "receipt");
        System.out.println("2 decoded bytes=" + der.length);

        CMSSignedData cms = new CMSSignedData(ContentInfo.getInstance(ASN1Primitive.fromByteArray(der)));
        byte[] payload = (byte[]) cms.getSignedContent().getContent();
        List<SignerInformation> signers = new ArrayList<>(cms.getSignerInfos().getSigners());
        SignerInformation signer = signers.get(0);
        System.out.println("4 eContent bytes=" + payload.length
                + " signerInfos=" + signers.size()
                + " signedAttrs=" + (signer.getSignedAttributes() != null)
                + " digest=" + signer.getDigestAlgOID()
                + " sigAlg=" + signer.getEncryptionAlgOID()
                + " sid.issuer=" + signer.getSID().getIssuer()
                + " sid.byKeyId=" + (signer.getSID().getSubjectKeyIdentifier() != null));
        Long creation = ReceiptDecoder.readCreationDate(payload);
        System.out.println("4 creation date=" + (creation == null ? null : Instant.ofEpochMilli(creation)));

        ReceiptCertificates certificates = ReceiptCertificates.decode(cms);
        for (X509Certificate c : certificates.all()) {
            System.out.println("5 bag: " + name(c) + " notAfter=" + c.getNotAfter().toInstant() + " sig=" + c.getSigAlgName());
        }
        List<X509Certificate> matches = certificates.signers(signer);
        System.out.println("5 sid matches=" + matches.size() + " first=" + name(matches.get(0)));

        Method topDown = ReceiptCore.class.getDeclaredMethod("authenticatedTopDown", List.class, Set.class);
        topDown.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<X509Certificate> authenticated = (List<X509Certificate>) topDown.invoke(null, certificates.all(), anchors);
        for (X509Certificate c : authenticated) {
            System.out.println("6 authenticated, in acceptance order: " + name(c));
        }

        Method validateChain = ReceiptCore.class.getDeclaredMethod(
                "validateChain", X509Certificate.class, List.class, Date.class, Set.class);
        validateChain.setAccessible(true);
        X509Certificate leaf = matches.get(0);
        Date at = new Date(creation != null ? creation : now);
        List<?> path = (List<?>) validateChain.invoke(null, leaf, authenticated, at, anchors);
        System.out.println("7 path at " + at.toInstant() + ", size=" + path.size());
        for (Object o : path) {
            System.out.println("7 path: " + name((X509Certificate) o));
        }
        try {
            validateChain.invoke(null, leaf, authenticated, new Date(now), anchors);
            System.out.println("7 same chain at the clock: ok");
        } catch (InvocationTargetException e) {
            VerificationException v = (VerificationException) e.getCause();
            System.out.println("7 same chain at the clock: " + v.reason() + " (" + v.getMessage() + ")");
        }

        System.out.println("8 leaf marker=" + (leaf.getExtensionValue(AppleTrust.SIGNING_LEAF_OID) != null)
                + " intermediate marker="
                + (((X509Certificate) path.get(1)).getExtensionValue(AppleTrust.INTERMEDIATE_OID) != null));
        System.out.println("9 CMS signature valid=" + signer.verify(ReceiptCore.signerVerifier(leaf)));

        ReceiptPayload parsed = ReceiptDecoder.parse(payload);
        System.out.println("10 receiptType=" + parsed.receiptType() + " environment=" + parsed.environment()
                + " inApp=" + parsed.inApp().size() + " raw types=" + parsed.unknownAttributes().keySet());

        VerificationResult<ReceiptPayload> result = Verifier.create(Config.defaults()).verifyReceipt(b64);
        System.out.println("verifyReceipt verified=" + result.verified());
    }

    private static String name(X509Certificate c) {
        return c.getSubjectX500Principal().getName("RFC2253");
    }

    private Trace() {}
}
