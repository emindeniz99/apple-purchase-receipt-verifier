package io.github.emindeniz99.applepurchasereceiptverifier;

import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.jspecify.annotations.Nullable;

/**
 * The child JVM of {@link HostPolicyTest}: run under a host policy, it
 * prints one line per check, and exits non-zero if the library refuses
 * anything it should accept.
 *
 * <p>The first line is the premise: the JDK's own PKIX code, asked to build
 * the genuine legacy receipt chain, refuses it under this policy. Without
 * that, the library accepting the same chain would prove nothing.</p>
 */
public final class HostPolicyProbe {

    static final String JDK_REFUSES = "premise: the JDK's own PKIX refuses the legacy chain";
    static final String JDK_ACCEPTS = "premise not met: the JDK's own PKIX accepts the legacy chain";
    static final String LEGACY = "legacy receipt verifies";
    static final String CURRENT = "current receipt verifies";
    static final String JWS = "jws verifies";

    private static final Path FIXTURES = Paths.get("..", "fixtures");

    private HostPolicyProbe() {}

    public static void main(String[] args) throws Exception {
        byte[] legacy = publicReceipt("receipt-sandbox-legacy");
        AppReceipt receipt = ReceiptVerifier.verifyReceiptCore(legacy, AppleRootCerts.receiptRoots());
        String refusal = jdkRefusal(legacy, receipt.creationDate());
        System.out.println(refusal == null ? JDK_ACCEPTS : JDK_REFUSES + ": " + refusal);
        System.out.println(LEGACY + ": " + receipt.bundleId());

        ReceiptVerifier.verifyReceiptCore(publicReceipt("receipt-sandbox-g5"), AppleRootCerts.receiptRoots());
        System.out.println(CURRENT);

        X509Certificate jwsRoot = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(
                        Files.readAllBytes(FIXTURES.resolve("generated").resolve("jws-root.der"))));
        String jws = new String(
                        Files.readAllBytes(FIXTURES.resolve("generated").resolve("transaction.jws")),
                        StandardCharsets.US_ASCII)
                .trim();
        new JwsVerifier(Collections.singleton(jwsRoot), "com.example.app", EnumSet.of(Environment.SANDBOX))
                .verifyTransaction(jws);
        System.out.println(JWS);
    }

    static byte[] publicReceipt(String name) throws Exception {
        return Base64.getMimeDecoder()
                .decode(new String(
                        Files.readAllBytes(FIXTURES.resolve("public-receipts").resolve(name + ".b64")),
                        StandardCharsets.US_ASCII));
    }

    /**
     * Why the JDK's default PKIX provider will not build the chain embedded in
     * {@code receipt} to the bundled Apple roots at {@code at}, or null if it
     * builds it. Everything here goes through the JVM's provider list on
     * purpose: this is the code path the library no longer uses.
     */
    static @Nullable String jdkRefusal(byte[] receipt, @Nullable Instant at) throws Exception {
        CMSSignedData cms = new CMSSignedData(receipt);
        SignerId signer = cms.getSignerInfos().getSigners().iterator().next().getSID();
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> embedded = new ArrayList<X509Certificate>();
        for (X509CertificateHolder holder : cms.getCertificates().getMatches(null)) {
            embedded.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(holder.getEncoded())));
        }
        Set<TrustAnchor> anchors = new HashSet<TrustAnchor>();
        for (X509Certificate root : AppleRootCerts.receiptRoots()) {
            anchors.add(new TrustAnchor(
                    (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(root.getEncoded())), null));
        }
        X509CertSelector target = new X509CertSelector();
        target.setIssuer(signer.getIssuer().getEncoded());
        target.setSerialNumber(signer.getSerialNumber());
        PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, target);
        params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(embedded)));
        params.setRevocationEnabled(false);
        if (at != null) {
            params.setDate(Date.from(at));
        }
        try {
            CertPathBuilder.getInstance("PKIX").build(params);
            return null;
        } catch (Exception e) {
            return e.toString();
        }
    }
}
