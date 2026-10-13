package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.Set;

/**
 * A genuine test-PKI JWS whose x5c[0] is the leaf followed by three zero
 * octets, the leaf twice, or the leaf as PEM text: what JwsCore answers for
 * each now that x5c is read with Certificate.getInstance rather than
 * BouncyCastle's CertificateFactory.
 */
public class X5cTrailProbe {
    public static void main(String[] a) throws Exception {
        TestPki pki = TestPki.jws();
        Set<TrustAnchor> anchors = AppleTrust.anchors(Collections.singleton(pki.root));
        byte[] leaf = pki.leaf.getEncoded();
        byte[] trailing = java.util.Arrays.copyOf(leaf, leaf.length + 3);
        byte[] second = new byte[leaf.length * 2];
        System.arraycopy(leaf, 0, second, 0, leaf.length);
        System.arraycopy(leaf, 0, second, leaf.length, leaf.length);
        byte[] pem = ("-----BEGIN CERTIFICATE-----\n" + java.util.Base64.getMimeEncoder().encodeToString(leaf)
                + "\n-----END CERTIFICATE-----\n").getBytes("US-ASCII");
        String[][] cases = {{"trailing", TestPki.b64(trailing)}, {"second", TestPki.b64(second)}, {"pem", TestPki.b64(pem)}};
        for (String[] c : cases) {
            String jws = pki.signJwsWithHeader("{\"alg\":\"ES256\",\"x5c\":[\"" + c[1] + "\",\"" + TestPki.b64(pki.intermediate.getEncoded()) + "\",\"" + TestPki.b64(pki.root.getEncoded()) + "\"]}", "{}");
            String verdict;
            try { JwsCore.verify(jws, anchors, System.currentTimeMillis()); verdict = "ACCEPTED"; }
            catch (VerificationException e) { verdict = e.reason() + ": " + e.getMessage(); }
            System.out.println(c[0] + " " + verdict);
        }
    }
}
