package io.github.emindeniz99.applepurchasereceiptverifier;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * After the post-build length check was deleted (2026-10-12, Q108 a): what
 * does Java answer for TestPki.crossCertifiedReceipt with four and five CAs
 * above the deep copy (six and seven certificates below the anchor), with
 * no defect and with each defect of TestPki.CrossDefect on the long route?
 * 20 receipts per row, fresh keys each. The instant in a validity message
 * is replaced by "<instant>" so equal answers count together.
 */
class CrossDefectProbeTest {

    @Test
    void probe() throws Exception {
        for (TestPki.CrossDefect d : TestPki.CrossDefect.values()) {
            for (int n : new int[] {4, 5}) {
                Map<String, Integer> out = new TreeMap<>();
                for (int i = 0; i < 20; i++) {
                    TestPki pki = TestPki.crossCertifiedReceipt(n, d);
                    String created = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
                    byte[] payload = TestPki.receiptPayload(
                            "b", "1", new byte[] {1}, new byte[20], created, Collections.<byte[]>emptyList());
                    String r;
                    try {
                        Checks.receipt(Checks.verifier(pki), pki.signReceipt(payload));
                        r = "ok";
                    } catch (VerificationException e) {
                        r = e.reason() + ": " + e.getMessage().replaceAll("\\d{10,}", "<instant>");
                    }
                    out.merge(r, 1, Integer::sum);
                }
                System.out.println("DEFECT " + d + " intermediates=" + n + " -> " + out);
            }
        }
    }
}
