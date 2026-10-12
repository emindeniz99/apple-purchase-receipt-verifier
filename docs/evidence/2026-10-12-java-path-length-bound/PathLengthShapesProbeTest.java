package io.github.emindeniz99.applepurchasereceiptverifier;

import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * Which receipt shapes reach the post-build path-length check in
 * ReceiptCore.validateChain, and how often. Each shape is minted 20 times
 * with fresh keys, verified through the Java implementation, and written
 * to $SCRATCH/pathlen-exp (receipt base64, root DER, Java's answer) for
 * the Go probe to run through the core.
 *
 * <p>Shapes, every certificate genuinely signed, valid from a day ago for
 * a year unless stated:</p>
 * <ul>
 *   <li>{@code self-N}: root, then N certificates named "CN=X CA" on one key,
 *       the first issued by the root and each next one self-issued by that
 *       key; the leaf is issued by "CN=X CA".</li>
 *   <li>{@code cross-expired-N}: "CN=X CA" on one key, issued by the root
 *       in a copy that expired 5 days ago, and again at the bottom of N CAs
 *       with their own names and keys; the leaf is issued by "CN=X CA".</li>
 *   <li>{@code cross-valid-N}: the same, with the copy under the root
 *       valid.</li>
 * </ul>
 */
class PathLengthShapesProbeTest {

    static final Path OUT = Paths.get(System.getenv("SCRATCH"), "pathlen-exp");
    static final String WWDR = "1.2.840.113635.100.6.2.1";
    static final String LEAF = "1.2.840.113635.100.6.11.1";

    static KeyPair rsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    static X509Certificate cert(String subject, KeyPair kp, String issuer, PrivateKey by, String oid, Date nb, Date na)
            throws Exception {
        return TestPki.cert(subject, kp, issuer, by, !LEAF.equals(oid), oid, nb, na, "SHA256withRSA");
    }

    static String run(String shape, int n, String tag) throws Exception {
        long now = System.currentTimeMillis();
        Date nb = new Date(now - 86_400_000L);
        Date na = new Date(now + 365L * 86_400_000L);
        KeyPair rootKp = rsa();
        KeyPair caKp = rsa();
        KeyPair leafKp = rsa();
        X509Certificate root = cert("CN=X Root", rootKp, "CN=X Root", rootKp.getPrivate(), null, nb, na);
        List<X509Certificate> cas = new ArrayList<>();
        if (shape.equals("self")) {
            String issuer = "CN=X Root";
            PrivateKey issuerKey = rootKp.getPrivate();
            for (int i = 1; i <= n; i++) {
                cas.add(cert("CN=X CA", caKp, issuer, issuerKey, WWDR, nb, na));
                issuer = "CN=X CA";
                issuerKey = caKp.getPrivate();
            }
        } else {
            boolean expired = shape.equals("cross-expired");
            Date pnb = expired ? new Date(now - 10 * 86_400_000L) : nb;
            Date pna = expired ? new Date(now - 5 * 86_400_000L) : na;
            cas.add(cert("CN=X CA", caKp, "CN=X Root", rootKp.getPrivate(), WWDR, pnb, pna));
            String issuer = "CN=X Root";
            PrivateKey issuerKey = rootKp.getPrivate();
            for (int i = 1; i <= n; i++) {
                KeyPair kp = rsa();
                cas.add(cert("CN=X B" + i, kp, issuer, issuerKey, null, nb, na));
                issuer = "CN=X B" + i;
                issuerKey = kp.getPrivate();
            }
            cas.add(cert("CN=X CA", caKp, issuer, issuerKey, WWDR, nb, na));
        }
        X509Certificate leaf = cert("CN=X Leaf", leafKp, "CN=X CA", caKp.getPrivate(), LEAF, nb, na);
        List<X509Certificate> embedded = new ArrayList<>();
        embedded.add(leaf);
        List<X509Certificate> reversed = new ArrayList<>(cas);
        Collections.reverse(reversed);
        embedded.addAll(reversed);
        embedded.add(root);
        // TestPki's chain constructor is private; this probe is not part of the suite.
        Constructor<TestPki> c = TestPki.class.getDeclaredConstructor(
                X509Certificate.class, X509Certificate.class, X509Certificate.class, PrivateKey.class, List.class);
        c.setAccessible(true);
        TestPki pki = c.newInstance(root, reversed.get(0), leaf, leafKp.getPrivate(), embedded);
        String created = Instant.ofEpochMilli(now).truncatedTo(ChronoUnit.SECONDS).toString();
        byte[] payload = TestPki.receiptPayload(
                "b", "1", new byte[] {1}, new byte[20], created, Collections.<byte[]>emptyList());
        byte[] der = pki.signReceipt(payload);
        String out;
        try {
            Checks.receipt(Checks.verifier(pki), der);
            out = "ok";
        } catch (VerificationException e) {
            out = e.reason() + ": " + e.getMessage();
        }
        Files.createDirectories(OUT);
        Files.write(OUT.resolve(tag + ".b64"), Base64.getEncoder().encode(der));
        Files.write(OUT.resolve(tag + ".root.der"), root.getEncoded());
        Files.write(OUT.resolve(tag + ".java.txt"), out.getBytes(StandardCharsets.UTF_8));
        return out;
    }

    @Test
    void probe() throws Exception {
        String[][] runs = {{"self", "6"}, {"self", "7"}, {"cross-expired", "5"}, {"cross-valid", "5"}, {"cross-expired", "4"}};
        for (String[] r : runs) {
            Map<String, Integer> outcomes = new TreeMap<>();
            for (int i = 0; i < 20; i++) {
                outcomes.merge(run(r[0], Integer.parseInt(r[1]), r[0] + "-" + r[1] + "-" + i), 1, Integer::sum);
            }
            System.out.println("JAVA " + r[0] + "-" + r[1] + " -> " + outcomes);
        }
    }

    /**
     * Run in a JVM of its own after {@link #probe}: is Java's answer for one
     * receipt's bytes stable, across JVMs and across calls?
     */
    @Test
    void rerun() throws Exception {
        int same = 0;
        int differ = 0;
        try (java.util.stream.Stream<Path> files = Files.list(OUT)) {
            for (Path b64 : (Iterable<Path>) files.filter(p -> p.toString().endsWith(".b64"))::iterator) {
                String tag = b64.getFileName().toString().replace(".b64", "");
                X509Certificate root = (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                        .generateCertificate(Files.newInputStream(OUT.resolve(tag + ".root.der")));
                String first = new String(Files.readAllBytes(OUT.resolve(tag + ".java.txt")), StandardCharsets.UTF_8);
                for (int i = 0; i < 3; i++) {
                    String out;
                    try {
                        Checks.receipt(Checks.verifier(root), new String(Files.readAllBytes(b64), StandardCharsets.US_ASCII));
                        out = "ok";
                    } catch (VerificationException e) {
                        out = e.reason() + ": " + e.getMessage();
                    }
                    if (out.equals(first)) {
                        same++;
                    } else {
                        differ++;
                    }
                }
            }
        }
        System.out.println("JAVA rerun: same answer " + same + ", different " + differ);
    }
}
