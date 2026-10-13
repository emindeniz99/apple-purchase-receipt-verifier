package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.Test;

/**
 * {@link ReceiptCore#REFUSED_DIGESTS} is the slow cluster of the digests
 * BouncyCastle's CMS layer resolves: every refused digest costs more than
 * {@link #REFUSED_ABOVE} times SHA-256, every other one less than
 * {@link #ALLOWED_BELOW} times.
 *
 * <p>A SignerInfo's digestAlgorithm is unsigned, and BouncyCastle digests the
 * whole content with it before any signature is checked. Every digest OID the
 * provider registers is offered to the calculator provider the CMS verifier
 * builds; each one it resolves is timed over the same bytes, interleaved,
 * and its best time is divided by SHA-256's from the same run. A
 * BouncyCastle that adds a slow digest, or speeds a refused one up, fails
 * here and the list is revisited.</p>
 *
 * <p>Two edges, not one cut. A ratio moves by up to a third between runs and
 * JDKs, so a single threshold near any digest would flap. The band between
 * the edges is a dead zone: a digest measured inside it passes whether it is
 * refused or not, and only one that leaves the band on the wrong side fails.
 * On BouncyCastle 1.86 (JDK 8, 11 and 21) the fastest refused digest, DSTU
 * 7564-256, measured 2.9 times SHA-256 at its lowest and the slowest
 * allowed one, RIPEMD-160, 2.6 at its highest; each edge sits at
 * least a fifth away from the nearest measurement
 * (docs/evidence/2026-10-13-java-digest-cost.md). A digest whose JIT
 * compilation lags reads slow for a few rounds, so rounds continue, keeping
 * each digest's best, until the table agrees or {@link #MAX_ROUNDS} have
 * run. Ratios, never milliseconds, so a slow runner does not fail it.</p>
 */
class DigestDenylistCostTest {

    /** A refused digest must cost more than this many times SHA-256. */
    private static final double REFUSED_ABOVE = 2.4;

    /** An allowed digest must cost less than this many times SHA-256. */
    private static final double ALLOWED_BELOW = 3.2;

    private static final int BUFFER_BYTES = 512 * 1024;
    private static final int WARM_ROUNDS = 2;
    private static final int MIN_ROUNDS = 7;
    private static final int MAX_ROUNDS = 20;
    private static final String SHA256 = "2.16.840.1.101.3.4.2.1";
    private static final Pattern OID = Pattern.compile("[0-2](\\.[0-9]+)+");

    @Test
    void theRefusedDigestsAreTheSlowClusterAndTheRestAreFast() throws Exception {
        DigestCalculatorProvider calculators = new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastle.PROVIDER)
                .build();
        TreeSet<String> resolved = resolvedDigests(calculators);
        assertTrue(resolved.contains(SHA256), "SHA-256 did not resolve: " + resolved);
        assertTrue(resolved.containsAll(ReceiptCore.REFUSED_DIGESTS), "a refused digest did not resolve: " + resolved);
        byte[] content = new byte[BUFFER_BYTES];
        new Random(1).nextBytes(content);
        Map<String, Long> best = new TreeMap<String, Long>();
        String table = "";
        for (int round = 0; round < MAX_ROUNDS; round++) {
            for (String oid : resolved) {
                long nanos = digestNanos(calculators, oid, content);
                if (round >= WARM_ROUNDS && (!best.containsKey(oid) || nanos < best.get(oid))) {
                    best.put(oid, nanos);
                }
            }
            if (round + 1 >= MIN_ROUNDS) {
                table = table(best, round + 1);
                if (!table.contains("wrong side")) {
                    return;
                }
            }
        }
        fail(table);
    }

    /** Every digest OID the provider registers that the CMS verifier's calculator provider builds. */
    private static TreeSet<String> resolvedDigests(DigestCalculatorProvider calculators) {
        TreeSet<String> resolved = new TreeSet<String>();
        // A copy: BouncyCastle registers entries lazily while one is built.
        for (Object key : new ArrayList<Object>(BouncyCastle.PROVIDER.keySet())) {
            String name = String.valueOf(key);
            if (!name.startsWith("MessageDigest.") && !name.startsWith("Alg.Alias.MessageDigest.")) {
                continue;
            }
            Matcher oid = OID.matcher(name);
            while (oid.find()) {
                try {
                    calculators.get(new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid.group())));
                    resolved.add(oid.group());
                } catch (Exception e) {
                    // Not a digest the CMS verifier can build.
                }
            }
        }
        return resolved;
    }

    private static long digestNanos(DigestCalculatorProvider calculators, String oid, byte[] content) throws Exception {
        DigestCalculator calculator = calculators.get(new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid)));
        long start = System.nanoTime();
        OutputStream out = calculator.getOutputStream();
        out.write(content);
        out.close();
        calculator.getDigest();
        return System.nanoTime() - start;
    }

    /** Each digest's best time over SHA-256's, refused or not, and whether it left the band on the wrong side. */
    private static String table(Map<String, Long> best, int rounds) {
        StringBuilder table = new StringBuilder("best time over SHA-256's, " + rounds + " rounds of " + BUFFER_BYTES
                + " bytes, refused above " + REFUSED_ABOVE + ", allowed below " + ALLOWED_BELOW + ":\n");
        for (Map.Entry<String, Long> row : best.entrySet()) {
            double ratio = row.getValue() / (double) best.get(SHA256);
            boolean refused = ReceiptCore.REFUSED_DIGESTS.contains(row.getKey());
            boolean wrong = refused ? ratio <= REFUSED_ABOVE : ratio >= ALLOWED_BELOW;
            table.append(String.format(
                    "%-28s %6.2f%s%s%n",
                    row.getKey(), ratio, refused ? "  refused" : "", wrong ? "  <-- wrong side" : ""));
        }
        return table.toString();
    }
}
