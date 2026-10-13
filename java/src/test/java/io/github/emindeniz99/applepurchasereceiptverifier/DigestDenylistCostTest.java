package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.OutputStream;
import java.lang.reflect.Field;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.Test;

/**
 * {@link ReceiptCore#REFUSED_DIGESTS} is the slow cluster of the digests
 * BouncyCastle's CMS layer resolves, and md2WithRSAEncryption, refused by
 * {@link ReceiptCore#REFUSED_SIGNATURE_ALGORITHMS}, the one slow signature
 * label: every one refused for its cost costs more than {@link #REFUSED_ABOVE}
 * times the baseline, every one allowed less than {@link #ALLOWED_BELOW} times.
 *
 * <p>A SignerInfo's digestAlgorithm is unsigned, and BouncyCastle digests the
 * whole content with it before any signature is checked. Every digest the CMS
 * verifier's calculator provider resolves is timed over the same bytes,
 * interleaved, and its best time is divided by SHA-256's from the same run:
 * the OIDs the provider registers, the ones the calculator maps to a digest
 * name from BouncyCastle's own tables (Tiger is in no provider entry), and
 * SHAKE with an output length, at each length the provider names. A
 * BouncyCastle that adds a slow digest, or speeds a refused one up, fails
 * here and the list is revisited.</p>
 *
 * <p>The signatureAlgorithm is unsigned too, and with signed attributes
 * BouncyCastle hashes them with the digest it names before the signature is
 * checked. Every Signature OID the provider registers is offered to the CMS
 * verifier as SignerInformation offers it, with SHA-256 as the digest, for an
 * RSA and an EC key, and each content verifier that builds is timed against
 * rsaEncryption's or id-ecPublicKey's.</p>
 *
 * <p>Two edges, not one cut. A ratio moves by up to a third between runs and
 * JDKs, so a single threshold near any digest would flap. The band between
 * the edges is a dead zone: a digest measured inside it passes whether it is
 * refused or not, and only one that leaves the band on the wrong side fails.
 * On BouncyCastle 1.86 (JDK 8, 11 and 21) the fastest refused digest, DSTU
 * 7564-256, measured 2.9 times SHA-256 at its lowest and the slowest
 * allowed one, RIPEMD-160, 2.6 at its highest; each edge sits at
 * least a fifth away from the nearest measurement
 * (docs/evidence/2026-10-13-java-digest-cost.md). md2WithRSAEncryption
 * measured 16 times rsaEncryption and every other label 2.4 at most
 * (docs/evidence/2026-10-13-java-pretrust-reencoding.md). A digest whose JIT
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
    private static final String RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
    private static final String EC_PUBLIC_KEY = "1.2.840.10045.2.1";

    /** The one signature label refused for what its digest costs. */
    private static final String MD2_WITH_RSA = "1.2.840.113549.1.1.2";

    private static final Pattern OID = Pattern.compile("[0-2](\\.[0-9]+)+");
    private static final Pattern SHAKE_LENGTH = Pattern.compile("MessageDigest\\.SHAKE(128|256)-([0-9]+)");

    /** The time {@code algorithm} takes over {@code content}. */
    private interface Timer {
        long nanos(AlgorithmIdentifier algorithm, byte[] content) throws Exception;
    }

    @Test
    void theRefusedDigestsAreTheSlowClusterAndTheRestAreFast() throws Exception {
        DigestCalculatorProvider calculators = new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastle.PROVIDER)
                .build();
        Map<String, AlgorithmIdentifier> resolved = resolvedDigests(calculators);
        assertTrue(resolved.containsKey(SHA256), "SHA-256 did not resolve: " + resolved.keySet());
        assertTrue(
                resolved.keySet().containsAll(ReceiptCore.REFUSED_DIGESTS),
                "a refused digest did not resolve: " + resolved.keySet());
        assertInBand(
                resolved,
                SHA256,
                (algorithm, content) -> digestNanos(calculators, algorithm, content),
                ReceiptCore.REFUSED_DIGESTS::contains,
                ReceiptCore.REFUSED_DIGESTS::contains);
    }

    @Test
    void md2WithRsaIsTheOneSlowSignatureLabel() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA", BouncyCastle.PROVIDER);
        rsa.initialize(2048);
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC", BouncyCastle.PROVIDER);
        ec.initialize(256);
        for (KeyPair key : new KeyPair[] {rsa.generateKeyPair(), ec.generateKeyPair()}) {
            SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider(BouncyCastle.PROVIDER)
                    .build(key.getPublic());
            Map<String, AlgorithmIdentifier> labels = buildableLabels(verifier);
            String baseline = key.getPublic().getAlgorithm().equals("RSA") ? RSA_ENCRYPTION : EC_PUBLIC_KEY;
            assertTrue(labels.containsKey(baseline), baseline + " did not build: " + labels.keySet());
            assertTrue(
                    !baseline.equals(RSA_ENCRYPTION) || labels.containsKey(MD2_WITH_RSA),
                    "md2WithRSAEncryption did not build for an RSA key: " + labels.keySet());
            assertInBand(
                    labels,
                    baseline,
                    (algorithm, content) -> labelNanos(verifier, algorithm, content),
                    ReceiptCore.REFUSED_SIGNATURE_ALGORITHMS::contains,
                    ReceiptCore.REFUSED_SIGNATURE_ALGORITHMS::contains);
        }
    }

    /**
     * Times every entry of {@code algorithms} over the same bytes, round after
     * round, and fails with the table unless every one {@code mustBeSlow}
     * names costs more than {@link #REFUSED_ABOVE} times {@code baseline} and
     * every one {@code refused} does not name costs less than
     * {@link #ALLOWED_BELOW} times.
     */
    private static void assertInBand(
            Map<String, AlgorithmIdentifier> algorithms,
            String baseline,
            Timer timer,
            Predicate<String> mustBeSlow,
            Predicate<String> refused)
            throws Exception {
        byte[] content = new byte[BUFFER_BYTES];
        new Random(1).nextBytes(content);
        Map<String, Long> best = new TreeMap<String, Long>();
        String table = "";
        for (int round = 0; round < MAX_ROUNDS; round++) {
            for (Map.Entry<String, AlgorithmIdentifier> algorithm : algorithms.entrySet()) {
                long nanos = timer.nanos(algorithm.getValue(), content);
                String name = algorithm.getKey();
                if (round >= WARM_ROUNDS && (!best.containsKey(name) || nanos < best.get(name))) {
                    best.put(name, nanos);
                }
            }
            if (round + 1 >= MIN_ROUNDS) {
                table = table(best, baseline, round + 1, mustBeSlow, refused);
                if (!table.contains("wrong side")) {
                    return;
                }
            }
        }
        fail(table);
    }

    /**
     * Every digest the CMS verifier's calculator provider builds, keyed by
     * OID (and output length): the provider's own OIDs, the OIDs
     * BouncyCastle's digest tables name, which the calculator reads by
     * reflection here only, and SHAKE with each length the provider names.
     */
    private static Map<String, AlgorithmIdentifier> resolvedDigests(DigestCalculatorProvider calculators)
            throws Exception {
        Map<String, AlgorithmIdentifier> candidates = new TreeMap<String, AlgorithmIdentifier>();
        // A copy: BouncyCastle registers entries lazily while one is built.
        for (Object key : new ArrayList<Object>(BouncyCastle.PROVIDER.keySet())) {
            String name = String.valueOf(key);
            if (!name.startsWith("MessageDigest.") && !name.startsWith("Alg.Alias.MessageDigest.")) {
                continue;
            }
            Matcher oid = OID.matcher(name);
            while (oid.find()) {
                candidates.put(oid.group(), new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid.group())));
            }
            Matcher shake = SHAKE_LENGTH.matcher(name);
            if (shake.matches()) {
                ASN1ObjectIdentifier withLength = shake.group(1).equals("128")
                        ? NISTObjectIdentifiers.id_shake128_len
                        : NISTObjectIdentifiers.id_shake256_len;
                candidates.put(
                        withLength.getId() + "(" + shake.group(2) + ")",
                        new AlgorithmIdentifier(withLength, new ASN1Integer(Long.parseLong(shake.group(2)))));
            }
        }
        for (String table : new String[] {
            "org.bouncycastle.jcajce.util.MessageDigestUtils#digestOidMap",
            "org.bouncycastle.operator.jcajce.OperatorHelper#oids"
        }) {
            for (Object oid : tableKeys(table)) {
                candidates.put(oid.toString(), new AlgorithmIdentifier((ASN1ObjectIdentifier) oid));
            }
        }
        Map<String, AlgorithmIdentifier> resolved = new TreeMap<String, AlgorithmIdentifier>();
        for (Map.Entry<String, AlgorithmIdentifier> candidate : candidates.entrySet()) {
            try {
                calculators.get(candidate.getValue());
                resolved.put(candidate.getKey(), candidate.getValue());
            } catch (Exception e) {
                // Not a digest the CMS verifier can build.
            }
        }
        return resolved;
    }

    /** The keys of a private static map, {@code type#field}. */
    private static Iterable<?> tableKeys(String table) throws Exception {
        String[] parts = table.split("#");
        Field field = Class.forName(parts[0]).getDeclaredField(parts[1]);
        field.setAccessible(true);
        return ((Map<?, ?>) field.get(null)).keySet();
    }

    /** Every Signature OID the provider registers, plus the key's own, that builds a content verifier for SHA-256. */
    private static Map<String, AlgorithmIdentifier> buildableLabels(SignerInformationVerifier verifier) {
        Map<String, AlgorithmIdentifier> labels = new TreeMap<String, AlgorithmIdentifier>();
        Set<String> oids = new TreeSet<String>();
        oids.add(RSA_ENCRYPTION);
        oids.add(EC_PUBLIC_KEY);
        for (Object key : new ArrayList<Object>(BouncyCastle.PROVIDER.keySet())) {
            String name = String.valueOf(key);
            if (!name.startsWith("Signature.") && !name.startsWith("Alg.Alias.Signature.")) {
                continue;
            }
            Matcher oid = OID.matcher(name);
            while (oid.find()) {
                oids.add(oid.group());
            }
        }
        byte[] probe = new byte[1024];
        for (String oid : oids) {
            AlgorithmIdentifier label = new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid), DERNull.INSTANCE);
            try {
                labelNanos(verifier, label, probe);
                labels.put(oid, label);
            } catch (Exception e) {
                // No content verifier for this key: SignerInformation fails
                // it before hashing anything.
            }
        }
        return labels;
    }

    private static long digestNanos(DigestCalculatorProvider calculators, AlgorithmIdentifier algorithm, byte[] content)
            throws Exception {
        DigestCalculator calculator = calculators.get(algorithm);
        long start = System.nanoTime();
        OutputStream out = calculator.getOutputStream();
        out.write(content);
        out.close();
        calculator.getDigest();
        return System.nanoTime() - start;
    }

    /** What the signed attributes cost a content verifier for {@code label} before it checks a signature. */
    private static long labelNanos(SignerInformationVerifier verifier, AlgorithmIdentifier label, byte[] content)
            throws Exception {
        ContentVerifier contentVerifier = verifier.getContentVerifier(
                label, new AlgorithmIdentifier(new ASN1ObjectIdentifier(SHA256), DERNull.INSTANCE));
        long start = System.nanoTime();
        OutputStream out = contentVerifier.getOutputStream();
        out.write(content);
        out.close();
        return System.nanoTime() - start;
    }

    /** Each entry's best time over the baseline's, and whether it left the band on the wrong side. */
    private static String table(
            Map<String, Long> best,
            String baseline,
            int rounds,
            Predicate<String> mustBeSlow,
            Predicate<String> refused) {
        StringBuilder table = new StringBuilder("best time over " + baseline + "'s, " + rounds + " rounds of "
                + BUFFER_BYTES + " bytes, refused above " + REFUSED_ABOVE + ", allowed below " + ALLOWED_BELOW
                + ":\n");
        for (Map.Entry<String, Long> row : best.entrySet()) {
            double ratio = row.getValue() / (double) best.get(baseline);
            boolean slow = mustBeSlow.test(row.getKey());
            boolean wrong = slow ? ratio <= REFUSED_ABOVE : !refused.test(row.getKey()) && ratio >= ALLOWED_BELOW;
            table.append(String.format(
                    "%-28s %6.2f%s%s%n",
                    row.getKey(),
                    ratio,
                    refused.test(row.getKey()) ? "  refused" : "",
                    wrong ? "  <-- wrong side" : ""));
        }
        return table.toString();
    }
}
