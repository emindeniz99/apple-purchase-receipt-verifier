import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationResult;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Counts the fuzz seeds the Java implementation verifies under the anchor
 * set the receipt fuzz targets build: Apple's three roots plus one fixture
 * receipt root, once with the 0.6 root and once with the 0.7 root.
 *
 * DER seeds are base64-encoded first, as FuzzReceiptDer and PHP's
 * verify-receipt target do; base64 seeds are passed as text, as
 * FuzzReceiptBase64 does. Seeds are read at full size.
 *
 *   java -cp <library jar and its runtime deps> CountSeeds.java <fixtures dir>
 */
public final class CountSeeds {

    public static void main(String[] args) throws Exception {
        Path fixtures = Paths.get(args[0]);
        Map<String, Verifier> anchors = new TreeMap<>();
        anchors.put("0.6 root (generated/receipt-root.der)", verifier(fixtures.resolve("generated/receipt-root.der")));
        anchors.put("0.7 root (generated-0.7/receipt-root.der)", verifier(fixtures.resolve("generated-0.7/receipt-root.der")));

        for (Map.Entry<String, Verifier> anchor : anchors.entrySet()) {
            System.out.println("== Apple roots + " + anchor.getKey());
            count(anchor.getValue(), fixtures, "generated", "*.der", false);
            count(anchor.getValue(), fixtures, "generated-0.7", "*.der", false);
            count(anchor.getValue(), fixtures, "apple-official/certs", "*", false);
            count(anchor.getValue(), fixtures, "generated/receipt-b64", "*", true);
            count(anchor.getValue(), fixtures, "public-receipts", "*", true);
            count(anchor.getValue(), fixtures, "apple-official/xcode", "*", true);
        }
    }

    private static Verifier verifier(Path root) throws Exception {
        Set<X509Certificate> roots = new LinkedHashSet<>(Config.defaults().roots());
        roots.add((X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(root))));
        return Verifier.create(Config.builder().roots(roots).build());
    }

    private static void count(Verifier verifier, Path fixtures, String dir, String glob, boolean text)
            throws Exception {
        List<Path> files = new ArrayList<>();
        try (Stream<Path> listing = Files.list(fixtures.resolve(dir))) {
            java.nio.file.PathMatcher matcher = fixtures.getFileSystem().getPathMatcher("glob:" + glob);
            files.addAll(listing.filter(Files::isRegularFile)
                    .filter(p -> matcher.matches(p.getFileName()))
                    .sorted()
                    .collect(Collectors.toList()));
        }
        List<String> verified = new ArrayList<>();
        Map<String, Integer> reasons = new TreeMap<>();
        for (Path file : files) {
            byte[] bytes = Files.readAllBytes(file);
            String input = text
                    ? new String(bytes, StandardCharsets.ISO_8859_1)
                    : Base64.getEncoder().encodeToString(bytes);
            VerificationResult<?> result = verifier.verifyReceipt(input);
            if (result.verified()) {
                verified.add(file.getFileName() + " (" + bytes.length + " B)");
            } else {
                reasons.merge(result.failure().reason().name(), 1, Integer::sum);
            }
        }
        System.out.printf("%-24s %3d of %3d verify; refused: %s%n", dir + "/" + glob, verified.size(), files.size(), reasons);
        for (String name : verified) {
            System.out.println("    " + name);
        }
    }
}
