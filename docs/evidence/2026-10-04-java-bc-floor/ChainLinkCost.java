import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.JsonPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload;
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
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * What does the second check of each chain signature cost? Both paths first
 * walk the chain down from the pinned roots (ReceiptCore.authenticatedTopDown,
 * JwsCore.authenticateTopDown), so no unvouched key is decoded (#161), and
 * then BouncyCastle's PKIX builder or validator checks the same links again.
 * This times one link check, X509Certificate.verify(issuerKey, provider), for
 * each link PKIX repeats, and one whole verify call for the same input.
 *
 * Inputs: the public sandbox receipt fixtures/public-receipts/
 * receipt-sandbox-legacy.b64 under the default roots (its path to the anchor
 * is leaf, WWDR, Apple Inc. Root CA: two links), and the synthetic
 * fixtures/generated/transaction.jws under fixtures/generated/jws-root.der
 * (leaf, intermediate, root: two links).
 *
 * Usage: java -cp <library + bcprov/bcutil/bcpkix + jackson-core + this> ChainLinkCost <fixtures dir>
 *
 * The provider is a fresh BouncyCastleProvider, the same class the library
 * holds privately. Each timing warms up, then measures, on one thread.
 */
public final class ChainLinkCost {
    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
    private static final int LINK_WARMUP = 5_000;
    private static final int LINK_CALLS = 20_000;
    private static final int VERIFY_WARMUP = 3_000;
    private static final int VERIFY_CALLS = 3_000;

    public static void main(String[] args) throws Exception {
        Path fixtures = Paths.get(args[0]);
        receipt(fixtures.resolve("public-receipts/receipt-sandbox-legacy.b64"));
        jws(fixtures.resolve("generated/transaction.jws"), fixtures.resolve("generated/jws-root.der"));
    }

    private static void receipt(Path file) throws Exception {
        String base64 = new String(Files.readAllBytes(file), StandardCharsets.US_ASCII).trim();
        CMSSignedData cms = new CMSSignedData(Base64.getDecoder().decode(base64));
        List<X509Certificate> embedded = new ArrayList<>();
        for (Object holder : cms.getCertificates().getMatches(null)) {
            embedded.add(certificate(((X509CertificateHolder) holder).getEncoded()));
        }
        Collection<X509Certificate> roots = Config.defaults().roots();
        X509Certificate leaf = leafOf(embedded);
        X509Certificate wwdr = issuerOf(leaf, embedded);
        X509Certificate root = issuerOf(wwdr, roots);

        Verifier verifier = Verifier.create(Config.defaults());
        VerificationResult<ReceiptPayload> result = verifier.verifyReceipt(base64);
        System.out.println("receipt-sandbox-legacy: verified=" + result.verified() + ", "
                + embedded.size() + " embedded certificates");
        double leafLink = link("leaf <- WWDR", leaf, wwdr);
        double wwdrLink = link("WWDR <- root", wwdr, root);
        double verify = timeVerify(() -> verifier.verifyReceipt(base64).verified());
        report(leafLink + wwdrLink, verify);
    }

    private static void jws(Path file, Path rootFile) throws Exception {
        String jws = new String(Files.readAllBytes(file), StandardCharsets.US_ASCII).trim();
        String header = new String(Base64.getUrlDecoder().decode(jws.substring(0, jws.indexOf('.'))),
                StandardCharsets.UTF_8);
        Matcher entries = Pattern.compile("\"([A-Za-z0-9+/=]+)\"")
                .matcher(header.substring(header.indexOf('[', header.indexOf("\"x5c\""))));
        List<X509Certificate> x5c = new ArrayList<>();
        while (x5c.size() < 3 && entries.find()) {
            x5c.add(certificate(Base64.getDecoder().decode(entries.group(1))));
        }
        X509Certificate root = certificate(Files.readAllBytes(rootFile));
        X509Certificate leaf = x5c.get(0);
        X509Certificate intermediate = x5c.get(1);

        Verifier verifier = Verifier.create(
                Config.builder().roots(Collections.singleton(root)).build());
        VerificationResult<JsonPayload> result = verifier.verifySignedData(jws);
        System.out.println("transaction.jws: verified=" + result.verified() + ", "
                + leaf.getSigAlgName() + " / " + intermediate.getSigAlgName());
        double leafLink = link("leaf <- intermediate", leaf, intermediate);
        double intermediateLink = link("intermediate <- root", intermediate, root);
        double verify = timeVerify(() -> verifier.verifySignedData(jws).verified());
        report(leafLink + intermediateLink, verify);
    }

    /** Milliseconds per {@code certificate.verify(issuer key)}, the check both the walk and PKIX make. */
    private static double link(String name, X509Certificate certificate, X509Certificate issuer) throws Exception {
        for (int i = 0; i < LINK_WARMUP; i++) {
            certificate.verify(issuer.getPublicKey(), PROVIDER);
        }
        long start = System.nanoTime();
        for (int i = 0; i < LINK_CALLS; i++) {
            certificate.verify(issuer.getPublicKey(), PROVIDER);
        }
        double ms = (System.nanoTime() - start) / 1e6 / LINK_CALLS;
        System.out.printf("  link %-22s %s: %.4f ms%n", name, certificate.getSigAlgName(), ms);
        return ms;
    }

    private interface Call {
        boolean verified();
    }

    /** Milliseconds per whole verify call. */
    private static double timeVerify(Call call) {
        for (int i = 0; i < VERIFY_WARMUP; i++) {
            if (!call.verified()) {
                throw new AssertionError("the fixture did not verify");
            }
        }
        long start = System.nanoTime();
        for (int i = 0; i < VERIFY_CALLS; i++) {
            call.verified();
        }
        return (System.nanoTime() - start) / 1e6 / VERIFY_CALLS;
    }

    private static void report(double duplicate, double verify) {
        System.out.printf("  PKIX repeats 2 links: %.3f ms of a %.3f ms verify (%.1f%%)%n",
                duplicate, verify, 100 * duplicate / verify);
    }

    private static X509Certificate certificate(byte[] der) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509", PROVIDER)
                .generateCertificate(new ByteArrayInputStream(der));
    }

    /** The embedded certificate that issued none of the others. */
    private static X509Certificate leafOf(List<X509Certificate> certificates) {
        for (X509Certificate candidate : certificates) {
            boolean issuedAnother = false;
            for (X509Certificate other : certificates) {
                if (other != candidate
                        && other.getIssuerX500Principal().equals(candidate.getSubjectX500Principal())) {
                    issuedAnother = true;
                }
            }
            if (!issuedAnother) {
                return candidate;
            }
        }
        throw new IllegalStateException("no leaf among the embedded certificates");
    }

    private static X509Certificate issuerOf(X509Certificate certificate, Collection<X509Certificate> candidates) {
        for (X509Certificate candidate : candidates) {
            if (candidate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
                return candidate;
            }
        }
        throw new IllegalStateException("no issuer for " + certificate.getSubjectX500Principal());
    }
}
