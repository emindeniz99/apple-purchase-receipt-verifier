package io.github.emindeniz99.applepurchasereceiptverifier.bench;

import io.github.emindeniz99.applepurchasereceiptverifier.AppleRootCerts;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.VerifyReceiptEndpoint;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

/**
 * Cost of verifying a genuine Apple-signed receipt through each public entry
 * point, and of rejecting one whose signature was tampered with.
 *
 * <p>Every input is prepared in {@link #setUp()}, which also checks that each
 * benchmark gets the answer the conformance suite expects for the fixture, so
 * a benchmark can never time a fast failure by accident.</p>
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(2)
public class ReceiptBenchmark {

    /**
     * Fixture file under fixtures/public-receipts, and the bundle id and
     * in-app count fixtures/cases.json pins for it.
     */
    @Param({"receipt-sandbox-g5", "receipt-sandbox-legacy"})
    public String fixture;

    /** Any fixed instant: it only feeds the endpoint's request_date fields. */
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);

    private Set<X509Certificate> roots;
    private byte[] der;
    private byte[] tamperedDer;
    private String base64;
    private Map<String, Object> request;
    private String requestJson;
    private ReceiptVerifier verifier;
    private VerifyReceiptEndpoint sandboxEndpoint;
    private VerifyReceiptEndpoint productionEndpoint;

    @Setup
    public void setUp() throws Exception {
        String bundleId;
        int inAppCount;
        String sha256;
        if ("receipt-sandbox-g5".equals(fixture)) {
            bundleId = "dev.bonzer.weeka.app";
            inAppCount = 2;
            sha256 = "bebb16e2a17104d973eeef08177003f2c3303a19ddced83b42df349b4ac25ee0";
        } else if ("receipt-sandbox-legacy".equals(fixture)) {
            bundleId = "com.nutcall.alert";
            inAppCount = 187;
            sha256 = "ec62c6bd4a34bd8e56b11e675bf5a28319ce69b71d050e73344bab22f46799a8";
        } else {
            throw new IllegalStateException("unknown fixture " + fixture);
        }

        // Decoded the way ConformanceCasesTest decodes a base64 fixture, and
        // checked against the digest cases.json records for it.
        File file = new File(fixturesDir(), "public-receipts/" + fixture + ".b64");
        String text = new String(Files.readAllBytes(file.toPath()), StandardCharsets.US_ASCII);
        der = Base64.getMimeDecoder().decode(text);
        if (!sha256.equals(hex(MessageDigest.getInstance("SHA-256").digest(der)))) {
            throw new IllegalStateException(fixture + " does not match its contentSha256 in cases.json");
        }
        base64 = Base64.getEncoder().encodeToString(der);
        request = Collections.<String, Object>singletonMap("receipt-data", base64);
        requestJson = "{\"receipt-data\":\"" + base64 + "\"}";
        tamperedDer = flipSignatureByte(der);

        roots = AppleRootCerts.receiptRoots();
        verifier = new ReceiptVerifier(roots, bundleId);
        sandboxEndpoint = new VerifyReceiptEndpoint(roots, Environment.SANDBOX, CLOCK);
        productionEndpoint = new VerifyReceiptEndpoint(roots, Environment.PRODUCTION, CLOCK);

        checkReceipt(ReceiptVerifier.verifyReceiptCore(der, roots), bundleId, inAppCount);
        checkReceipt(verifier.verify(base64), bundleId, inAppCount);
        Map<String, Object> ok = sandboxEndpoint.verifyReceipt(request);
        if (!Integer.valueOf(0).equals(ok.get("status"))) {
            throw new IllegalStateException("endpointMap answered " + ok);
        }
        List<?> inApp = (List<?>) ((Map<?, ?>) ok.get("receipt")).get("in_app");
        if (inApp.size() != inAppCount) {
            throw new IllegalStateException("endpointMap rendered " + inApp.size() + " in_app entries");
        }
        if (!sandboxEndpoint.verifyReceiptJson(requestJson).startsWith("{\"status\":0,")) {
            throw new IllegalStateException("endpointJson did not answer status 0");
        }
        Object wrongEnv = productionEndpoint.verifyReceipt(request).get("status");
        if (!Integer.valueOf(VerifyReceiptEndpoint.STATUS_SANDBOX_RECEIPT_ON_PRODUCTION)
                .equals(wrongEnv)) {
            throw new IllegalStateException("endpointWrongEnv answered " + wrongEnv);
        }
        try {
            ReceiptVerifier.verifyReceiptCore(tamperedDer, roots);
            throw new IllegalStateException("tampered " + fixture + " verified");
        } catch (VerificationException e) {
            if (e.reason() != VerificationException.Reason.INVALID_SIGNATURE) {
                throw new IllegalStateException("tampered " + fixture + " rejected with " + e.reason(), e);
            }
        }
    }

    @Benchmark
    public AppReceipt core() throws VerificationException {
        return ReceiptVerifier.verifyReceiptCore(der, roots);
    }

    @Benchmark
    public AppReceipt verifierBase64() throws VerificationException {
        return verifier.verify(base64);
    }

    @Benchmark
    public Map<String, Object> endpointMap() {
        return sandboxEndpoint.verifyReceipt(request);
    }

    @Benchmark
    public String endpointJson() {
        return sandboxEndpoint.verifyReceiptJson(requestJson);
    }

    @Benchmark
    public Map<String, Object> endpointWrongEnv() {
        return productionEndpoint.verifyReceipt(request);
    }

    @Benchmark
    public void rejectTamperedSignature(Blackhole bh) {
        try {
            bh.consume(ReceiptVerifier.verifyReceiptCore(tamperedDer, roots));
        } catch (VerificationException e) {
            bh.consume(e);
        }
    }

    private static void checkReceipt(AppReceipt receipt, String bundleId, int inAppCount) {
        if (!bundleId.equals(receipt.bundleId()) || receipt.inAppPurchases().size() != inAppCount) {
            throw new IllegalStateException("unexpected receipt " + receipt.bundleId() + " with "
                    + receipt.inAppPurchases().size() + " in-app purchases");
        }
    }

    /**
     * Returns a copy of the receipt with one bit flipped in the middle of its
     * single SignerInfo's signature value. Everything else, including the
     * certificate chain, is untouched, so only the signature check can fail.
     */
    private static byte[] flipSignatureByte(byte[] der) throws CMSException {
        Collection<SignerInformation> signers =
                new CMSSignedData(der).getSignerInfos().getSigners();
        if (signers.size() != 1) {
            throw new IllegalStateException("expected one SignerInfo, found " + signers.size());
        }
        byte[] signature = signers.iterator().next().getSignature();
        int offset = lastIndexOf(der, signature);
        if (offset < 0) {
            throw new IllegalStateException("signature bytes not found in the DER");
        }
        byte[] tampered = der.clone();
        tampered[offset + signature.length / 2] ^= 0x01;
        return tampered;
    }

    private static int lastIndexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = haystack.length - needle.length; i >= 0; i--) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /** Walks up from the working directory to the repository's fixtures/. */
    private static File fixturesDir() throws IOException {
        for (File dir = new File("").getAbsoluteFile(); dir != null; dir = dir.getParentFile()) {
            File candidate = new File(dir, "fixtures/cases.json");
            if (candidate.isFile()) {
                return candidate.getParentFile();
            }
        }
        throw new IOException(
                "no fixtures/cases.json above " + new File("").getAbsolutePath() + "; run from inside the repository");
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
