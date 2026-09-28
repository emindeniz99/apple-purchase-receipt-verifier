package io.github.emindeniz99.applepurchasereceiptverifier.bench;

import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.Failure;
import io.github.emindeniz99.applepurchasereceiptverifier.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationResult;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;
import java.io.File;
import java.io.IOException;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
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

    /**
     * The library's own receipt-data decoder, {@code ReceiptBase64.decode},
     * which is package-private. Bound once by reflection so the cross-port
     * {@code decodeBase64} benchmark (BENCHMARKS.md) can time it alone; a
     * static final handle costs nothing per call once compiled.
     */
    private static final MethodHandle DECODE = decodeHandle();

    private byte[] der;
    private String base64;
    private String tamperedBase64;
    private String requestJson;
    private Verifier verifier;

    @Setup
    public void setUp() throws Throwable {
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
        requestJson = "{\"receipt-data\":\"" + base64 + "\"}";
        tamperedBase64 = Base64.getEncoder().encodeToString(flipSignatureByte(der));

        // The built-in Apple roots; the fixed clock only reaches request_date.
        verifier = Verifier.create(
                Config.builder().roots(Config.defaults().roots()).clock(CLOCK).build());

        if (!Arrays.equals(decodeBase64(), der)) {
            throw new IllegalStateException("decodeBase64 did not return the fixture's DER");
        }
        checkReceipt(verifyReceipt(), bundleId, inAppCount);
        String ok = endpointJson();
        if (!ok.startsWith("{\"status\":0,\"environment\":\"Sandbox\",")) {
            throw new IllegalStateException("endpointJson did not answer status 0 for Sandbox");
        }
        int rendered = count(ok, "\"transaction_id\":");
        if (rendered != inAppCount) {
            throw new IllegalStateException("endpointJson rendered " + rendered + " in_app entries");
        }
        String wrongEnv = endpointWrongEnv();
        if (!wrongEnv.equals("{\"status\":21007}")) {
            throw new IllegalStateException("endpointWrongEnv answered " + wrongEnv);
        }
        Failure failure = rejectTamperedSignature().failure();
        if (failure == null || failure.reason() != Reason.INVALID_SIGNATURE) {
            throw new IllegalStateException("tampered " + fixture + " answered " + failure);
        }
    }

    @Benchmark
    public byte[] decodeBase64() throws Throwable {
        return (byte[]) DECODE.invokeExact(base64);
    }

    @Benchmark
    public VerificationResult<ReceiptPayload> verifyReceipt() {
        return verifier.verifyReceipt(base64);
    }

    @Benchmark
    public String endpointJson() {
        return verifier.verifyReceiptEndpoint(Environment.SANDBOX, requestJson);
    }

    @Benchmark
    public String endpointWrongEnv() {
        return verifier.verifyReceiptEndpoint(Environment.PRODUCTION, requestJson);
    }

    @Benchmark
    public VerificationResult<ReceiptPayload> rejectTamperedSignature() {
        return verifier.verifyReceipt(tamperedBase64);
    }

    private static void checkReceipt(VerificationResult<ReceiptPayload> result, String bundleId, int inAppCount) {
        ReceiptPayload receipt = result.payload();
        if (receipt == null) {
            throw new IllegalStateException("receipt did not verify: " + result.failure());
        }
        if (!bundleId.equals(receipt.bundleId()) || receipt.inApp().size() != inAppCount) {
            throw new IllegalStateException("unexpected receipt " + receipt.bundleId() + " with "
                    + receipt.inApp().size() + " in-app purchases");
        }
    }

    private static int count(String haystack, String needle) {
        int n = 0;
        for (int i = haystack.indexOf(needle); i >= 0; i = haystack.indexOf(needle, i + needle.length())) {
            n++;
        }
        return n;
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

    private static MethodHandle decodeHandle() {
        try {
            Method decode = Class.forName("io.github.emindeniz99.applepurchasereceiptverifier.ReceiptBase64")
                    .getDeclaredMethod("decode", String.class);
            decode.setAccessible(true);
            return MethodHandles.lookup().unreflect(decode);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("ReceiptBase64.decode(String) is not where this expects it", e);
        }
    }

    /** Walks up from the working directory to the repository's fixtures/. */
    static File fixturesDir() throws IOException {
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
