package io.github.emindeniz99.applepurchasereceiptverifier.bench;

import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.JsonPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationResult;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

/**
 * Cost of {@code verifySignedData} on the shared StoreKit 2 transaction
 * fixture. A class of its own so {@link ReceiptBenchmark}'s receipt
 * parameter does not time the same JWS twice.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(2)
public class SignedDataBenchmark {

    private String jws;
    private Verifier verifier;

    @Setup
    public void setUp() throws Exception {
        File generated = new File(ReceiptBenchmark.fixturesDir(), "generated");
        jws = new String(Files.readAllBytes(new File(generated, "transaction.jws").toPath()), StandardCharsets.US_ASCII)
                .trim();
        X509Certificate root = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(
                        new ByteArrayInputStream(Files.readAllBytes(new File(generated, "jws-root.der").toPath())));
        verifier = Verifier.create(
                Config.builder().roots(Collections.singleton(root)).build());

        JsonPayload payload = verifySignedData().payload();
        if (payload == null || !payload.json().contains("\"transactionId\":\"2000000000000001\"")) {
            throw new IllegalStateException("transaction.jws did not verify: " + verifySignedData());
        }
    }

    @Benchmark
    public VerificationResult<JsonPayload> verifySignedData() {
        return verifier.verifySignedData(jws);
    }
}
