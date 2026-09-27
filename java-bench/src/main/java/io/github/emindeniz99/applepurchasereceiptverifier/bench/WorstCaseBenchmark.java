package io.github.emindeniz99.applepurchasereceiptverifier.bench;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.Failure;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationResult;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;
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
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.CommandLineOptions;
import org.openjdk.jmh.runner.options.OptionsBuilder;

/**
 * Cost of every shared case in fixtures/cases.json that carries a
 * {@code maxMillis} budget: the hostile inputs (oversized untrusted keys,
 * certificate meshes, encoding oddities inside certificates) the shared suite
 * bounds in time. The README's worst-case CPU figure comes from this class.
 *
 * <p>{@link #main} reads the budgeted case ids from cases.json and runs one
 * JMH benchmark per id, so the list is never copied here:</p>
 *
 * <pre>
 * java -cp java-bench/target/benchmarks.jar \
 *     io.github.emindeniz99.applepurchasereceiptverifier.bench.WorstCaseBenchmark
 * </pre>
 *
 * <p>Any JMH option may follow ({@code -rf json}, {@code -f 2}, ...).
 * {@link #setUp()} runs the case once and requires the answer it expects.</p>
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
public class WorstCaseBenchmark {

    /** A budgeted case id; {@link #main} supplies every one. */
    @Param({})
    public String caseId;

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);

    private Verifier verifier;
    private String operation;
    private String input;

    public static void main(String[] args) throws Exception {
        List<String> ids = new ArrayList<>();
        for (JsonNode kase : cases().get("cases")) {
            if (kase.has("maxMillis")) {
                ids.add(kase.get("id").asText());
            }
        }
        new Runner(new OptionsBuilder()
                        .parent(new CommandLineOptions(args))
                        .include(WorstCaseBenchmark.class.getName() + ".call")
                        .param("caseId", ids.toArray(new String[0]))
                        .build())
                .run();
    }

    @Setup
    public void setUp() throws Exception {
        JsonNode file = cases();
        JsonNode registry = file.get("fixtures");
        JsonNode kase = null;
        for (JsonNode candidate : file.get("cases")) {
            if (caseId.equals(candidate.get("id").asText())) {
                kase = candidate;
            }
        }
        if (kase == null || !kase.has("maxMillis")) {
            throw new IllegalStateException(caseId + " is not a budgeted case in cases.json");
        }

        Config.Builder config =
                Config.builder().roots(Config.defaults().roots()).clock(CLOCK);
        JsonNode trusted = kase.get("config").get("trustedRoots");
        if ("fixtures".equals(trusted.get("source").asText())) {
            List<X509Certificate> roots = new ArrayList<>();
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (JsonNode id : trusted.get("fixtures")) {
                roots.add((X509Certificate)
                        factory.generateCertificate(new ByteArrayInputStream(fixtureBytes(registry, id.asText()))));
            }
            config.roots(roots);
        }
        verifier = Verifier.create(config.build());

        String fixture = kase.get("input").get("fixture").asText();
        byte[] bytes = fixtureBytes(registry, fixture);
        String codec = registry.get(fixture).get("codec").asText();
        operation = kase.get("operation").asText();
        if ("verifyReceipt".equals(operation) && ("raw".equals(codec) || "base64".equals(codec))) {
            input = Base64.getEncoder().encodeToString(bytes);
        } else if ("verifyReceipt".equals(operation) || "verifySignedData".equals(operation)) {
            input = new String(bytes, StandardCharsets.UTF_8);
        } else {
            throw new IllegalStateException(caseId + ": no adapter for operation " + operation);
        }

        // The answer the case expects, before anything is timed.
        Failure failure = call().failure();
        String outcome = failure == null ? "ok" : failure.reason().name();
        JsonNode expected = kase.get("expected");
        boolean matches = false;
        if (expected.has("oneOf")) {
            for (JsonNode allowed : expected.get("oneOf")) {
                matches |= outcome.equals(allowed.asText());
            }
        } else {
            String want = "ok".equals(expected.get("status").asText())
                    ? "ok"
                    : expected.get("reason").asText();
            matches = outcome.equals(want);
        }
        if (!matches) {
            throw new IllegalStateException(caseId + " answered " + outcome);
        }
    }

    @Benchmark
    public VerificationResult<?> call() {
        return "verifyReceipt".equals(operation) ? verifier.verifyReceipt(input) : verifier.verifySignedData(input);
    }

    private static JsonNode cases() throws Exception {
        return new ObjectMapper().readTree(new File(ReceiptBenchmark.fixturesDir(), "cases.json"));
    }

    /** A registered fixture's logical bytes, per its codec, as ConformanceCasesTest decodes them. */
    private static byte[] fixtureBytes(JsonNode registry, String id) throws Exception {
        JsonNode entry = registry.get(id);
        byte[] stored = Files.readAllBytes(
                new File(ReceiptBenchmark.fixturesDir(), entry.get("path").asText()).toPath());
        String codec = entry.get("codec").asText();
        if ("raw".equals(codec) || "text".equals(codec)) {
            return stored;
        }
        String text = new String(stored, StandardCharsets.UTF_8).trim();
        if ("base64".equals(codec)) {
            return Base64.getMimeDecoder().decode(text);
        }
        if ("utf8".equals(codec)) {
            return text.getBytes(StandardCharsets.UTF_8);
        }
        throw new IllegalStateException("fixture " + id + " has codec " + codec);
    }
}
