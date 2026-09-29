package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Not a test: the corpus runner of MIGRATION step 3.7, run against the built
 * jar by {@code scripts/corpus.sh}. It reads a calls file in round 13's
 * mapping (docs/evidence/2026-09-29-canonical-abi-final/py/calls_bytes.py:
 * {@code {"id","fn","env","config","now","b64"}}, or {@code {"id","map"}})
 * and writes one row per call in the Node runner's format: {@code {"id","out"}},
 * {@code {"id","trap"}} or {@code {"id","map"}}, in input order.
 *
 * <p>Each worker thread keeps one instance per {@code init} configuration,
 * {@code init}s it once, and discards it after a trap, which is the pool's
 * rule; the rows are dealt round-robin to the threads, so N threads must
 * give the single-thread rows.</p>
 *
 * <pre>java -cp JAR:TEST_CLASSES:DEPS ...CorpusMain CALLS.jsonl [THREADS] &gt; OUT.jsonl</pre>
 */
public final class CorpusMain {

    private CorpusMain() {}

    public static void main(String[] args) throws Exception {
        List<String> lines = new ArrayList<>();
        try (BufferedReader in = Files.newBufferedReader(Paths.get(args[0]), StandardCharsets.UTF_8)) {
            String line;
            while ((line = in.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    lines.add(line);
                }
            }
        }
        int threads = args.length > 1 ? Integer.parseInt(args[1]) : 1;
        String[] rows = new String[lines.size()];
        long[] traps = new long[threads];
        long[] created = new long[threads];
        long start = System.nanoTime();
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<?>> workers = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                int worker = t;
                workers.add(pool.submit(() -> {
                    Map<String, EndiveGuest> instances = new HashMap<>();
                    for (int i = worker; i < lines.size(); i += threads) {
                        rows[i] = row(lines.get(i), instances, traps, created, worker);
                    }
                    return null;
                }));
            }
            for (Future<?> worker : workers) {
                worker.get();
            }
        } finally {
            pool.shutdown();
        }
        long millis = (System.nanoTime() - start) / 1_000_000;
        try (BufferedWriter out =
                new BufferedWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8), 1 << 20)) {
            for (String row : rows) {
                out.write(row);
                out.write('\n');
            }
        }
        long trapped = 0;
        long made = 0;
        for (int t = 0; t < threads; t++) {
            trapped += traps[t];
            made += created[t];
        }
        System.err.println("{\"host\":\"java-wasm endive\",\"java\":" + Engine.javaFeatureVersion() + ",\"threads\":"
                + threads + ",\"rows\":" + rows.length + ",\"traps\":" + trapped + ",\"instances\":" + made
                + ",\"ms\":" + millis + "}");
    }

    private static String row(
            String line, Map<String, EndiveGuest> instances, long[] traps, long[] created, int worker) {
        JsonNode c;
        try {
            c = Cases.MAPPER.readTree(line);
        } catch (Exception e) {
            throw new IllegalStateException("not a calls row", e);
        }
        String id = quote(c.get("id").asText());
        if (c.has("map")) {
            return "{\"id\":" + id + ",\"map\":" + quote(c.get("map").asText()) + "}";
        }
        String config = c.get("config").asText();
        EndiveGuest guest = instances.get(config);
        String answer = null;
        if (guest == null) {
            guest = new EndiveGuest(new SecureRandom());
            created[worker]++;
            String ok = guest.init(config.getBytes(StandardCharsets.UTF_8));
            if (ok.equals("{\"ok\":true}")) {
                instances.put(config, guest);
            } else {
                answer = ok; // init refused the configuration: that is the row's answer
            }
        }
        long now = c.get("now").isNull()
                ? System.currentTimeMillis()
                : c.get("now").asLong();
        byte[] input = Base64.getDecoder().decode(c.get("b64").asText());
        try {
            if (answer == null) {
                switch (c.get("fn").asText()) {
                    case "verify-receipt":
                        answer = guest.verifyReceipt(now, input);
                        break;
                    case "verify-signed-data":
                        answer = guest.verifySignedData(now, input);
                        break;
                    default:
                        answer = guest.verifyReceiptEndpoint(c.get("env").asInt(), now, input);
                }
            }
            return "{\"id\":" + id + ",\"out\":" + quote(answer) + "}";
        } catch (RuntimeException e) {
            traps[worker]++;
            instances.remove(config);
            return "{\"id\":" + id + ",\"trap\":" + quote(String.valueOf(e.getMessage())) + "}";
        }
    }

    private static String quote(String text) {
        try {
            return Cases.MAPPER.writeValueAsString(text);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
