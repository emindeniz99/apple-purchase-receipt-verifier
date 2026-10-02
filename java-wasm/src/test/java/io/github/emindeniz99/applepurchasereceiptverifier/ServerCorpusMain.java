package io.github.emindeniz99.applepurchasereceiptverifier;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Not a test: {@link CorpusMain} through the server engine's managed child,
 * run by {@code scripts/corpus.sh} with a binary. Same calls, same rows: one
 * child per {@code init} configuration (the roots go in the handshake, the
 * empty configuration is the built-in roots), each call one request with the
 * call's clock as {@code X-Aprv-Now-Ms}. A 200 is the module's answer as
 * written, and so is a 413 (a body over the server's cap, whose first
 * 3,145,729 bytes the module answered with its size refusal); a roots
 * refusal at start is the module's {@code init} answer; any other status
 * is a {@code trap} row.
 *
 * <pre>java -cp JAR:TEST_CLASSES:DEPS ...ServerCorpusMain CALLS.jsonl BINARY [THREADS] &gt; OUT.jsonl</pre>
 */
public final class ServerCorpusMain {

    private ServerCorpusMain() {}

    public static void main(String[] args) throws Exception {
        List<JsonNode> calls = new ArrayList<>();
        try (BufferedReader in = Files.newBufferedReader(Paths.get(args[0]), StandardCharsets.UTF_8)) {
            String line;
            while ((line = in.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    calls.add(Cases.MAPPER.readTree(line));
                }
            }
        }
        java.nio.file.Path binary = Paths.get(args[1]);
        int threads = args.length > 2 ? Integer.parseInt(args[2]) : 1;
        String[] rows = new String[calls.size()];
        Map<String, List<Integer>> byConfig = new LinkedHashMap<>();
        for (int i = 0; i < calls.size(); i++) {
            JsonNode c = calls.get(i);
            if (c.has("map")) {
                rows[i] = "{\"id\":" + quote(c.get("id").asText()) + ",\"map\":"
                        + quote(c.get("map").asText()) + "}";
            } else {
                byConfig.computeIfAbsent(c.get("config").asText(), k -> new ArrayList<>())
                        .add(i);
            }
        }
        AtomicInteger overCap = new AtomicInteger();
        AtomicInteger problems = new AtomicInteger();
        int refusals = 0;
        long start = System.nanoTime();
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            for (Map.Entry<String, List<Integer>> group : byConfig.entrySet()) {
                String config = group.getKey();
                ServerConnection connection;
                try {
                    connection = ServerConnection.managed(
                            new ServerProcess(binary, null, config.isEmpty() ? "{}" : config), "corpus");
                } catch (InitRefused e) {
                    refusals++;
                    for (int i : group.getValue()) {
                        rows[i] = "{\"id\":" + quote(calls.get(i).get("id").asText()) + ",\"out\":" + quote(e.answer())
                                + "}";
                    }
                    continue;
                }
                try {
                    List<Future<?>> work = new ArrayList<>();
                    for (int i : group.getValue()) {
                        work.add(pool.submit(() -> {
                            rows[i] = row(connection, calls.get(i), overCap, problems);
                            return null;
                        }));
                    }
                    for (Future<?> f : work) {
                        f.get();
                    }
                } finally {
                    connection.close();
                }
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
        System.err.println("{\"host\":\"java-wasm server\",\"java\":" + Engine.javaFeatureVersion() + ",\"threads\":"
                + threads + ",\"rows\":" + rows.length + ",\"children\":" + byConfig.size() + ",\"init_refused\":"
                + refusals + ",\"over_cap_413\":" + overCap.get() + ",\"problems\":" + problems.get() + ",\"ms\":"
                + millis + "}");
    }

    private static String row(ServerConnection connection, JsonNode c, AtomicInteger overCap, AtomicInteger problems) {
        String id = quote(c.get("id").asText());
        String path;
        switch (c.get("fn").asText()) {
            case "verify-receipt":
                path = "/v1/receipt/verify";
                break;
            case "verify-signed-data":
                path = "/v1/signed-data/verify";
                break;
            default:
                path = c.get("env").asInt() == 0 ? "/v1/verify-receipt/production" : "/v1/verify-receipt/sandbox";
        }
        byte[] input = Base64.getDecoder().decode(c.get("b64").asText());
        Long now = c.get("now").isNull()
                ? System.currentTimeMillis()
                : c.get("now").asLong();
        try {
            ServerConnection.Response response = connection.send("POST", path, input, now);
            if (ServerVerifier.moduleAnswered(response)) {
                if (response.status == 413) {
                    overCap.incrementAndGet();
                }
                return "{\"id\":" + id + ",\"out\":" + quote(response.text()) + "}";
            }
            problems.incrementAndGet();
            return "{\"id\":" + id + ",\"trap\":" + quote("HTTP " + response.status + " " + response.text()) + "}";
        } catch (RuntimeException e) {
            problems.incrementAndGet();
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
