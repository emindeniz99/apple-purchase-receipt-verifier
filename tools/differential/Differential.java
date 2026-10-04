import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.Failure;
import io.github.emindeniz99.applepurchasereceiptverifier.JsonPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationResult;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The 0.7 Java implementation over a call file, for the differential
 * campaign (DECISIONS.md R33): the Java side of tools/differential.sh.
 *
 * <pre>java -cp &lt;java jar&gt;:&lt;its runtime classpath&gt;:&lt;dir&gt; Differential &lt;calls.jsonl&gt;</pre>
 *
 * <p>A call file has one JSON object per line, the format
 * tools/wasm-trap-host.mjs reads in its {@code calls} mode: {@code id},
 * {@code fn} ({@code verify-receipt}, {@code verify-signed-data},
 * {@code verify-receipt-endpoint}), {@code config} (init's JSON text,
 * {@code {"roots":[base64 DER, ...]}}, or {@code {}} for Apple's
 * roots; an empty list is answered with the module's refusal, as the
 * module answers it), {@code now} (epoch milliseconds), {@code env} (0 production, 1
 * sandbox) and {@code b64} (the input bytes, base64); or {@code id} and
 * {@code map} for a row that makes no call. It prints one row per call on
 * stdout, in the core's wire JSON, so a row compares with the module's:
 * {@code {"id","out"}}; {@code {"id","map"}} when the call cannot be made
 * through the Java API ({@code not-utf8}: Java takes a {@code String},
 * so input bytes that are not UTF-8 have no Java spelling;
 * {@code root-not-a-certificate}: the config's root does not decode); and
 * {@code {"id","threw"}} if the library threw, which its contract says it
 * never does.</p>
 *
 * <p>No verification logic: the roots are decoded only because the Java
 * {@link Config} takes {@link X509Certificate}s.</p>
 */
public final class Differential {

    private static final JsonFactory JSON = new JsonFactory();

    private Differential() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: Differential <calls.jsonl>");
            System.exit(2);
        }
        Map<String, Verifier> verifiers = new HashMap<String, Verifier>();
        Map<String, String> refused = new HashMap<String, String>();
        Writer out = new OutputStreamWriter(System.out, StandardCharsets.UTF_8);
        int rows = 0;
        int threw = 0;
        try (BufferedReader in = Files.newBufferedReader(Paths.get(args[0]), StandardCharsets.UTF_8)) {
            String line;
            while ((line = in.readLine()) != null) {
                if (line.trim().isEmpty()) {
                    continue;
                }
                rows++;
                Map<String, Object> call = flat(line);
                String id = (String) call.get("id");
                Map<String, String> row = new LinkedHashMap<String, String>();
                row.put("id", id);
                if (call.containsKey("map")) {
                    row.put("map", (String) call.get("map"));
                    out.write(object(row));
                    continue;
                }
                String config = (String) call.get("config");
                long now = ((Number) call.get("now")).longValue();
                if (!ROOTS.containsKey(config) && !refused.containsKey(config)) {
                    try {
                        ROOTS.put(config, roots(config));
                    } catch (IllegalArgumentException | java.security.cert.CertificateException e) {
                        refused.put(config, "root-not-a-certificate");
                    }
                }
                if (refused.containsKey(config)) {
                    row.put("map", refused.get(config));
                    out.write(object(row));
                    continue;
                }
                List<X509Certificate> listed = ROOTS.get(config);
                if (listed != null && listed.isEmpty()) {
                    // The module refuses an empty list (R23, Q30); Java's Config
                    // would too, so the row carries the module's answer.
                    row.put("out", "{\"ok\":false,\"message\":\"roots must not be empty\"}");
                    out.write(object(row));
                    continue;
                }
                String input = utf8((String) call.get("b64"));
                if (input == null) {
                    row.put("map", "not-utf8");
                    out.write(object(row));
                    continue;
                }
                // The clock is part of the Config, so the verifier for a
                // config is rebuilt only when the call's instant changes.
                Verifier verifier = at(verifiers, config, now);
                try {
                    row.put("out", call(verifier, (String) call.get("fn"), call.get("env"), input));
                } catch (RuntimeException e) {
                    threw++;
                    row.put("threw", e.toString());
                }
                out.write(object(row));
            }
        }
        out.flush();
        System.err.println("{\"host\":\"java " + System.getProperty("java.version") + "\",\"rows\":" + rows
                + ",\"threw\":" + threw + "}");
        System.exit(threw == 0 ? 0 : 1);
    }

    private static final Map<String, Long> INSTANT = new HashMap<String, Long>();
    private static final Map<String, List<X509Certificate>> ROOTS = new HashMap<String, List<X509Certificate>>();

    private static Verifier at(Map<String, Verifier> verifiers, String config, long now) {
        Long was = INSTANT.get(config);
        if (was != null && was == now) {
            return verifiers.get(config);
        }
        Clock clock = Clock.fixed(Instant.ofEpochMilli(now), ZoneOffset.UTC);
        Config.Builder builder = Config.builder().clock(clock);
        List<X509Certificate> roots = ROOTS.get(config);
        if (roots != null) {
            builder.roots(roots);
        }
        Verifier verifier = Verifier.create(builder.build());
        verifiers.put(config, verifier);
        INSTANT.put(config, now);
        return verifier;
    }

    /** The config's roots: null when the member is absent (Apple's roots), else the list, empty included. */
    private static List<X509Certificate> roots(String config)
            throws IOException, java.security.cert.CertificateException {
        List<X509Certificate> roots = null;
        JsonParser p = JSON.createParser(config);
        p.nextToken();
        while (p.nextToken() == JsonToken.FIELD_NAME) {
            String name = p.currentName();
            p.nextToken();
            if ("roots".equals(name) && p.currentToken() == JsonToken.START_ARRAY) {
                roots = new ArrayList<X509Certificate>();
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                while (p.nextToken() == JsonToken.VALUE_STRING) {
                    byte[] der = Base64.getDecoder().decode(p.getText());
                    roots.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der)));
                }
            } else {
                p.skipChildren();
            }
        }
        return roots;
    }

    private static String call(Verifier verifier, String fn, Object env, String input) throws IOException {
        if ("verify-receipt".equals(fn)) {
            VerificationResult<ReceiptPayload> r = verifier.verifyReceipt(input);
            return r.verified() ? "{\"verified\":true,\"payload\":" + r.payload().toJson() + "}" : failure(r.failure());
        }
        if ("verify-signed-data".equals(fn)) {
            VerificationResult<JsonPayload> r = verifier.verifySignedData(input);
            if (!r.verified()) {
                return failure(r.failure());
            }
            StringWriter w = new StringWriter();
            try (JsonGenerator g = JSON.createGenerator(w)) {
                g.writeStartObject();
                g.writeBooleanField("verified", true);
                g.writeStringField("payload", r.payload().json());
                g.writeEndObject();
            }
            return w.toString();
        }
        if ("verify-receipt-endpoint".equals(fn)) {
            int e = ((Number) env).intValue();
            return verifier.verifyReceiptEndpoint(e == 0 ? Environment.PRODUCTION : Environment.SANDBOX, input);
        }
        throw new IllegalArgumentException("unknown fn " + fn);
    }

    private static String failure(Failure f) throws IOException {
        StringWriter w = new StringWriter();
        try (JsonGenerator g = JSON.createGenerator(w)) {
            g.writeStartObject();
            g.writeBooleanField("verified", false);
            g.writeStringField("reason", f.reason().name());
            g.writeStringField("message", f.message());
            g.writeEndObject();
        }
        return w.toString();
    }

    /** The bytes as a String when they are well-formed UTF-8, else null. */
    private static String utf8(String b64) {
        byte[] bytes = Base64.getDecoder().decode(b64);
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    /** A call row's top-level scalars. */
    private static Map<String, Object> flat(String line) throws IOException {
        Map<String, Object> m = new HashMap<String, Object>();
        JsonParser p = JSON.createParser(line);
        p.nextToken();
        while (p.nextToken() == JsonToken.FIELD_NAME) {
            String name = p.currentName();
            JsonToken t = p.nextToken();
            if (t == JsonToken.VALUE_STRING) {
                m.put(name, p.getText());
            } else if (t == JsonToken.VALUE_NUMBER_INT) {
                m.put(name, p.getLongValue());
            } else {
                p.skipChildren();
            }
        }
        return m;
    }

    private static String object(Map<String, String> row) throws IOException {
        StringWriter w = new StringWriter();
        try (JsonGenerator g = JSON.createGenerator(w)) {
            g.writeStartObject();
            for (Map.Entry<String, String> e : row.entrySet()) {
                g.writeStringField(e.getKey(), e.getValue());
            }
            g.writeEndObject();
        }
        return w + "\n";
    }
}
