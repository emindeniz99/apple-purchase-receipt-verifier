import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import io.github.emindeniz99.applepurchasereceiptverifier.Config;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.Failure;
import io.github.emindeniz99.applepurchasereceiptverifier.JsonPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.RevokedCertificate;
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
 * {@code verify-receipt-endpoint}, {@code build-config}), {@code config}
 * (init's JSON text: {@code roots}, base64 DER certificates, or none for
 * Apple's roots; {@code revocation_lists}, base64 CRL files;
 * {@code revocation_issuers}, base64 DER certificates; {@code distrust},
 * {@code {"issuer","serial"}} objects; {@code {}} for none of them),
 * {@code now} (epoch milliseconds), {@code env} (0 production, 1 sandbox)
 * and {@code b64} (the input bytes, base64; {@code build-config} reads
 * none); or {@code id} and {@code map} for a row that makes no call. An
 * empty roots list is answered with the module's refusal, as the module
 * answers it, and so is a configuration {@link Verifier#create} refuses:
 * {@code {"ok":false,"message":...}}. It prints one row per call on stdout,
 * in the core's wire JSON, so a row compares with the module's:
 * {@code {"id","out"}}; {@code {"id","map"}} when the call cannot be made
 * through the Java API ({@code not-utf8}: Java takes a {@code String}, so
 * input bytes that are not UTF-8 have no Java spelling;
 * {@code root-not-a-certificate} and {@code issuer-not-a-certificate}: a
 * root or an added issuer of the config does not decode); and
 * {@code {"id","threw"}} if the library threw, which its contract says it
 * never does.</p>
 *
 * <p>A {@code build-config} call builds the verifier and answers what the
 * configuration states about revocation, as the module's init does, minus
 * the input cap Java has no counterpart for:
 * {@code {"ok":true,"revocation_urls":[...],"revocation_valid_until_ms":N|null}}.
 * A refusal's message is not compared (docs/design/revocation.md section
 * 4).</p>
 *
 * <p>No verification logic: the certificates are decoded only because the
 * Java {@link Config} takes {@link X509Certificate}s.</p>
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
                String fn = (String) call.get("fn");
                long now = ((Number) call.get("now")).longValue();
                if (!SETTINGS.containsKey(config) && !refused.containsKey(config)) {
                    try {
                        SETTINGS.put(config, settings(config));
                    } catch (NotACertificate e) {
                        refused.put(config, e.map);
                    }
                }
                if (refused.containsKey(config)) {
                    row.put("map", refused.get(config));
                    out.write(object(row));
                    continue;
                }
                List<X509Certificate> listed = SETTINGS.get(config).roots;
                if (listed != null && listed.isEmpty()) {
                    // The module refuses an empty list (R23, Q30); Java's Config
                    // would too, so the row carries the module's answer.
                    row.put("out", "{\"ok\":false,\"message\":\"roots must not be empty\"}");
                    out.write(object(row));
                    continue;
                }
                boolean build = "build-config".equals(fn);
                String input = build ? "" : utf8((String) call.get("b64"));
                if (input == null) {
                    row.put("map", "not-utf8");
                    out.write(object(row));
                    continue;
                }
                // The clock is part of the Config, so the verifier for a
                // config is rebuilt only when the call's instant changes.
                Verifier verifier;
                try {
                    verifier = at(verifiers, config, now);
                } catch (IllegalArgumentException e) {
                    // Verifier.create refuses the configuration, as its
                    // documentation says: the answer the module's init gives.
                    row.put("out", refusal(e.getMessage()));
                    out.write(object(row));
                    continue;
                }
                try {
                    row.put("out", build ? built(verifier) : call(verifier, fn, call.get("env"), input));
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
    private static final Map<String, Settings> SETTINGS = new HashMap<String, Settings>();

    /** What a call's config JSON states, decoded for {@link Config}. */
    private static final class Settings {
        /** The roots: null when the member is absent (Apple's roots), else the list, empty included. */
        List<X509Certificate> roots;

        final List<byte[]> lists = new ArrayList<byte[]>();
        final List<X509Certificate> issuers = new ArrayList<X509Certificate>();
        final List<RevokedCertificate> distrust = new ArrayList<RevokedCertificate>();
    }

    /** A root or an added issuer that is no certificate; {@code map} is the row's answer. */
    private static final class NotACertificate extends Exception {
        private static final long serialVersionUID = 1L;
        final String map;

        NotACertificate(String map) {
            super(map);
            this.map = map;
        }
    }

    private static Verifier at(Map<String, Verifier> verifiers, String config, long now) {
        Long was = INSTANT.get(config);
        if (was != null && was == now) {
            return verifiers.get(config);
        }
        Clock clock = Clock.fixed(Instant.ofEpochMilli(now), ZoneOffset.UTC);
        Config.Builder builder = Config.builder().clock(clock);
        Settings settings = SETTINGS.get(config);
        if (settings.roots != null) {
            builder.roots(settings.roots);
        }
        if (!settings.lists.isEmpty()) {
            builder.revocationLists(settings.lists);
        }
        if (!settings.issuers.isEmpty()) {
            builder.revocationIssuers(settings.issuers);
        }
        if (!settings.distrust.isEmpty()) {
            builder.distrust(settings.distrust);
        }
        Verifier verifier = Verifier.create(builder.build());
        verifiers.put(config, verifier);
        INSTANT.put(config, now);
        return verifier;
    }

    /** The config's roots, revocation lists, added issuers and distrust entries; see {@link Settings}. */
    private static Settings settings(String config)
            throws NotACertificate, IOException, java.security.cert.CertificateException {
        Settings settings = new Settings();
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        JsonParser p = JSON.createParser(config);
        p.nextToken();
        while (p.nextToken() == JsonToken.FIELD_NAME) {
            String name = p.currentName();
            p.nextToken();
            boolean array = p.currentToken() == JsonToken.START_ARRAY;
            if ("roots".equals(name) && array) {
                settings.roots = new ArrayList<X509Certificate>();
                for (String text : strings(p)) {
                    settings.roots.add(certificate(factory, text, "root-not-a-certificate"));
                }
            } else if ("revocation_lists".equals(name) && array) {
                for (String text : strings(p)) {
                    settings.lists.add(Base64.getDecoder().decode(text));
                }
            } else if ("revocation_issuers".equals(name) && array) {
                for (String text : strings(p)) {
                    settings.issuers.add(certificate(factory, text, "issuer-not-a-certificate"));
                }
            } else if ("distrust".equals(name) && array) {
                while (p.nextToken() == JsonToken.START_OBJECT) {
                    String issuer = null;
                    String serial = null;
                    while (p.nextToken() == JsonToken.FIELD_NAME) {
                        String key = p.currentName();
                        p.nextToken();
                        if ("issuer".equals(key)) {
                            issuer = p.getText();
                        } else if ("serial".equals(key)) {
                            serial = p.getText();
                        } else {
                            p.skipChildren();
                        }
                    }
                    settings.distrust.add(new RevokedCertificate(issuer, serial));
                }
            } else {
                p.skipChildren();
            }
        }
        return settings;
    }

    /** The string elements of the array the parser has just entered. */
    private static List<String> strings(JsonParser p) throws IOException {
        List<String> texts = new ArrayList<String>();
        while (p.nextToken() == JsonToken.VALUE_STRING) {
            texts.add(p.getText());
        }
        return texts;
    }

    private static X509Certificate certificate(CertificateFactory factory, String base64, String map)
            throws NotACertificate {
        try {
            byte[] der = Base64.getDecoder().decode(base64);
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
        } catch (IllegalArgumentException | java.security.cert.CertificateException e) {
            throw new NotACertificate(map);
        }
    }

    /** A build-config call's answer: what the verifier states about revocation. */
    private static String built(Verifier verifier) throws IOException {
        StringWriter w = new StringWriter();
        try (JsonGenerator g = JSON.createGenerator(w)) {
            g.writeStartObject();
            g.writeBooleanField("ok", true);
            g.writeArrayFieldStart("revocation_urls");
            for (String url : verifier.revocationUrls()) {
                g.writeString(url);
            }
            g.writeEndArray();
            Instant until = verifier.revocationValidUntil();
            if (until == null) {
                g.writeNullField("revocation_valid_until_ms");
            } else {
                g.writeNumberField("revocation_valid_until_ms", until.toEpochMilli());
            }
            g.writeEndObject();
        }
        return w.toString();
    }

    /** The module's init answer to a configuration it refuses. */
    private static String refusal(String message) throws IOException {
        StringWriter w = new StringWriter();
        try (JsonGenerator g = JSON.createGenerator(w)) {
            g.writeStartObject();
            g.writeBooleanField("ok", false);
            g.writeStringField("message", message == null ? "" : message);
            g.writeEndObject();
        }
        return w.toString();
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
