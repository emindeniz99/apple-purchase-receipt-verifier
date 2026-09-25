package aprvj;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.emindeniz99.applepurchasereceiptverifier.AppleRootCerts;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.internal.BouncyCastle;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.InAppPurchase;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.VerifyReceiptEndpoint;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.VerifyReceiptResult;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The mechanical half of the spike's C ABI: plain Java values in, one
 * {@link Result} (a code and a JSON string) out. It builds the library's own
 * verifier objects from an options object and calls their public methods. It
 * holds no verification rule: no ASN.1, CMS, X.509, chain, OID, signature,
 * bundle-id, environment, device-hash or verifyReceipt-status logic lives
 * here. Everything below either converts inputs, converts outputs, or maps an
 * exception to a code.
 *
 * <p>Pure Java 8, no GraalVM dependency, so the same class runs on a JVM as
 * the differential oracle (OracleCli) and inside the native image behind the
 * {@code @CEntryPoint} shims (NativeEntryPoints).
 */
public final class Bridge {

    /** Verified. */
    public static final int OK = 0;
    /** A caller error at the ABI: null pointer, bad options JSON, bad handle kind. */
    public static final int ABI_INVALID_ARGUMENT = -1;
    /** Anything unexpected: a Throwable that is not a VerificationException. Never success. */
    public static final int ABI_INTERNAL = -2;
    /** The library refused its own configuration (IllegalStateException, e.g. a missing root). */
    public static final int ABI_CONFIGURATION = -3;

    public static final int JWS_TRANSACTION = 0;
    public static final int JWS_APP_TRANSACTION = 1;
    public static final int JWS_RAW = 2;

    private static final ObjectMapper JSON = new ObjectMapper();
    /** FIELD visibility, as ConformanceCasesTest normalizes the payload models. */
    private static final ObjectMapper FIELDS =
            new ObjectMapper().setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);

    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<Map<String, Object>>() {};

    private Bridge() {}

    /** One call's answer: {@code code} and a UTF-8 JSON document. */
    public static final class Result {
        public final int code;
        public final String json;

        Result(int code, String json) {
            this.code = code;
            this.json = json;
        }
    }

    // ------------------------------------------------------------ reason codes

    /**
     * Stable wire code per Reason name. Codes 1-10 and 12 are the Rust C ABI's
     * (rust/ffi/include), so a harness can compare the two directly.
     */
    public static int reasonCode(VerificationException.Reason reason) {
        switch (reason.name()) {
            case "INVALID_JWS_FORMAT": return 1;
            case "INVALID_CERTIFICATE": return 2;
            case "INVALID_CERTIFICATE_PURPOSE": return 3;
            case "INVALID_CHAIN": return 4;
            case "INVALID_SIGNATURE": return 5;
            case "WRONG_BUNDLE_ID": return 6;
            case "WRONG_ENVIRONMENT": return 7;
            case "WRONG_APP_APPLE_ID": return 8;
            case "INVALID_RECEIPT_FORMAT": return 9;
            case "DEVICE_HASH_MISMATCH": return 10;
            case "MALFORMED_REQUEST": return 11;
            case "INTERNAL_ERROR": return 12;
            case "REQUEST_TOO_LARGE": return 13;
            default: return ABI_INTERNAL; // a Reason this bridge does not know: never success
        }
    }

    // ----------------------------------------------------------- constructors

    /** Options: {"bundleId": "...", "roots": ["<base64 DER>", ...]}; roots absent = bundled Apple roots. */
    public static ReceiptVerifier newReceiptVerifier(String optionsJson) throws Exception {
        JsonNode options = options(optionsJson);
        Set<X509Certificate> roots = roots(options, false);
        return new ReceiptVerifier(roots, text(options, "bundleId"));
    }

    /** Options: bundleId, acceptedEnvironments ["Production", ...], appAppleId (number), roots. */
    public static JwsVerifier newJwsVerifier(String optionsJson) throws Exception {
        JsonNode options = options(optionsJson);
        Set<X509Certificate> roots = roots(options, true);
        Set<Environment> environments = EnumSet.noneOf(Environment.class);
        JsonNode accepted = options.path("acceptedEnvironments");
        for (JsonNode name : accepted) {
            Environment environment = Environment.fromValue(name.asText());
            if (environment == null) {
                throw new IllegalArgumentException("unknown environment " + name.asText());
            }
            environments.add(environment);
        }
        Long appAppleId = options.hasNonNull("appAppleId") ? Long.valueOf(options.get("appAppleId").asLong()) : null;
        return new JwsVerifier(roots, text(options, "bundleId"), environments, appAppleId);
    }

    /** Options: environment ("Production"|"Sandbox"), roots, nowMillis (fixed clock, optional). */
    public static VerifyReceiptEndpoint newEndpoint(String optionsJson) throws Exception {
        JsonNode options = options(optionsJson);
        Set<X509Certificate> roots = roots(options, false);
        Environment environment = Environment.fromValue(text(options, "environment"));
        Clock clock = options.hasNonNull("nowMillis")
                ? Clock.fixed(Instant.ofEpochMilli(options.get("nowMillis").asLong()), ZoneOffset.UTC)
                : null;
        return new VerifyReceiptEndpoint(roots, environment, clock);
    }

    // ------------------------------------------------------------------ calls

    /** Receipt: DER bytes, or the base64 text when {@code base64}; optional device GUID. */
    public static Result verifyReceipt(Object verifier, byte[] input, boolean base64, byte[] deviceGuid) {
        try {
            ReceiptVerifier receiptVerifier = cast(verifier, ReceiptVerifier.class);
            AppReceipt receipt = base64
                    ? receiptVerifier.verify(new String(input, StandardCharsets.UTF_8), deviceGuid)
                    : receiptVerifier.verify(input, deviceGuid);
            return new Result(OK, JSON.writeValueAsString(normalize(receipt)));
        } catch (Throwable t) {
            return failure(t);
        }
    }

    /** JWS: transaction, app transaction or raw claims, per {@code operation}. */
    public static Result verifyJws(Object verifier, String jws, int operation) {
        try {
            JwsVerifier jwsVerifier = cast(verifier, JwsVerifier.class);
            Object payload;
            if (operation == JWS_TRANSACTION) {
                payload = FIELDS.convertValue(jwsVerifier.verifyTransaction(jws), MAP);
            } else if (operation == JWS_APP_TRANSACTION) {
                payload = FIELDS.convertValue(jwsVerifier.verifyAppTransaction(jws), MAP);
            } else if (operation == JWS_RAW) {
                payload = jwsVerifier.verifyRaw(jws);
            } else {
                throw new IllegalArgumentException("unknown JWS operation " + operation);
            }
            return new Result(OK, JSON.writeValueAsString(payload));
        } catch (Throwable t) {
            return failure(t);
        }
    }

    /**
     * The verifyReceipt endpoint: Apple's request JSON in, Apple's response
     * JSON out. {@code code} is the result's failureReason code (0 when it
     * has none), which is not on Apple's wire; the verdict is the JSON's
     * {@code status}.
     */
    public static Result verifyReceiptJson(Object endpoint, String requestJson) {
        try {
            VerifyReceiptResult result = cast(endpoint, VerifyReceiptEndpoint.class).verifyReceiptResult(requestJson);
            int code = result.failureReason() == null ? OK : reasonCode(result.failureReason());
            return new Result(code, result.toJson());
        } catch (Throwable t) {
            return failure(t);
        }
    }

    /** SHA-256 of each bundled root, as AppleRootCerts loads and pins them. */
    public static Result selfCheck() {
        try {
            Map<String, Object> out = new LinkedHashMap<String, Object>();
            List<String> digests = new ArrayList<String>();
            for (X509Certificate root : AppleRootCerts.receiptRoots()) {
                digests.add(hex(MessageDigest.getInstance("SHA-256").digest(root.getEncoded())));
            }
            out.put("receiptRootsSha256", digests);
            out.put("jwsRoots", Integer.valueOf(AppleRootCerts.jwsRoots().size()));
            out.put("bouncyCastle", BouncyCastle.PROVIDER.getInfo());
            out.put("javaVersion", System.getProperty("java.version"));
            out.put("vm", System.getProperty("java.vm.name"));
            return new Result(OK, JSON.writeValueAsString(out));
        } catch (Throwable t) {
            return failure(t);
        }
    }

    // ------------------------------------------------------------ exceptions

    /**
     * Every Throwable becomes a non-zero code with a JSON body. Only
     * VerificationException carries a verdict; everything else is an ABI or
     * internal code, so an unexpected failure can never read as success.
     */
    public static Result failure(Throwable t) {
        int code;
        String reason;
        if (t instanceof VerificationException) {
            VerificationException e = (VerificationException) t;
            code = reasonCode(e.reason());
            reason = e.reason().name();
        } else if (t instanceof IllegalArgumentException || t instanceof ClassCastException) {
            code = ABI_INVALID_ARGUMENT;
            reason = "ABI_INVALID_ARGUMENT";
        } else if (t instanceof IllegalStateException) {
            code = ABI_CONFIGURATION;
            reason = "ABI_CONFIGURATION";
        } else {
            code = ABI_INTERNAL;
            reason = "ABI_INTERNAL";
        }
        return new Result(code, errorJson(reason, t));
    }

    public static String errorJson(String reason, Throwable t) {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("reason", reason);
        out.put("exception", t.getClass().getName());
        out.put("message", String.valueOf(t.getMessage()));
        try {
            return JSON.writeValueAsString(out);
        } catch (Throwable ignored) {
            // Hand-built fallback: the error path must not fail itself.
            return "{\"reason\":\"" + reason + "\"}";
        }
    }

    // --------------------------------------------------------------- helpers

    private static <T> T cast(Object value, Class<T> type) {
        if (!type.isInstance(value)) {
            throw new IllegalArgumentException(
                    "handle is not a " + type.getSimpleName() + ": " + (value == null ? "null" : value.getClass().getName()));
        }
        return type.cast(value);
    }

    private static JsonNode options(String optionsJson) throws Exception {
        if (optionsJson == null) {
            throw new IllegalArgumentException("options JSON is null");
        }
        JsonNode node;
        try {
            node = JSON.readTree(optionsJson);
        } catch (Exception e) {
            throw new IllegalArgumentException("options are not JSON: " + e.getMessage(), e);
        }
        if (node == null || !node.isObject()) {
            throw new IllegalArgumentException("options must be a JSON object");
        }
        return node;
    }

    private static String text(JsonNode options, String name) {
        JsonNode value = options.get(name);
        return value == null || value.isNull() ? null : value.asText();
    }

    /**
     * Custom roots are decoded by the JDK's default X.509 factory, exactly as
     * ConformanceCasesTest does; absent means the library's bundled roots.
     */
    private static Set<X509Certificate> roots(JsonNode options, boolean jws) throws Exception {
        JsonNode roots = options.get("roots");
        if (roots == null || roots.isNull()) {
            return jws ? AppleRootCerts.jwsRoots() : AppleRootCerts.receiptRoots();
        }
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Set<X509Certificate> out = new LinkedHashSet<X509Certificate>();
        for (JsonNode der : roots) {
            try {
                out.add((X509Certificate) factory.generateCertificate(
                        new ByteArrayInputStream(Base64.getDecoder().decode(der.asText()))));
            } catch (Exception e) {
                throw new IllegalArgumentException("a root in options.roots is not a certificate: " + e.getMessage(), e);
            }
        }
        return out;
    }

    /** The receipt model onto cases.json's shared names; a copy of ConformanceCasesTest.normalize. */
    private static Map<String, Object> normalize(AppReceipt receipt) {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("receiptType", receipt.receiptType());
        out.put("bundleId", receipt.bundleId());
        out.put("appVersion", receipt.appVersion());
        out.put("originalAppVersion", receipt.originalAppVersion());
        out.put("creationDate", iso(receipt.creationDate()));
        out.put("originalPurchaseDate", iso(receipt.originalPurchaseDate()));
        out.put("expirationDate", iso(receipt.expirationDate()));
        out.put("appItemId", receipt.appItemId());
        out.put("downloadId", receipt.downloadId());
        out.put("versionExternalIdentifier", receipt.versionExternalIdentifier());
        out.put("opaqueValueHex", hex(receipt.opaqueValue()));
        out.put("sha1HashHex", hex(receipt.sha1Hash()));
        List<Object> purchases = new ArrayList<Object>();
        for (InAppPurchase purchase : receipt.inAppPurchases()) {
            Map<String, Object> p = new LinkedHashMap<String, Object>();
            p.put("quantity", purchase.quantity());
            p.put("productId", purchase.productId());
            p.put("transactionId", purchase.transactionId());
            p.put("originalTransactionId", purchase.originalTransactionId());
            p.put("purchaseDate", iso(purchase.purchaseDate()));
            p.put("originalPurchaseDate", iso(purchase.originalPurchaseDate()));
            p.put("expiresDate", iso(purchase.expiresDate()));
            p.put("cancellationDate", iso(purchase.cancellationDate()));
            p.put("webOrderLineItemId", purchase.webOrderLineItemId());
            p.put("isTrialPeriod", purchase.isTrialPeriod());
            p.put("isInIntroOfferPeriod", purchase.isInIntroOfferPeriod());
            p.put("unknownAttributes", unknownAttributes(purchase.unknownAttributes()));
            purchases.add(p);
        }
        out.put("inAppPurchases", purchases);
        out.put("unknownAttributes", unknownAttributes(receipt.unknownAttributes()));
        return out;
    }

    private static Map<String, Object> unknownAttributes(Map<Integer, List<byte[]>> attributes) {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        for (Map.Entry<Integer, List<byte[]>> entry : attributes.entrySet()) {
            List<Object> values = new ArrayList<Object>();
            for (byte[] value : entry.getValue()) {
                values.add(hex(value));
            }
            out.put(String.valueOf(entry.getKey()), values);
        }
        return out;
    }

    private static String iso(Instant instant) {
        return instant == null ? null : instant.toString();
    }

    static String hex(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b >> 4) & 0xf, 16));
            out.append(Character.forDigit(b & 0xf, 16));
        }
        return out.toString();
    }
}
