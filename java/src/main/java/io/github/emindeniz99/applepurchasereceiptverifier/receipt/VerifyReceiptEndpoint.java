package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Drop-in local replacement for Apple's deprecated {@code verifyReceipt}
 * endpoint: same request body, same response body shape, same status codes —
 * but verified offline against the pinned Apple root instead of by calling
 * Apple. Field-by-field fidelity and the unavoidable gaps (fields that only
 * exist in Apple's server-side subscription database, like
 * {@code latest_receipt_info} / {@code pending_renewal_info}) are documented
 * in COMPARISON.md.
 *
 * <p>Like Apple's endpoint, this does NOT check the bundle id — the caller
 * compares {@code receipt.bundle_id}, exactly as with the real endpoint.</p>
 *
 * <p>Thread-safe once constructed: every instance field is final, the anchor
 * set is copied at construction and never handed out, both methods keep their
 * per-call state in locals, and the one object they share is a configured
 * Jackson {@link ObjectMapper}, which Jackson documents as safe to use from
 * many threads. One instance can serve every request of a process (a
 * singleton bean, for example) rather than one per request.</p>
 */
public final class VerifyReceiptEndpoint {

    public static final int STATUS_OK = 0;
    /** Malformed request or receipt-data property. */
    public static final int STATUS_MALFORMED = 21002;
    /** Receipt could not be authenticated. */
    public static final int STATUS_NOT_AUTHENTICATED = 21003;
    /** Sandbox receipt sent to the production environment. */
    public static final int STATUS_SANDBOX_RECEIPT_ON_PRODUCTION = 21007;
    /** Production receipt sent to the sandbox environment. */
    public static final int STATUS_PRODUCTION_RECEIPT_ON_SANDBOX = 21008;
    /** Internal error. */
    public static final int STATUS_INTERNAL = 21009;

    /**
     * Ceiling on the raw request body {@link #verifyReceiptJson(String)} will
     * parse, in characters.
     *
     * <p>"Neither method ever throws" is a promise about exceptions, and heap
     * exhaustion is not one: it is an {@link OutOfMemoryError}, so the caller
     * gets no body at all and the promise stops holding on exactly the hostile
     * input it exists for. JSON parsing allocates a multiple of the body, and
     * that happens before any verification.
     *
     * <p>The number is the php port's {@code MAX_REQUEST_BYTES}, and it is
     * deliberately below {@link ReceiptVerifier#MAX_RECEIPT_BYTES}: the JSON
     * entry point has an amplification the pre-decoded {@link
     * #verifyReceipt(Map)} entry point does not. A 1 MiB body carries any real
     * request with room to spare; the largest genuine receipt in the shared
     * corpus is 106 KB of base64.
     */
    public static final int MAX_REQUEST_BYTES = 1048576;

    /**
     * How deep a JSON structure the request body may nest. Stated rather than
     * inherited: Jackson 2.15 and later default to 1000, but a host BOM that
     * pins an older Jackson 2 links cleanly and silently loses the guard. A
     * verifyReceipt body is a flat object of strings.
     */
    private static final int MAX_JSON_NESTING_DEPTH = 64;

    // Locale.ROOT pinned so a JVM default locale can never reach the
    // rendering, matching node (en-CA) and swift (en_US_POSIX).
    private static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withLocale(Locale.ROOT);
    private static final ObjectMapper MAPPER = new ObjectMapper(JsonFactory.builder()
            .streamReadConstraints(StreamReadConstraints.builder()
                    .maxNestingDepth(MAX_JSON_NESTING_DEPTH)
                    // Nothing inside the body can be larger than the body, so
                    // both length bounds are MAX_REQUEST_BYTES.
                    .maxStringLength(MAX_REQUEST_BYTES)
                    .maxDocumentLength(MAX_REQUEST_BYTES)
                    .build())
            .build());
    private static final String MALFORMED_JSON = "{\"status\":" + STATUS_MALFORMED + "}";
    private static final ZoneId GMT = ZoneId.of("UTC");
    private static final ZoneId PACIFIC = ZoneId.of("America/Los_Angeles");

    private final Set<X509Certificate> trustedRoots;
    private final Environment environment;
    private final Clock clock;

    /**
     * @param trustedRoots pinned roots (production:
     *                     {@code AppleRootCerts.receiptRoots()})
     * @param environment  which environment this instance emulates (drives
     *                     21007/21008 routing). Only {@link Environment#PRODUCTION}
     *                     and {@link Environment#SANDBOX} exist on Apple's
     *                     endpoint; anything else is rejected.
     */
    public VerifyReceiptEndpoint(Set<X509Certificate> trustedRoots, Environment environment) {
        this(trustedRoots, environment, null);
    }

    /**
     * @param clock source of "now"; {@code null} (the two-argument
     *              constructor's default) means {@link Clock#systemUTC()}, so
     *              existing callers are unaffected. It drives the
     *              {@code request_date} / {@code request_date_ms} /
     *              {@code request_date_pst} response fields, and nothing else:
     *              Apple's endpoint stamps them with the time the request was
     *              answered, which is wall-clock by definition. It deliberately
     *              does NOT reach receipt verification, whose only use for a
     *              "now" is a certificate-validity instant — see
     *              {@link ReceiptVerifier}.
     */
    public VerifyReceiptEndpoint(Set<X509Certificate> trustedRoots, Environment environment, @Nullable Clock clock) {
        if (trustedRoots == null || trustedRoots.isEmpty()) {
            throw new IllegalArgumentException("trustedRoots must not be empty");
        }
        if (environment != Environment.PRODUCTION && environment != Environment.SANDBOX) {
            throw new IllegalArgumentException("environment must be PRODUCTION or SANDBOX, got " + environment);
        }
        this.trustedRoots = new HashSet<X509Certificate>(trustedRoots);
        this.environment = environment;
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    /**
     * @param production which environment this instance emulates
     * @deprecated use {@link #VerifyReceiptEndpoint(Set, Environment)} — the
     *             environment is an enum in cases.json and in every other
     *             port, and a boolean cannot say which of the two it means at
     *             a call site. {@code true} is {@link Environment#PRODUCTION},
     *             {@code false} is {@link Environment#SANDBOX}.
     */
    @Deprecated
    public VerifyReceiptEndpoint(Set<X509Certificate> trustedRoots, boolean production) {
        this(trustedRoots, production ? Environment.PRODUCTION : Environment.SANDBOX, null);
    }

    /**
     * @param production which environment this instance emulates
     * @deprecated use {@link #VerifyReceiptEndpoint(Set, Environment, Clock)}.
     */
    @Deprecated
    public VerifyReceiptEndpoint(Set<X509Certificate> trustedRoots, boolean production, @Nullable Clock clock) {
        this(trustedRoots, production ? Environment.PRODUCTION : Environment.SANDBOX, clock);
    }

    /**
     * Handles one verifyReceipt request body. Never throws — like the real
     * endpoint, failures are reported through {@code status}.
     */
    public Map<String, Object> verifyReceipt(@Nullable Map<String, ? extends @Nullable Object> requestBody) {
        Object receiptData = requestBody == null ? null : requestBody.get("receipt-data");
        if (!(receiptData instanceof String) || ((String) receiptData).isEmpty()) {
            return status(STATUS_MALFORMED);
        }
        // This entry point decodes before verifyReceiptCore could apply its
        // own cap, so the cap is applied to the transport string here: the
        // same string and the same limit ReceiptVerifier.verify(String) would
        // have measured. The answer is 21002 either way; the difference is
        // that nothing is allocated first.
        if (((String) receiptData).length() > ReceiptVerifier.MAX_RECEIPT_BYTES) {
            return status(STATUS_MALFORMED);
        }
        byte[] der;
        try {
            der = ReceiptBase64.decode((String) receiptData);
        } catch (VerificationException e) {
            return status(STATUS_MALFORMED);
        }
        AppReceipt receipt;
        try {
            // The primitive itself, not a ReceiptVerifier built around a
            // wildcard bundle id: like Apple's endpoint, no bundle-id
            // claim is checked here (callers compare receipt.bundle_id).
            receipt = ReceiptVerifier.verifyReceiptCore(der, trustedRoots);
        } catch (VerificationException e) {
            return status(e.reason() == Reason.INVALID_RECEIPT_FORMAT ? STATUS_MALFORMED : STATUS_NOT_AUTHENTICATED);
        } catch (RuntimeException e) {
            return status(STATUS_INTERNAL);
        }

        // 21007/21008 environment routing from the receipt_type attribute.
        // Production types are exactly "Production" and "ProductionVPP";
        // everything else ("ProductionSandbox", "ProductionVPPSandbox",
        // "Xcode", or a missing attribute) fails closed as non-production.
        // "Xcode" is listed for completeness only: an Xcode-generated
        // receipt is not Apple-signed, so it fails chain verification with
        // 21003 above and never reaches this branch.
        boolean productionReceipt =
                "Production".equals(receipt.receiptType()) || "ProductionVPP".equals(receipt.receiptType());
        if (environment == Environment.PRODUCTION && !productionReceipt) {
            return status(STATUS_SANDBOX_RECEIPT_ON_PRODUCTION);
        }
        if (environment == Environment.SANDBOX && productionReceipt) {
            return status(STATUS_PRODUCTION_RECEIPT_ON_SANDBOX);
        }

        Map<String, Object> response = new LinkedHashMap<String, Object>();
        response.put("status", STATUS_OK);
        response.put("environment", environment.value());
        response.put("receipt", receiptJson(receipt, clock.instant()));
        return response;
    }

    /**
     * Handles one verifyReceipt request body in its raw wire form: the JSON
     * request body in, the JSON response body out, so an HTTP framework's
     * body can be piped straight through without a DTO in between. A thin
     * wrapper over {@link #verifyReceipt(Map)} — every verification
     * decision is made there.
     *
     * <p>A body that is not a JSON object (unparseable, {@code null}, an
     * array, a scalar) answers <code>{"status":21002}</code>. Apple has no
     * status code for "that wasn't JSON"; 21002 ("The data in the
     * receipt-data property was malformed or missing") is the closest, and
     * it is what a JSON object without usable {@code receipt-data} gets
     * anyway.</p>
     *
     * <p>Output is deterministic — the response map preserves insertion
     * order, so equal inputs serialize to equal bytes. Key order is not
     * part of the JSON contract.</p>
     *
     * <p>Deliberately a distinct name rather than a {@code verifyReceipt}
     * overload: an overload would make an existing
     * {@code verifyReceipt(null)} call ambiguous, and this is a published
     * library.</p>
     *
     * @param requestJson raw JSON request body
     * @return raw JSON response body; never throws
     */
    public String verifyReceiptJson(@Nullable String requestJson) {
        if (requestJson != null && requestJson.length() > MAX_REQUEST_BYTES) {
            return MALFORMED_JSON;
        }
        Object parsed;
        try {
            parsed = MAPPER.readValue(requestJson, Object.class);
        } catch (IOException e) {
            return MALFORMED_JSON;
        } catch (RuntimeException e) {
            return MALFORMED_JSON;
        }
        if (!(parsed instanceof Map)) {
            return MALFORMED_JSON;
        }
        @SuppressWarnings("unchecked")
        Map<String, ? extends @Nullable Object> requestBody = (Map<String, ? extends @Nullable Object>) parsed;
        try {
            return MAPPER.writeValueAsString(verifyReceipt(requestBody));
        } catch (JsonProcessingException e) {
            return "{\"status\":" + STATUS_INTERNAL + "}";
        }
    }

    private static Map<String, Object> status(int code) {
        Map<String, Object> response = new LinkedHashMap<String, Object>();
        response.put("status", code);
        return response;
    }

    private static Map<String, Object> receiptJson(AppReceipt receipt, Instant requestDate) {
        Map<String, Object> json = new LinkedHashMap<String, Object>();
        put(json, "receipt_type", receipt.receiptType());
        put(json, "bundle_id", receipt.bundleId());
        put(json, "application_version", receipt.appVersion());
        put(json, "original_application_version", receipt.originalAppVersion());
        appleDates(json, "receipt_creation_date", receipt.creationDate());
        appleDates(json, "request_date", requestDate);
        appleDates(json, "original_purchase_date", receipt.originalPurchaseDate());
        appleDates(json, "expiration_date", receipt.expirationDate());
        List<Map<String, Object>> inApp = new ArrayList<Map<String, Object>>();
        for (InAppPurchase purchase : receipt.inAppPurchases()) {
            inApp.add(inAppJson(purchase));
        }
        json.put("in_app", inApp);
        return json;
    }

    private static Map<String, Object> inAppJson(InAppPurchase purchase) {
        Map<String, Object> json = new LinkedHashMap<String, Object>();
        put(json, "quantity", stringOrNull(purchase.quantity()));
        put(json, "product_id", purchase.productId());
        put(json, "transaction_id", purchase.transactionId());
        put(json, "original_transaction_id", purchase.originalTransactionId());
        appleDates(json, "purchase_date", purchase.purchaseDate());
        appleDates(json, "original_purchase_date", purchase.originalPurchaseDate());
        appleDates(json, "expires_date", purchase.expiresDate());
        appleDates(json, "cancellation_date", purchase.cancellationDate());
        put(json, "web_order_line_item_id", stringOrNull(purchase.webOrderLineItemId()));
        if (purchase.isInIntroOfferPeriod() != null) {
            json.put("is_in_intro_offer_period", String.valueOf(purchase.isInIntroOfferPeriod() == 1L));
        }
        return json;
    }

    private static @Nullable String stringOrNull(@Nullable Long value) {
        return value == null ? null : String.valueOf(value);
    }

    private static void put(Map<String, Object> json, String key, @Nullable Object value) {
        if (value != null) {
            json.put(key, value);
        }
    }

    /** Apple's three date renderings: {@code x} (GMT), {@code x_ms}, {@code x_pst}. */
    private static void appleDates(Map<String, Object> json, String prefix, @Nullable Instant instant) {
        if (instant == null) {
            return;
        }
        json.put(prefix, FORMAT.format(instant.atZone(GMT)) + " Etc/GMT");
        json.put(prefix + "_ms", String.valueOf(instant.toEpochMilli()));
        json.put(prefix + "_pst", FORMAT.format(instant.atZone(PACIFIC)) + " America/Los_Angeles");
    }
}
