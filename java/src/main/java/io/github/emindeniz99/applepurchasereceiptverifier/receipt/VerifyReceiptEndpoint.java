package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.internal.AppleTrust;
import io.github.emindeniz99.applepurchasereceiptverifier.internal.BoundedJson;
import java.io.IOException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Drop-in local replacement for Apple's deprecated {@code verifyReceipt}
 * endpoint: same request body, same response body shape, same status codes —
 * but verified offline against the pinned Apple root instead of by calling
 * Apple. Field-by-field fidelity and the unavoidable gaps (fields that only
 * exist in Apple's server-side subscription database, like
 * {@code latest_receipt_info} / {@code pending_renewal_info}) are not
 * produced.
 *
 * <p>Like Apple's endpoint, this does NOT check the bundle id — the caller
 * compares {@code receipt.bundle_id}, exactly as with the real endpoint.</p>
 *
 * <p>Thread-safe once constructed: every instance field is final, the anchor
 * set is copied at construction and never handed out, every method keeps its
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
     * Ceiling on the raw request body {@link #verifyReceiptResult(String)}
     * and {@link #verifyReceiptJson(String)} will parse, in UTF-8 bytes:
     * 3 MiB, Apple's own limit: both of Apple's verifyReceipt endpoints
     * answer a body of 3,145,728 bytes and send HTTP 413 for 3,145,729, and
     * the count is bytes, not characters. A larger body answers status 21002
     * with {@link Reason#REQUEST_TOO_LARGE}, decided before any parsing. The body
     * is measured without being encoded, so a Java {@code String} of any
     * size costs no copy to refuse.
     *
     * <p>A fixed constant, the same in every port. "No method ever throws"
     * is a promise about exceptions, and heap exhaustion is not one: JSON
     * parsing allocates a multiple of the body, so the bound is what keeps
     * the promise on hostile input.</p>
     */
    public static final int MAX_REQUEST_BYTES = 3145728;

    // Shared with VerifyReceiptResult, which serializes the response.
    // Nothing inside the body can be larger than the body, and a body within
    // MAX_REQUEST_BYTES bytes is within it in characters too, so both length
    // bounds (counted in characters for String input) are MAX_REQUEST_BYTES.
    static final ObjectMapper MAPPER = new ObjectMapper(BoundedJson.factory(MAX_REQUEST_BYTES));

    private final Set<TrustAnchor> trustAnchors;
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
     *              constructor's default) means {@link Clock#systemUTC()}. It
     *              drives the {@code request_date} / {@code request_date_ms} /
     *              {@code request_date_pst} response fields, and nothing else:
     *              Apple's endpoint stamps them with the time the request was
     *              answered, which is wall-clock by definition. It deliberately
     *              does NOT reach receipt verification, whose only use for a
     *              "now" is a certificate-validity instant — see
     *              {@link ReceiptVerifier}.
     */
    public VerifyReceiptEndpoint(Set<X509Certificate> trustedRoots, Environment environment, @Nullable Clock clock) {
        Set<TrustAnchor> anchors = AppleTrust.anchors(trustedRoots);
        if (environment != Environment.PRODUCTION && environment != Environment.SANDBOX) {
            throw new IllegalArgumentException("environment must be PRODUCTION or SANDBOX, got " + environment);
        }
        this.trustAnchors = anchors;
        this.environment = environment;
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    /**
     * Handles one verifyReceipt request body. Never throws — like the real
     * endpoint, failures are reported through the result's status and
     * {@link VerifyReceiptResult#failureReason()}. {@code request_date} is
     * the endpoint's clock at the time of the call.
     */
    public VerifyReceiptResult verifyReceiptResult(@Nullable Map<String, ? extends @Nullable Object> requestBody) {
        return verifyReceiptResult(requestBody, null);
    }

    /**
     * As {@link #verifyReceiptResult(Map)}, with {@code request_date} set to
     * {@code requestDate} instead of the endpoint's clock ({@code null} falls
     * back to the clock). It feeds {@code request_date} and nothing else.
     */
    public VerifyReceiptResult verifyReceiptResult(
            @Nullable Map<String, ? extends @Nullable Object> requestBody, @Nullable Instant requestDate) {
        Instant at = requestDate(requestDate);
        Object receiptData;
        try {
            receiptData = requestBody == null ? null : requestBody.get("receipt-data");
        } catch (RuntimeException e) {
            return VerifyReceiptResult.internalError(environment, e, at);
        }
        if (!(receiptData instanceof String)) {
            return VerifyReceiptResult.failed(environment, Reason.MALFORMED_REQUEST, at);
        }
        return verify((String) receiptData, at);
    }

    /**
     * Handles one verifyReceipt request body in its raw wire form, the JSON
     * text an HTTP framework hands over. Never throws.
     *
     * <p>A body over {@link #MAX_REQUEST_BYTES} UTF-8 bytes fails with
     * {@link Reason#REQUEST_TOO_LARGE}, status 21002, where Apple answers
     * HTTP 413. A body that is not a JSON object (unparseable, {@code null},
     * an array, a scalar) or nests deeper than 64 fails with
     * {@link Reason#MALFORMED_REQUEST}, status 21002. Apple has no
     * status code for "that wasn't JSON"; 21002 ("The data in the
     * receipt-data property was malformed or missing") is the closest, and
     * it is what a JSON object without usable {@code receipt-data} gets
     * anyway.</p>
     *
     * <p>A literal {@code null} argument needs a cast to pick this overload
     * over {@link #verifyReceiptResult(Map)}.</p>
     */
    public VerifyReceiptResult verifyReceiptResult(@Nullable String requestJson) {
        return verifyReceiptResult(requestJson, null);
    }

    /**
     * As {@link #verifyReceiptResult(String)}, with {@code request_date} set
     * to {@code requestDate} instead of the endpoint's clock.
     */
    public VerifyReceiptResult verifyReceiptResult(@Nullable String requestJson, @Nullable Instant requestDate) {
        Instant at = requestDate(requestDate);
        if (requestJson == null) {
            return VerifyReceiptResult.failed(environment, Reason.MALFORMED_REQUEST, at);
        }
        if (Utf8Length.exceeds(requestJson, MAX_REQUEST_BYTES)) {
            return VerifyReceiptResult.failed(environment, Reason.REQUEST_TOO_LARGE, at);
        }
        Object parsed;
        try {
            parsed = readJson(requestJson);
        } catch (IOException e) {
            return VerifyReceiptResult.failed(environment, Reason.MALFORMED_REQUEST, at);
        } catch (RuntimeException e) {
            // What the JSON parser throws unchecked is still a body it could
            // not read, and it has always answered 21002.
            return VerifyReceiptResult.failed(environment, Reason.MALFORMED_REQUEST, at);
        }
        if (!(parsed instanceof Map)) {
            return VerifyReceiptResult.failed(environment, Reason.MALFORMED_REQUEST, at);
        }
        @SuppressWarnings("unchecked")
        Map<String, ? extends @Nullable Object> requestBody = (Map<String, ? extends @Nullable Object>) parsed;
        return verifyReceiptResult(requestBody, at);
    }

    /**
     * Verifies a bare base64 receipt, the value a request body would carry as
     * {@code receipt-data}, with no envelope around it. Never throws; a
     * {@code null} or empty string fails with
     * {@link Reason#MALFORMED_REQUEST}, as a missing {@code receipt-data}
     * does.
     */
    public VerifyReceiptResult verifyReceiptData(@Nullable String base64) {
        return verifyReceiptData(base64, null);
    }

    /**
     * As {@link #verifyReceiptData(String)}, with {@code request_date} set to
     * {@code requestDate} instead of the endpoint's clock.
     */
    public VerifyReceiptResult verifyReceiptData(@Nullable String base64, @Nullable Instant requestDate) {
        return verify(base64, requestDate(requestDate));
    }

    /**
     * Handles one verifyReceipt request body in its raw wire form: the JSON
     * request body in, the JSON response body out, so an HTTP framework's
     * body can be piped straight through without a DTO in between. The same
     * as {@code verifyReceiptResult(requestJson).toJson()}.
     *
     * <p>Output is deterministic — the response map preserves insertion
     * order, so equal inputs serialize to equal bytes. Key order is not
     * part of the JSON contract.</p>
     *
     * @param requestJson raw JSON request body
     * @return raw JSON response body; never throws
     */
    public String verifyReceiptJson(@Nullable String requestJson) {
        return verifyReceiptResult(requestJson).toJson();
    }

    /**
     * {@code MAPPER.readValue(json, Object.class)}, with the parser reading
     * the whole body from one array.
     *
     * <p>Given a String longer than 32,768 characters, Jackson wraps it in a
     * StringReader and reads it in chunks of a few thousand characters, and a
     * string value longer than a chunk goes through its slow
     * character-at-a-time path. {@code receipt-data} is such a value for any
     * receipt with more than a handful of purchases (105,000 characters for
     * the 187-purchase legacy fixture), and reading it that way took longer
     * than decoding it. Over a char array Jackson builds the same parser
     * class it uses for a short String, with the same constraints and
     * features; the only difference is that the buffer is not recycled.</p>
     */
    static @Nullable Object readJson(String json) throws IOException {
        try (JsonParser parser = MAPPER.getFactory().createParser(json.toCharArray())) {
            return MAPPER.readValue(parser, Object.class);
        }
    }

    private Instant requestDate(@Nullable Instant requestDate) {
        return requestDate != null ? requestDate : clock.instant();
    }

    /**
     * The one verification path every entry point ends in. {@code at} only
     * becomes {@code request_date}: certificate validity is judged inside
     * {@link ReceiptVerifier#verifyReceiptCore}, which takes no time input.
     */
    private VerifyReceiptResult verify(@Nullable String receiptData, Instant at) {
        try {
            if (receiptData == null || receiptData.isEmpty()) {
                return VerifyReceiptResult.failed(environment, Reason.MALFORMED_REQUEST, at);
            }
            // Decoding happens before verifyReceiptCore could apply its own
            // cap, so the cap is applied to the transport string here: the
            // same string and the same limit ReceiptVerifier.verify(String)
            // would have measured, and the same reason it throws.
            if (receiptData.length() > ReceiptVerifier.MAX_RECEIPT_BYTES) {
                return VerifyReceiptResult.failed(environment, Reason.INVALID_RECEIPT_FORMAT, at);
            }
            byte[] der = ReceiptBase64.decode(receiptData);
            // The primitive under verifyReceiptCore, not a ReceiptVerifier
            // built around a wildcard bundle id: like Apple's endpoint, no
            // bundle-id claim is checked here (callers compare
            // receipt.bundle_id). It takes the anchors built at construction.
            AppReceipt receipt = ReceiptVerifier.verifyCore(der, trustAnchors);
            return VerifyReceiptResult.verified(environment, receipt, at);
        } catch (VerificationException e) {
            return VerifyReceiptResult.failed(environment, e.reason(), at);
        } catch (RuntimeException e) {
            return VerifyReceiptResult.internalError(environment, e, at);
        }
    }
}
