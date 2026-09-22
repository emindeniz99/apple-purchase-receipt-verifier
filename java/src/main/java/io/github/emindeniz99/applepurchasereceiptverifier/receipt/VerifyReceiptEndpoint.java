package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.HashSet;
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
     * Ceiling on the raw request body {@link #verifyReceiptJson(String)} will
     * parse, in characters.
     *
     * <p>"No method ever throws" is a promise about exceptions, and heap
     * exhaustion is not one: it is an {@link OutOfMemoryError}, so the caller
     * gets no body at all and the promise stops holding on exactly the hostile
     * input it exists for. JSON parsing allocates a multiple of the body, and
     * that happens before any verification.
     *
     * <p>The number is the php port's {@code MAX_REQUEST_BYTES}, and it is
     * deliberately below {@link ReceiptVerifier#MAX_RECEIPT_BYTES}: the JSON
     * entry point has an amplification the pre-decoded {@link
     * #verifyReceiptResult(Map)} entry point does not. A 1 MiB body carries any real
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

    // Shared with VerifyReceiptResult, which serializes the response.
    static final ObjectMapper MAPPER = new ObjectMapper(JsonFactory.builder()
            .streamReadConstraints(StreamReadConstraints.builder()
                    .maxNestingDepth(MAX_JSON_NESTING_DEPTH)
                    // Nothing inside the body can be larger than the body, so
                    // both length bounds are MAX_REQUEST_BYTES.
                    .maxStringLength(MAX_REQUEST_BYTES)
                    .maxDocumentLength(MAX_REQUEST_BYTES)
                    .build())
            .build());

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
     * <p>A body that is not a JSON object (unparseable, {@code null}, an
     * array, a scalar) or is longer than {@link #MAX_REQUEST_BYTES} fails
     * with {@link Reason#MALFORMED_REQUEST}, status 21002. Apple has no
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
        if (requestJson == null || requestJson.length() > MAX_REQUEST_BYTES) {
            return VerifyReceiptResult.failed(environment, Reason.MALFORMED_REQUEST, at);
        }
        Object parsed;
        try {
            parsed = MAPPER.readValue(requestJson, Object.class);
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
            // The primitive itself, not a ReceiptVerifier built around a
            // wildcard bundle id: like Apple's endpoint, no bundle-id
            // claim is checked here (callers compare receipt.bundle_id).
            AppReceipt receipt = ReceiptVerifier.verifyReceiptCore(der, trustedRoots);
            return VerifyReceiptResult.verified(environment, receipt, at);
        } catch (VerificationException e) {
            return VerifyReceiptResult.failed(environment, e.reason(), at);
        } catch (RuntimeException e) {
            return VerifyReceiptResult.internalError(environment, e, at);
        }
    }
}
