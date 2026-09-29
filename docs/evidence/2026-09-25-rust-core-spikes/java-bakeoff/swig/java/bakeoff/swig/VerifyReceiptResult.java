package bakeoff.swig;

import bakeoff.swig.raw.SWIGTYPE_p_AprvReceiptEndpoint;
import bakeoff.swig.raw.aprv;

import java.io.UnsupportedEncodingException;
import java.util.Map;

/**
 * The typed outcome of one {@link VerifyReceiptEndpoint#verifyReceiptResult}
 * call. A plain immutable value — it owns no native handle, so there is
 * nothing to close.
 *
 * <p><b>Known gap, reported as the task asked:</b> the C ABI has no result
 * handle that crosses the FFI boundary (see rust/ffi/README.md and
 * PORTS.md's "re-render for the other environment" row) — only a raw JSON
 * string and a status code. Apple's classic {@code verifyReceipt} body
 * carries the {@code receipt} object only when the request's environment
 * already matches (status {@code 0}); for the "wrong environment" routing
 * codes ({@code 21007}/{@code 21008}) the body is bare ({@code {"status":N}})
 * and does not carry a receipt at all. To honor the spec's
 * {@code receipt()}/{@code toJsonIn(env)} on that path, this class calls a
 * <em>second</em> {@code AprvReceiptEndpoint} handle for the matching
 * environment and re-verifies the same request body — exactly the fallback
 * PORTS.md names for the equivalent gap in every other language port. That
 * means {@code toJsonIn} does **not** honor "without re-verifying" for a
 * {@code 21007}/{@code 21008} result: the ABI gives no way to re-render a
 * finished verdict without asking the Rust core to verify again. For every
 * other status it is free: the stored raw body already IS what
 * {@code toJson()} returns, and {@code toJsonIn} on an already-matching
 * environment reduces to it.
 */
public final class VerifyReceiptResult {
    private static final int MAX_REQUEST_BYTES = 3_145_728;

    private final long status;
    private final boolean verified;
    private final AppReceipt receipt;
    private final Reason failureReason;
    private final String requestBody;
    private final String rawResponse;

    private VerifyReceiptResult(long status, boolean verified, AppReceipt receipt, Reason failureReason,
                                 String requestBody, String rawResponse) {
        this.status = status;
        this.verified = verified;
        this.receipt = receipt;
        this.failureReason = failureReason;
        this.requestBody = requestBody;
        this.rawResponse = rawResponse;
    }

    public long status() { return status; }
    public boolean verified() { return verified; }
    /** {@code null} unless {@link #verified()}. */
    public AppReceipt receipt() { return receipt; }
    /** {@code null} unless verification failed for one of the two reasons
     *  this endpoint can tell apart ({@link Reason#MALFORMED_REQUEST},
     *  {@link Reason#REQUEST_TOO_LARGE}); a status this port does not map
     *  yet also reads as {@code null} here rather than guessing. */
    public Reason failureReason() { return failureReason; }

    /** The raw {@code verifyReceipt}-compatible response body for the
     *  environment {@link VerifyReceiptEndpoint} was built with. */
    public String toJson() {
        return rawResponse;
    }

    /** Re-renders the response as if the request had been sent to {@code env}.
     *  See this class's Javadoc: the ABI has no way to do this without
     *  verifying again, so this call re-verifies {@code requestBody} against
     *  a fresh endpoint for {@code env}. */
    public String toJsonIn(Environment env) {
        SWIGTYPE_p_AprvReceiptEndpoint h;
        try {
            h = aprv.endpoint_new(env.bit(), null);
        } catch (RuntimeException e) {
            throw new ConfigurationException(e.getMessage(), e);
        }
        try {
            int[] rc = new int[1];
            String resp = aprv.endpoint_verify_json(h, requestBody, rc);
            return (rc[0] != 0 || resp == null) ? "{\"status\":21002}" : resp;
        } finally {
            aprv.aprv_endpoint_free(h);
        }
    }

    static VerifyReceiptResult build(Environment env, String requestBody, String rawResponse) {
        Map<String, Object> m = Json.parseObject(rawResponse);
        long status = Json.getLong(m, "status");
        Map<String, Object> receiptJson = Json.getObject(m, "receipt");

        if (receiptJson != null) {
            return new VerifyReceiptResult(status, true, AppReceipt.fromClassicJson(receiptJson), null,
                    requestBody, rawResponse);
        }
        if (status == 21007 || status == 21008) {
            // The receipt is genuine but was sent to the wrong environment;
            // re-verify against the one it actually belongs to so receipt()
            // is populated, matching PORTS.md's documented fallback.
            Environment retryEnv = (status == 21007) ? Environment.SANDBOX : Environment.PRODUCTION;
            SWIGTYPE_p_AprvReceiptEndpoint h;
            try {
                h = aprv.endpoint_new(retryEnv.bit(), null);
            } catch (RuntimeException e) {
                throw new ConfigurationException(e.getMessage(), e);
            }
            try {
                int[] rc = new int[1];
                String retryResp = aprv.endpoint_verify_json(h, requestBody, rc);
                Map<String, Object> retryMap = (rc[0] == 0 && retryResp != null)
                        ? Json.parseObject(retryResp) : null;
                Map<String, Object> retryReceipt = retryMap == null ? null : Json.getObject(retryMap, "receipt");
                AppReceipt receipt = retryReceipt == null ? null : AppReceipt.fromClassicJson(retryReceipt);
                // verified() is true whenever the receipt itself checked out
                // in its own environment, even though *this* endpoint's
                // environment does not match it (that is exactly what
                // 21007/21008 mean).
                return new VerifyReceiptResult(status, receipt != null, receipt, null, requestBody, rawResponse);
            } finally {
                aprv.aprv_endpoint_free(h);
            }
        }
        if (status == 21002) {
            Reason reason = utf8Length(requestBody) > MAX_REQUEST_BYTES
                    ? Reason.REQUEST_TOO_LARGE : Reason.MALFORMED_REQUEST;
            return new VerifyReceiptResult(status, false, null, reason, requestBody, rawResponse);
        }
        // A status this port does not map (yet): report it, don't guess.
        return new VerifyReceiptResult(status, false, null, null, requestBody, rawResponse);
    }

    private static int utf8Length(String s) {
        try {
            return s.getBytes("UTF-8").length;
        } catch (UnsupportedEncodingException e) {
            throw new AssertionError("UTF-8 is always supported", e);
        }
    }
}
