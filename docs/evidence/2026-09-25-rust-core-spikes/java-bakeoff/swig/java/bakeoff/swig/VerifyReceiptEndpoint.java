package bakeoff.swig;

import bakeoff.swig.raw.SWIGTYPE_p_AprvReceiptEndpoint;
import bakeoff.swig.raw.aprv;

/**
 * A drop-in for Apple's local {@code verifyReceipt} endpoint, pinned to
 * Apple's three bundled roots. Thread-safe on the same terms as
 * {@link ReceiptVerifier}. Like Apple's endpoint, and the C ABI it wraps,
 * this never checks the bundle id — check {@code receipt().bundleId()}
 * yourself, or use {@link ReceiptVerifier} instead.
 */
public final class VerifyReceiptEndpoint implements AutoCloseable {
    private final Environment env;
    private final SWIGTYPE_p_AprvReceiptEndpoint handle;

    public VerifyReceiptEndpoint(Environment env) {
        this.env = env;
        try {
            handle = aprv.endpoint_new(env.bit(), null);
        } catch (RuntimeException e) {
            throw new ConfigurationException(e.getMessage(), e);
        }
    }

    /** Handles one request body and returns Apple's response body. Never
     *  throws: every verdict, including a malformed body, is reported inside
     *  the returned JSON's {@code status} field. */
    public String verifyReceiptJson(String body) {
        int[] rc = new int[1];
        String resp = aprv.endpoint_verify_json(handle, body, rc);
        // rc != 0 means the *call* was malformed (null argument, non-UTF-8
        // body) rather than a verification verdict; a Java String is always
        // valid UTF-16 -> UTF-8, so this is not reachable from this API, but
        // this method still must never throw, so it answers as Apple's own
        // endpoint would for a body it cannot read: malformed-request.
        return (rc[0] != 0 || resp == null) ? "{\"status\":21002}" : resp;
    }

    /** {@link #verifyReceiptJson} plus the typed reading of it described in
     *  {@link VerifyReceiptResult}. */
    public VerifyReceiptResult verifyReceiptResult(String body) {
        return VerifyReceiptResult.build(env, body, verifyReceiptJson(body));
    }

    @Override
    public void close() {
        aprv.aprv_endpoint_free(handle);
    }
}
