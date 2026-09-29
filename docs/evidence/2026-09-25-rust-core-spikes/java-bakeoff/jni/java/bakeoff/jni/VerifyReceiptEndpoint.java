package bakeoff.jni;

/**
 * A local stand-in for Apple's deprecated verifyReceipt endpoint: same JSON
 * request, same JSON response. Never throws on a bad request. Thread-safe.
 */
public final class VerifyReceiptEndpoint extends NativeHandle {
    /**
     * An endpoint emulating {@code environment}, trusting Apple's pinned roots.
     * @param environment PRODUCTION or SANDBOX
     * @throws ConfigurationException if the environment is not supported
     */
    public VerifyReceiptEndpoint(Environment environment) { super(Native.epNew(environment.ordinal())); }

    @Override void free(long h) { Native.epFree(h); }

    /**
     * @param body the raw JSON request body
     * @return the raw JSON response body
     */
    public String verifyReceiptJson(String body) { return call(h -> Native.epVerifyJson(h, body)); }

    /**
     * @param body the raw JSON request body
     * @return the result; close it when done
     */
    public VerifyReceiptResult verifyReceiptResult(String body) {
        return new VerifyReceiptResult(call(h -> Native.epVerifyResult(h, body)));
    }
}
