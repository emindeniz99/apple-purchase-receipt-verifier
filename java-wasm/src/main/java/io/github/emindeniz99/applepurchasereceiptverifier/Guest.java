package io.github.emindeniz99.applepurchasereceiptverifier;

/**
 * One instance of the verifier module, {@code aprv.wasm}, and its four
 * operations as the WIT file declares them ({@code aprv:verifier/verify@0.1.0}).
 * Each returns the module's answer, the JSON text the core wrote. Not
 * thread-safe: one call at a time, which {@link GuestPool} guarantees.
 *
 * <p>Any {@link RuntimeException} out of a method means the instance can no
 * longer be trusted (a trap, a runtime failure, an answer out of bounds);
 * the caller discards it. An implementation holds no verification logic:
 * bytes in, the module's answer out.</p>
 */
interface Guest {

    /** {@code init(config-json: list<u8>) -> string}: once per instance. */
    String init(byte[] configJson);

    /** {@code verify-receipt(now-ms: u64, receipt-base64: list<u8>) -> string}. */
    String verifyReceipt(long nowMs, byte[] receiptBase64);

    /** {@code verify-signed-data(now-ms: u64, jws: list<u8>) -> string}. */
    String verifySignedData(long nowMs, byte[] jws);

    /** {@code verify-receipt-endpoint(env: u32, now-ms: u64, request-json: list<u8>) -> string}; env 0 or 1. */
    String verifyReceiptEndpoint(int env, long nowMs, byte[] requestJson);
}
