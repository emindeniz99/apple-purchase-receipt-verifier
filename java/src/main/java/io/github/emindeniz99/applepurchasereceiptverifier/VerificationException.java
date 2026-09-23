package io.github.emindeniz99.applepurchasereceiptverifier;

/**
 * Thrown when a signed payload fails verification. {@link #reason()} is the
 * machine-readable cause; the message carries human-readable detail. A payload
 * that throws must be treated as fully untrusted — there is no partial success.
 */
public class VerificationException extends Exception {

    private static final long serialVersionUID = 1L;

    public enum Reason {
        /** Not a parseable compact JWS, wrong alg, or malformed x5c header. */
        INVALID_JWS_FORMAT,
        /** A certificate in the chain could not be decoded. */
        INVALID_CERTIFICATE,
        /** Leaf/intermediate is missing the required Apple marker OID. */
        INVALID_CERTIFICATE_PURPOSE,
        /** Certificate chain does not validate to a pinned Apple root. */
        INVALID_CHAIN,
        /** Cryptographic signature check failed. */
        INVALID_SIGNATURE,
        /** Payload's bundle id does not match the expected one. */
        WRONG_BUNDLE_ID,
        /** Payload's environment does not match the expected one. */
        WRONG_ENVIRONMENT,
        /** Payload's app Apple id does not match (production only). */
        WRONG_APP_APPLE_ID,
        /**
         * The receipt is not usable PKCS#7/CMS: not canonical base64, over the
         * size cap, not well-formed, or carrying bytes after it. Signed content
         * that cannot be read is {@link #INTERNAL_ERROR} instead.
         */
        INVALID_RECEIPT_FORMAT,
        /** SHA-1 device-hash binding check failed. */
        DEVICE_HASH_MISMATCH,
        /** Payload is older than the verifier's configured max signed age. */
        STALE_PAYLOAD,
        /**
         * The verifyReceipt request envelope is unusable: the body is not a
         * JSON object or nests deeper than 64, or {@code receipt-data} is
         * missing, empty or not a string. Reported only by
         * {@code VerifyReceiptResult.failureReason()}; never thrown.
         */
        MALFORMED_REQUEST,
        /**
         * Not the client's fault, status 21009 at the endpoint. Thrown when a
         * trusted signer signed receipt content or a JWS claim this library
         * cannot read (found only after the chain and the signature passed;
         * the parser's exception is the {@link #getCause() cause}), when the
         * runtime lacks an algorithm the check needs, and reported by the
         * endpoint for an unexpected runtime exception inside it. Alert and
         * retry or escalate; do not deny the user on it, and do not grant
         * access on it either. It keeps the position
         * it had when it was endpoint-only, so no ordinal moved.
         */
        INTERNAL_ERROR,
        /**
         * The raw verifyReceipt request body is over
         * {@code VerifyReceiptEndpoint.MAX_REQUEST_BYTES} (3,145,728 UTF-8
         * bytes), the size at which Apple's endpoint answers HTTP 413. Status
         * 21002 in the response body; an HTTP layer can map it to 413 as
         * Apple does. Reported only by
         * {@code VerifyReceiptResult.failureReason()}; never thrown.
         */
        REQUEST_TOO_LARGE
    }

    private final Reason reason;

    public VerificationException(Reason reason, String message) {
        super(reason + ": " + message);
        this.reason = reason;
    }

    public VerificationException(Reason reason, String message, Throwable cause) {
        super(reason + ": " + message, cause);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
