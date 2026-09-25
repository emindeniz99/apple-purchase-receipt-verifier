package bakeoff.jni;

/** Why verification failed. The constant names are the core's reason tokens. */
public enum Reason {
    /** The JWS is not three base64url segments with a valid header. */
    INVALID_JWS_FORMAT,
    /** A certificate could not be parsed or is outside its validity. */
    INVALID_CERTIFICATE,
    /** A certificate lacks the Apple marker OID for its role. */
    INVALID_CERTIFICATE_PURPOSE,
    /** The chain does not end at a trusted root. */
    INVALID_CHAIN,
    /** The signature does not verify. */
    INVALID_SIGNATURE,
    /** The bundle id does not match. */
    WRONG_BUNDLE_ID,
    /** The environment is not accepted. */
    WRONG_ENVIRONMENT,
    /** The app Apple id does not match. */
    WRONG_APP_APPLE_ID,
    /** The receipt is not a well-formed PKCS#7 receipt. */
    INVALID_RECEIPT_FORMAT,
    /** The receipt was issued for another device. */
    DEVICE_HASH_MISMATCH,
    /** The request body is malformed. */
    MALFORMED_REQUEST,
    /** An internal error; also used for a token this binding does not know. */
    INTERNAL_ERROR,
    /** The request exceeds the size limit. */
    REQUEST_TOO_LARGE;

    static Reason fromToken(String token) {
        try {
            return valueOf(token);
        } catch (IllegalArgumentException e) {
            return INTERNAL_ERROR;
        }
    }
}
