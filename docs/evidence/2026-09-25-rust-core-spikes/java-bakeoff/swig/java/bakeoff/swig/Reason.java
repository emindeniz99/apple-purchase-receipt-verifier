package bakeoff.swig;

import java.util.HashMap;
import java.util.Map;

/**
 * The canonical cross-port verification-failure vocabulary: a verdict about
 * the input, mirroring {@code AprvReason}'s {@code 1..12} band (the C ABI's
 * {@code 100+} band is a mistake in the call itself, never a verdict, and is
 * surfaced as {@link ConfigurationException} instead — see its Javadoc).
 */
public enum Reason {
    INVALID_JWS_FORMAT(1),
    INVALID_CERTIFICATE(2),
    INVALID_CERTIFICATE_PURPOSE(3),
    INVALID_CHAIN(4),
    INVALID_SIGNATURE(5),
    WRONG_BUNDLE_ID(6),
    WRONG_ENVIRONMENT(7),
    WRONG_APP_APPLE_ID(8),
    INVALID_RECEIPT_FORMAT(9),
    DEVICE_HASH_MISMATCH(10),
    /* 11 (STALE_PAYLOAD) is retired and never reused, per the ABI header. */
    INTERNAL_ERROR(12),
    /* Not in the ABI's 1..12 band at all: these two are read off the local
       verifyReceipt endpoint's numeric `status` (21002), which carries no
       reason token of its own. See VerifyReceiptResult for how they are
       told apart. */
    MALFORMED_REQUEST(-1),
    REQUEST_TOO_LARGE(-2);

    private final int code;

    Reason(int code) {
        this.code = code;
    }

    private static final Map<Integer, Reason> BY_CODE = new HashMap<Integer, Reason>();
    static {
        for (Reason r : values()) {
            if (r.code > 0) BY_CODE.put(r.code, r);
        }
    }

    /** Maps an {@code AprvReason} value in the 1..12 band to its {@link Reason}.
     *  Throws {@link ConfigurationException} for anything outside that band —
     *  callers only ever reach this after checking the status is 1..12. */
    static Reason fromAbiCode(int code) {
        Reason r = BY_CODE.get(code);
        if (r == null) {
            throw new ConfigurationException("unmapped AprvReason code " + code);
        }
        return r;
    }
}
