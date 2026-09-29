package io.github.emindeniz99.applepurchasereceiptverifier;

/**
 * {@code aprv-server} answered with an RFC 9457 problem instead of a
 * verification result: 400 {@code BAD_REQUEST}, 401 {@code UNAUTHORIZED},
 * 404, 405, 413 {@code PAYLOAD_TOO_LARGE}, or 500 {@code WASM_TRAP},
 * {@code ABI_ERROR} or {@code INTERNAL_ERROR}. 413 becomes
 * {@link Reason#TOO_LARGE} (21002 from the endpoint); every other problem is
 * {@link Reason#INTERNAL_ERROR} (21009) with this as the cause, which keeps
 * the server's category in {@link #code()}.
 */
final class ServerProblem extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final int status;
    private final String code;

    ServerProblem(int status, String code, String detail) {
        super("aprv-server answered HTTP " + status + " " + code + ": " + detail);
        this.status = status;
        this.code = code;
    }

    int status() {
        return status;
    }

    /** The problem's {@code code}, such as {@code WASM_TRAP}; {@code HTTP_<status>} when the body had none. */
    String code() {
        return code;
    }
}
