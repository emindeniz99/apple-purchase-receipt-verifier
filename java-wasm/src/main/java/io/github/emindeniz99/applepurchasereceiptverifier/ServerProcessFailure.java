package io.github.emindeniz99.applepurchasereceiptverifier;

/**
 * {@code aprv-server} did not answer: it could not be started, the child
 * died, the connection broke, or it answered something that is not HTTP.
 * The verify methods answer {@link Reason#INTERNAL_ERROR} (21009 from the
 * endpoint) with this as the cause. Its own type, so a process failure is
 * never mistaken for a trap in the module ({@link ServerProblem} with
 * {@code WASM_TRAP}).
 */
final class ServerProcessFailure extends RuntimeException {

    private static final long serialVersionUID = 1L;

    ServerProcessFailure(String message, Throwable cause) {
        super(message, cause);
    }

    ServerProcessFailure(String message) {
        super(message);
    }
}
