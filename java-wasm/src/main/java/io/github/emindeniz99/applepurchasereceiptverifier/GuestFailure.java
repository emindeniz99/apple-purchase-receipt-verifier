package io.github.emindeniz99.applepurchasereceiptverifier;

/**
 * A module instance failed: it trapped, the runtime threw, it could not be
 * created, it lacks the ABI this library binds, or its answer is out of
 * bounds or unreadable. The verify methods answer
 * {@link Reason#INTERNAL_ERROR} with this as the cause, and the instance is
 * discarded. The message names the category and the runtime's exception;
 * it never quotes the input.
 */
final class GuestFailure extends RuntimeException {

    private static final long serialVersionUID = 1L;

    GuestFailure(String message, Throwable cause) {
        super(message, cause);
    }

    GuestFailure(String message) {
        super(message);
    }
}
