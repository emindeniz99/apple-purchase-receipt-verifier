package io.github.emindeniz99.applepurchasereceiptverifier;

import java.time.Clock;
import org.jspecify.annotations.Nullable;

/**
 * The configured clock for one call: read at most once, and only when a
 * verdict needs it, so input that fails its own checks never reaches it.
 *
 * <p>A clock that throws is the host's fault, not the input's. It surfaces
 * as {@link Reason#INTERNAL_ERROR}, a {@link VerificationException} the
 * guards that turn unexpected exceptions on unverified input into
 * {@link Reason#MALFORMED} pass through unchanged.</p>
 *
 * <p>One instance per call and per thread: the cached value is not
 * synchronized.</p>
 */
final class CallClock {

    private final Clock clock;
    private @Nullable Long millis;

    CallClock(Clock clock) {
        this.clock = clock;
    }

    /** The current time in epoch milliseconds, the same value on every call. */
    long millis() throws VerificationException {
        Long read = millis;
        if (read == null) {
            try {
                read = Long.valueOf(clock.millis());
            } catch (RuntimeException e) {
                throw new VerificationException(Reason.INTERNAL_ERROR, "the configured clock failed", e);
            }
            millis = read;
        }
        return read.longValue();
    }
}
