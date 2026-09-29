package io.github.emindeniz99.applepurchasereceiptverifier;

import org.jspecify.annotations.Nullable;

/**
 * The module's {@code init} answered {@code {"ok":false}}: it refused the
 * configuration, which carries only the roots, so one of them is not a
 * certificate the core accepts. A caller's mistake: {@link Verifier#create}
 * turns it into {@link IllegalArgumentException}.
 */
final class InitRefused extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final @Nullable String answer;

    InitRefused(String message) {
        this(message, null);
    }

    /** With the module's {@code init} answer as it was written, where a host has it. */
    InitRefused(String message, @Nullable String answer) {
        super(message);
        this.answer = answer;
    }

    /** The module's {@code init} answer, byte for byte, or null. */
    @Nullable
    String answer() {
        return answer;
    }
}
