package io.github.emindeniz99.applepurchasereceiptverifier;

/**
 * The module's {@code init} answered {@code {"ok":false}}: it refused the
 * configuration, which carries only the roots, so one of them is not a
 * certificate the core accepts. A caller's mistake: {@link Verifier#create}
 * turns it into {@link IllegalArgumentException}.
 */
final class InitRefused extends RuntimeException {

    private static final long serialVersionUID = 1L;

    InitRefused(String message) {
        super(message);
    }
}
