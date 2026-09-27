package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * What a {@link Verifier} trusts and what time it thinks it is. Immutable.
 *
 * <p><strong>Roots</strong> are the pinned trust anchors every chain must
 * reach; {@link #defaults()} uses the three Apple roots bundled with this
 * library, and tests substitute their own.</p>
 *
 * <p><strong>The clock</strong> answers "what time is it now?" and nothing
 * else. It is read once per call and used for two things: the
 * chain-validity instant when a receipt or JWS states no signing date, and
 * {@code request_date} in the endpoint response. It must be safe to
 * call from several threads.</p>
 */
public final class Config {

    private final Set<X509Certificate> roots;
    private final Clock clock;

    private Config(Set<X509Certificate> roots, Clock clock) {
        this.roots = roots;
        this.clock = clock;
    }

    /**
     * Apple's three pinned roots and {@link Clock#systemUTC()}.
     *
     * @throws IllegalStateException if the bundled roots are missing, do not
     *                               parse, or do not match their pinned
     *                               fingerprints
     */
    public static Config defaults() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    /** The trusted roots, as an unmodifiable set. */
    public Set<X509Certificate> roots() {
        return roots;
    }

    public Clock clock() {
        return clock;
    }

    /** Builds a {@link Config}; unset values take the {@link #defaults()}. */
    public static final class Builder {

        private @Nullable Set<X509Certificate> roots;
        private Clock clock = Clock.systemUTC();

        private Builder() {}

        /**
         * Replaces the trusted roots, copied. Leaving them unset means Apple's
         * bundled roots. An empty collection is accepted here and refused by
         * {@link Verifier#create}.
         */
        public Builder roots(Collection<X509Certificate> roots) {
            Set<X509Certificate> copy = new LinkedHashSet<X509Certificate>();
            for (X509Certificate root : roots) {
                copy.add(Objects.requireNonNull(root, "root"));
            }
            this.roots = copy;
            return this;
        }

        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * @throws IllegalStateException if no roots were set and the bundled
         *                               Apple roots fail to load
         */
        public Config build() {
            // roots(...) already copied, and never touches a set it handed on.
            return new Config(roots != null ? Collections.unmodifiableSet(roots) : AppleRootCerts.roots(), clock);
        }
    }
}
