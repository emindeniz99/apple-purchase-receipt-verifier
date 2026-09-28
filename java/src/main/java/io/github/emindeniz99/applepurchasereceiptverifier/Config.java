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
 *
 * <p><strong>The runtime probe</strong>, on by default, runs at
 * {@link Verifier#create}; see {@link Builder#runtimeProbe(boolean)}.</p>
 */
public final class Config {

    private final Set<X509Certificate> roots;
    private final Clock clock;
    private final boolean runtimeProbe;

    private Config(Set<X509Certificate> roots, Clock clock, boolean runtimeProbe) {
        this.roots = roots;
        this.clock = clock;
        this.runtimeProbe = runtimeProbe;
    }

    /**
     * Apple's three pinned roots and {@link Clock#systemUTC()}.
     *
     * @throws IllegalStateException if the bundled roots do not parse
     */
    public static Config defaults() {
        return builder().build();
    }

    /** A builder that starts from the {@link #defaults()}. */
    public static Builder builder() {
        return new Builder();
    }

    /** The trusted roots, as an unmodifiable set. */
    public Set<X509Certificate> roots() {
        return roots;
    }

    /** The clock read once per call; see the class comment for what it decides. */
    public Clock clock() {
        return clock;
    }

    /**
     * Whether {@link Verifier#create} probes the runtime; see
     * {@link Builder#runtimeProbe(boolean)}.
     */
    public boolean runtimeProbe() {
        return runtimeProbe;
    }

    /** Builds a {@link Config}; unset values take the {@link #defaults()}. */
    public static final class Builder {

        private @Nullable Set<X509Certificate> roots;
        private Clock clock = Clock.systemUTC();
        private boolean runtimeProbe = true;

        private Builder() {}

        /**
         * Replaces the trusted roots, copied. Leaving them unset means Apple's
         * bundled roots. An empty collection is accepted here and refused by
         * {@link Verifier#create}.
         */
        public Builder roots(Collection<X509Certificate> roots) {
            Set<X509Certificate> copy = new LinkedHashSet<>();
            for (X509Certificate root : roots) {
                copy.add(Objects.requireNonNull(root, "root"));
            }
            this.roots = copy;
            return this;
        }

        /**
         * Replaces the clock, which must be safe to call from several threads.
         * Leaving it unset means {@link Clock#systemUTC()}.
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * Turns the runtime probe on or off. When on, {@link Verifier#create}
         * asks the BouncyCastle provider for the digest, ES256, X.509 and PKIX
         * engines and checks each bundled Apple root's own signature, and
         * throws {@link IllegalStateException} if any of that fails. Turned
         * off, a runtime that cannot verify shows up as
         * {@link Reason#INTERNAL_ERROR} on the first call instead. Leaving it
         * unset means on.
         */
        public Builder runtimeProbe(boolean runtimeProbe) {
            this.runtimeProbe = runtimeProbe;
            return this;
        }

        /**
         * @throws IllegalStateException if no roots were set and the bundled
         *                               Apple roots fail to load
         */
        public Config build() {
            // roots(...) already copied, and never touches a set it handed on.
            return new Config(
                    roots != null ? Collections.unmodifiableSet(roots) : AppleRootCerts.roots(), clock, runtimeProbe);
        }
    }
}
