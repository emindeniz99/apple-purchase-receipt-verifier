package io.github.emindeniz99.applepurchasereceiptverifier;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * What a {@link Verifier} trusts and what time it thinks it is. Immutable.
 *
 * <p><strong>Roots</strong> are the pinned trust anchors every chain must
 * reach; {@link #defaults()} uses the three Apple roots bundled with this
 * library, and a caller substitutes its own.</p>
 *
 * <p><strong>The clock</strong> answers "what time is it now?" and nothing
 * else. It is read once per call and used for two things: the
 * chain-validity instant when a receipt or JWS states no signing date, and
 * {@code request_date} in the endpoint response. It must be safe to
 * call from several threads.</p>
 *
 * <p><strong>Revocation</strong>: the built-in list of certificates Apple
 * has revoked is always checked. {@link Builder#revocationLists},
 * {@link Builder#revocationIssuers} and {@link Builder#distrust} add to it;
 * all three are empty by default, and {@link Verifier#create} checks them
 * (docs/design/revocation.md). Nothing here downloads anything: the caller
 * fetches Apple's lists (the URLs are {@link Verifier#revocationUrls()}),
 * builds a new {@link Verifier} and swaps the reference.</p>
 *
 * <p><strong>The runtime probe</strong>, on by default, runs at
 * {@link Verifier#create}; see {@link Builder#runtimeProbe(boolean)}.</p>
 */
public final class Config {

    private final Set<X509Certificate> roots;
    private final Clock clock;
    private final boolean runtimeProbe;
    private final List<byte[]> revocationLists;
    private final List<X509Certificate> revocationIssuers;
    private final List<RevokedCertificate> distrust;

    private Config(
            Set<X509Certificate> roots,
            Clock clock,
            boolean runtimeProbe,
            List<byte[]> revocationLists,
            List<X509Certificate> revocationIssuers,
            List<RevokedCertificate> distrust) {
        this.roots = roots;
        this.clock = clock;
        this.runtimeProbe = runtimeProbe;
        this.revocationLists = revocationLists;
        this.revocationIssuers = revocationIssuers;
        this.distrust = distrust;
    }

    /**
     * Apple's three pinned roots and {@link Clock#systemUTC()}.
     *
     * @throws LinkageError if the bundled Apple roots cannot be loaded (a
     *     missing crypto library, or a root that does not parse); they are
     *     parsed when first used
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

    /**
     * The revocation lists (CRL files, DER), in the order given, as an
     * unmodifiable list of copies; each call copies the bytes again.
     */
    public List<byte[]> revocationLists() {
        List<byte[]> copies = new ArrayList<>(revocationLists.size());
        for (byte[] list : revocationLists) {
            copies.add(list.clone());
        }
        return Collections.unmodifiableList(copies);
    }

    /** The added issuers of revocation lists, in the order given, as an unmodifiable list. */
    public List<X509Certificate> revocationIssuers() {
        return revocationIssuers;
    }

    /** The distrust entries, in the order given, as an unmodifiable list. */
    public List<RevokedCertificate> distrust() {
        return distrust;
    }

    /** Builds a {@link Config}; unset values take the {@link #defaults()}. */
    public static final class Builder {

        private @Nullable Set<X509Certificate> roots;
        private Clock clock = Clock.systemUTC();
        private boolean runtimeProbe = true;
        private List<byte[]> revocationLists = Collections.emptyList();
        private List<X509Certificate> revocationIssuers = Collections.emptyList();
        private List<RevokedCertificate> distrust = Collections.emptyList();

        private Builder() {}

        /**
         * Replaces the trusted roots, copied. Leaving them unset means Apple's
         * bundled roots. An empty collection is accepted here and refused by
         * {@link Verifier#create}.
         *
         * @throws NullPointerException if {@code roots} or any element is null
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
         *
         * @throws NullPointerException if {@code clock} is null
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * Turns the runtime probe on or off. When on, {@link Verifier#create}
         * proves that this runtime can verify before it returns, and throws as
         * its documentation states if it cannot; that documentation also says
         * what the probe checks. Turned off, {@code create} skips the check,
         * and a runtime that cannot verify shows it on the first call
         * instead, as a failure whose reason depends on what is missing.
         * Leaving it unset means on.
         */
        public Builder runtimeProbe(boolean runtimeProbe) {
            this.runtimeProbe = runtimeProbe;
            return this;
        }

        /**
         * Replaces the revocation lists, copied: CRL files exactly as
         * downloaded (DER), in any order, for example Apple's lists at the
         * URLs {@link Verifier#revocationUrls()} names. Leaving them unset
         * means none, so only the built-in list and {@link #distrust} apply.
         *
         * <p>{@link Verifier#create} refuses the configuration, naming the
         * first problem and the list's index, when there are more than 16
         * lists or more than 100,000 entries in all, when a list is over
         * 1 MiB or is not a DER CRL, when no configured root or accepted
         * issuer whose name (and key identifier, when the list names one)
         * matches has signed it, or when it is older than the newest list
         * the built-in list records for its issuer. A genuine list of a
         * shape this library does not support (version 1, no
         * {@code nextUpdate}, a distribution point, delta or indirect list,
         * an unknown critical extension, a repeated serial) is ignored:
         * it counts as missing in {@link Verifier#revocationValidUntil()}.
         * When several lists come from one issuer, the one with the highest
         * CRL Number is kept (the latest {@code thisUpdate} when one lacks a
         * number); lists are never merged.</p>
         *
         * <p>A listed certificate is revoked whatever the list's age; a
         * {@code certificateHold} entry counts only while its list is fresh
         * at the call's clock, and a {@code removeFromCRL} entry never. A
         * missing or stale list does not fail a call.</p>
         *
         * @throws NullPointerException if {@code lists} or any element is null
         */
        public Builder revocationLists(Collection<byte[]> lists) {
            List<byte[]> copy = new ArrayList<>(lists.size());
            for (byte[] list : lists) {
                copy.add(Objects.requireNonNull(list, "revocation list").clone());
            }
            this.revocationLists = Collections.unmodifiableList(copy);
            return this;
        }

        /**
         * Replaces the added issuers of revocation lists, copied, in the
         * form {@link #roots} takes. The built-in issuers (Apple's WWDR G5
         * and G6 intermediates, and the configured roots) need no entry
         * here; add a new Apple intermediate before a release knows it, or
         * a test PKI's CA. Leaving them unset means none.
         *
         * <p>{@link Verifier#create} refuses the configuration, naming the
         * certificate's index, unless the certificate is signed by a
         * configured root under that root's name, is a CA, has
         * {@code cRLSign} when it has a keyUsage, carries Apple's WWDR
         * marker OID 1.2.840.113635.100.6.2.1. Its validity dates are not
         * judged. One that is itself revoked is set aside, with any list it
         * signed, rather than refused: paths through it fail with
         * {@link Reason#CERTIFICATE_REVOKED}.</p>
         *
         * @throws NullPointerException if {@code issuers} or any element is null
         */
        public Builder revocationIssuers(Collection<X509Certificate> issuers) {
            List<X509Certificate> copy = new ArrayList<>(issuers.size());
            for (X509Certificate issuer : issuers) {
                copy.add(Objects.requireNonNull(issuer, "revocation issuer"));
            }
            this.revocationIssuers = Collections.unmodifiableList(copy);
            return this;
        }

        /**
         * Replaces the distrust entries, copied: certificates to refuse
         * wherever they appear below the trust anchor, whatever any list
         * says. Leaving them unset means none. {@link Verifier#create}
         * refuses more than 1,000 entries, or an entry that is not 64 hex
         * digits of issuer id and a hex serial, naming its index.
         *
         * @throws NullPointerException if {@code entries} or any element is null
         */
        public Builder distrust(Collection<RevokedCertificate> entries) {
            List<RevokedCertificate> copy = new ArrayList<>(entries.size());
            for (RevokedCertificate entry : entries) {
                copy.add(Objects.requireNonNull(entry, "distrust entry"));
            }
            this.distrust = Collections.unmodifiableList(copy);
            return this;
        }

        /**
         * @throws LinkageError if no roots were set and the bundled Apple
         *     roots cannot be loaded (a missing crypto library, or a root
         *     that does not parse)
         */
        public Config build() {
            // roots(...) already copied, and never touches a set it handed on.
            // Every list setter already copied and wrapped what it keeps.
            return new Config(
                    roots != null ? Collections.unmodifiableSet(roots) : AppleRootCerts.roots(),
                    clock,
                    runtimeProbe,
                    revocationLists,
                    revocationIssuers,
                    distrust);
        }
    }
}
