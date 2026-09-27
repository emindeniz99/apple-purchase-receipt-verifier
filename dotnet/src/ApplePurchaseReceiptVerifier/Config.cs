using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Internal;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// Immutable configuration for an <see cref="IVerifier"/>: the pinned trust
    /// anchors and the clock it reads "now" from.
    /// </summary>
    /// <remarks>
    /// <para><see cref="Roots"/> defaults to the three bundled, pinned Apple
    /// roots. Tests replace them with their own via <see cref="Builder"/>.</para>
    /// <para><see cref="Clock"/> answers "what time is it now?" and nothing
    /// else. The library reads it in two places: the chain check when the
    /// receipt or JWS carries no signing date, and <c>request_date</c> in the
    /// endpoint response. A caller-supplied clock must be safe to call from
    /// several threads.</para>
    /// <para><see cref="Defaults"/> throws <see cref="InvalidOperationException"/>
    /// when the bundled roots are missing or unreadable. Building a
    /// <see cref="Config"/> whose resolved root set is empty throws
    /// <see cref="ArgumentException"/> — a verifier with no roots would answer
    /// <c>UNTRUSTED_CHAIN</c> to everything and nobody would notice until
    /// production. Both happen once, at startup.</para>
    /// </remarks>
    public sealed class Config
    {
        private readonly List<X509Certificate2> _roots;

        private Config(List<X509Certificate2> roots, Func<long> clock)
        {
            _roots = roots;
            Clock = clock;
        }

        /// <summary>The default configuration: Apple's pinned roots and the system clock.</summary>
        public static Config Defaults() => new Builder().Build();

        /// <summary>Starts building a <see cref="Config"/> with different roots or a different clock.</summary>
        public static Builder CreateBuilder() => new Builder();

        /// <summary>The pinned trust anchors, an unmodifiable copy taken at build time.</summary>
        public IReadOnlyList<X509Certificate2> Roots => _roots;

        /// <summary>The source of "now", in epoch milliseconds.</summary>
        public Func<long> Clock { get; }

        /// <summary>Builds a <see cref="Config"/>.</summary>
        public sealed class Builder
        {
            private IEnumerable<X509Certificate2>? _roots;
            private Func<long>? _clock;

            /// <summary>
            /// The trust anchors to pin. Copied when <see cref="Build"/> is
            /// called, so the caller may dispose theirs afterwards. Defaults to
            /// the three bundled, pinned Apple roots when never called.
            /// </summary>
            public Builder Roots(IEnumerable<X509Certificate2> roots)
            {
                _roots = roots ?? throw new ArgumentNullException(nameof(roots));
                return this;
            }

            /// <summary>The clock to read "now" from. Defaults to the system clock.</summary>
            public Builder Clock(Func<long> clock)
            {
                _clock = clock ?? throw new ArgumentNullException(nameof(clock));
                return this;
            }

            /// <summary>Builds the immutable <see cref="Config"/>.</summary>
            /// <exception cref="ArgumentException">The resolved root set is empty, or contains an unreadable certificate.</exception>
            public Config Build()
            {
                IEnumerable<X509Certificate2> source = _roots ?? BundledRoots();
                List<X509Certificate2> roots = Certificates.CopyAnchors(source, "roots");
                return new Config(roots, _clock ?? SystemClockMillis);
            }

            private static List<X509Certificate2> BundledRoots()
            {
                try
                {
                    return new List<X509Certificate2>(AppleRootCertificates.Bundled());
                }
                catch (Exception e) when (e is not OutOfMemoryException)
                {
                    throw new InvalidOperationException(
                        "the bundled Apple root certificates are missing or unreadable", e);
                }
            }
        }

        private static long SystemClockMillis() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    }
}
