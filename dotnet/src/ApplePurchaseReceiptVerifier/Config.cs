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
    /// <para><see cref="Roots"/> is either the caller's own trust anchors or,
    /// by default, empty, which means the three pinned Apple roots inside the
    /// verification module. This library carries no copy of them for the
    /// verifier to use. To trust Apple's roots and one of your own, pass all
    /// four; <see cref="AppleRootCertificates.Bundled"/> lists Apple's.</para>
    /// <para><see cref="Clock"/> answers "what time is it now?" and nothing
    /// else. The library reads it in two places: the chain check when the
    /// receipt or JWS carries no signing date, and <c>request_date</c> in the
    /// endpoint response. A caller-supplied clock must be safe to call from
    /// several threads.</para>
    /// <para>Building a <see cref="Config"/> from a root set that was passed
    /// in but is empty throws <see cref="ArgumentException"/> — a verifier
    /// with no roots would answer <c>UNTRUSTED_CHAIN</c> to everything and
    /// nobody would notice until production. That happens once, at startup,
    /// and so does <see cref="Verifier.Create"/> refusing a root the module
    /// cannot read.</para>
    /// </remarks>
    public sealed class Config
    {
        private readonly List<byte[]>? _rootDer;

        private Config(List<byte[]>? rootDer, Func<long> clock)
        {
            _rootDer = rootDer;
            Clock = clock;
        }

        /// <summary>The default configuration: the module's built-in Apple roots and the system clock.</summary>
        public static Config Defaults() => new Builder().Build();

        /// <summary>Starts building a <see cref="Config"/> with different roots or a different clock.</summary>
        public static Builder CreateBuilder() => new Builder();

        /// <summary>
        /// The trust anchors the caller passed in: an unmodifiable list of
        /// fresh copies on every call, so nothing a caller does to what it gets
        /// back — casting the list, disposing a certificate — reaches this
        /// config or a verifier built from it. Empty when the config uses the
        /// module's built-in Apple roots, which is what
        /// <see cref="Defaults"/> does.
        /// </summary>
        public IReadOnlyList<X509Certificate2> Roots
        {
            get
            {
                List<X509Certificate2> copies = new List<X509Certificate2>();
                if (_rootDer is not null)
                {
                    foreach (byte[] der in _rootDer)
                    {
                        copies.Add(Certificates.TryLoad(der)
                            ?? throw new InvalidOperationException("a configured root is unreadable"));
                    }
                }

                return copies.AsReadOnly();
            }
        }

        /// <summary>
        /// The DER of each root, for the verifier's <c>init</c>; <see langword="null"/>
        /// means the module's built-in roots. Never handed to a caller.
        /// </summary>
        internal IReadOnlyList<byte[]>? RootDer => _rootDer;

        /// <summary>The source of "now", in epoch milliseconds.</summary>
        public Func<long> Clock { get; }

        /// <summary>Builds a <see cref="Config"/>.</summary>
        public sealed class Builder
        {
            private IEnumerable<X509Certificate2>? _roots;
            private Func<long>? _clock;

            /// <summary>
            /// The trust anchors to pin, replacing the built-in Apple roots.
            /// Copied when <see cref="Build"/> is called, so the caller may
            /// dispose theirs afterwards. When never called, the verifier
            /// trusts the three Apple roots pinned inside its module.
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
            /// <exception cref="ArgumentException">A root set was passed in and it is empty, or contains null.</exception>
            public Config Build()
            {
                Func<long> clock = _clock ?? SystemClockMillis;
                if (_roots is null)
                {
                    return new Config(null, clock);
                }

                List<byte[]> rootDer = new List<byte[]>();
                foreach (X509Certificate2 root in _roots)
                {
                    if (root is null)
                    {
                        throw new ArgumentException("roots must not contain null", "roots");
                    }

                    rootDer.Add(root.RawData);
                }

                if (rootDer.Count == 0)
                {
                    throw new ArgumentException("roots must not be empty", "roots");
                }

                return new Config(rootDer, clock);
            }
        }

        private static long SystemClockMillis() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    }
}
