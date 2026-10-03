using System;
using System.Collections.Generic;
using System.Security.Cryptography;
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
    /// verification module. This library carries no copy of them. To trust
    /// Apple's roots and one of your own, pass all four, loading Apple's from
    /// its PKI page or the repository's <c>certs/</c>.</para>
    /// <para><see cref="Clock"/> answers "what time is it now?" and nothing
    /// else. The library reads it in two places: the chain check when the
    /// receipt or JWS carries no signing date, and <c>request_date</c> in the
    /// endpoint response. A caller-supplied clock must be safe to call from
    /// several threads.</para>
    /// <para>Constructing a <see cref="Config"/> from a root set that was passed
    /// in but is empty throws <see cref="ArgumentException"/> — a verifier
    /// with no roots would answer <c>UNTRUSTED_CHAIN</c> to everything and
    /// nobody would notice until production. That happens once, at startup,
    /// and so does <see cref="Verifier.Create"/> refusing a root the module
    /// cannot read.</para>
    /// </remarks>
    public sealed class Config
    {
        private readonly List<byte[]>? _rootDer;

        /// <summary>
        /// Creates a configuration. With no arguments it is the default: the
        /// module's built-in Apple roots and the system clock.
        /// </summary>
        /// <param name="roots">
        /// The trust anchors to pin, replacing the built-in Apple roots, or
        /// <see langword="null"/> for the three Apple roots pinned inside the
        /// module. Each certificate's DER is copied here, so the caller may
        /// dispose theirs afterwards.
        /// </param>
        /// <param name="clock">
        /// The clock to read "now" from, in epoch milliseconds, or
        /// <see langword="null"/> for the system clock.
        /// </param>
        /// <exception cref="ArgumentException"><paramref name="roots"/> was passed in and it is empty, or contains null or a certificate with no data.</exception>
        public Config(IEnumerable<X509Certificate2>? roots = null, Func<long>? clock = null)
        {
            _rootDer = roots is null ? null : CopyDer(roots);
            Clock = clock ?? SystemClockMillis;
        }

        /// <summary>
        /// The trust anchors the caller passed in: an unmodifiable list of
        /// fresh copies on every call, so nothing a caller does to what it gets
        /// back — casting the list, disposing a certificate — reaches this
        /// config or a verifier built from it. Empty when the config uses the
        /// module's built-in Apple roots, which is what
        /// <c>new Config()</c> does.
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

        private static List<byte[]> CopyDer(IEnumerable<X509Certificate2> roots)
        {
            List<byte[]> rootDer = new List<byte[]>();
            foreach (X509Certificate2 root in roots)
            {
                if (root is null)
                {
                    throw new ArgumentException("roots must not contain null", nameof(roots));
                }

                byte[] der;
                try
                {
                    der = root.RawData;
                }
                catch (CryptographicException)
                {
                    der = Array.Empty<byte>();
                }

                if (der.Length == 0)
                {
                    throw new ArgumentException("roots contains an unreadable certificate", nameof(roots));
                }

                rootDer.Add(der);
            }

            if (rootDer.Count == 0)
            {
                throw new ArgumentException("roots must not be empty", nameof(roots));
            }

            return rootDer;
        }

        private static long SystemClockMillis() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    }
}
