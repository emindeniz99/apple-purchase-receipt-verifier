using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Internal;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// Immutable configuration for an <see cref="IVerifier"/>: the pinned trust
    /// anchors, the clock it reads "now" from, and the revocation settings.
    /// </summary>
    /// <remarks>
    /// <para><see cref="Roots"/> is either the caller's own trust anchors or,
    /// by default, empty, which means the three pinned Apple roots inside the
    /// verification module. This library carries no copy of them. To trust
    /// Apple's roots and one of your own, pass all four, loading Apple's from
    /// its PKI page or the repository's <c>certs/</c>.</para>
    /// <para><see cref="Clock"/> answers "what time is it now?" and nothing
    /// else. The library reads it in three places: the chain check when the
    /// receipt or JWS carries no signing date, <c>request_date</c> in the
    /// endpoint response, and whether a revocation list is still fresh when it
    /// holds a <c>certificateHold</c> entry for a certificate on the path. A
    /// caller-supplied clock must be safe to call from several threads.</para>
    /// <para>The revocation settings (docs/design/revocation.md §4) are empty
    /// by default: <see cref="RevocationLists"/>, Apple's revocation lists,
    /// which the caller downloads from <see cref="IVerifier.RevocationUrls"/>;
    /// <see cref="RevocationIssuers"/>, certificates that sign such lists beyond
    /// the ones the module knows; and <see cref="Distrust"/>, certificates the
    /// caller refuses by name. The list built into the module is always on.
    /// The module judges all three when <see cref="Verifier.Create"/> builds a
    /// verifier.</para>
    /// <para>Constructing a <see cref="Config"/> from a root set that was passed
    /// in but is empty throws <see cref="ArgumentException"/> — a verifier
    /// with no roots would answer <c>UNTRUSTED_CHAIN</c> to everything and
    /// nobody would notice until production. That happens once, at startup,
    /// and so does <see cref="Verifier.Create"/> refusing a root the module
    /// cannot read, or a revocation setting it refuses.</para>
    /// </remarks>
    public sealed class Config
    {
        private readonly List<byte[]>? _rootDer;
        private readonly List<byte[]> _revocationLists;
        private readonly List<byte[]> _revocationIssuerDer;
        private readonly List<RevokedCertificate> _distrust;

        /// <summary>
        /// Creates a configuration. With no arguments it is the default: the
        /// module's built-in Apple roots, the system clock and no revocation
        /// settings beyond the list built into the module.
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
        /// <param name="revocationLists">
        /// Certificate revocation lists (CRLs) exactly as downloaded (DER), in
        /// any order: at most 16, each at most 1 MiB. Each is copied here.
        /// <see langword="null"/> means none.
        /// </param>
        /// <param name="revocationIssuers">
        /// CA certificates that sign revocation lists, added to the ones built
        /// into the module: a new Apple intermediate, or a test PKI's. Each
        /// must chain to a configured root. As with <paramref name="roots"/>,
        /// each certificate's DER is copied here and only that reaches the
        /// module. <see langword="null"/> means none.
        /// </param>
        /// <param name="distrust">
        /// Certificates to refuse, at most 1,000. <see langword="null"/> means none.
        /// </param>
        /// <exception cref="ArgumentException"><paramref name="roots"/> was passed in and it is empty, or contains null or a certificate with no data; or a revocation setting contains null or a certificate with no data.</exception>
        public Config(
            IEnumerable<X509Certificate2>? roots = null,
            Func<long>? clock = null,
            IEnumerable<byte[]>? revocationLists = null,
            IEnumerable<X509Certificate2>? revocationIssuers = null,
            IEnumerable<RevokedCertificate>? distrust = null)
        {
            _rootDer = roots is null ? null : CopyDer(roots);
            Clock = clock ?? SystemClockMillis;
            _revocationLists = CopyLists(revocationLists);
            _revocationIssuerDer = revocationIssuers is null
                ? new List<byte[]>()
                : CopyCertificates(revocationIssuers, nameof(revocationIssuers));
            _distrust = CopyDistrust(distrust);
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

        /// <summary>
        /// The revocation lists the caller passed in, as an unmodifiable list
        /// of fresh copies on every call. Empty by default.
        /// </summary>
        public IReadOnlyList<byte[]> RevocationLists
        {
            get
            {
                List<byte[]> copies = new List<byte[]>();
                foreach (byte[] list in _revocationLists)
                {
                    copies.Add((byte[])list.Clone());
                }

                return copies.AsReadOnly();
            }
        }

        /// <summary>
        /// The revocation issuers the caller passed in: an unmodifiable list of
        /// fresh copies on every call, as <see cref="Roots"/> is. Empty by
        /// default.
        /// </summary>
        public IReadOnlyList<X509Certificate2> RevocationIssuers
        {
            get
            {
                List<X509Certificate2> copies = new List<X509Certificate2>();
                foreach (byte[] der in _revocationIssuerDer)
                {
                    copies.Add(Certificates.TryLoad(der)
                        ?? throw new InvalidOperationException("a configured revocation issuer is unreadable"));
                }

                return copies.AsReadOnly();
            }
        }

        /// <summary>The certificates the caller refuses, unmodifiable. Empty by default.</summary>
        public IReadOnlyList<RevokedCertificate> Distrust => _distrust.AsReadOnly();

        /// <summary>The revocation lists for the verifier's <c>init</c>. Never handed to a caller.</summary>
        internal IReadOnlyList<byte[]> RevocationListBytes => _revocationLists;

        /// <summary>The DER of each revocation issuer, for the verifier's <c>init</c>. Never handed to a caller.</summary>
        internal IReadOnlyList<byte[]> RevocationIssuerDer => _revocationIssuerDer;

        private static List<byte[]> CopyDer(IEnumerable<X509Certificate2> roots)
        {
            List<byte[]> rootDer = CopyCertificates(roots, nameof(roots));
            if (rootDer.Count == 0)
            {
                throw new ArgumentException("roots must not be empty", nameof(roots));
            }

            return rootDer;
        }

        private static List<byte[]> CopyCertificates(IEnumerable<X509Certificate2> certificates, string name)
        {
            List<byte[]> copies = new List<byte[]>();
            foreach (X509Certificate2 certificate in certificates)
            {
                if (certificate is null)
                {
                    throw new ArgumentException(name + " must not contain null", name);
                }

                byte[] der;
                try
                {
                    der = certificate.RawData;
                }
                catch (CryptographicException)
                {
                    der = Array.Empty<byte>();
                }

                if (der.Length == 0)
                {
                    throw new ArgumentException(name + " contains an unreadable certificate", name);
                }

                copies.Add(der);
            }

            return copies;
        }

        private static List<byte[]> CopyLists(IEnumerable<byte[]>? revocationLists)
        {
            List<byte[]> copies = new List<byte[]>();
            if (revocationLists is not null)
            {
                foreach (byte[] list in revocationLists)
                {
                    if (list is null)
                    {
                        throw new ArgumentException("revocationLists must not contain null", nameof(revocationLists));
                    }

                    copies.Add((byte[])list.Clone());
                }
            }

            return copies;
        }

        private static List<RevokedCertificate> CopyDistrust(IEnumerable<RevokedCertificate>? distrust)
        {
            List<RevokedCertificate> copies = new List<RevokedCertificate>();
            if (distrust is not null)
            {
                foreach (RevokedCertificate entry in distrust)
                {
                    if (entry is null)
                    {
                        throw new ArgumentException("distrust must not contain null", nameof(distrust));
                    }

                    copies.Add(entry);
                }
            }

            return copies;
        }

        private static long SystemClockMillis() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    }
}
