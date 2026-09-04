using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Internal;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// The Apple root certificates bundled with this library — copies of the
    /// public roots from <see href="https://www.apple.com/certificateauthority/">Apple PKI</see>.
    /// These are the production trust anchors; tests use a generated fake PKI.
    /// </summary>
    /// <remarks>
    /// <para>Both sets contain all three published Apple roots (PLAN.md D15).
    /// Apple documents the JWS chain as ending in "an Apple root certificate",
    /// not a specific one, and its guidance is to trust every root on the PKI
    /// page — anchoring on a single root would break silently if Apple
    /// re-anchored a path.</para>
    /// <para>The bytes are compiled in, never read from disk at call time, and
    /// never fetched (PLAN.md D12). Each call returns fresh instances, so a
    /// caller disposing one set does not affect the next.</para>
    /// </remarks>
    public static class AppleRootCertificates
    {
        /// <summary>Trust anchors for StoreKit 2 / App Store Server JWS chains.</summary>
        public static IReadOnlyList<X509Certificate2> JwsRoots() => LoadAll();

        /// <summary>Trust anchors for legacy PKCS#7 app-receipt chains.</summary>
        public static IReadOnlyList<X509Certificate2> ReceiptRoots() => LoadAll();

        private static List<X509Certificate2> LoadAll()
        {
            List<X509Certificate2> roots = new List<X509Certificate2>(AppleRootData.All.Length);
            foreach (string base64 in AppleRootData.All)
            {
                X509Certificate2 root = Certificates.TryLoad(Convert.FromBase64String(base64))
                    ?? throw new InvalidOperationException("a bundled Apple root certificate is unreadable");
                roots.Add(root);
            }

            return roots;
        }
    }
}
