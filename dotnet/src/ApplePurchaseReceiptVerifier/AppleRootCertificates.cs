using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Internal;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// The Apple root certificates bundled with this library — copies of the
    /// public roots from <see href="https://www.apple.com/certificateauthority/">Apple PKI</see>.
    /// The verifier's own copy of the same roots is pinned inside its
    /// verification module and is what <see cref="Config.Defaults"/> trusts;
    /// this list is for callers who want to trust Apple's roots and one of
    /// their own (pass all of them to <see cref="Config.Builder.Roots"/>).
    /// </summary>
    /// <remarks>
    /// <para>Apple documents both the receipt and the JWS chain as ending in
    /// "an Apple root certificate", not a specific one, and its guidance is to
    /// trust every root on the PKI page — anchoring on a single root would
    /// break silently if Apple re-anchored a path. One bundled set covers
    /// both <see cref="IVerifier.VerifyReceipt"/> and
    /// <see cref="IVerifier.VerifySignedData"/>.</para>
    /// <para>The bytes are compiled in, never read from disk at call time, and
    /// never fetched. Each call returns fresh instances, so a caller disposing
    /// one set does not affect the next.</para>
    /// </remarks>
    public static class AppleRootCertificates
    {
        /// <summary>The bundled trust anchors, one fresh set per call.</summary>
        public static IReadOnlyList<X509Certificate2> Bundled()
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
