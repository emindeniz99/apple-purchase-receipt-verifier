using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Receipt;

namespace ApplePurchaseReceiptVerifier.Fuzz.Targets
{
    /// <summary>
    /// The whole legacy-receipt path on DER bytes: the structural pre-scan,
    /// then <c>SignedCms</c> (BER), the payload parse, the chain build and the
    /// signature check.
    /// </summary>
    /// <remarks>
    /// The invariants are the Go port's three. Nothing may escape but a
    /// <see cref="VerificationException"/>; the pre-scan and the full path must
    /// agree on the certificate bound; and an accepted receipt is accepted
    /// <em>because of</em> the anchors, proven by re-running it against an
    /// unrelated anchor set and requiring failure. Without that last one a
    /// fuzzer finds crashes and never "accepts what it should not".
    /// <para>The trusted set is the pinned Apple roots plus the generated
    /// fixture receipt root, so the shared fixtures and the two public Apple
    /// receipts get past the chain check and the fuzzer can explore what lies
    /// beyond it. The unrelated set is the fixture <em>JWS</em> root.</para>
    /// </remarks>
    internal sealed class ReceiptDer : IDisposable
    {
        private readonly List<X509Certificate2> _trusted;
        private readonly List<X509Certificate2> _unrelated;

        internal ReceiptDer()
        {
            _trusted = new List<X509Certificate2>(AppleRootCertificates.ReceiptRoots())
            {
                Fixtures.ReceiptRoot(),
            };
            _unrelated = new List<X509Certificate2> { Fixtures.JwsRoot() };
        }

        internal void Run(ReadOnlySpan<byte> data)
        {
            byte[] der = data.ToArray();

            // The pre-scan runs before SignedCms sees anything, so fuzz it
            // both as the library calls it and on its own: its refusal to
            // decode a certificate is what keeps a certificate flood cheap,
            // and a leak here is a leak before any bound applies.
            int embedded;
            try
            {
                embedded = Internals.CmsPreScan(der, Internals.MaxEmbeddedCertificates);
            }
            catch (Exception e)
            {
                Invariant.Contained("CmsPreScan.Scan", e);
                embedded = -1;
            }

            AppReceipt receipt;
            try
            {
                receipt = ReceiptVerifier.VerifyReceiptCore(der, _trusted);
            }
            catch (Exception e)
            {
                Invariant.Contained("VerifyReceiptCore", e);
                return;
            }

            Invariant.Require(receipt is not null, "a receipt that verified came back null");
            Invariant.Require(
                embedded >= 0 && embedded <= Internals.MaxEmbeddedCertificates,
                $"a receipt verified while the pre-scan counted {embedded} embedded certificates");

            try
            {
                ReceiptVerifier.VerifyReceiptCore(der, _unrelated);
            }
            catch (VerificationException)
            {
                return;
            }

            throw new InvariantException(
                "this input verifies against an unrelated anchor set too, "
                + "so the anchors are not being enforced");
        }

        public void Dispose()
        {
            foreach (X509Certificate2 anchor in _trusted)
            {
                anchor.Dispose();
            }

            foreach (X509Certificate2 anchor in _unrelated)
            {
                anchor.Dispose();
            }
        }
    }
}
