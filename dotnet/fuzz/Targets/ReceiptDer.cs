using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier;

namespace ApplePurchaseReceiptVerifier.Fuzz.Targets
{
    /// <summary>
    /// The whole legacy-receipt path on DER bytes, re-encoded as the base64
    /// string the 0.7 API takes: the CMS structural parse, the payload parse,
    /// the chain build and the signature check.
    /// </summary>
    /// <remarks>
    /// Nothing may escape but a result carrying a <see cref="Failure"/>; and
    /// an accepted receipt is accepted <em>because of</em> the anchors,
    /// proven by re-running it against an unrelated anchor set and requiring
    /// failure. Without that last one a fuzzer finds crashes and never
    /// "accepts what it should not".
    /// <para>The trusted set is the pinned Apple roots plus the generated
    /// fixture receipt root, so the shared fixtures and the two public Apple
    /// receipts get past the chain check and the fuzzer can explore what lies
    /// beyond it. The unrelated set is the fixture <em>JWS</em> root.</para>
    /// </remarks>
    internal sealed class ReceiptDer : IDisposable
    {
        private readonly IVerifier _trusted;
        private readonly IVerifier _unrelated;
        private readonly List<X509Certificate2> _trustedRoots;
        private readonly List<X509Certificate2> _unrelatedRoots;

        internal ReceiptDer()
        {
            _trustedRoots = new List<X509Certificate2>(Fixtures.AppleRoots()) { Fixtures.ReceiptRoot() };
            _unrelatedRoots = new List<X509Certificate2> { Fixtures.JwsRoot() };
            _trusted = Verifier.Create(Config.CreateBuilder().Roots(_trustedRoots).Build());
            _unrelated = Verifier.Create(Config.CreateBuilder().Roots(_unrelatedRoots).Build());
        }

        internal void Run(ReadOnlySpan<byte> data)
        {
            string base64 = Convert.ToBase64String(data);

            VerificationResult<ReceiptPayload> result;
            try
            {
                result = _trusted.VerifyReceipt(base64);
            }
            catch (Exception e)
            {
                throw new InvariantException(
                    $"VerifyReceipt is documented as never throwing, but threw {e.GetType().FullName}: {e.Message}");
            }

            if (!result.Verified)
            {
                return;
            }

            Invariant.Require(result.Payload is not null, "a receipt that verified came back with no payload");

            VerificationResult<ReceiptPayload> retry = _unrelated.VerifyReceipt(base64);
            if (!retry.Verified)
            {
                return;
            }

            throw new InvariantException(
                "this input verifies against an unrelated anchor set too, "
                + "so the anchors are not being enforced");
        }

        public void Dispose()
        {
            foreach (X509Certificate2 anchor in _trustedRoots)
            {
                anchor.Dispose();
            }

            foreach (X509Certificate2 anchor in _unrelatedRoots)
            {
                anchor.Dispose();
            }
        }
    }
}
