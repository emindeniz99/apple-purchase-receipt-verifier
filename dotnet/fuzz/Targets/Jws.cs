using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier;

namespace ApplePurchaseReceiptVerifier.Fuzz.Targets
{
    /// <summary>
    /// The StoreKit 2 path: compact-JWS split, strict base64url, JSON header
    /// and payload, the <c>x5c</c> certificates, the chain, then the ES256
    /// signature.
    /// </summary>
    /// <remarks>
    /// Nothing but a result carrying a <see cref="Failure"/> ever comes back,
    /// and a JWS that verifies under the generated fixture root must be
    /// refused under Apple's real roots, <c>new Config()</c> — otherwise
    /// the anchors are not what decided it.
    /// </remarks>
    internal sealed class Jws : IDisposable
    {
        private readonly IVerifier _fixture;
        private readonly IVerifier _unrelated;
        private readonly X509Certificate2 _root;

        internal Jws()
        {
            _root = Fixtures.JwsRoot();
            _fixture = Verifier.Create(new Config(roots: new[] { _root }));
            _unrelated = Verifier.Create(new Config());
        }

        internal void Run(ReadOnlySpan<byte> data)
        {
            string jws;
            try
            {
                jws = new UTF8Encoding(false, true).GetString(data.ToArray());
            }
            catch (DecoderFallbackException)
            {
                return;
            }

            VerificationResult<JsonPayload> result;
            try
            {
                result = _fixture.VerifySignedData(jws);
            }
            catch (Exception e)
            {
                throw new InvariantException(
                    $"VerifySignedData is documented as never throwing, but threw {e.GetType().FullName}: {e.Message}");
            }

            if (!result.Verified)
            {
                return;
            }

            VerificationResult<JsonPayload> retry = _unrelated.VerifySignedData(jws);
            if (!retry.Verified)
            {
                return;
            }

            throw new InvariantException(
                "this input verifies against Apple's roots too, "
                + "so the anchors are not being enforced");
        }

        public void Dispose() => _root.Dispose();
    }
}
