using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier;

namespace ApplePurchaseReceiptVerifier.Fuzz.Targets
{
    /// <summary>
    /// <c>IVerifier.VerifyReceipt(string)</c> fed the fuzzer's bytes as text
    /// directly — the transport form a client actually sends, with its own
    /// rule (canonical standard base64 only, so whitespace, the URL-safe
    /// alphabet and wrong padding are refused) and its own fixture family
    /// under <c>fixtures/generated/receipt-b64/</c>.
    /// </summary>
    /// <remarks>
    /// A separate target from <see cref="ReceiptDer"/>, which always hands
    /// canonical base64 of the fuzzer's bytes; this one exercises the base64
    /// decoder itself on arbitrary text.
    /// </remarks>
    internal sealed class ReceiptBase64 : IDisposable
    {
        private readonly IVerifier _verifier;
        private readonly List<X509Certificate2> _anchors;

        internal ReceiptBase64()
        {
            _anchors = new List<X509Certificate2>(Fixtures.AppleRoots()) { Fixtures.ReceiptRoot() };
            _verifier = Verifier.Create(new Config(roots: _anchors));
        }

        internal void Run(ReadOnlySpan<byte> data)
        {
            string text;
            try
            {
                text = new UTF8Encoding(false, true).GetString(data.ToArray());
            }
            catch (DecoderFallbackException)
            {
                return;
            }

            try
            {
                _verifier.VerifyReceipt(text);
            }
            catch (Exception e)
            {
                throw new InvariantException(
                    $"VerifyReceipt is documented as never throwing, but threw {e.GetType().FullName}: {e.Message}");
            }
        }

        public void Dispose()
        {
            foreach (X509Certificate2 anchor in _anchors)
            {
                anchor.Dispose();
            }
        }
    }
}
