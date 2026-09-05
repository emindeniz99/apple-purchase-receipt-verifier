using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier.Receipt;

namespace ApplePurchaseReceiptVerifier.Fuzz.Targets
{
    /// <summary>
    /// <c>ReceiptVerifier.Verify(string)</c> — the base64 string a client
    /// actually sends, with the decoder in front of the DER path.
    /// </summary>
    /// <remarks>
    /// A separate target from <see cref="ReceiptDer"/> because the transport
    /// form has its own rules (whitespace, PEM line breaks, URL-safe alphabet,
    /// padding) and its own fixture family under
    /// <c>fixtures/generated/receipt-b64/</c>. The bundle id is the genuine
    /// fixture's, so a real receipt reaches the claim check rather than
    /// stopping at WRONG_BUNDLE_ID; the device-guid overload is driven too,
    /// splitting the input so the SHA-1 binding is reachable.
    /// </remarks>
    internal sealed class ReceiptBase64 : IDisposable
    {
        private readonly ReceiptVerifier _verifier;
        private readonly List<X509Certificate2> _anchors;

        internal ReceiptBase64()
        {
            _anchors = new List<X509Certificate2>(AppleRootCertificates.ReceiptRoots())
            {
                Fixtures.ReceiptRoot(),
            };
            _verifier = new ReceiptVerifier(_anchors, "dev.bonzer.weeka.app");
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
                _verifier.Verify(text);
            }
            catch (Exception e)
            {
                Invariant.Contained("ReceiptVerifier.Verify(string)", e);
            }

            // The 16-byte identifierForVendor overload, driven from the head of
            // the same input so the device-hash branch is reachable at all.
            if (data.Length < 16)
            {
                return;
            }

            byte[] guid = data.Slice(0, 16).ToArray();
            try
            {
                _verifier.Verify(text, guid);
            }
            catch (Exception e)
            {
                Invariant.Contained("ReceiptVerifier.Verify(string, byte[])", e);
            }
        }

        public void Dispose()
        {
            _verifier.Dispose();
            foreach (X509Certificate2 anchor in _anchors)
            {
                anchor.Dispose();
            }
        }
    }
}
