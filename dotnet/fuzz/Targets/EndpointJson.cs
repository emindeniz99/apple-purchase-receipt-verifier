using System;
using System.Collections.Generic;
using System.Text;
using ApplePurchaseReceiptVerifier.Receipt;

namespace ApplePurchaseReceiptVerifier.Fuzz.Targets
{
    /// <summary>
    /// <c>VerifyReceiptEndpoint.VerifyReceiptJson</c> — the one entry point
    /// that takes a request body rather than a receipt: JSON parse,
    /// <c>receipt-data</c> extraction, the base64 rule, then the DER path.
    /// </summary>
    /// <remarks>
    /// Its documented contract is that it never throws and that every body,
    /// whatever the bytes, gets a JSON object with a numeric <c>status</c>
    /// back. That is the invariant asserted after each call — and it is
    /// stronger than "no crash", because the failure mode this endpoint
    /// actually has is answering something a client cannot parse.
    /// </remarks>
    internal sealed class EndpointJson : IDisposable
    {
        private readonly VerifyReceiptEndpoint _endpoint;

        internal EndpointJson()
        {
            _endpoint = new VerifyReceiptEndpoint(
                AppleRootCertificates.ReceiptRoots(), AppleEnvironment.Sandbox);
        }

        internal void Run(ReadOnlySpan<byte> data)
        {
            string body;
            try
            {
                body = new UTF8Encoding(false, true).GetString(data.ToArray());
            }
            catch (DecoderFallbackException)
            {
                return;
            }

            string response;
            try
            {
                response = _endpoint.VerifyReceiptJson(body);
            }
            catch (Exception e)
            {
                throw new InvariantException(
                    $"VerifyReceiptJson is documented as never throwing, but threw "
                    + $"{e.GetType().FullName}: {e.Message}");
            }

            object? parsed;
            try
            {
                parsed = Internals.JsonParse(response);
            }
            catch (Exception e)
            {
                throw new InvariantException(
                    $"the endpoint answered something that is not JSON ({e.GetType().FullName}): {response}");
            }

            Invariant.Require(
                parsed is IReadOnlyDictionary<string, object?> map
                    && map.TryGetValue("status", out object? status)
                    && status is long,
                $"the endpoint answers with a numeric status: {response}");
        }

        public void Dispose() => _endpoint.Dispose();
    }
}
