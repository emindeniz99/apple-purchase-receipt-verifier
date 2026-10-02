using System;
using System.Text;
using System.Text.Json;
using ApplePurchaseReceiptVerifier;

namespace ApplePurchaseReceiptVerifier.Fuzz.Targets
{
    /// <summary>
    /// <c>IVerifier.VerifyReceiptEndpoint</c> — the one entry point that
    /// takes a request body rather than a receipt: JSON parse,
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
        private readonly IVerifier _verifier;

        internal EndpointJson()
        {
            _verifier = Verifier.Create(Config.Defaults());
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
                response = _verifier.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, body);
            }
            catch (Exception e)
            {
                throw new InvariantException(
                    $"VerifyReceiptEndpoint is documented as never throwing, but threw "
                    + $"{e.GetType().FullName}: {e.Message}");
            }

            bool numericStatus;
            try
            {
                using (JsonDocument parsed = JsonDocument.Parse(response))
                {
                    numericStatus = parsed.RootElement.ValueKind == JsonValueKind.Object
                        && parsed.RootElement.TryGetProperty("status", out JsonElement status)
                        && status.ValueKind == JsonValueKind.Number
                        && status.TryGetInt64(out _);
                }
            }
            catch (Exception e)
            {
                throw new InvariantException(
                    $"the endpoint answered something that is not JSON ({e.GetType().FullName}): {response}");
            }

            Invariant.Require(numericStatus, $"the endpoint answers with a numeric status: {response}");
        }

        public void Dispose()
        {
        }
    }
}
