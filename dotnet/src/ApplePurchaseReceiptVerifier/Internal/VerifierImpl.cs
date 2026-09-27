using System;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>The one <see cref="IVerifier"/> implementation. Immutable, thread-safe, never throws.</summary>
    internal sealed class VerifierImpl : IVerifier
    {
        private readonly Config _config;

        internal VerifierImpl(Config config)
        {
            _config = config;
        }

        public VerificationResult<ReceiptPayload> VerifyReceipt(string base64)
        {
            try
            {
                return VerificationResult<ReceiptPayload>.Ok(
                    ReceiptVerifierCore.Verify(base64, _config.Roots, _config.Clock));
            }
            catch (VerificationException e)
            {
                return VerificationResult<ReceiptPayload>.Failed(e);
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                return VerificationResult<ReceiptPayload>.Failed(VerificationReason.InternalError, "unexpected error", e);
            }
        }

        public VerificationResult<JsonPayload> VerifySignedData(string jws)
        {
            try
            {
                return VerificationResult<JsonPayload>.Ok(
                    JwsVerifierCore.Verify(jws, _config.Roots, _config.Clock));
            }
            catch (VerificationException e)
            {
                return VerificationResult<JsonPayload>.Failed(e);
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                return VerificationResult<JsonPayload>.Failed(VerificationReason.InternalError, "unexpected error", e);
            }
        }

        public string VerifyReceiptEndpoint(AppleEnvironment environment, string requestJson)
        {
            if (environment != AppleEnvironment.Production && environment != AppleEnvironment.Sandbox)
            {
                throw new ArgumentOutOfRangeException(nameof(environment));
            }

            return EndpointCore.Verify(environment, requestJson, _config.Roots, _config.Clock);
        }
    }
}
