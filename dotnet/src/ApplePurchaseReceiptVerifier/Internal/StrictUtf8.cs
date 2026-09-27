using System.Text;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>Strict UTF-8 decoding: invalid bytes fail rather than becoming U+FFFD.</summary>
    internal static class StrictUtf8
    {
        private static readonly UTF8Encoding Strict = new UTF8Encoding(
            encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        /// <summary>Decodes <paramref name="bytes"/>, or returns <see langword="null"/> when they are not valid UTF-8.</summary>
        internal static string? Decode(byte[] bytes)
        {
            try
            {
                return Strict.GetString(bytes);
            }
            catch (DecoderFallbackException)
            {
                return null;
            }
        }
    }
}
