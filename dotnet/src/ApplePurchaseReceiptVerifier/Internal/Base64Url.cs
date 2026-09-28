using System;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// RFC 7515 §2 base64url: unpadded, canonical, <c>A-Za-z0-9-_</c> only.
    /// </summary>
    internal static class Base64Url
    {
        /// <summary>
        /// Decodes <paramref name="value"/>, or returns <see langword="null"/>
        /// when it is not canonical base64url: any character outside the
        /// alphabet (this also rejects <c>=</c>, <c>+</c> and <c>/</c>), an
        /// impossible length, or a segment whose final character carries
        /// non-zero unused bits (checked by requiring the decoded bytes to
        /// re-encode to the same string).
        /// </summary>
        internal static byte[]? Decode(string value)
        {
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                bool isValid =
                    (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_';
                if (!isValid)
                {
                    return null;
                }
            }

            string standard = value.Replace('-', '+').Replace('_', '/');
            switch (standard.Length % 4)
            {
                case 2: standard += "=="; break;
                case 3: standard += "="; break;
                case 1: return null;
                default: break;
            }

            byte[] decoded;
            try
            {
                decoded = Convert.FromBase64String(standard);
            }
            catch (FormatException)
            {
                return null;
            }

            string reencoded = Convert.ToBase64String(decoded).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            return string.Equals(reencoded, value, StringComparison.Ordinal) ? decoded : null;
        }
    }
}
