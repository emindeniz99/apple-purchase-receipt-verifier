using System;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// Decodes non-empty standard base64 (<c>[A-Za-z0-9+/]</c>) carrying
    /// exactly the canonical <c>=</c> padding for its length, and nothing
    /// else: the rule Apple's verifyReceipt applies to <c>receipt-data</c>
    /// (measured 2026-09-23, see
    /// <c>docs/evidence/2026-09-23-verifyreceipt-base64.md</c>) and the one
    /// RFC 7515 §4.1.6 gives an <c>x5c</c> entry. Unused low bits in the
    /// last data character are accepted, as Apple accepts them.
    /// </summary>
    /// <remarks>
    /// <see cref="Convert.FromBase64String"/> enforces the alphabet and the
    /// padding, but it skips space, tab, CR and LF anywhere and decodes the
    /// empty string. So the length and the characters are checked first: a
    /// non-zero multiple of four, and only the alphabet before at most two
    /// trailing <c>=</c>. <c>System.Buffers.Text.Base64</c> is not used: it
    /// refuses the trailing bits Apple accepts.
    /// </remarks>
    internal static class CanonicalBase64
    {
        /// <summary>The decoded bytes, or <see langword="null"/> when the
        /// text is not canonical standard base64.</summary>
        internal static byte[]? Decode(string text)
        {
            int length = text.Length;
            if (length == 0 || length % 4 != 0)
            {
                return null;
            }

            int dataLength = length;
            if (text[dataLength - 1] == '=')
            {
                dataLength--;
                if (text[dataLength - 1] == '=')
                {
                    dataLength--;
                }
            }

            for (int i = 0; i < dataLength; i++)
            {
                char c = text[i];
                if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                      || c == '+' || c == '/'))
                {
                    return null;
                }
            }

            try
            {
                return Convert.FromBase64String(text);
            }
            catch (FormatException)
            {
                return null;
            }
        }
    }
}
