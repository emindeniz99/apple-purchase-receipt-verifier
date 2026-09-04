using System;
using System.Formats.Asn1;
using System.Numerics;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// Converts ECDSA signatures between the two encodings this library meets.
    /// </summary>
    /// <remarks>
    /// <para>.NET's <c>ECDsa.VerifyData(data, signature, hash)</c> expects IEEE
    /// P1363 <c>r‖s</c> — the opposite of the OpenSSL/JCA default. A JWS ES256
    /// signature is already P1363 (RFC 7515) and is passed straight through; an
    /// X.509 certificate signature is DER <c>SEQUENCE { r, s }</c> and must be
    /// converted first. Getting this backwards is a silent
    /// <c>INVALID_CHAIN</c> on every ECDSA-signed certificate.</para>
    /// <para>The <c>DSASignatureFormat</c> overloads that would do this exist
    /// only from net5.0, so the conversion is hand-written once and used on
    /// both target frameworks.</para>
    /// </remarks>
    internal static class EcdsaSignatureFormat
    {
        /// <summary>
        /// DER <c>SEQUENCE { INTEGER r, INTEGER s }</c> to <c>r‖s</c>, each
        /// left-padded to <paramref name="fieldSizeBytes"/>.
        /// </summary>
        /// <returns><see langword="null"/> when the input is not a well-formed
        /// signature for a field of that size — a failed check, never a
        /// "skip the check".</returns>
        internal static byte[]? DerToP1363(byte[] der, int fieldSizeBytes)
        {
            if (der is null || der.Length == 0 || fieldSizeBytes <= 0)
            {
                return null;
            }

            BigInteger r;
            BigInteger s;
            try
            {
                AsnReader reader = new AsnReader(der, AsnEncodingRules.DER);
                AsnReader sequence = reader.ReadSequence();
                r = sequence.ReadInteger();
                s = sequence.ReadInteger();
                if (sequence.HasData || reader.HasData)
                {
                    return null;
                }
            }
            catch (AsnContentException)
            {
                return null;
            }

            byte[] output = new byte[fieldSizeBytes * 2];
            if (!TryWriteUnsigned(r, output, 0, fieldSizeBytes)
                || !TryWriteUnsigned(s, output, fieldSizeBytes, fieldSizeBytes))
            {
                return null;
            }

            return output;
        }

        private static bool TryWriteUnsigned(BigInteger value, byte[] destination, int offset, int size)
        {
            if (value.Sign <= 0)
            {
                return false;
            }

            byte[] magnitude = value.ToByteArray();
            Array.Reverse(magnitude);

            // BigInteger.ToByteArray is two's complement, so a value whose top
            // bit is set carries a leading 0x00. Drop it, then require the rest
            // to fit the field — a longer value is malformed, not truncatable.
            int start = 0;
            while (start < magnitude.Length - 1 && magnitude[start] == 0)
            {
                start++;
            }

            int length = magnitude.Length - start;
            if (length > size)
            {
                return false;
            }

            Buffer.BlockCopy(magnitude, start, destination, offset + size - length, length);
            return true;
        }
    }
}
