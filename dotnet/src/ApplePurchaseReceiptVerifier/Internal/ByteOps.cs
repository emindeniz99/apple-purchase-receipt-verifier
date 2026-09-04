using System;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>Byte helpers that must behave identically on every target framework.</summary>
    internal static class ByteOps
    {
        /// <summary>
        /// Length-checked constant-time comparison.
        /// <c>CryptographicOperations.FixedTimeEquals</c> does not exist on
        /// netstandard2.0, so this is hand-written once and used on both TFMs —
        /// one code path, no behavioural fork.
        /// </summary>
        internal static bool FixedTimeEquals(byte[]? left, byte[]? right)
        {
            if (left is null || right is null || left.Length != right.Length)
            {
                return false;
            }

            int difference = 0;
            for (int i = 0; i < left.Length; i++)
            {
                difference |= left[i] ^ right[i];
            }

            return difference == 0;
        }

        /// <summary>Ordinary (non-constant-time) byte equality, for public structural data.</summary>
        internal static bool SequenceEqual(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            if (left.Length != right.Length)
            {
                return false;
            }

            for (int i = 0; i < left.Length; i++)
            {
                if (left[i] != right[i])
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>A defensive copy; <see langword="null"/> stays <see langword="null"/>.</summary>
        internal static byte[]? Copy(byte[]? value)
        {
            if (value is null)
            {
                return null;
            }

            byte[] copy = new byte[value.Length];
            Buffer.BlockCopy(value, 0, copy, 0, value.Length);
            return copy;
        }

        /// <summary>Lowercase hex, the spelling the conformance vectors use for byte fields.</summary>
        internal static string ToHex(byte[] value)
        {
            char[] chars = new char[value.Length * 2];
            const string Digits = "0123456789abcdef";
            for (int i = 0; i < value.Length; i++)
            {
                chars[(i * 2) + 0] = Digits[value[i] >> 4];
                chars[(i * 2) + 1] = Digits[value[i] & 0xF];
            }

            return new string(chars);
        }
    }
}
