using System;
using System.Collections.Generic;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>Typed reads over the claim model the JSON reader produces.</summary>
    internal static class Claims
    {
        /// <summary>The claim as a string, or <see langword="null"/> if absent or another type.</summary>
        internal static string? String(IReadOnlyDictionary<string, object?> claims, string name)
        {
            return claims.TryGetValue(name, out object? value) ? value as string : null;
        }

        /// <summary>
        /// The claim as a JSON number, or <see langword="null"/> if absent or
        /// another type. Every numeric shape the reader can produce is a
        /// number, fractional and out-of-range ones included: whether a stated
        /// value is <em>usable</em> is the caller's decision, and reading a
        /// present claim as absent would silently skip a check instead of
        /// failing it.
        /// </summary>
        internal static double? Number(IReadOnlyDictionary<string, object?> claims, string name)
        {
            if (!claims.TryGetValue(name, out object? value))
            {
                return null;
            }

            switch (value)
            {
                case long l:
                    return l;
                case double d:
                    return d;
                default:
                    return null;
            }
        }

        /// <summary>
        /// The claim as a 64-bit integer, or <see langword="null"/> if absent
        /// or not exactly representable as one. A fractional number is not an
        /// epoch-millisecond claim, so it is read as absent rather than
        /// truncated.
        /// </summary>
        internal static long? Int64(IReadOnlyDictionary<string, object?> claims, string name)
        {
            if (!claims.TryGetValue(name, out object? value))
            {
                return null;
            }

            switch (value)
            {
                case long l:
                    return l;
                case double d when d >= -9.2233720368547758E18 && d <= 9.2233720368547758E18 && d == Math.Floor(d):
                    return (long)d;
                default:
                    return null;
            }
        }

        /// <summary>The claim as a 32-bit integer, or <see langword="null"/>.</summary>
        internal static int? Int32(IReadOnlyDictionary<string, object?> claims, string name)
        {
            long? value = Int64(claims, name);
            return value is >= int.MinValue and <= int.MaxValue ? (int)value.Value : null;
        }
    }
}
