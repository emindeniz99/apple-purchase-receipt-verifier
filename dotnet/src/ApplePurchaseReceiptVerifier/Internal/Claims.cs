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
        /// The claim of a typed payload model as a string, or
        /// <see langword="null"/> if absent or JSON null.
        /// </summary>
        /// <exception cref="VerificationException">
        /// <see cref="VerificationReason.InternalError"/>: the claim is another type.
        /// </exception>
        internal static string? TypedString(IReadOnlyDictionary<string, object?> claims, string name)
        {
            if (!claims.TryGetValue(name, out object? value) || value is null)
            {
                return null;
            }

            return value as string ?? throw NotA(name, "string");
        }

        /// <summary>
        /// The claim of a typed payload model as a 64-bit integer, or
        /// <see langword="null"/> if absent or JSON null. A whole-number
        /// double such as <c>1.0</c> is read as its integer.
        /// </summary>
        /// <exception cref="VerificationException">
        /// <see cref="VerificationReason.InternalError"/>: the claim is not a
        /// number, is fractional, or is outside the 64-bit range. A signed
        /// payload the model cannot hold is this library's problem to report,
        /// not a claim to read as absent, which would silently skip any check
        /// made on it.
        /// </exception>
        internal static long? Int64(IReadOnlyDictionary<string, object?> claims, string name)
        {
            return Integer(claims, name, "64-bit integer");
        }

        /// <summary>The claim of a typed payload model as a 32-bit integer; see <see cref="Int64"/>.</summary>
        internal static int? Int32(IReadOnlyDictionary<string, object?> claims, string name)
        {
            long? value = Integer(claims, name, "32-bit integer");
            if (value is < int.MinValue or > int.MaxValue)
            {
                throw NotA(name, "32-bit integer");
            }

            return (int?)value;
        }

        private static long? Integer(IReadOnlyDictionary<string, object?> claims, string name, string type)
        {
            if (!claims.TryGetValue(name, out object? value) || value is null)
            {
                return null;
            }

            switch (value)
            {
                case long l:
                    return l;
                // 2^63 itself is a double but not a long, hence the open upper bound.
                case double d when d >= -9.2233720368547758E18 && d < 9.2233720368547758E18 && d == Math.Floor(d):
                    return (long)d;
                default:
                    throw NotA(name, type);
            }
        }

        private static VerificationException NotA(string name, string type)
        {
            return new VerificationException(
                VerificationReason.InternalError, "signed payload claim " + name + " is not a " + type);
        }
    }
}
