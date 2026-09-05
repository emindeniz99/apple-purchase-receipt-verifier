using System;

namespace ApplePurchaseReceiptVerifier.Fuzz
{
    /// <summary>Thrown when a fuzz target's invariant does not hold.</summary>
    /// <remarks>
    /// Escaping the target action is what SharpFuzz reports to libFuzzer as a
    /// crash, so this is how an invariant failure — as opposed to a plain
    /// unhandled exception from the library — reaches the artifact directory.
    /// </remarks>
    internal sealed class InvariantException : Exception
    {
        internal InvariantException(string message)
            : base(message)
        {
        }
    }

    /// <summary>The assertions every target shares.</summary>
    internal static class Invariant
    {
        /// <summary>Fails the execution when <paramref name="condition"/> is false.</summary>
        internal static void Require(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvariantException(message);
            }
        }

        /// <summary>
        /// The containment rule: the only thing a public entry point may throw
        /// is the library's own <see cref="VerificationException"/>.
        /// </summary>
        /// <remarks>
        /// Stated categorically rather than as a deny-list of
        /// <c>IndexOutOfRangeException</c> / <c>NullReferenceException</c> /
        /// <c>CryptographicException</c>: the interesting leak is always the
        /// type nobody thought to list — <c>AsnContentException</c> derives
        /// from <see cref="Exception"/> and not from
        /// <c>CryptographicException</c>, which is exactly how a type-by-type
        /// catch springs a leak.
        /// </remarks>
        internal static void Contained(string entryPoint, Exception e)
        {
            if (e is VerificationException)
            {
                return;
            }

            throw new InvariantException(
                $"{entryPoint} escaped as {e.GetType().FullName}: {e.Message}");
        }
    }
}
