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
        /// The 0.7 containment rule: a public entry point never throws at
        /// all — it returns a <c>VerificationResult</c> — so any exception
        /// reaching a target's own try/catch is itself the invariant failure.
        /// Every target throws <see cref="InvariantException"/> directly from
        /// that catch instead of routing through here.
        /// </summary>
        internal static void Contained(string entryPoint, Exception e)
        {
            throw new InvariantException($"{entryPoint} escaped as {e.GetType().FullName}: {e.Message}");
        }
    }
}
