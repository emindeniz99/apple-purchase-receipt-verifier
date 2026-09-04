using System;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// Thrown when a signed payload fails verification. <see cref="Reason"/> is
    /// the machine-readable cause; the message carries human-readable detail.
    /// A payload that throws must be treated as fully untrusted — this library
    /// never returns a partially verified result.
    /// </summary>
    /// <remarks>
    /// Misconfiguration is not a verification verdict: an empty trust-anchor
    /// set, a null bundle id or an empty accepted-environment set raise
    /// <see cref="ArgumentException"/> from the constructor instead.
    /// </remarks>
#if NETSTANDARD2_0
    [Serializable]
#endif
    public class VerificationException : Exception
    {
        /// <summary>Creates an exception carrying <paramref name="reason"/>.</summary>
        public VerificationException(VerificationReason reason, string message)
            : base(VerificationReasonCodes.ToCode(reason) + ": " + message)
        {
            Reason = reason;
        }

        /// <summary>Creates an exception carrying <paramref name="reason"/> and an inner cause.</summary>
        public VerificationException(VerificationReason reason, string message, Exception? innerException)
            : base(VerificationReasonCodes.ToCode(reason) + ": " + message, innerException)
        {
            Reason = reason;
        }

#if NETSTANDARD2_0
        /// <summary>Deserialization constructor (netstandard2.0 only).</summary>
        protected VerificationException(System.Runtime.Serialization.SerializationInfo info,
            System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        {
            Reason = (VerificationReason)info.GetInt32(nameof(Reason));
        }

        /// <inheritdoc/>
        public override void GetObjectData(System.Runtime.Serialization.SerializationInfo info,
            System.Runtime.Serialization.StreamingContext context)
        {
            if (info is null)
            {
                throw new ArgumentNullException(nameof(info));
            }

            base.GetObjectData(info, context);
            info.AddValue(nameof(Reason), (int)Reason);
        }
#endif

        /// <summary>The machine-readable cause. Switch on this, never on the message.</summary>
        public VerificationReason Reason { get; }

        /// <summary>
        /// The canonical cross-port token for <see cref="Reason"/>, e.g.
        /// <c>"INVALID_CHAIN"</c> — the spelling to put in telemetry.
        /// </summary>
        public string ReasonCode => VerificationReasonCodes.ToCode(Reason);
    }
}
