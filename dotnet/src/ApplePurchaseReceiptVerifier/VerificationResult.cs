using System;
using System.Diagnostics.CodeAnalysis;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// The outcome of one <see cref="IVerifier"/> call: either a verified
    /// <typeparamref name="T"/>, or a <see cref="Failure"/>. Exactly one of
    /// <see cref="Payload"/> and <see cref="Failure"/> is non-null.
    /// </summary>
    public sealed class VerificationResult<T>
        where T : class
    {
        private VerificationResult(T? payload, Failure? failure)
        {
            Payload = payload;
            Failure = failure;
        }

        /// <summary>Whether the input verified.</summary>
        [MemberNotNullWhen(true, nameof(Payload))]
        [MemberNotNullWhen(false, nameof(Failure))]
        public bool Verified => Payload is not null;

        /// <summary>The verified payload, or <see langword="null"/> when verification failed.</summary>
        public T? Payload { get; }

        /// <summary>Why verification failed, or <see langword="null"/> when it verified.</summary>
        public Failure? Failure { get; }

        /// <summary>A verified result carrying <paramref name="payload"/>; for callers mocking <see cref="IVerifier"/>.</summary>
        /// <exception cref="ArgumentNullException"><paramref name="payload"/> is <see langword="null"/>.</exception>
        public static VerificationResult<T> Of(T payload) =>
            new VerificationResult<T>(payload ?? throw new ArgumentNullException(nameof(payload)), null);

        /// <summary>A failed result; for callers mocking <see cref="IVerifier"/>.</summary>
        /// <exception cref="ArgumentNullException"><paramref name="failure"/> is <see langword="null"/>.</exception>
        public static VerificationResult<T> Failed(Failure failure) =>
            new VerificationResult<T>(null, failure ?? throw new ArgumentNullException(nameof(failure)));

        internal static VerificationResult<T> Ok(T payload) => new VerificationResult<T>(payload, null);

        internal static VerificationResult<T> Failed(VerificationReason reason, string message, Exception? cause) =>
            new VerificationResult<T>(null, new Failure(reason, message, cause));

        /// <summary>
        /// The public view of <paramref name="e"/>. Its inner exception is kept
        /// only where it explains Apple-signed content that did not parse, or
        /// the library's own failure; for any other reason it describes input
        /// nobody vouched for, and a library message can quote that input.
        /// </summary>
        internal static VerificationResult<T> Failed(VerificationException e) =>
            Failed(
                e.Reason,
                e.Detail,
                e.Reason is VerificationReason.UnreadablePayload or VerificationReason.InternalError
                    ? e.InnerException
                    : null);
    }
}
