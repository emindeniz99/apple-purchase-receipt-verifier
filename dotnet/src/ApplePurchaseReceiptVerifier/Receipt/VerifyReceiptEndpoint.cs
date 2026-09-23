using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Internal;
using Result = ApplePurchaseReceiptVerifier.Receipt.VerifyReceiptResult;

namespace ApplePurchaseReceiptVerifier.Receipt
{
    /// <summary>
    /// A drop-in local replacement for Apple's deprecated <c>verifyReceipt</c>
    /// endpoint: the same request body, the same response body shape, the same
    /// status codes — verified offline against pinned Apple roots instead of by
    /// calling Apple.
    /// </summary>
    /// <remarks>
    /// <para>Field-by-field fidelity and the unavoidable gaps (fields that only
    /// exist in Apple's server-side subscription database, such as
    /// <c>latest_receipt_info</c>) are documented in COMPARISON.md.</para>
    /// <para>Like Apple's endpoint, this does <strong>not</strong> check the
    /// bundle id — the caller compares <c>receipt.bundle_id</c>, exactly as
    /// with the real endpoint. It never throws: every call returns a
    /// <see cref="Result"/>, and a failure is reported through its
    /// status and failure reason.</para>
    /// </remarks>
    public sealed class VerifyReceiptEndpoint : IDisposable
    {
        /// <summary>The receipt verified.</summary>
        public const int StatusOk = 0;

        /// <summary>The request or its <c>receipt-data</c> property was malformed.</summary>
        public const int StatusMalformed = 21002;

        /// <summary>The receipt could not be authenticated.</summary>
        public const int StatusNotAuthenticated = 21003;

        /// <summary>A sandbox receipt was sent to the production environment.</summary>
        public const int StatusSandboxReceiptOnProduction = 21007;

        /// <summary>A production receipt was sent to the sandbox environment.</summary>
        public const int StatusProductionReceiptOnSandbox = 21008;

        /// <summary>An internal error.</summary>
        public const int StatusInternal = 21009;

        /// <summary>
        /// The longest raw request body <see cref="VerifyReceiptResult(string, DateTimeOffset?)"/>
        /// will parse: 3 MiB (3,145,728), counted in UTF-8 bytes, Apple's own
        /// limit. A longer one fails with
        /// <see cref="VerificationReason.RequestTooLarge"/>, status 21002,
        /// before it is parsed.
        /// </summary>
        /// <remarks>
        /// Measured on 2026-09-23 against both of Apple's verifyReceipt
        /// endpoints, a body of 3,145,728 bytes is answered and one of
        /// 3,145,729 bytes gets HTTP 413, and the count is bytes, not
        /// characters. The body is measured without being encoded, so a string
        /// of any size costs no copy to refuse. A fixed constant, the same in
        /// every port: JSON parsing allocates a multiple of the body before
        /// any verification, so the bound is what keeps "never throws" true on
        /// hostile input.
        /// </remarks>
        public const int MaxRequestBytes = 3145728;

        private readonly List<X509Certificate2> _anchors;
        private readonly AppleEnvironment _environment;
        private readonly IClock _clock;
        private readonly TimeZoneInfo _pacific;
        private bool _disposed;

        /// <summary>Builds an endpoint.</summary>
        /// <param name="trustedRoots">
        /// Pinned root CAs — in production
        /// <see cref="AppleRootCertificates.ReceiptRoots"/>.
        /// </param>
        /// <param name="environment">
        /// Which environment this instance emulates; drives the 21007/21008
        /// routing. Only <see cref="AppleEnvironment.Production"/> and
        /// <see cref="AppleEnvironment.Sandbox"/> exist on Apple's endpoint.
        /// </param>
        /// <param name="clock">
        /// Source of "now" for the <c>request_date</c> triple, which Apple
        /// stamps with the time the request was answered. It does not reach
        /// receipt verification — see <see cref="IClock"/>.
        /// </param>
        /// <exception cref="ArgumentException">
        /// The roots are empty, or the environment is neither Production nor
        /// Sandbox.
        /// </exception>
        public VerifyReceiptEndpoint(
            IEnumerable<X509Certificate2> trustedRoots,
            AppleEnvironment environment,
            IClock? clock = null)
        {
            if (environment != AppleEnvironment.Production && environment != AppleEnvironment.Sandbox)
            {
                throw new ArgumentException(
                    "environment must be Production or Sandbox", nameof(environment));
            }

            _anchors = Certificates.CopyAnchors(trustedRoots, nameof(trustedRoots));
            _environment = environment;
            _clock = clock ?? SystemClock.Instance;
            _pacific = ResolvePacific();
        }

        /// <summary>
        /// Handles one <c>verifyReceipt</c> request body. Never throws: like
        /// the real endpoint, a failure is reported through the result's
        /// status and <see cref="ApplePurchaseReceiptVerifier.Receipt.VerifyReceiptResult.FailureReason"/>.
        /// </summary>
        /// <param name="requestBody">The parsed request body.</param>
        /// <param name="now">
        /// The instant to render as <c>request_date</c> instead of reading
        /// the endpoint's clock. It reaches <c>request_date</c> and nothing
        /// else: certificate validity never sees it.
        /// </param>
        /// <remarks>
        /// <para><c>password</c> and <c>exclude-old-transactions</c> are
        /// accepted for wire compatibility and never read.</para>
        /// <para>A literal <see langword="null"/> argument needs a cast to pick
        /// this overload over the <see cref="string"/> one.</para>
        /// </remarks>
        public VerifyReceiptResult VerifyReceiptResult(
            IReadOnlyDictionary<string, object?>? requestBody, DateTimeOffset? now = null)
        {
            if (Start(now, out DateTimeOffset at) is Result refused)
            {
                return refused;
            }

            object? receiptData;
            try
            {
                if (requestBody is null || !requestBody.TryGetValue("receipt-data", out receiptData))
                {
                    return Result.Failed(_environment, _pacific, VerificationReason.MalformedRequest, at);
                }
            }
            catch (Exception e)
            {
                // A caller's dictionary implementation, not a verdict.
                return Result.InternalError(_environment, _pacific, e, at);
            }

            if (receiptData is not string base64)
            {
                return Result.Failed(_environment, _pacific, VerificationReason.MalformedRequest, at);
            }

            return Verify(base64, at);
        }

        /// <summary>
        /// Handles one request body in its raw wire form, the JSON text an HTTP
        /// framework hands over. Never throws.
        /// </summary>
        /// <param name="requestJson">The raw JSON request body.</param>
        /// <param name="now">
        /// The instant to render as <c>request_date</c> instead of reading
        /// the endpoint's clock; it reaches nothing else.
        /// </param>
        /// <remarks>
        /// A body over <see cref="MaxRequestBytes"/> UTF-8 bytes fails with
        /// <see cref="VerificationReason.RequestTooLarge"/>, status 21002,
        /// where Apple answers HTTP 413; it is refused before any parsing. A
        /// body that is not a JSON object (unparseable, <c>null</c>, an array,
        /// a scalar) or nests more than 64 arrays and objects deep fails with
        /// <see cref="VerificationReason.MalformedRequest"/>, status 21002. Apple has no status code for "that wasn't JSON"; 21002
        /// is the closest, and it is what a JSON object without usable
        /// <c>receipt-data</c> gets anyway.
        /// </remarks>
        public VerifyReceiptResult VerifyReceiptResult(string? requestJson, DateTimeOffset? now = null)
        {
            if (Start(now, out DateTimeOffset at) is Result refused)
            {
                return refused;
            }

            if (requestJson is null)
            {
                return Result.Failed(_environment, _pacific, VerificationReason.MalformedRequest, at);
            }

            if (Utf8Length.Exceeds(requestJson, MaxRequestBytes))
            {
                return Result.Failed(_environment, _pacific, VerificationReason.RequestTooLarge, at);
            }

            OrderedMap body;
            try
            {
                body = Json.ParseObject(requestJson);
            }
            catch (Exception)
            {
                // Categorical, like every other boundary here: the reader's
                // failure surface is not something a caller should have to
                // know, and a body it cannot read has always answered 21002.
                return Result.Failed(_environment, _pacific, VerificationReason.MalformedRequest, at);
            }

            return VerifyReceiptResult(body, at);
        }

        /// <summary>
        /// Verifies a bare base64 receipt, the value a request body would carry
        /// as <c>receipt-data</c>, with no envelope around it. Never throws; a
        /// null or empty string fails with
        /// <see cref="VerificationReason.MalformedRequest"/>, as a missing
        /// <c>receipt-data</c> does.
        /// </summary>
        /// <param name="base64">The receipt as the client sent it.</param>
        /// <param name="now">
        /// The instant to render as <c>request_date</c> instead of reading
        /// the endpoint's clock; it reaches nothing else.
        /// </param>
        public VerifyReceiptResult VerifyReceiptData(string? base64, DateTimeOffset? now = null)
        {
            if (Start(now, out DateTimeOffset at) is Result refused)
            {
                return refused;
            }

            return Verify(base64, at);
        }

        /// <summary>
        /// Handles one request in its raw wire form: the JSON request body in,
        /// the JSON response body out, so an HTTP framework's body can be piped
        /// straight through without a DTO in between. The same as
        /// <c>VerifyReceiptResult(requestJson).ToJson()</c>.
        /// </summary>
        /// <remarks>
        /// Never throws. Output is deterministic: equal inputs serialize to
        /// equal bytes.
        /// </remarks>
        public string VerifyReceiptJson(string requestJson)
        {
            return VerifyReceiptResult(requestJson).ToJson();
        }

        /// <summary>Releases the endpoint's private copies of the trust anchors.</summary>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            foreach (X509Certificate2 anchor in _anchors)
            {
                anchor.Dispose();
            }
        }

        private static TimeZoneInfo ResolvePacific()
        {
            // The IANA id works on Linux and macOS, and on Windows from .NET 6.
            // The Windows id is the fallback for older hosts. Neither resolving
            // is a loud failure, not a silent UTC substitution.
            foreach (string id in new[] { "America/Los_Angeles", "Pacific Standard Time" })
            {
                try
                {
                    return TimeZoneInfo.FindSystemTimeZoneById(id);
                }
                catch (TimeZoneNotFoundException)
                {
                }
                catch (InvalidTimeZoneException)
                {
                }
            }

            throw new InvalidOperationException(
                "the US Pacific time zone is not available on this host, so the "
                + "verifyReceipt endpoint cannot render request_date_pst");
        }

        /// <summary>
        /// Fixes the request date, reading the clock at most once, and answers
        /// for a disposed endpoint. Returns null when the call may go on.
        /// </summary>
        private Result? Start(DateTimeOffset? now, out DateTimeOffset at)
        {
            try
            {
                at = (now ?? _clock.UtcNow).ToUniversalTime();
            }
            catch (Exception e)
            {
                // An injected clock that throws is a bug outside this library,
                // answered as 21009 like any other. The result still needs a
                // request date, and the system clock is the only other one.
                at = SystemClock.Instance.UtcNow;
                return Result.InternalError(_environment, _pacific, e, at);
            }

            if (_disposed)
            {
                return Result.InternalError(
                    _environment, _pacific, new ObjectDisposedException(nameof(VerifyReceiptEndpoint)), at);
            }

            return null;
        }

        /// <summary>
        /// The one verification path every entry point ends in. <paramref name="at"/>
        /// only becomes <c>request_date</c>: certificate validity is judged
        /// inside <see cref="ReceiptVerifier.VerifyReceiptCore"/>, which takes no
        /// time input.
        /// </summary>
        private Result Verify(string? receiptData, DateTimeOffset at)
        {
            if (string.IsNullOrEmpty(receiptData))
            {
                return Result.Failed(_environment, _pacific, VerificationReason.MalformedRequest, at);
            }

            try
            {
                byte[] der = ReceiptVerifier.DecodeBase64(receiptData!);

                // The primitive itself, not a ReceiptVerifier built around a
                // wildcard bundle id: like Apple's endpoint, no bundle-id claim
                // is checked here. VerifyCore rather than the public
                // VerifyReceiptCore: that one copies the anchors on every
                // call, and _anchors is already this endpoint's private copy.
                AppReceipt receipt = ReceiptVerifier.VerifyCore(der, _anchors);
                return Result.Verified(_environment, _pacific, receipt, at);
            }
            catch (VerificationException e) when (e.Reason == VerificationReason.InternalError)
            {
                // Signed content that could not be read keeps what is behind
                // it, the parser's error, as the failure cause.
                return Result.InternalError(_environment, _pacific, e.InnerException ?? e, at);
            }
            catch (VerificationException e)
            {
                return Result.Failed(_environment, _pacific, e.Reason, at);
            }
            catch (Exception e)
            {
                return Result.InternalError(_environment, _pacific, e, at);
            }
        }
    }
}
