using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using ApplePurchaseReceiptVerifier.Internal;

namespace ApplePurchaseReceiptVerifier.Receipt
{
    /// <summary>
    /// The outcome of one <see cref="VerifyReceiptEndpoint"/> call: the Apple
    /// status, the verified receipt or the reason there is none, and Apple's
    /// response body, rendered only when asked for.
    /// </summary>
    /// <remarks>
    /// <para>Exactly one of <see cref="Receipt"/> and
    /// <see cref="FailureReason"/> is non-null. The receipt is present whenever
    /// its bytes verified, including when the endpoint's own environment
    /// answers 21007 or 21008, so a caller can re-render for the other
    /// environment with <see cref="ToJson(AppleEnvironment)"/> without
    /// verifying twice. The status is always recomputed from the receipt's own
    /// <c>receipt_type</c>, so no render can answer 0 for a receipt from the
    /// wrong environment.</para>
    /// <para>Immutable and thread-safe. Only the endpoint creates one: a caller
    /// cannot construct a result carrying status 0.</para>
    /// </remarks>
    public sealed class VerifyReceiptResult
    {
        private const string DateFormat = "yyyy-MM-dd HH:mm:ss";

        private readonly AppleEnvironment _environment;
        private readonly TimeZoneInfo _pacific;

        private VerifyReceiptResult(
            AppleEnvironment environment,
            TimeZoneInfo pacific,
            AppReceipt? receipt,
            VerificationReason? failureReason,
            Exception? failureCause,
            DateTimeOffset requestDate)
        {
            _environment = environment;
            _pacific = pacific;
            Receipt = receipt;
            FailureReason = failureReason;
            FailureCause = failureCause;
            RequestDate = requestDate;
        }

        /// <summary>The Apple status for the endpoint's own environment.</summary>
        public int Status => StatusFor(_environment);

        /// <summary>
        /// Whether the receipt bytes verified: <see langword="true"/> exactly
        /// when <see cref="Receipt"/> is non-null.
        /// </summary>
        /// <remarks>
        /// This includes 21007 and 21008 results: the receipt verified, only
        /// its environment differs from this endpoint's own. So it is
        /// <strong>not</strong> the same check as <c>Status == 0</c>.
        /// <c>Status == 0</c> answers "does this endpoint's own environment
        /// accept the receipt"; <c>IsVerified</c> answers "did the receipt
        /// verify at all", which is what to check before trusting
        /// <see cref="Receipt"/>'s fields or re-rendering with
        /// <see cref="ToResponse(AppleEnvironment)"/>.
        /// </remarks>
        [MemberNotNullWhen(true, nameof(Receipt))]
        [MemberNotNullWhen(false, nameof(FailureReason))]
        public bool IsVerified => Receipt is not null;

        /// <summary>
        /// The verified receipt, or <see langword="null"/> when verification
        /// failed. Present for 21007 and 21008 too: those say the receipt
        /// belongs to the other environment, not that it failed to verify.
        /// </summary>
        /// <remarks>
        /// Like Apple's endpoint, nothing in it has been checked against your
        /// app: compare <see cref="AppReceipt.BundleId"/> yourself.
        /// </remarks>
        public AppReceipt? Receipt { get; }

        /// <summary>
        /// Why there is no receipt; non-null exactly when
        /// <see cref="Receipt"/> is null.
        /// </summary>
        public VerificationReason? FailureReason { get; }

        /// <summary>
        /// The unexpected exception behind
        /// <see cref="VerificationReason.InternalError"/>; null for every other
        /// outcome. For logging, not for deciding anything.
        /// </summary>
        public Exception? FailureCause { get; }

        /// <summary>
        /// The instant rendered as <c>request_date</c>, in UTC, fixed when the
        /// call was made.
        /// </summary>
        public DateTimeOffset RequestDate { get; }

        /// <summary>
        /// The response body the endpoint's own environment answers, as a new
        /// map on each call. Same keys, order and types as Apple's endpoint;
        /// see COMPARISON.md.
        /// </summary>
        public IReadOnlyDictionary<string, object?> ToResponse() => ToResponse(_environment);

        /// <summary><see cref="ToResponse()"/> serialized as the JSON response body.</summary>
        public string ToJson() => ToJson(_environment);

        /// <summary>
        /// The response an endpoint of <paramref name="environment"/> would
        /// answer for the same receipt, at the same <see cref="RequestDate"/>.
        /// A production receipt answers 0 on Production and 21008 on Sandbox;
        /// any other receipt answers 21007 on Production and 0 on Sandbox; a
        /// failed result answers its own status on both.
        /// </summary>
        /// <exception cref="ArgumentException">
        /// <paramref name="environment"/> is neither Production nor Sandbox,
        /// the same refusal as the endpoint's constructor.
        /// </exception>
        public IReadOnlyDictionary<string, object?> ToResponse(AppleEnvironment environment)
        {
            int status = StatusFor(environment);
            if (status != VerifyReceiptEndpoint.StatusOk || Receipt is null)
            {
                return StatusOnly(status);
            }

            try
            {
                OrderedMap response = new OrderedMap();
                response.Set("status", status);
                response.Set("environment", AppleEnvironments.ToValue(environment));
                response.Set("receipt", ReceiptJson(Receipt));
                return response;
            }
            catch (Exception)
            {
                // Rendering touches the time-zone database. A host where that
                // fails still gets an answer, as it always has, rather than an
                // exception out of an endpoint documented as never throwing.
                return StatusOnly(VerifyReceiptEndpoint.StatusInternal);
            }
        }

        /// <summary><see cref="ToResponse(AppleEnvironment)"/> serialized as the JSON response body.</summary>
        /// <exception cref="ArgumentException">
        /// <paramref name="environment"/> is neither Production nor Sandbox.
        /// </exception>
        public string ToJson(AppleEnvironment environment)
        {
            IReadOnlyDictionary<string, object?> response = ToResponse(environment);
            try
            {
                return Json.Write(response);
            }
            catch (Exception)
            {
                return "{\"status\":" + VerifyReceiptEndpoint.StatusInternal.ToString(CultureInfo.InvariantCulture) + "}";
            }
        }

        internal static VerifyReceiptResult Verified(
            AppleEnvironment environment, TimeZoneInfo pacific, AppReceipt receipt, DateTimeOffset requestDate) =>
            new VerifyReceiptResult(environment, pacific, receipt, null, null, requestDate);

        internal static VerifyReceiptResult Failed(
            AppleEnvironment environment, TimeZoneInfo pacific, VerificationReason reason, DateTimeOffset requestDate) =>
            new VerifyReceiptResult(environment, pacific, null, reason, null, requestDate);

        internal static VerifyReceiptResult InternalError(
            AppleEnvironment environment, TimeZoneInfo pacific, Exception cause, DateTimeOffset requestDate) =>
            new VerifyReceiptResult(environment, pacific, null, VerificationReason.InternalError, cause, requestDate);

        private int StatusFor(AppleEnvironment environment)
        {
            if (environment != AppleEnvironment.Production && environment != AppleEnvironment.Sandbox)
            {
                throw new ArgumentException(
                    "environment must be Production or Sandbox", nameof(environment));
            }

            if (Receipt is null)
            {
                switch (FailureReason)
                {
                    case VerificationReason.MalformedRequest:
                    case VerificationReason.InvalidReceiptFormat:
                        return VerifyReceiptEndpoint.StatusMalformed;
                    case VerificationReason.InternalError:
                        return VerifyReceiptEndpoint.StatusInternal;
                    default:
                        return VerifyReceiptEndpoint.StatusNotAuthenticated;
                }
            }

            // 21007/21008 routing from the receipt_type attribute, failing
            // closed: production is exactly "Production" and "ProductionVPP".
            // Everything else ("ProductionSandbox", "ProductionVPPSandbox",
            // "Xcode", or a missing attribute) routes as non-production.
            // ("Xcode" is listed for completeness: an Xcode receipt is not
            // Apple-signed, so it fails with 21003 and never gets here.)
            bool production = string.Equals(Receipt.ReceiptType, "Production", StringComparison.Ordinal)
                || string.Equals(Receipt.ReceiptType, "ProductionVPP", StringComparison.Ordinal);
            if (environment == AppleEnvironment.Production && !production)
            {
                return VerifyReceiptEndpoint.StatusSandboxReceiptOnProduction;
            }

            if (environment == AppleEnvironment.Sandbox && production)
            {
                return VerifyReceiptEndpoint.StatusProductionReceiptOnSandbox;
            }

            return VerifyReceiptEndpoint.StatusOk;
        }

        private static OrderedMap StatusOnly(int code)
        {
            OrderedMap response = new OrderedMap();
            response.Set("status", code);
            return response;
        }

        private OrderedMap ReceiptJson(AppReceipt receipt)
        {
            OrderedMap json = new OrderedMap();
            json.SetIfPresent("receipt_type", receipt.ReceiptType);

            // Apple echoes attribute 1 under both names (its response
            // reference defines adam_id as "See app_item_id") and as JSON
            // numbers, not as the strings the in-app integers are rendered
            // with.
            json.SetIfPresent("adam_id", receipt.AppItemId);
            json.SetIfPresent("app_item_id", receipt.AppItemId);
            json.SetIfPresent("bundle_id", receipt.BundleId);
            json.SetIfPresent("application_version", receipt.AppVersion);
            json.SetIfPresent("download_id", receipt.DownloadId);
            json.SetIfPresent("version_external_identifier", receipt.VersionExternalIdentifier);
            json.SetIfPresent("original_application_version", receipt.OriginalAppVersion);
            AppleDates(json, "receipt_creation_date", receipt.CreationDate);
            AppleDates(json, "request_date", RequestDate);
            AppleDates(json, "original_purchase_date", receipt.OriginalPurchaseDate);
            AppleDates(json, "expiration_date", receipt.ExpirationDate);

            List<object?> inApp = new List<object?>(receipt.InAppPurchases.Count);
            foreach (InAppPurchase purchase in receipt.InAppPurchases)
            {
                inApp.Add(InAppJson(purchase));
            }

            json.Set("in_app", inApp);
            return json;
        }

        private OrderedMap InAppJson(InAppPurchase purchase)
        {
            OrderedMap json = new OrderedMap();
            json.SetIfPresent("quantity", Text(purchase.Quantity));
            json.SetIfPresent("product_id", purchase.ProductId);
            json.SetIfPresent("transaction_id", purchase.TransactionId);
            json.SetIfPresent("original_transaction_id", purchase.OriginalTransactionId);
            AppleDates(json, "purchase_date", purchase.PurchaseDate);
            AppleDates(json, "original_purchase_date", purchase.OriginalPurchaseDate);
            AppleDates(json, "expires_date", purchase.ExpiresDate);
            AppleDates(json, "cancellation_date", purchase.CancellationDate);
            json.SetIfPresent("web_order_line_item_id", Text(purchase.WebOrderLineItemId));
            if (purchase.IsTrialPeriod is long trial)
            {
                json.Set("is_trial_period", trial == 1 ? "true" : "false");
            }

            if (purchase.IsInIntroOfferPeriod is long flag)
            {
                json.Set("is_in_intro_offer_period", flag == 1 ? "true" : "false");
            }

            return json;
        }

        private static string? Text(long? value)
        {
            return value is long l ? l.ToString(CultureInfo.InvariantCulture) : null;
        }

        /// <summary>Apple's three renderings of one instant: GMT, epoch millis, US Pacific.</summary>
        private void AppleDates(OrderedMap json, string prefix, DateTimeOffset? instant)
        {
            if (instant is not DateTimeOffset value)
            {
                return;
            }

            DateTimeOffset utc = value.ToUniversalTime();
            json.Set(prefix, utc.UtcDateTime.ToString(DateFormat, CultureInfo.InvariantCulture) + " Etc/GMT");
            json.Set(
                prefix + "_ms",
                utc.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture));
            json.Set(
                prefix + "_pst",
                TimeZoneInfo.ConvertTime(utc, _pacific).DateTime
                    .ToString(DateFormat, CultureInfo.InvariantCulture)
                + " America/Los_Angeles");
        }
    }
}
