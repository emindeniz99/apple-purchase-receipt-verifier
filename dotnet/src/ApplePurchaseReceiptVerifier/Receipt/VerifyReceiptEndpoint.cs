using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Internal;

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
    /// with the real endpoint. It never throws: a failure is reported through
    /// <c>status</c>.</para>
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

        private const string DateFormat = "yyyy-MM-dd HH:mm:ss";
        private const string MalformedJson = "{\"status\":21002}";

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
        /// Handles one <c>verifyReceipt</c> request body. Never throws — like
        /// the real endpoint, failures are reported through <c>status</c>.
        /// </summary>
        /// <remarks>
        /// <c>password</c> and <c>exclude-old-transactions</c> are accepted for
        /// wire compatibility and never read.
        /// </remarks>
        public IReadOnlyDictionary<string, object?> VerifyReceipt(
            IReadOnlyDictionary<string, object?>? requestBody)
        {
            if (_disposed)
            {
                return Status(StatusInternal);
            }

            if (requestBody is null
                || !requestBody.TryGetValue("receipt-data", out object? receiptData)
                || receiptData is not string base64
                || base64.Length == 0)
            {
                return Status(StatusMalformed);
            }

            byte[] der;
            try
            {
                der = ReceiptVerifier.DecodeBase64(base64);
            }
            catch (VerificationException)
            {
                return Status(StatusMalformed);
            }

            try
            {
                // The primitive itself, not a ReceiptVerifier built around a
                // wildcard bundle id: like Apple's endpoint, no bundle-id claim
                // is checked here.
                AppReceipt receipt = ReceiptVerifier.VerifyReceiptCore(der, _anchors);

                // 21007/21008 routing from the receipt_type attribute, failing
                // closed: production is exactly "Production" and
                // "ProductionVPP". Everything else — "ProductionSandbox",
                // "ProductionVPPSandbox", "Xcode", or a missing attribute —
                // routes as non-production. ("Xcode" is listed for completeness:
                // an Xcode receipt is not Apple-signed, so it fails above with
                // 21003 and never reaches this branch.)
                bool production = string.Equals(receipt.ReceiptType, "Production", StringComparison.Ordinal)
                    || string.Equals(receipt.ReceiptType, "ProductionVPP", StringComparison.Ordinal);
                if (_environment == AppleEnvironment.Production && !production)
                {
                    return Status(StatusSandboxReceiptOnProduction);
                }

                if (_environment == AppleEnvironment.Sandbox && production)
                {
                    return Status(StatusProductionReceiptOnSandbox);
                }

                // Response rendering stays inside the guard: date formatting
                // touches the time-zone database, and a host without one must
                // answer 21009 rather than throw out of a method documented as
                // never throwing.
                OrderedMap response = new OrderedMap();
                response.Set("status", StatusOk);
                response.Set("environment", AppleEnvironments.ToValue(_environment));
                response.Set("receipt", ReceiptJson(receipt, _clock.UtcNow));
                return response;
            }
            catch (VerificationException e)
            {
                return Status(e.Reason == VerificationReason.InvalidReceiptFormat
                    ? StatusMalformed : StatusNotAuthenticated);
            }
            catch (Exception)
            {
                return Status(StatusInternal);
            }
        }

        /// <summary>
        /// Handles one request in its raw wire form: the JSON request body in,
        /// the JSON response body out, so an HTTP framework's body can be piped
        /// straight through without a DTO in between.
        /// </summary>
        /// <remarks>
        /// A body that is not a JSON object (unparseable, <c>null</c>, an array,
        /// a scalar) answers <c>{"status":21002}</c>. Apple has no status code
        /// for "that wasn't JSON"; 21002 is the closest, and it is what a JSON
        /// object without usable <c>receipt-data</c> gets anyway. Output is
        /// deterministic: equal inputs serialize to equal bytes.
        /// </remarks>
        public string VerifyReceiptJson(string requestJson)
        {
            OrderedMap body;
            try
            {
                body = Json.ParseObject(requestJson);
            }
            catch (Exception)
            {
                // Categorical, like every other boundary here: this method is
                // documented as never throwing, and the reader's failure
                // surface is not something a caller should have to know.
                return MalformedJson;
            }

            try
            {
                return Json.Write(VerifyReceipt(body));
            }
            catch (Exception)
            {
                return "{\"status\":" + StatusInternal.ToString(CultureInfo.InvariantCulture) + "}";
            }
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

        private static OrderedMap Status(int code)
        {
            OrderedMap response = new OrderedMap();
            response.Set("status", code);
            return response;
        }

        private OrderedMap ReceiptJson(AppReceipt receipt, DateTimeOffset requestDate)
        {
            OrderedMap json = new OrderedMap();
            json.SetIfPresent("receipt_type", receipt.ReceiptType);
            json.SetIfPresent("bundle_id", receipt.BundleId);
            json.SetIfPresent("application_version", receipt.AppVersion);
            json.SetIfPresent("original_application_version", receipt.OriginalAppVersion);
            AppleDates(json, "receipt_creation_date", receipt.CreationDate);
            AppleDates(json, "request_date", requestDate);
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
