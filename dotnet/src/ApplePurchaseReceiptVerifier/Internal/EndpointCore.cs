using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// <c>verifyReceiptEndpoint(environment, requestJson)</c>: runs
    /// <see cref="ReceiptVerifierCore"/> and renders the result the way
    /// Apple's own verifyReceipt would, as JSON text. Never throws.
    /// </summary>
    internal static class EndpointCore
    {
        internal const int MaxRequestBytes = 3145728;

        private const string DateFormat = "yyyy-MM-dd HH:mm:ss";

        private static readonly Lazy<TimeZoneInfo> Pacific = new Lazy<TimeZoneInfo>(ResolvePacific);

        internal static string Verify(
            AppleEnvironment environment, string? requestJson, IReadOnlyList<X509Certificate2> anchors, Func<long> clock)
        {
            long requestDateMs;
            try
            {
                requestDateMs = clock();
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                return StatusOnlyJson(AppleStatus.InternalDataAccessError);
            }

            try
            {
                return VerifyUnguarded(environment, requestJson, anchors, requestDateMs);
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                return StatusOnlyJson(AppleStatus.InternalDataAccessError);
            }
        }

        private static string VerifyUnguarded(
            AppleEnvironment environment, string? requestJson, IReadOnlyList<X509Certificate2> anchors, long requestDateMs)
        {
            if (requestJson is null)
            {
                return StatusOnlyJson(AppleStatus.MalformedReceiptData);
            }

            if (Utf8Length.Exceeds(requestJson, MaxRequestBytes))
            {
                return StatusOnlyJson(AppleStatus.MalformedReceiptData);
            }

            OrderedMap body;
            try
            {
                body = Json.ParseObject(requestJson);
            }
            catch (JsonException)
            {
                return StatusOnlyJson(AppleStatus.MalformedReceiptData);
            }

            // password and exclude-old-transactions are accepted for wire
            // compatibility and never read.
            if (!body.TryGetValue("receipt-data", out object? receiptDataValue) || receiptDataValue is not string base64)
            {
                return StatusOnlyJson(AppleStatus.MalformedReceiptData);
            }

            ReceiptPayload payload;
            try
            {
                payload = ReceiptVerifierCore.Verify(base64, anchors, () => requestDateMs);
            }
            catch (VerificationException e)
            {
                return StatusOnlyJson(StatusFor(e.Reason));
            }

            AppleEnvironment? receiptEnvironment = AppleEnvironments.FromReceiptType(payload.ReceiptType);
            bool isProduction = receiptEnvironment == AppleEnvironment.Production;
            int status;
            if (environment == AppleEnvironment.Production && !isProduction)
            {
                status = AppleStatus.SandboxReceiptOnProduction;
            }
            else if (environment == AppleEnvironment.Sandbox && isProduction)
            {
                status = AppleStatus.ProductionReceiptOnSandbox;
            }
            else
            {
                status = AppleStatus.Ok;
            }

            if (status != AppleStatus.Ok)
            {
                return StatusOnlyJson(status);
            }

            OrderedMap response = new OrderedMap();
            response.Set("status", AppleStatus.Ok);
            response.Set("environment", AppleEnvironments.ToValue(environment));
            response.Set("receipt", ReceiptJson(payload, requestDateMs));
            return Json.Write(response);
        }

        private static int StatusFor(VerificationReason reason)
        {
            switch (reason)
            {
                case VerificationReason.Malformed:
                case VerificationReason.TooLarge:
                    return AppleStatus.MalformedReceiptData;
                case VerificationReason.InvalidSignature:
                case VerificationReason.UntrustedChain:
                case VerificationReason.InvalidCertificate:
                case VerificationReason.InvalidCertificatePurpose:
                    return AppleStatus.NotAuthenticated;
                default:
                    return AppleStatus.InternalDataAccessError;
            }
        }

        private static string StatusOnlyJson(int status)
        {
            OrderedMap response = new OrderedMap();
            response.Set("status", status);
            return Json.Write(response);
        }

        private static OrderedMap ReceiptJson(ReceiptPayload receipt, long requestDateMs)
        {
            OrderedMap json = new OrderedMap();
            json.SetIfPresent("receipt_type", receipt.ReceiptType);
            // Apple's real endpoint renders these two as JSON numbers, unlike
            // our own canonical toJson(), which renders every 64-bit id as a
            // string; the reference implementation's response is matched here.
            json.SetIfPresent("adam_id", receipt.AppItemId);
            json.SetIfPresent("app_item_id", receipt.AppItemId);
            json.SetIfPresent("bundle_id", receipt.BundleId);
            json.SetIfPresent("application_version", receipt.ApplicationVersion);
            json.SetIfPresent("download_id", receipt.DownloadId);
            json.SetIfPresent("version_external_identifier", receipt.VersionExternalIdentifier);
            json.SetIfPresent("original_application_version", receipt.OriginalApplicationVersion);
            AppleDates(json, "receipt_creation_date", receipt.ReceiptCreationDateMs);
            AppleDates(json, "request_date", requestDateMs);
            AppleDates(json, "original_purchase_date", receipt.OriginalPurchaseDateMs);
            AppleDates(json, "expiration_date", receipt.ExpirationDateMs);

            List<object?> inApp = new List<object?>(receipt.InApp.Count);
            foreach (InAppPurchase purchase in receipt.InApp)
            {
                inApp.Add(InAppJson(purchase));
            }

            json.Set("in_app", inApp);
            return json;
        }

        private static OrderedMap InAppJson(InAppPurchase purchase)
        {
            OrderedMap json = new OrderedMap();
            json.SetIfPresent("quantity", Text(purchase.Quantity));
            json.SetIfPresent("product_id", purchase.ProductId);
            json.SetIfPresent("transaction_id", purchase.TransactionId);
            json.SetIfPresent("original_transaction_id", purchase.OriginalTransactionId);
            AppleDates(json, "purchase_date", purchase.PurchaseDateMs);
            AppleDates(json, "original_purchase_date", purchase.OriginalPurchaseDateMs);
            AppleDates(json, "expires_date", purchase.ExpiresDateMs);
            AppleDates(json, "cancellation_date", purchase.CancellationDateMs);

            // Omitted when attribute 1711 is 0, as Apple omits it for consumables.
            if (purchase.WebOrderLineItemId is long webOrderLineItemId && webOrderLineItemId != 0)
            {
                json.Set("web_order_line_item_id", webOrderLineItemId.ToString(CultureInfo.InvariantCulture));
            }

            if (purchase.IsTrialPeriod is bool trial)
            {
                json.Set("is_trial_period", trial ? "true" : "false");
            }

            if (purchase.IsInIntroOfferPeriod is bool intro)
            {
                json.Set("is_in_intro_offer_period", intro ? "true" : "false");
            }

            return json;
        }

        private static string? Text(long? value) => value is long l ? l.ToString(CultureInfo.InvariantCulture) : null;

        /// <summary>Apple's three renderings of one instant: GMT text, epoch millis, US Pacific.</summary>
        private static void AppleDates(OrderedMap json, string prefix, long? instantMs)
        {
            if (instantMs is not long ms)
            {
                return;
            }

            DateTimeOffset utc = DateTimeOffset.FromUnixTimeMilliseconds(ms);
            json.Set(prefix, utc.UtcDateTime.ToString(DateFormat, CultureInfo.InvariantCulture) + " Etc/GMT");
            json.Set(prefix + "_ms", ms.ToString(CultureInfo.InvariantCulture));
            json.Set(
                prefix + "_pst",
                TimeZoneInfo.ConvertTime(utc, Pacific.Value).DateTime.ToString(DateFormat, CultureInfo.InvariantCulture)
                + " America/Los_Angeles");
        }

        private static TimeZoneInfo ResolvePacific()
        {
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

            return TimeZoneInfo.Utc;
        }
    }
}
