using System;
using System.Collections.Generic;

namespace ApplePurchaseReceiptVerifier.Jws
{
    /// <summary>
    /// A decoded <c>AppTransaction</c> payload (StoreKit 2, iOS 16+):
    /// app-level proof of purchase or download.
    /// </summary>
    /// <remarks>
    /// The environment lives in <see cref="ReceiptType"/>. Dates are
    /// milliseconds since the epoch, exactly as Apple ships them;
    /// <see langword="null"/> means the claim was absent.
    /// </remarks>
    public sealed class AppTransactionPayload
    {
        internal AppTransactionPayload(IReadOnlyDictionary<string, object?> claims)
        {
            ClaimsMap = claims;
            AppAppleId = Internal.Claims.Int64(claims, "appAppleId");
            AppTransactionId = Internal.Claims.String(claims, "appTransactionId");
            ApplicationVersion = Internal.Claims.String(claims, "applicationVersion");
            BundleId = Internal.Claims.String(claims, "bundleId");
            DeviceVerification = Internal.Claims.String(claims, "deviceVerification");
            DeviceVerificationNonce = Internal.Claims.String(claims, "deviceVerificationNonce");
            OriginalApplicationVersion = Internal.Claims.String(claims, "originalApplicationVersion");
            OriginalPurchaseDate = Internal.Claims.Int64(claims, "originalPurchaseDate");
            PreorderDate = Internal.Claims.Int64(claims, "preorderDate");
            ReceiptCreationDate = Internal.Claims.Int64(claims, "receiptCreationDate");
            ReceiptType = Internal.Claims.String(claims, "receiptType");
            VersionExternalIdentifier = Internal.Claims.Int64(claims, "versionExternalIdentifier");
        }

        /// <summary>Every claim in the verified payload, including unmodelled ones.</summary>
        public IReadOnlyDictionary<string, object?> ClaimsMap { get; }

        /// <summary>The <c>appAppleId</c> claim.</summary>
        public long? AppAppleId { get; }

        /// <summary>The <c>appTransactionId</c> claim.</summary>
        public string? AppTransactionId { get; }

        /// <summary>The <c>applicationVersion</c> claim.</summary>
        public string? ApplicationVersion { get; }

        /// <summary>The <c>bundleId</c> claim.</summary>
        public string? BundleId { get; }

        /// <summary>The <c>deviceVerification</c> claim.</summary>
        public string? DeviceVerification { get; }

        /// <summary>The <c>deviceVerificationNonce</c> claim.</summary>
        public string? DeviceVerificationNonce { get; }

        /// <summary>The <c>originalApplicationVersion</c> claim.</summary>
        public string? OriginalApplicationVersion { get; }

        /// <summary>The <c>originalPurchaseDate</c> claim, in epoch milliseconds.</summary>
        public long? OriginalPurchaseDate { get; }

        /// <summary>The <c>preorderDate</c> claim, in epoch milliseconds.</summary>
        public long? PreorderDate { get; }

        /// <summary>The <c>receiptCreationDate</c> claim, in epoch milliseconds.</summary>
        public long? ReceiptCreationDate { get; }

        /// <summary>The environment claim of an AppTransaction, e.g. <c>"Production"</c>.</summary>
        public string? ReceiptType { get; }

        /// <summary>The <c>versionExternalIdentifier</c> claim.</summary>
        public long? VersionExternalIdentifier { get; }
    }
}
