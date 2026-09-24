using System;
using System.Collections.Generic;
using ApplePurchaseReceiptVerifier.Internal;

namespace ApplePurchaseReceiptVerifier.Jws
{
    /// <summary>
    /// A decoded <c>JWSTransactionDecodedPayload</c> — the payload of a
    /// StoreKit 2 <c>Transaction.jwsRepresentation</c> or an App Store Server
    /// <c>signedTransactionInfo</c>.
    /// </summary>
    /// <remarks>
    /// Dates are milliseconds since the epoch, exactly as Apple ships them.
    /// They are deliberately not <see cref="DateTimeOffset"/>: converting loses
    /// the raw claim and invites a timezone bug, and every port pins the raw
    /// integer. <see langword="null"/> means the claim was absent or JSON
    /// null; a modelled claim of the wrong JSON type fails verification with
    /// <see cref="VerificationReason.InternalError"/>. Claims this
    /// class does not model stay reachable through <see cref="ClaimsMap"/>.
    /// </remarks>
    public sealed class TransactionPayload
    {
        internal TransactionPayload(IReadOnlyDictionary<string, object?> claims)
        {
            ClaimsMap = claims;
            AppAccountToken = Internal.Claims.TypedString(claims, "appAccountToken");
            BundleId = Internal.Claims.TypedString(claims, "bundleId");
            Currency = Internal.Claims.TypedString(claims, "currency");
            Environment = Internal.Claims.TypedString(claims, "environment");
            ExpiresDate = Internal.Claims.Int64(claims, "expiresDate");
            InAppOwnershipType = Internal.Claims.TypedString(claims, "inAppOwnershipType");
            OfferIdentifier = Internal.Claims.TypedString(claims, "offerIdentifier");
            OfferType = Internal.Claims.Int32(claims, "offerType");
            OriginalPurchaseDate = Internal.Claims.Int64(claims, "originalPurchaseDate");
            OriginalTransactionId = Internal.Claims.TypedString(claims, "originalTransactionId");
            Price = Internal.Claims.Int64(claims, "price");
            ProductId = Internal.Claims.TypedString(claims, "productId");
            PurchaseDate = Internal.Claims.Int64(claims, "purchaseDate");
            Quantity = Internal.Claims.Int32(claims, "quantity");
            RevocationDate = Internal.Claims.Int64(claims, "revocationDate");
            RevocationReason = Internal.Claims.Int32(claims, "revocationReason");
            SignedDate = Internal.Claims.Int64(claims, "signedDate");
            Storefront = Internal.Claims.TypedString(claims, "storefront");
            SubscriptionGroupIdentifier = Internal.Claims.TypedString(claims, "subscriptionGroupIdentifier");
            TransactionId = Internal.Claims.TypedString(claims, "transactionId");
            TransactionReason = Internal.Claims.TypedString(claims, "transactionReason");
            Type = Internal.Claims.TypedString(claims, "type");
            WebOrderLineItemId = Internal.Claims.TypedString(claims, "webOrderLineItemId");
        }

        /// <summary>Every claim in the verified payload, including unmodelled ones.</summary>
        public IReadOnlyDictionary<string, object?> ClaimsMap { get; }

        /// <summary>The <c>appAccountToken</c> claim.</summary>
        public string? AppAccountToken { get; }

        /// <summary>The <c>bundleId</c> claim.</summary>
        public string? BundleId { get; }

        /// <summary>The <c>currency</c> claim.</summary>
        public string? Currency { get; }

        /// <summary>The <c>environment</c> claim, as Apple spells it.</summary>
        public string? Environment { get; }

        /// <summary>The <c>expiresDate</c> claim, in epoch milliseconds.</summary>
        public long? ExpiresDate { get; }

        /// <summary>The <c>inAppOwnershipType</c> claim.</summary>
        public string? InAppOwnershipType { get; }

        /// <summary>The <c>offerIdentifier</c> claim.</summary>
        public string? OfferIdentifier { get; }

        /// <summary>The <c>offerType</c> claim.</summary>
        public int? OfferType { get; }

        /// <summary>The <c>originalPurchaseDate</c> claim, in epoch milliseconds.</summary>
        public long? OriginalPurchaseDate { get; }

        /// <summary>The <c>originalTransactionId</c> claim.</summary>
        public string? OriginalTransactionId { get; }

        /// <summary>The <c>price</c> claim.</summary>
        public long? Price { get; }

        /// <summary>The <c>productId</c> claim.</summary>
        public string? ProductId { get; }

        /// <summary>The <c>purchaseDate</c> claim, in epoch milliseconds.</summary>
        public long? PurchaseDate { get; }

        /// <summary>The <c>quantity</c> claim.</summary>
        public int? Quantity { get; }

        /// <summary>The <c>revocationDate</c> claim, in epoch milliseconds.</summary>
        public long? RevocationDate { get; }

        /// <summary>The <c>revocationReason</c> claim.</summary>
        public int? RevocationReason { get; }

        /// <summary>The <c>signedDate</c> claim, in epoch milliseconds.</summary>
        public long? SignedDate { get; }

        /// <summary>The <c>storefront</c> claim.</summary>
        public string? Storefront { get; }

        /// <summary>The <c>subscriptionGroupIdentifier</c> claim.</summary>
        public string? SubscriptionGroupIdentifier { get; }

        /// <summary>The <c>transactionId</c> claim.</summary>
        public string? TransactionId { get; }

        /// <summary>The <c>transactionReason</c> claim.</summary>
        public string? TransactionReason { get; }

        /// <summary>The <c>type</c> claim.</summary>
        public string? Type { get; }

        /// <summary>The <c>webOrderLineItemId</c> claim.</summary>
        public string? WebOrderLineItemId { get; }
    }
}
