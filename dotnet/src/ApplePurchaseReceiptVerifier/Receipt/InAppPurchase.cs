using System;
using System.Collections.Generic;
using ApplePurchaseReceiptVerifier.Internal;

namespace ApplePurchaseReceiptVerifier.Receipt
{
    /// <summary>
    /// One in-app purchase from a legacy app receipt (attribute 17). Field set
    /// per Apple's "Validating receipts on the device" attribute table;
    /// <see langword="null"/> means the attribute was absent.
    /// </summary>
    public sealed class InAppPurchase
    {
        internal InAppPurchase(
            long? quantity,
            string? productId,
            string? transactionId,
            string? originalTransactionId,
            DateTimeOffset? purchaseDate,
            DateTimeOffset? originalPurchaseDate,
            DateTimeOffset? expiresDate,
            DateTimeOffset? cancellationDate,
            long? webOrderLineItemId,
            long? isInIntroOfferPeriod,
            IReadOnlyDictionary<int, IReadOnlyList<byte[]>> unknownAttributes)
        {
            Quantity = quantity;
            ProductId = productId;
            TransactionId = transactionId;
            OriginalTransactionId = originalTransactionId;
            PurchaseDate = purchaseDate;
            OriginalPurchaseDate = originalPurchaseDate;
            ExpiresDate = expiresDate;
            CancellationDate = cancellationDate;
            WebOrderLineItemId = webOrderLineItemId;
            IsInIntroOfferPeriod = isInIntroOfferPeriod;
            UnknownAttributes = unknownAttributes;
        }

        /// <summary>Attribute 1701.</summary>
        public long? Quantity { get; }

        /// <summary>Attribute 1702.</summary>
        public string? ProductId { get; }

        /// <summary>Attribute 1703.</summary>
        public string? TransactionId { get; }

        /// <summary>Attribute 1705.</summary>
        public string? OriginalTransactionId { get; }

        /// <summary>Attribute 1704.</summary>
        public DateTimeOffset? PurchaseDate { get; }

        /// <summary>Attribute 1706.</summary>
        public DateTimeOffset? OriginalPurchaseDate { get; }

        /// <summary>Subscription expiration (attribute 1708), if this is a subscription.</summary>
        public DateTimeOffset? ExpiresDate { get; }

        /// <summary>Set when Apple customer support cancelled or refunded (attribute 1712).</summary>
        public DateTimeOffset? CancellationDate { get; }

        /// <summary>Attribute 1711.</summary>
        public long? WebOrderLineItemId { get; }

        /// <summary>Attribute 1719.</summary>
        public long? IsInIntroOfferPeriod { get; }

        /// <summary>
        /// Raw values of attribute types this library does not model, keyed by
        /// type — forward compatibility for fields Apple may add (PLAN D10).
        /// The arrays are this library's own copies of verified receipt bytes;
        /// treat them as read-only.
        /// </summary>
        public IReadOnlyDictionary<int, IReadOnlyList<byte[]>> UnknownAttributes { get; }
    }
}
