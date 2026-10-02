using System.Collections.Generic;
using System.Text.Json;
using ApplePurchaseReceiptVerifier.Internal;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// One in-app purchase from a legacy app receipt (attribute 17).
    /// <see langword="null"/> means the attribute was absent, or present with
    /// a value this library could not parse (see <see cref="UnknownAttributes"/>).
    /// </summary>
    public sealed class InAppPurchase
    {
        private readonly IReadOnlyDictionary<int, IReadOnlyList<byte[]>> _unknownAttributes;

        /// <summary>
        /// Builds a purchase by hand, for a caller's own tests. The unknown
        /// attributes are copied, so changing what was passed in afterwards
        /// does not change the purchase.
        /// </summary>
        /// <exception cref="System.ArgumentNullException"><paramref name="unknownAttributes"/> or one of
        /// its values is <see langword="null"/>.</exception>
        public InAppPurchase(
            long? quantity,
            string? productId,
            string? transactionId,
            long? purchaseDateMs,
            string? originalTransactionId,
            long? originalPurchaseDateMs,
            long? expiresDateMs,
            long? webOrderLineItemId,
            long? cancellationDateMs,
            bool? isTrialPeriod,
            bool? isInIntroOfferPeriod,
            IReadOnlyDictionary<int, IReadOnlyList<byte[]>> unknownAttributes)
        {
            Quantity = quantity;
            ProductId = productId;
            TransactionId = transactionId;
            PurchaseDateMs = purchaseDateMs;
            OriginalTransactionId = originalTransactionId;
            OriginalPurchaseDateMs = originalPurchaseDateMs;
            ExpiresDateMs = expiresDateMs;
            WebOrderLineItemId = webOrderLineItemId;
            CancellationDateMs = cancellationDateMs;
            IsTrialPeriod = isTrialPeriod;
            IsInIntroOfferPeriod = isInIntroOfferPeriod;
            _unknownAttributes = ByteOps.CopyAttributes(unknownAttributes, nameof(unknownAttributes));
        }

        /// <summary>Attribute 1701.</summary>
        public long? Quantity { get; }

        /// <summary>Attribute 1702.</summary>
        public string? ProductId { get; }

        /// <summary>Attribute 1703.</summary>
        public string? TransactionId { get; }

        /// <summary>Attribute 1704, epoch milliseconds UTC.</summary>
        public long? PurchaseDateMs { get; }

        /// <summary>Attribute 1705.</summary>
        public string? OriginalTransactionId { get; }

        /// <summary>Attribute 1706, epoch milliseconds UTC.</summary>
        public long? OriginalPurchaseDateMs { get; }

        /// <summary>Attribute 1708, epoch milliseconds UTC — subscription expiration, if this is a subscription.</summary>
        public long? ExpiresDateMs { get; }

        /// <summary>Attribute 1711.</summary>
        public long? WebOrderLineItemId { get; }

        /// <summary>Attribute 1712, epoch milliseconds UTC — set when Apple customer support cancelled or refunded.</summary>
        public long? CancellationDateMs { get; }

        /// <summary>Attribute 1713 — 0 is <see langword="false"/>, any other value is <see langword="true"/>.</summary>
        public bool? IsTrialPeriod { get; }

        /// <summary>Attribute 1719 — 0 is <see langword="false"/>, any other value is <see langword="true"/>.</summary>
        public bool? IsInIntroOfferPeriod { get; }

        /// <summary>
        /// Raw values of attribute types this library does not model, keyed by
        /// type, in receipt order. Same rules as
        /// <see cref="ReceiptPayload.UnknownAttributes"/>. A fresh copy per call.
        /// </summary>
        public IReadOnlyDictionary<int, IReadOnlyList<byte[]>> UnknownAttributes =>
            ByteOps.CopyAttributes(_unknownAttributes, nameof(UnknownAttributes));

        /// <summary>Writes this purchase as one <c>in_app</c> element of <see cref="ReceiptPayload.ToJson"/>.</summary>
        internal void WriteTo(Utf8JsonWriter json)
        {
            json.WriteStartObject();
            Json.WriteNumberOrNull(json, "quantity", Quantity);
            json.WriteString("product_id", ProductId);
            json.WriteString("transaction_id", TransactionId);
            Json.WriteNumberOrNull(json, "purchase_date_ms", PurchaseDateMs);
            json.WriteString("original_transaction_id", OriginalTransactionId);
            Json.WriteNumberOrNull(json, "original_purchase_date_ms", OriginalPurchaseDateMs);
            Json.WriteNumberOrNull(json, "expires_date_ms", ExpiresDateMs);
            json.WriteString("web_order_line_item_id", ReceiptPayload.IdString(WebOrderLineItemId));
            Json.WriteNumberOrNull(json, "cancellation_date_ms", CancellationDateMs);
            Json.WriteBooleanOrNull(json, "is_trial_period", IsTrialPeriod);
            Json.WriteBooleanOrNull(json, "is_in_intro_offer_period", IsInIntroOfferPeriod);
            ReceiptPayload.WriteUnknownAttributes(json, _unknownAttributes);
            json.WriteEndObject();
        }
    }
}
