using System;
using System.Collections.Generic;
using ApplePurchaseReceiptVerifier.Internal;

namespace ApplePurchaseReceiptVerifier.Receipt
{
    /// <summary>
    /// A verified legacy app receipt (the PKCS#7 payload). Only receipts
    /// returned by <see cref="ReceiptVerifier"/> should be trusted — this class
    /// carries no proof by itself. <see langword="null"/> fields were absent
    /// from the receipt.
    /// </summary>
    public sealed class AppReceipt
    {
        private readonly byte[]? _bundleIdBytes;
        private readonly byte[]? _opaqueValue;
        private readonly byte[]? _sha1Hash;

        internal AppReceipt(
            string? receiptType,
            string? bundleId,
            byte[]? bundleIdBytes,
            string? appVersion,
            byte[]? opaqueValue,
            byte[]? sha1Hash,
            DateTimeOffset? creationDate,
            DateTimeOffset? originalPurchaseDate,
            string? originalAppVersion,
            DateTimeOffset? expirationDate,
            IReadOnlyList<InAppPurchase> inAppPurchases,
            IReadOnlyDictionary<int, IReadOnlyList<byte[]>> unknownAttributes)
        {
            ReceiptType = receiptType;
            BundleId = bundleId;
            _bundleIdBytes = bundleIdBytes;
            AppVersion = appVersion;
            _opaqueValue = opaqueValue;
            _sha1Hash = sha1Hash;
            CreationDate = creationDate;
            OriginalPurchaseDate = originalPurchaseDate;
            OriginalAppVersion = originalAppVersion;
            ExpirationDate = expirationDate;
            InAppPurchases = inAppPurchases;
            UnknownAttributes = unknownAttributes;
        }

        /// <summary>Attribute 0, e.g. "Production" / "ProductionSandbox" (undocumented).</summary>
        public string? ReceiptType { get; }

        /// <summary>Attribute 2.</summary>
        public string? BundleId { get; }

        /// <summary>
        /// Raw DER bytes of attribute 2 — the third input to the device-hash
        /// check. A fresh copy per call, so a caller cannot mutate the receipt.
        /// </summary>
        public byte[]? BundleIdBytes => ByteOps.Copy(_bundleIdBytes);

        /// <summary>Attribute 3.</summary>
        public string? AppVersion { get; }

        /// <summary>Attribute 4 — the device-specific opaque value. A fresh copy per call.</summary>
        public byte[]? OpaqueValue => ByteOps.Copy(_opaqueValue);

        /// <summary>
        /// Attribute 5 — SHA-1 of (device GUID ‖ opaque value ‖ bundle id
        /// bytes). A fresh copy per call.
        /// </summary>
        public byte[]? Sha1Hash => ByteOps.Copy(_sha1Hash);

        /// <summary>Attribute 12 — when Apple signed this receipt.</summary>
        public DateTimeOffset? CreationDate { get; }

        /// <summary>Attribute 18 (undocumented; community-established).</summary>
        public DateTimeOffset? OriginalPurchaseDate { get; }

        /// <summary>Attribute 19 — the version the user originally purchased.</summary>
        public string? OriginalAppVersion { get; }

        /// <summary>Attribute 21 — only present in receipts with an expiry (e.g. VPP).</summary>
        public DateTimeOffset? ExpirationDate { get; }

        /// <summary>Attribute 17, repeated.</summary>
        public IReadOnlyList<InAppPurchase> InAppPurchases { get; }

        /// <summary>
        /// Raw values of attribute types this library does not model, keyed by
        /// type — forward compatibility for fields Apple may add (PLAN D10).
        /// The arrays are this library's own copies of verified receipt bytes;
        /// treat them as read-only.
        /// </summary>
        public IReadOnlyDictionary<int, IReadOnlyList<byte[]>> UnknownAttributes { get; }

        internal byte[]? BundleIdBytesInternal => _bundleIdBytes;

        internal byte[]? OpaqueValueInternal => _opaqueValue;

        internal byte[]? Sha1HashInternal => _sha1Hash;
    }
}
