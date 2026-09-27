using System;
using System.Collections.Generic;
using System.Globalization;
using ApplePurchaseReceiptVerifier.Internal;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// A verified legacy app receipt (the PKCS#7 payload). Only a payload
    /// returned by <see cref="IVerifier.VerifyReceipt"/> should be trusted —
    /// this class carries no proof by itself. <see langword="null"/> fields
    /// were absent from the receipt, or present with a value this library
    /// could not parse (see <see cref="UnknownAttributes"/>).
    /// </summary>
    public sealed class ReceiptPayload
    {
        private readonly byte[]? _bundleIdBytes;
        private readonly byte[]? _opaqueValue;
        private readonly byte[]? _sha1Hash;

        /// <summary>Builds a payload by hand, for a caller's own tests.</summary>
        public ReceiptPayload(
            string? receiptType,
            long? appItemId,
            string? bundleId,
            byte[]? bundleIdBytes,
            string? applicationVersion,
            byte[]? opaqueValue,
            byte[]? sha1Hash,
            long? receiptCreationDateMs,
            long? downloadId,
            long? versionExternalIdentifier,
            IReadOnlyList<InAppPurchase> inApp,
            long? originalPurchaseDateMs,
            string? originalApplicationVersion,
            long? expirationDateMs,
            IReadOnlyDictionary<int, IReadOnlyList<byte[]>> unknownAttributes)
        {
            ReceiptType = receiptType;
            AppItemId = appItemId;
            BundleId = bundleId;
            _bundleIdBytes = bundleIdBytes;
            ApplicationVersion = applicationVersion;
            _opaqueValue = opaqueValue;
            _sha1Hash = sha1Hash;
            ReceiptCreationDateMs = receiptCreationDateMs;
            DownloadId = downloadId;
            VersionExternalIdentifier = versionExternalIdentifier;
            InApp = inApp;
            OriginalPurchaseDateMs = originalPurchaseDateMs;
            OriginalApplicationVersion = originalApplicationVersion;
            ExpirationDateMs = expirationDateMs;
            UnknownAttributes = unknownAttributes;
        }

        /// <summary>Attribute 0.</summary>
        public string? ReceiptType { get; }

        /// <summary>Attribute 1 — echoed by Apple's verifyReceipt as both <c>adam_id</c> and <c>app_item_id</c>.</summary>
        public long? AppItemId { get; }

        /// <summary>Attribute 2.</summary>
        public string? BundleId { get; }

        /// <summary>
        /// Attribute 2's raw value octets, exactly as they sit in the receipt —
        /// one of the three inputs to Apple's device-hash formula. A fresh
        /// copy per call.
        /// </summary>
        public byte[]? BundleIdBytes => ByteOps.Copy(_bundleIdBytes);

        /// <summary>Attribute 3.</summary>
        public string? ApplicationVersion { get; }

        /// <summary>Attribute 4 — the device-specific opaque value. A fresh copy per call.</summary>
        public byte[]? OpaqueValue => ByteOps.Copy(_opaqueValue);

        /// <summary>Attribute 5. A fresh copy per call.</summary>
        public byte[]? Sha1Hash => ByteOps.Copy(_sha1Hash);

        /// <summary>Attribute 12, epoch milliseconds UTC — when Apple signed this receipt.</summary>
        public long? ReceiptCreationDateMs { get; }

        /// <summary>Attribute 15.</summary>
        public long? DownloadId { get; }

        /// <summary>Attribute 16.</summary>
        public long? VersionExternalIdentifier { get; }

        /// <summary>Attribute 17, repeated.</summary>
        public IReadOnlyList<InAppPurchase> InApp { get; }

        /// <summary>Attribute 18, epoch milliseconds UTC.</summary>
        public long? OriginalPurchaseDateMs { get; }

        /// <summary>Attribute 19 — the version the user originally purchased.</summary>
        public string? OriginalApplicationVersion { get; }

        /// <summary>Attribute 21, epoch milliseconds UTC — only present in receipts with an expiry (e.g. VPP).</summary>
        public long? ExpirationDateMs { get; }

        /// <summary>
        /// Raw values of attribute types this library does not model, keyed by
        /// type, in receipt order: an attribute type this library does not
        /// model, the second and later copies of a known attribute, and a
        /// known attribute whose value does not parse (whose typed field is
        /// then <see langword="null"/>).
        /// </summary>
        public IReadOnlyDictionary<int, IReadOnlyList<byte[]>> UnknownAttributes { get; }

        /// <summary>
        /// The canonical JSON rendering, for logging and storage: fixed key
        /// order, no whitespace, 64-bit ids as strings, dates as epoch
        /// milliseconds, bytes as standard base64. The same bytes in every
        /// port (docs/design/0.7-api.md, "Our JSON").
        /// </summary>
        public string ToJson()
        {
            OrderedMap json = new OrderedMap();
            json.Set("receipt_type", ReceiptType);
            json.Set("app_item_id", IdString(AppItemId));
            json.Set("bundle_id", BundleId);
            json.Set("bundle_id_bytes", Base64OrNull(_bundleIdBytes));
            json.Set("application_version", ApplicationVersion);
            json.Set("opaque_value", Base64OrNull(_opaqueValue));
            json.Set("sha1_hash", Base64OrNull(_sha1Hash));
            json.Set("receipt_creation_date_ms", ReceiptCreationDateMs);
            json.Set("download_id", IdString(DownloadId));
            json.Set("version_external_identifier", IdString(VersionExternalIdentifier));

            List<object?> inApp = new List<object?>(InApp.Count);
            foreach (InAppPurchase purchase in InApp)
            {
                inApp.Add(purchase.ToJsonValue());
            }

            json.Set("in_app", inApp);
            json.Set("original_purchase_date_ms", OriginalPurchaseDateMs);
            json.Set("original_application_version", OriginalApplicationVersion);
            json.Set("expiration_date_ms", ExpirationDateMs);
            json.Set("unknown_attributes", UnknownAttributesJson(UnknownAttributes));
            return Json.Write(json);
        }

        internal static string? IdString(long? value) =>
            value is long v ? v.ToString(CultureInfo.InvariantCulture) : null;

        internal static string? Base64OrNull(byte[]? value) => value is null ? null : Convert.ToBase64String(value);

        internal static OrderedMap UnknownAttributesJson(IReadOnlyDictionary<int, IReadOnlyList<byte[]>> unknown)
        {
            OrderedMap map = new OrderedMap();
            List<int> keys = new List<int>(unknown.Keys);
            keys.Sort();
            foreach (int key in keys)
            {
                List<object?> values = new List<object?>();
                foreach (byte[] value in unknown[key])
                {
                    values.Add(Convert.ToBase64String(value));
                }

                map.Set(key.ToString(CultureInfo.InvariantCulture), values);
            }

            return map;
        }
    }
}
