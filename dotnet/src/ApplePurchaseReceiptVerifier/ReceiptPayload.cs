using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;
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
        private readonly IReadOnlyDictionary<int, IReadOnlyList<byte[]>> _unknownAttributes;

        /// <summary>
        /// Builds a payload by hand, for a caller's own tests. The byte arrays,
        /// the in-app list and the unknown attributes are copied, so changing
        /// what was passed in afterwards does not change the payload.
        /// </summary>
        /// <exception cref="ArgumentNullException"><paramref name="inApp"/>, one of its purchases,
        /// <paramref name="unknownAttributes"/> or one of its values is <see langword="null"/>.</exception>
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
            IReadOnlyDictionary<int, IReadOnlyList<byte[]>> unknownAttributes,
            AppleEnvironment? environment)
        {
            ReceiptType = receiptType;
            AppItemId = appItemId;
            BundleId = bundleId;
            _bundleIdBytes = ByteOps.Copy(bundleIdBytes);
            ApplicationVersion = applicationVersion;
            _opaqueValue = ByteOps.Copy(opaqueValue);
            _sha1Hash = ByteOps.Copy(sha1Hash);
            ReceiptCreationDateMs = receiptCreationDateMs;
            DownloadId = downloadId;
            VersionExternalIdentifier = versionExternalIdentifier;
            InApp = CopyInApp(inApp);
            OriginalPurchaseDateMs = originalPurchaseDateMs;
            OriginalApplicationVersion = originalApplicationVersion;
            ExpirationDateMs = expirationDateMs;
            _unknownAttributes = ByteOps.CopyAttributes(unknownAttributes, nameof(unknownAttributes));
            Environment = environment;
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
        /// then <see langword="null"/>). A fresh copy per call.
        /// </summary>
        public IReadOnlyDictionary<int, IReadOnlyList<byte[]>> UnknownAttributes =>
            ByteOps.CopyAttributes(_unknownAttributes, nameof(UnknownAttributes));

        /// <summary>
        /// The environment the verifier read from attribute 0
        /// (docs/rust-core/DECISIONS.md R42): <see cref="AppleEnvironment.Production"/>
        /// for <c>Production</c> and <c>ProductionVPP</c>,
        /// <see cref="AppleEnvironment.Sandbox"/> for <c>ProductionSandbox</c> and
        /// <c>ProductionVPPSandbox</c>, <see langword="null"/> for anything else
        /// (<c>Xcode</c>, a missing value). Not part of <see cref="ToJson"/>.
        /// </summary>
        public AppleEnvironment? Environment { get; }

        /// <summary>
        /// This payload as JSON, for logging and storage: 64-bit ids as
        /// strings, dates as epoch milliseconds, bytes as standard base64,
        /// <c>null</c> for a missing field. Every port writes the same value;
        /// the bytes may differ (docs/design/0.7-api.md, "Our JSON").
        /// </summary>
        public string ToJson() => Json.Write(WriteTo);

        private void WriteTo(Utf8JsonWriter json)
        {
            json.WriteStartObject();
            json.WriteString("receipt_type", ReceiptType);
            json.WriteString("app_item_id", IdString(AppItemId));
            json.WriteString("bundle_id", BundleId);
            json.WriteString("bundle_id_bytes", Base64OrNull(_bundleIdBytes));
            json.WriteString("application_version", ApplicationVersion);
            json.WriteString("opaque_value", Base64OrNull(_opaqueValue));
            json.WriteString("sha1_hash", Base64OrNull(_sha1Hash));
            Json.WriteNumberOrNull(json, "receipt_creation_date_ms", ReceiptCreationDateMs);
            json.WriteString("download_id", IdString(DownloadId));
            json.WriteString("version_external_identifier", IdString(VersionExternalIdentifier));
            json.WriteStartArray("in_app");
            foreach (InAppPurchase purchase in InApp)
            {
                purchase.WriteTo(json);
            }

            json.WriteEndArray();
            Json.WriteNumberOrNull(json, "original_purchase_date_ms", OriginalPurchaseDateMs);
            json.WriteString("original_application_version", OriginalApplicationVersion);
            Json.WriteNumberOrNull(json, "expiration_date_ms", ExpirationDateMs);
            WriteUnknownAttributes(json, _unknownAttributes);
            json.WriteEndObject();
        }

        private static IReadOnlyList<InAppPurchase> CopyInApp(IReadOnlyList<InAppPurchase> inApp)
        {
            IReadOnlyList<InAppPurchase> source = inApp ?? throw new ArgumentNullException(nameof(inApp));
            InAppPurchase[] copy = new InAppPurchase[source.Count];
            for (int i = 0; i < copy.Length; i++)
            {
                copy[i] = source[i] ?? throw new ArgumentNullException(nameof(inApp), "an in-app purchase is null");
            }

            return Array.AsReadOnly(copy);
        }

        internal static string? IdString(long? value) =>
            value is long v ? v.ToString(CultureInfo.InvariantCulture) : null;

        internal static string? Base64OrNull(byte[]? value) => value is null ? null : Convert.ToBase64String(value);

        /// <summary>The <c>unknown_attributes</c> member: types in ascending order, each value as base64.</summary>
        internal static void WriteUnknownAttributes(Utf8JsonWriter json, IReadOnlyDictionary<int, IReadOnlyList<byte[]>> unknown)
        {
            json.WriteStartObject("unknown_attributes");
            List<int> keys = new List<int>(unknown.Keys);
            keys.Sort();
            foreach (int key in keys)
            {
                json.WriteStartArray(key.ToString(CultureInfo.InvariantCulture));
                foreach (byte[] value in unknown[key])
                {
                    json.WriteStringValue(Convert.ToBase64String(value));
                }

                json.WriteEndArray();
            }

            json.WriteEndObject();
        }
    }
}
