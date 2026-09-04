using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;
using ApplePurchaseReceiptVerifier.Receipt;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// The receipt payload attribute grammar (Apple, "Validating receipts on
    /// the device"): <c>SET OF SEQUENCE { type INTEGER, version INTEGER,
    /// value OCTET STRING }</c>.
    /// </summary>
    /// <remarks>
    /// Encoding rules are <see cref="AsnEncodingRules.BER"/>, not DER: Apple's
    /// Xcode receipts use indefinite lengths, which DER rules reject outright.
    /// Values are type-checked rather than coerced, and a value this parser
    /// cannot represent fails the receipt instead of being replaced by a
    /// sentinel.
    /// </remarks>
    internal static class ReceiptPayload
    {
        private const int AttrReceiptType = 0;
        private const int AttrBundleId = 2;
        private const int AttrAppVersion = 3;
        private const int AttrOpaqueValue = 4;
        private const int AttrSha1Hash = 5;
        private const int AttrCreationDate = 12;
        private const int AttrInApp = 17;
        private const int AttrOriginalPurchaseDate = 18;
        private const int AttrOriginalAppVersion = 19;
        private const int AttrExpirationDate = 21;

        private const int IapQuantity = 1701;
        private const int IapProductId = 1702;
        private const int IapTransactionId = 1703;
        private const int IapPurchaseDate = 1704;
        private const int IapOriginalTransactionId = 1705;
        private const int IapOriginalPurchaseDate = 1706;
        private const int IapExpiresDate = 1708;
        private const int IapWebOrderLineItemId = 1711;
        private const int IapCancellationDate = 1712;
        private const int IapIsInIntroOfferPeriod = 1719;

        /// <summary>
        /// Attribute <em>types</em> are a 32-bit signed space. Every type Apple
        /// has ever issued is a small number, and a value above this cannot be
        /// represented by ports whose type field is an int. Mapping such a type
        /// onto a sentinel would let two ports disagree about what the same
        /// receipt says, so it is a malformed receipt in every port.
        /// </summary>
        private const int MaxAttributeType = int.MaxValue;

        private static readonly Regex Rfc3339 = new Regex(
            @"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$",
            RegexOptions.CultureInvariant);

        /// <summary>Decodes the receipt payload into the modelled fields.</summary>
        internal static AppReceipt Parse(byte[] payload)
        {
            string? receiptType = null;
            string? bundleId = null;
            byte[]? bundleIdBytes = null;
            string? appVersion = null;
            byte[]? opaqueValue = null;
            byte[]? sha1Hash = null;
            DateTimeOffset? creationDate = null;
            DateTimeOffset? originalPurchaseDate = null;
            string? originalAppVersion = null;
            DateTimeOffset? expirationDate = null;
            List<InAppPurchase> purchases = new List<InAppPurchase>();
            Dictionary<int, List<byte[]>> unknown = new Dictionary<int, List<byte[]>>();

            foreach (Attribute attribute in ReadAttributeSet(payload, "receipt payload"))
            {
                switch (attribute.Type)
                {
                    case AttrReceiptType: receiptType = DecodeString(attribute.Value); break;
                    case AttrBundleId:
                        bundleId = DecodeString(attribute.Value);
                        bundleIdBytes = attribute.Value;
                        break;
                    case AttrAppVersion: appVersion = DecodeString(attribute.Value); break;
                    case AttrOpaqueValue: opaqueValue = attribute.Value; break;
                    case AttrSha1Hash: sha1Hash = attribute.Value; break;
                    case AttrCreationDate: creationDate = DecodeDate(attribute.Value); break;
                    case AttrInApp: purchases.Add(ParseInApp(attribute.Value)); break;
                    case AttrOriginalPurchaseDate: originalPurchaseDate = DecodeDate(attribute.Value); break;
                    case AttrOriginalAppVersion: originalAppVersion = DecodeString(attribute.Value); break;
                    case AttrExpirationDate: expirationDate = DecodeDate(attribute.Value); break;
                    default: Record(unknown, attribute); break;
                }
            }

            return new AppReceipt(
                receiptType, bundleId, bundleIdBytes, appVersion, opaqueValue, sha1Hash,
                creationDate, originalPurchaseDate, originalAppVersion, expirationDate,
                purchases, Freeze(unknown));
        }

        private static InAppPurchase ParseInApp(byte[] encoded)
        {
            long? quantity = null;
            string? productId = null;
            string? transactionId = null;
            string? originalTransactionId = null;
            DateTimeOffset? purchaseDate = null;
            DateTimeOffset? originalPurchaseDate = null;
            DateTimeOffset? expiresDate = null;
            DateTimeOffset? cancellationDate = null;
            long? webOrderLineItemId = null;
            long? isInIntroOfferPeriod = null;
            Dictionary<int, List<byte[]>> unknown = new Dictionary<int, List<byte[]>>();

            // One level only: a nested attribute 17 inside an in-app set is
            // recorded as unknown rather than recursed into, so the depth of
            // this parser is a constant no input can change.
            foreach (Attribute attribute in ReadAttributeSet(encoded, "in-app purchase attribute"))
            {
                switch (attribute.Type)
                {
                    case IapQuantity: quantity = DecodeInteger(attribute.Value); break;
                    case IapProductId: productId = DecodeString(attribute.Value); break;
                    case IapTransactionId: transactionId = DecodeString(attribute.Value); break;
                    case IapPurchaseDate: purchaseDate = DecodeDate(attribute.Value); break;
                    case IapOriginalTransactionId: originalTransactionId = DecodeString(attribute.Value); break;
                    case IapOriginalPurchaseDate: originalPurchaseDate = DecodeDate(attribute.Value); break;
                    case IapExpiresDate: expiresDate = DecodeDate(attribute.Value); break;
                    case IapWebOrderLineItemId: webOrderLineItemId = DecodeInteger(attribute.Value); break;
                    case IapCancellationDate: cancellationDate = DecodeDate(attribute.Value); break;
                    case IapIsInIntroOfferPeriod: isInIntroOfferPeriod = DecodeInteger(attribute.Value); break;
                    default: Record(unknown, attribute); break;
                }
            }

            return new InAppPurchase(
                quantity, productId, transactionId, originalTransactionId, purchaseDate,
                originalPurchaseDate, expiresDate, cancellationDate, webOrderLineItemId,
                isInIntroOfferPeriod, Freeze(unknown));
        }

        private static void Record(Dictionary<int, List<byte[]>> unknown, Attribute attribute)
        {
            if (!unknown.TryGetValue(attribute.Type, out List<byte[]>? values))
            {
                values = new List<byte[]>();
                unknown.Add(attribute.Type, values);
            }

            values.Add(attribute.Value);
        }

        private static IReadOnlyDictionary<int, IReadOnlyList<byte[]>> Freeze(
            Dictionary<int, List<byte[]>> unknown)
        {
            Dictionary<int, IReadOnlyList<byte[]>> frozen = new Dictionary<int, IReadOnlyList<byte[]>>(unknown.Count);
            foreach (KeyValuePair<int, List<byte[]>> entry in unknown)
            {
                frozen.Add(entry.Key, entry.Value);
            }

            return frozen;
        }

        private static List<Attribute> ReadAttributeSet(byte[] encoded, string what)
        {
            AsnReader set;
            try
            {
                AsnReader reader = new AsnReader(encoded, AsnEncodingRules.BER);
                if (reader.PeekTag().TagClass == TagClass.Universal && reader.PeekTag().TagValue == 4)
                {
                    // Xcode receipts double-wrap the payload in an extra OCTET
                    // STRING. Exactly one unwrap: after it the value must be a
                    // SET, so a nested-OCTET-STRING bomb cannot recurse.
                    byte[] unwrapped = reader.ReadOctetString();
                    RequireExhausted(reader, what);
                    reader = new AsnReader(unwrapped, AsnEncodingRules.BER);
                }

                set = reader.ReadSetOf(skipSortOrderValidation: true);

                // Anything after the first ASN.1 value is a different encoding
                // from the one this receipt claims to be, and discarding it
                // would mean reading less than the bytes say — two concatenated
                // SETs would present only the first one's bundle id. This is
                // the one parser that runs on untrusted bytes before any
                // signature check, so it reads exactly what is there or fails.
                RequireExhausted(reader, what);
            }
            catch (AsnContentException e)
            {
                throw Malformed(what + " is not a valid ASN.1 attribute set", e);
            }

            List<Attribute> attributes = new List<Attribute>();
            while (set.HasData)
            {
                attributes.Add(ReadAttribute(set));
            }

            return attributes;
        }

        private static void RequireExhausted(AsnReader reader, string what)
        {
            if (reader.HasData)
            {
                throw Malformed(what + " has trailing data after the attribute set", null);
            }
        }

        private static Attribute ReadAttribute(AsnReader set)
        {
            BigInteger type;
            byte[] value;
            try
            {
                AsnReader sequence = set.ReadSequence();
                type = sequence.ReadInteger();
                sequence.ReadEncodedValue();          // version — present, unread
                value = sequence.ReadOctetString();
            }
            catch (AsnContentException e)
            {
                throw Malformed("malformed receipt attribute", e);
            }

            if (type.Sign < 0 || type > MaxAttributeType)
            {
                throw Malformed(
                    "receipt attribute type is outside the 32-bit signed range", null);
            }

            return new Attribute((int)type, value);
        }

        private static AsnReader ReadSingleValue(byte[] encoded)
        {
            return new AsnReader(encoded, AsnEncodingRules.BER);
        }

        private static string DecodeString(byte[] encoded)
        {
            try
            {
                AsnReader reader = ReadSingleValue(encoded);
                Asn1Tag tag = reader.PeekTag();
                if (tag.TagClass != TagClass.Universal || (tag.TagValue != 12 && tag.TagValue != 22))
                {
                    throw Malformed("attribute value is not a UTF8String or IA5String", null);
                }

                string value = reader.ReadCharacterString(
                    tag.TagValue == 12 ? UniversalTagNumber.UTF8String : UniversalTagNumber.IA5String);
                if (reader.HasData)
                {
                    throw Malformed("attribute value has trailing data", null);
                }

                return value;
            }
            catch (AsnContentException e)
            {
                throw Malformed("attribute value is not valid ASN.1", e);
            }
            catch (DecoderFallbackException e)
            {
                throw Malformed("attribute value is not valid text", e);
            }
        }

        private static long DecodeInteger(byte[] encoded)
        {
            BigInteger value;
            try
            {
                AsnReader reader = ReadSingleValue(encoded);
                if (reader.PeekTag() != Asn1Tag.Integer)
                {
                    throw Malformed("attribute value is not an ASN.1 integer", null);
                }

                value = reader.ReadInteger();
                if (reader.HasData)
                {
                    throw Malformed("attribute value has trailing data", null);
                }
            }
            catch (AsnContentException e)
            {
                throw Malformed("attribute value is not valid ASN.1", e);
            }

            // Real receipts carry 7-byte integers (web_order_line_item_id);
            // negative values never occur.
            if (value.Sign < 0 || value > long.MaxValue)
            {
                throw Malformed("receipt integer is out of range", null);
            }

            return (long)value;
        }

        private static DateTimeOffset? DecodeDate(byte[] encoded)
        {
            string text = DecodeString(encoded);
            if (text.Length == 0)
            {
                // Real receipts use an empty string for an absent date.
                return null;
            }

            // The timezone designator is mandatory. A naive date would be read
            // as the server's local time, and the creation date is the instant
            // the chain's validity is judged at — the same receipt would verify
            // on one host and fail on another.
            if (!Rfc3339.IsMatch(text)
                || !DateTimeOffset.TryParse(
                        text,
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AdjustToUniversal,
                        out DateTimeOffset parsed))
            {
                throw Malformed("unparseable receipt date", null);
            }

            return parsed;
        }

        private static VerificationException Malformed(string detail, Exception? cause)
        {
            return new VerificationException(VerificationReason.InvalidReceiptFormat, detail, cause);
        }

        private readonly struct Attribute
        {
            internal Attribute(int type, byte[] value)
            {
                Type = type;
                Value = value;
            }

            internal int Type { get; }

            internal byte[] Value { get; }
        }
    }
}
