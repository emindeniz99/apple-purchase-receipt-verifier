using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Numerics;
using System.Text;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// Decodes the receipt payload attribute grammar (Apple, "Validating
    /// receipts on the device"): <c>SET OF SEQUENCE { type INTEGER, version
    /// INTEGER, value OCTET STRING }</c>, into a
    /// <see cref="ApplePurchaseReceiptVerifier.ReceiptPayload"/>.
    /// </summary>
    /// <remarks>
    /// <para>Encoding rules are <see cref="AsnEncodingRules.BER"/>, not DER:
    /// Apple's Xcode receipts use indefinite lengths, which DER rules reject
    /// outright.</para>
    /// <para>Owner rules of 2026-09-27 (docs/design/0.7-api.md, "Reading
    /// certificates and signed attributes" and "1. verifyReceipt"): the first
    /// occurrence of a known attribute wins, for the typed field and for the
    /// chain date; every attribute that does not end up in a typed field — a
    /// later copy of a known attribute, or a known attribute whose value does
    /// not parse — goes raw into <c>unknownAttributes</c>. An empty date
    /// string means "not set" and is not kept raw; any other non-empty date
    /// string that does not parse is kept raw. An IA5String holding a byte at
    /// or above 0x80, and an INTEGER that is not minimally (DER) encoded, do
    /// not parse either.</para>
    /// </remarks>
    internal static class ReceiptAttributes
    {
        private const int AttrReceiptType = 0;
        private const int AttrAppItemId = 1;
        private const int AttrBundleId = 2;
        private const int AttrAppVersion = 3;
        private const int AttrOpaqueValue = 4;
        private const int AttrSha1Hash = 5;
        private const int AttrCreationDate = 12;
        private const int AttrDownloadId = 15;
        private const int AttrVersionExternalIdentifier = 16;
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
        private const int IapIsTrialPeriod = 1713;
        private const int IapIsInIntroOfferPeriod = 1719;

        /// <summary>
        /// Attribute <em>types</em> are a 32-bit signed space; a wider one
        /// cannot be represented and makes the whole receipt
        /// <see cref="VerificationReason.UnreadablePayload"/> (docs/design's
        /// "types 0..2^31-1, wider makes the whole payload unreadable").
        /// </summary>
        private const int MaxAttributeType = int.MaxValue;

        /// <summary>
        /// The receipt creation date (attribute 12, first occurrence), read
        /// the only way anything in a payload is read before its signer is
        /// trusted: the top-level attribute SET is walked shallowly, and only
        /// the first occurrence's value of type 12 is decoded.
        /// </summary>
        /// <remarks>
        /// <see langword="null"/> means "judge the chain at the clock": no
        /// attribute 12, one that does not decode, or a walk that fails
        /// anywhere. Never throws: nothing is trusted yet, so nothing here can
        /// blame anyone.
        /// </remarks>
        internal static long? ReadCreationDateMs(byte[] payload)
        {
            try
            {
                foreach (Attribute attribute in ReadAttributeSet(payload, "receipt payload"))
                {
                    if (attribute.Type == AttrCreationDate)
                    {
                        return DecodeDate(attribute.Value, out long ms) == DateOutcome.Parsed ? ms : (long?)null;
                    }
                }

                return null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>Decodes the receipt payload into a <see cref="ReceiptPayload"/>. Throws on a structural or bound failure.</summary>
        internal static ReceiptPayload Parse(byte[] payload)
        {
            Builder builder = new Builder();
            HashSet<int> seen = new HashSet<int>();
            foreach (Attribute attribute in ReadAttributeSet(payload, "receipt payload"))
            {
                // Attribute 17 is repeated by design — one InAppPurchase per
                // occurrence, never deduplicated — so it is handled before
                // the first-occurrence-wins bookkeeping that every other
                // known attribute type goes through.
                if (attribute.Type == AttrInApp)
                {
                    try
                    {
                        builder.InApp.Add(ParseInApp(attribute.Value));
                    }
                    catch (VerificationException)
                    {
                        // The value is not a valid attribute SET (e.g. an
                        // OCTET STRING instead): a known attribute whose
                        // value does not parse, so no in_app entry and the
                        // raw octets go to unknownAttributes["17"] instead.
                        Record(builder.Unknown, attribute);
                    }

                    continue;
                }

                if (!seen.Add(attribute.Type))
                {
                    Record(builder.Unknown, attribute);
                    continue;
                }

                switch (attribute.Type)
                {
                    case AttrReceiptType: DecodeKnownString(attribute, builder.Unknown, v => builder.ReceiptType = v); break;
                    case AttrAppItemId: DecodeKnownInteger(attribute, builder.Unknown, v => builder.AppItemId = v); break;
                    case AttrBundleId:
                        // bundleIdBytes already carries the raw octets
                        // unconditionally, so a string-parse failure here must
                        // not also duplicate them into unknownAttributes.
                        builder.BundleIdBytes = attribute.Value;
                        try
                        {
                            builder.BundleId = DecodeString(attribute.Value);
                        }
                        catch (VerificationException)
                        {
                        }

                        break;
                    case AttrAppVersion: DecodeKnownString(attribute, builder.Unknown, v => builder.AppVersion = v); break;
                    case AttrOpaqueValue: builder.OpaqueValue = attribute.Value; break;
                    case AttrSha1Hash: builder.Sha1Hash = attribute.Value; break;
                    case AttrCreationDate: DecodeKnownDate(attribute, builder.Unknown, v => builder.ReceiptCreationDateMs = v); break;
                    case AttrDownloadId: DecodeKnownInteger(attribute, builder.Unknown, v => builder.DownloadId = v); break;
                    case AttrVersionExternalIdentifier: DecodeKnownInteger(attribute, builder.Unknown, v => builder.VersionExternalIdentifier = v); break;
                    case AttrOriginalPurchaseDate: DecodeKnownDate(attribute, builder.Unknown, v => builder.OriginalPurchaseDateMs = v); break;
                    case AttrOriginalAppVersion: DecodeKnownString(attribute, builder.Unknown, v => builder.OriginalApplicationVersion = v); break;
                    case AttrExpirationDate: DecodeKnownDate(attribute, builder.Unknown, v => builder.ExpirationDateMs = v); break;
                    default: Record(builder.Unknown, attribute); break;
                }
            }

            return builder.Build();
        }

        private static InAppPurchase ParseInApp(byte[] encoded)
        {
            InAppBuilder builder = new InAppBuilder();
            HashSet<int> seen = new HashSet<int>();

            // One level only: a nested attribute 17 inside an in-app set is
            // recorded as unknown rather than recursed into, so the depth of
            // this parser is a constant no input can change.
            foreach (Attribute attribute in ReadAttributeSet(encoded, "in-app purchase attribute"))
            {
                if (!seen.Add(attribute.Type))
                {
                    Record(builder.Unknown, attribute);
                    continue;
                }

                switch (attribute.Type)
                {
                    case IapQuantity: DecodeKnownInteger(attribute, builder.Unknown, v => builder.Quantity = v); break;
                    case IapProductId: DecodeKnownString(attribute, builder.Unknown, v => builder.ProductId = v); break;
                    case IapTransactionId: DecodeKnownString(attribute, builder.Unknown, v => builder.TransactionId = v); break;
                    case IapPurchaseDate: DecodeKnownDate(attribute, builder.Unknown, v => builder.PurchaseDateMs = v); break;
                    case IapOriginalTransactionId: DecodeKnownString(attribute, builder.Unknown, v => builder.OriginalTransactionId = v); break;
                    case IapOriginalPurchaseDate: DecodeKnownDate(attribute, builder.Unknown, v => builder.OriginalPurchaseDateMs = v); break;
                    case IapExpiresDate: DecodeKnownDate(attribute, builder.Unknown, v => builder.ExpiresDateMs = v); break;
                    case IapWebOrderLineItemId: DecodeKnownInteger(attribute, builder.Unknown, v => builder.WebOrderLineItemId = v); break;
                    case IapCancellationDate: DecodeKnownDate(attribute, builder.Unknown, v => builder.CancellationDateMs = v); break;
                    case IapIsTrialPeriod: DecodeKnownBoolean(attribute, builder.Unknown, v => builder.IsTrialPeriod = v); break;
                    case IapIsInIntroOfferPeriod: DecodeKnownBoolean(attribute, builder.Unknown, v => builder.IsInIntroOfferPeriod = v); break;
                    default: Record(builder.Unknown, attribute); break;
                }
            }

            return builder.Build();
        }

        private static void DecodeKnownString(Attribute attribute, Dictionary<int, List<byte[]>> unknown, Action<string> set)
        {
            try
            {
                set(DecodeString(attribute.Value));
            }
            catch (VerificationException)
            {
                Record(unknown, attribute);
            }
        }

        private static void DecodeKnownInteger(Attribute attribute, Dictionary<int, List<byte[]>> unknown, Action<long> set)
        {
            try
            {
                set(DecodeInteger(attribute.Value));
            }
            catch (VerificationException)
            {
                Record(unknown, attribute);
            }
        }

        private static void DecodeKnownBoolean(Attribute attribute, Dictionary<int, List<byte[]>> unknown, Action<bool> set)
        {
            try
            {
                set(DecodeInteger(attribute.Value) != 0);
            }
            catch (VerificationException)
            {
                Record(unknown, attribute);
            }
        }

        private static void DecodeKnownDate(Attribute attribute, Dictionary<int, List<byte[]>> unknown, Action<long> set)
        {
            switch (DecodeDate(attribute.Value, out long ms))
            {
                case DateOutcome.Parsed:
                    set(ms);
                    break;
                case DateOutcome.EmptySoNotSet:
                    break;
                default:
                    Record(unknown, attribute);
                    break;
            }
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

                byte[] setBytes = reader.PeekEncodedValue().ToArray();
                if (Asn1Depth.Exceeds(setBytes, Asn1Depth.MaxDepth))
                {
                    throw Malformed(what + " nests deeper than the maximum depth", null);
                }

                set = reader.ReadSetOf(skipSortOrderValidation: true);

                // Anything after the first ASN.1 value is a different encoding
                // from the one this receipt claims to be, and discarding it
                // would mean reading less than the bytes say.
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

                // A field after the third is tolerated (design, "Reading
                // certificates and signed attributes": encoding oddities
                // outside what a signature covers change no trust decision);
                // it is not read.
            }
            catch (AsnContentException e)
            {
                throw Malformed("malformed receipt attribute", e);
            }

            if (type.Sign < 0 || type > MaxAttributeType)
            {
                throw Malformed("receipt attribute type is outside the 32-bit signed range", null);
            }

            return new Attribute((int)type, value);
        }

        /// <summary>UTF8String or IA5String, strictly: an IA5String byte at or above 0x80 does not parse.</summary>
        private static string DecodeString(byte[] encoded)
        {
            try
            {
                AsnReader reader = new AsnReader(encoded, AsnEncodingRules.BER);
                Asn1Tag tag = reader.PeekTag();
                if (tag.TagClass != TagClass.Universal || tag.IsConstructed
                    || (tag.TagValue != 12 && tag.TagValue != 22))
                {
                    throw Malformed("attribute value is not a UTF8String or IA5String", null);
                }

                // AsnReader.ReadOctetString insists a Universal-class expected
                // tag be the OCTET STRING tag number, so a UTF8String/IA5String
                // primitive value is retagged as OCTET STRING (0x04) first —
                // its length and content octets are the same either way.
                byte[] tlv = reader.ReadEncodedValue().ToArray();
                if (reader.HasData)
                {
                    throw Malformed("attribute value has trailing data", null);
                }

                tlv[0] = 0x04;
                byte[] content = new AsnReader(tlv, AsnEncodingRules.BER).ReadOctetString();

                if (tag.TagValue == 22)
                {
                    foreach (byte b in content)
                    {
                        if (b >= 0x80)
                        {
                            throw Malformed("IA5String has a byte outside the 7-bit range", null);
                        }
                    }

                    char[] chars = new char[content.Length];
                    for (int i = 0; i < content.Length; i++)
                    {
                        chars[i] = (char)content[i];
                    }

                    return new string(chars);
                }

                return StrictUtf8.Decode(content)
                    ?? throw Malformed("attribute value is not valid UTF-8", null);
            }
            catch (AsnContentException e)
            {
                throw Malformed("attribute value is not valid ASN.1", e);
            }
        }

        private static long DecodeInteger(byte[] encoded)
        {
            BigInteger value;
            try
            {
                AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
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

            // Real receipts carry 7-byte non-negative integers, but the
            // decoder reports what is there: an ASN.1 INTEGER in hostile (or
            // adversarial-test) input may be negative, and the full signed
            // 64-bit range decodes as itself.
            if (value < long.MinValue || value > long.MaxValue)
            {
                throw Malformed("receipt integer is out of range", null);
            }

            return (long)value;
        }

        private enum DateOutcome
        {
            Parsed,
            EmptySoNotSet,
            Failed,
        }

        private static DateOutcome DecodeDate(byte[] encoded, out long epochMilliseconds)
        {
            epochMilliseconds = 0;
            string text;
            try
            {
                text = DecodeString(encoded);
            }
            catch (VerificationException)
            {
                return DateOutcome.Failed;
            }

            if (text.Length == 0)
            {
                return DateOutcome.EmptySoNotSet;
            }

            return ReceiptDate.TryParse(text, out epochMilliseconds) ? DateOutcome.Parsed : DateOutcome.Failed;
        }

        private static VerificationException Malformed(string detail, Exception? cause) =>
            new VerificationException(VerificationReason.Malformed, detail, cause);

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

        private sealed class Builder
        {
            internal string? ReceiptType;
            internal long? AppItemId;
            internal string? BundleId;
            internal byte[]? BundleIdBytes;
            internal string? AppVersion;
            internal byte[]? OpaqueValue;
            internal byte[]? Sha1Hash;
            internal long? ReceiptCreationDateMs;
            internal long? DownloadId;
            internal long? VersionExternalIdentifier;
            internal readonly List<InAppPurchase> InApp = new List<InAppPurchase>();
            internal long? OriginalPurchaseDateMs;
            internal string? OriginalApplicationVersion;
            internal long? ExpirationDateMs;
            internal readonly Dictionary<int, List<byte[]>> Unknown = new Dictionary<int, List<byte[]>>();

            internal ReceiptPayload Build() => new ReceiptPayload(
                ReceiptType, AppItemId, BundleId, BundleIdBytes, AppVersion, OpaqueValue, Sha1Hash,
                ReceiptCreationDateMs, DownloadId, VersionExternalIdentifier, InApp,
                OriginalPurchaseDateMs, OriginalApplicationVersion, ExpirationDateMs, Freeze(Unknown));
        }

        private sealed class InAppBuilder
        {
            internal long? Quantity;
            internal string? ProductId;
            internal string? TransactionId;
            internal long? PurchaseDateMs;
            internal string? OriginalTransactionId;
            internal long? OriginalPurchaseDateMs;
            internal long? ExpiresDateMs;
            internal long? WebOrderLineItemId;
            internal long? CancellationDateMs;
            internal bool? IsTrialPeriod;
            internal bool? IsInIntroOfferPeriod;
            internal readonly Dictionary<int, List<byte[]>> Unknown = new Dictionary<int, List<byte[]>>();

            internal InAppPurchase Build() => new InAppPurchase(
                Quantity, ProductId, TransactionId, PurchaseDateMs, OriginalTransactionId,
                OriginalPurchaseDateMs, ExpiresDateMs, WebOrderLineItemId, CancellationDateMs,
                IsTrialPeriod, IsInIntroOfferPeriod, Freeze(Unknown));
        }

        private static IReadOnlyDictionary<int, IReadOnlyList<byte[]>> Freeze(Dictionary<int, List<byte[]>> unknown)
        {
            Dictionary<int, IReadOnlyList<byte[]>> frozen = new Dictionary<int, IReadOnlyList<byte[]>>(unknown.Count);
            foreach (KeyValuePair<int, List<byte[]>> entry in unknown)
            {
                frozen.Add(entry.Key, entry.Value);
            }

            return frozen;
        }
    }
}
