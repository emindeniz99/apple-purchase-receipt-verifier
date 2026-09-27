using System.Collections.Generic;
using System.Formats.Asn1;
using System.Numerics;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>The receipt path's own rules: the attribute grammar and what the payload hands out.</summary>
public class ReceiptTests
{
    private static ReceiptPayload Verified(byte[] payload)
    {
        TestPki.ReceiptChain chain = TestPki.SharedReceipt.Value;
        VerificationResult<ReceiptPayload> result = chain.Verifier().VerifyReceipt(chain.SignBase64(payload));
        Assert.True(result.Verified, result.Failure?.ToString());
        return result.Payload;
    }

    /// <summary>
    /// The device-hash inputs are handed out as copies: a caller hashing, or
    /// scribbling on, what it was given cannot change what the next reader of
    /// the same payload sees.
    /// </summary>
    [Fact]
    public void ByteFieldsHandedToTheCallerAreCopies()
    {
        ReceiptPayload receipt = TestPki.FixtureVerifier("receipt-root")
            .VerifyReceipt(Fixtures070.ForReceipt("receipt")).Payload!;

        foreach (System.Func<byte[]?> field in new System.Func<byte[]?>[]
                 { () => receipt.OpaqueValue, () => receipt.Sha1Hash, () => receipt.BundleIdBytes })
        {
            byte[] first = field()!;
            byte original = first[0];
            first[0] ^= 0xFF;
            Assert.Equal(original, field()![0]);
        }
    }

    /// <summary>
    /// Nothing Apple signed is lost: attribute types the library does not
    /// model are kept raw, each under its type, every repeat in receipt order.
    /// </summary>
    [Fact]
    public void UnknownAttributesArePreservedInOrderWithTheirRepeats()
    {
        ReceiptPayload parsed = Verified(TestPki.AttributeSet(new (BigInteger, byte[])[]
        {
            (2, TestPki.Utf8("com.example.app")),
            (12, TestPki.Ia5("2024-08-06T12:00:00Z")),
            (9999, new byte[] { 1, 2, 3 }),
            (31337, new byte[] { 9 }),
            (9999, new byte[] { 4, 5 }),
        }));

        Assert.Equal(2, parsed.UnknownAttributes.Count);
        Assert.Equal(new[] { new byte[] { 1, 2, 3 }, new byte[] { 4, 5 } }, parsed.UnknownAttributes[9999]);
        Assert.Equal(new byte[] { 9 }, Assert.Single(parsed.UnknownAttributes[31337]));
        OrderedMap unknown = (OrderedMap)Json.ParseObject(parsed.ToJson())["unknown_attributes"]!;
        Assert.Equal(new object?[] { "AQID", "BAU=" }, (List<object?>)unknown["9999"]!);
        Assert.Equal(new object?[] { "CQ==" }, (List<object?>)unknown["31337"]!);
    }

    /// <summary>
    /// A date attribute whose string is empty means "not set": the typed field
    /// is null and nothing is kept raw, so Apple's empty 1712 values leave no
    /// trace. An empty string that is not a date is the value "".
    /// </summary>
    [Fact]
    public void AnEmptyDateStringMeansTheAttributeIsAbsent()
    {
        byte[] inApp = TestPki.AttributeSet(new (BigInteger, byte[])[]
        {
            (1702, TestPki.Utf8("com.example.app.pro")),
            (1712, TestPki.Ia5(string.Empty)),
        });
        ReceiptPayload parsed = Verified(TestPki.AttributeSet(new (BigInteger, byte[])[]
        {
            (2, TestPki.Utf8("com.example.app")),
            (12, TestPki.Ia5("2024-08-06T12:00:00Z")),
            (19, TestPki.Utf8(string.Empty)),
            (21, TestPki.Ia5(string.Empty)),
            (17, inApp),
        }));

        Assert.Null(parsed.ExpirationDateMs);
        Assert.Equal(string.Empty, parsed.OriginalApplicationVersion);
        Assert.Empty(parsed.UnknownAttributes);
        InAppPurchase purchase = Assert.Single(parsed.InApp);
        Assert.Null(purchase.CancellationDateMs);
        Assert.Empty(purchase.UnknownAttributes);
    }

    /// <summary>
    /// Xcode receipts wrap the attribute SET in one extra OCTET STRING
    /// (receipt/accept-double-wrapped-payload); exactly one unwrap is taken,
    /// so a payload wrapped twice is Apple-signed content that does not parse.
    /// </summary>
    [Fact]
    public void ADoubleWrappedPayloadIsUnwrappedExactlyOnce()
    {
        AsnWriter once = new(AsnEncodingRules.DER);
        once.WriteOctetString(TestPki.StandardPayload());
        Assert.Equal("com.example.app", Verified(once.Encode()).BundleId);

        AsnWriter twice = new(AsnEncodingRules.DER);
        twice.WriteOctetString(once.Encode());
        TestPki.ReceiptChain chain = TestPki.SharedReceipt.Value;
        Assert.Equal(
            VerificationReason.UnreadablePayload,
            chain.Verifier().VerifyReceipt(chain.SignBase64(twice.Encode())).Failure?.Reason);
    }

    /// <summary>
    /// A payload built by hand is a snapshot: a caller that keeps and later
    /// changes the arrays, the purchase list or the attribute map it passed
    /// in cannot change what the payload reports or what ToJson writes.
    /// </summary>
    [Fact]
    public void AHandBuiltPayloadDoesNotChangeWhenItsInputsDo()
    {
        byte[] bundleIdBytes = { 0x0c, 0x01, 0x61 };
        byte[] opaque = { 1, 2 };
        byte[] sha1 = { 3, 4 };
        byte[] raw = { 5, 6 };
        List<byte[]> rawValues = new() { raw };
        Dictionary<int, IReadOnlyList<byte[]>> purchaseUnknown = new() { [1799] = rawValues };
        InAppPurchase purchase = new(1, "p", "t", null, null, null, null, null, null, null, null, purchaseUnknown);
        List<InAppPurchase> inApp = new() { purchase };
        Dictionary<int, IReadOnlyList<byte[]>> unknown = new() { [9999] = new List<byte[]> { raw } };
        ReceiptPayload payload = new(
            "Production", null, "a", bundleIdBytes, null, opaque, sha1, null, null, null,
            inApp, null, null, null, unknown);
        string before = payload.ToJson();

        bundleIdBytes[0] = 0xff;
        opaque[0] = 0xff;
        sha1[0] = 0xff;
        raw[0] = 0xff;
        rawValues.Add(new byte[] { 7 });
        purchaseUnknown[42] = new List<byte[]> { new byte[] { 8 } };
        inApp.Add(purchase);
        unknown[1] = new List<byte[]> { new byte[] { 9 } };

        Assert.Equal(before, payload.ToJson());
        Assert.Equal(new byte[] { 0x0c, 0x01, 0x61 }, payload.BundleIdBytes);
        Assert.Equal(new byte[] { 5, 6 }, Assert.Single(payload.UnknownAttributes[9999]));
        Assert.Single(payload.InApp);
        Assert.Equal(new byte[] { 5, 6 }, Assert.Single(payload.InApp[0].UnknownAttributes[1799]));
        Assert.Single(payload.InApp[0].UnknownAttributes);
    }

    /// <summary>
    /// What a payload hands out cannot be recast and edited in place: the
    /// purchase list and the attribute collections are read-only wrappers.
    /// </summary>
    [Fact]
    public void AHandBuiltPayloadsCollectionsAreReadOnly()
    {
        ReceiptPayload payload = new(
            null, null, null, null, null, null, null, null, null, null,
            new List<InAppPurchase>(), null, null, null,
            new Dictionary<int, IReadOnlyList<byte[]>> { [9999] = new List<byte[]> { new byte[] { 1 } } });

        Assert.False(payload.InApp is List<InAppPurchase> || payload.InApp is InAppPurchase[]);
        Assert.False(payload.UnknownAttributes is Dictionary<int, IReadOnlyList<byte[]>>);
        Assert.True(((ICollection<byte[]>)payload.UnknownAttributes[9999]).IsReadOnly);
    }

    [Fact]
    public void AHandBuiltPayloadRefusesNullCollections()
    {
        Assert.Throws<System.ArgumentNullException>(() => new InAppPurchase(
            null, null, null, null, null, null, null, null, null, null, null, null!));
        Assert.Throws<System.ArgumentNullException>(() => new ReceiptPayload(
            null, null, null, null, null, null, null, null, null, null,
            null!, null, null, null, new Dictionary<int, IReadOnlyList<byte[]>>()));
        Assert.Throws<System.ArgumentNullException>(() => new ReceiptPayload(
            null, null, null, null, null, null, null, null, null, null,
            new List<InAppPurchase> { null! }, null, null, null, new Dictionary<int, IReadOnlyList<byte[]>>()));
    }
}
