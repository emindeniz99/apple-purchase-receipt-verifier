using System.Collections.Generic;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>What a receipt payload hands out: copies, read-only collections, and no shared state with what built it.</summary>
public class ReceiptTests
{
    /// <summary>
    /// The device-hash inputs are handed out as copies: a caller hashing, or
    /// scribbling on, what it was given cannot change what the next reader of
    /// the same payload sees.
    /// </summary>
    [Fact]
    public void ByteFieldsHandedToTheCallerAreCopies()
    {
        ReceiptPayload receipt = new(
            "Production", null, "a", new byte[] { 0x0c, 0x01, 0x61 }, null, new byte[] { 1, 2 }, new byte[] { 3, 4 },
            null, null, null, new List<InAppPurchase>(), null, null, null, new Dictionary<int, IReadOnlyList<byte[]>>());

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
        InAppPurchase onlyPurchase = Assert.Single(payload.InApp);
        Assert.Equal(new byte[] { 5, 6 }, Assert.Single(onlyPurchase.UnknownAttributes[1799]));
        Assert.Single(onlyPurchase.UnknownAttributes);
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

    /// <summary>
    /// A read-only wrapper still hands out the byte arrays inside it, so every
    /// getter that reaches bytes returns a fresh copy (as the Java port
    /// does): a caller editing what it read, say to zero it after use, must
    /// not change the verified payload, what it logs, or the next reader.
    /// </summary>
    [Fact]
    public void EditingWhatAGetterReturnedDoesNotChangeTheNextRead()
    {
        Dictionary<int, IReadOnlyList<byte[]>> Attributes() => new() { [9999] = new List<byte[]> { new byte[] { 5, 6 } } };
        InAppPurchase purchase = new(1, "p", "t", null, null, null, null, null, null, null, null, Attributes());
        ReceiptPayload payload = new(
            "Production", null, "a", new byte[] { 0x0c, 0x01, 0x61 }, null, new byte[] { 1, 2 }, new byte[] { 3, 4 },
            null, null, null, new List<InAppPurchase> { purchase }, null, null, null, Attributes());
        string before = payload.ToJson();

        payload.BundleIdBytes![0] = 0xff;
        payload.OpaqueValue![0] = 0xff;
        payload.Sha1Hash![0] = 0xff;
        payload.UnknownAttributes[9999][0][0] = 0xff;
        payload.InApp[0].UnknownAttributes[9999][0][0] = 0xff;

        Assert.Equal(new byte[] { 0x0c, 0x01, 0x61 }, payload.BundleIdBytes);
        Assert.Equal(new byte[] { 1, 2 }, payload.OpaqueValue);
        Assert.Equal(new byte[] { 3, 4 }, payload.Sha1Hash);
        Assert.Equal(new byte[] { 5, 6 }, Assert.Single(payload.UnknownAttributes[9999]));
        Assert.Equal(new byte[] { 5, 6 }, Assert.Single(payload.InApp[0].UnknownAttributes[9999]));
        Assert.Equal(before, payload.ToJson());
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
