using System;
using System.Collections.Generic;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>Reading the module's JSON into the public types: the round trip, and the members it insists on.</summary>
public class ModuleAnswersTests
{
    [Fact]
    public void AnAnswerReadBackIsThePayloadThatWasWritten()
    {
        ReceiptPayload written = SyntheticAnswers.Receipt();

        ReceiptPayload read = ModuleAnswers.ReadReceipt(SyntheticAnswers.Verified(written)).Payload!;

        Assert.Equal(written.ToJson(), read.ToJson());
        Assert.Equal(written.ReceiptType, read.ReceiptType);
        Assert.Equal(written.DownloadId, read.DownloadId);
        Assert.Equal(-42L, read.DownloadId);
        Assert.Equal(9007199254740993L, read.VersionExternalIdentifier);
        Assert.Equal(written.BundleIdBytes, read.BundleIdBytes);
        Assert.Equal(2, read.InApp.Count);
        Assert.Equal("café 😀 \"quoted\" \\ back", read.InApp[1].ProductId);
        Assert.Null(read.InApp[1].Quantity);
        Assert.Equal(new byte[] { 7, 7 }, Assert.Single(read.InApp[0].UnknownAttributes[1799]));
        Assert.Equal(2, read.UnknownAttributes.Count);
    }

    [Fact]
    public void AnEmptyPayloadOfNullsAndNoAttributesReadsBack()
    {
        ReceiptPayload empty = new(
            null, null, null, null, null, null, null, null, null, null,
            new List<InAppPurchase>(), null, null, null, new Dictionary<int, IReadOnlyList<byte[]>>());

        ReceiptPayload read = ModuleAnswers.ReadReceipt(SyntheticAnswers.Verified(empty)).Payload!;

        Assert.Equal(empty.ToJson(), read.ToJson());
        Assert.Empty(read.InApp);
        Assert.Empty(read.UnknownAttributes);
    }

    [Fact]
    public void AnAnswerTooLargeForTheReadersDefaultBoundIsStillRead()
    {
        List<InAppPurchase> many = new();
        for (int i = 0; i < 40_000; i++)
        {
            many.Add(new InAppPurchase(
                1, "com.example.product." + i, "100000000" + i, 1705320000000L, null, null, null, null, null, null, null,
                new Dictionary<int, IReadOnlyList<byte[]>>()));
        }

        ReceiptPayload big = new(
            null, null, "big", null, null, null, null, null, null, null, many, null, null, null,
            new Dictionary<int, IReadOnlyList<byte[]>>());
        string answer = SyntheticAnswers.Verified(big);
        Assert.True(answer.Length > 8 * 1024 * 1024, "the answer must be big enough to matter: " + answer.Length);

        Assert.Equal(40_000, ModuleAnswers.ReadReceipt(answer).Payload!.InApp.Count);
    }

    [Fact]
    public void InitsAnswersAreOkOrARefusalWithItsMessage()
    {
        ModuleAnswers.CheckInit("{\"ok\":true}");
        ArgumentException refused = Assert.Throws<ArgumentException>(
            () => ModuleAnswers.CheckInit("{\"ok\":false,\"message\":\"root 1: not a certificate\"}"));
        Assert.Contains("root 1: not a certificate", refused.Message, StringComparison.Ordinal);
        Assert.Throws<ModuleAnswers.AnswerException>(() => ModuleAnswers.CheckInit("{\"ok\":true,\"message\":\"x\"}"));
        Assert.Throws<ModuleAnswers.AnswerException>(() => ModuleAnswers.CheckInit("{\"ok\":false}"));
        Assert.Throws<ModuleAnswers.AnswerException>(() => ModuleAnswers.CheckInit("ok"));
    }

    [Theory]
    [InlineData("\"app_item_id\":\"12x\"")]
    [InlineData("\"download_id\":12")]
    [InlineData("\"receipt_creation_date_ms\":\"1\"")]
    [InlineData("\"receipt_creation_date_ms\":1.5")]
    [InlineData("\"bundle_id_bytes\":\"***\"")]
    [InlineData("\"in_app\":[1]")]
    [InlineData("\"unknown_attributes\":{\"x\":[]}")]
    [InlineData("\"unknown_attributes\":{\"1\":[7]}")]
    [InlineData("\"unknown_attributes\":{\"99999999999\":[]}")]
    public void AMemberOfTheWrongTypeMakesTheAnswerUnreadable(string replacement)
    {
        string member = replacement.Substring(0, replacement.IndexOf(':'));
        string json = SyntheticAnswers.Receipt().ToJson();
        string patched = ReplaceMember(json, member, replacement);
        Assert.Throws<ModuleAnswers.AnswerException>(
            () => ModuleAnswers.ReadReceipt("{\"verified\":true,\"payload\":" + patched + "}"));
    }

    /// <summary>Swaps one top-level member of the payload's JSON for another spelling, keeping the rest.</summary>
    private static string ReplaceMember(string json, string memberWithQuotes, string replacement)
    {
        OrderedMap map = Json.ParseObject(json);
        OrderedMap patched = new();
        string wanted = memberWithQuotes.Trim('"');
        foreach (KeyValuePair<string, object?> entry in map)
        {
            if (entry.Key == wanted)
            {
                patched.Set(entry.Key, Json.Parse("{" + replacement + "}") is OrderedMap one ? one[wanted] : null);
            }
            else
            {
                patched.Set(entry.Key, entry.Value);
            }
        }

        return Json.Write(patched);
    }
}
