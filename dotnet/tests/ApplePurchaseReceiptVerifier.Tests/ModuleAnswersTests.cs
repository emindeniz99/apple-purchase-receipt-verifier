using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
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
    /// <remarks>The new value keeps its literal text, so <c>1.0</c> stays <c>1.0</c>.</remarks>
    private static string ReplaceMember(string json, string memberWithQuotes, string replacement)
    {
        JsonObject map = JsonNode.Parse(json)!.AsObject();
        map[memberWithQuotes.Trim('"')] = JsonNode.Parse(replacement.Substring(replacement.IndexOf(':') + 1));
        return map.ToJsonString();
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("1")]
    [InlineData("\"x\"")]
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("")]
    [InlineData("{")]
    [InlineData("{\"verified\":true,}")]
    [InlineData("{\"verified\":false} {}")]
    [InlineData("{\"verified\":false} // a comment")]
    public void AnAnswerThatIsNotOneJsonObjectIsUnreadable(string answer)
    {
        Assert.Throws<ModuleAnswers.AnswerException>(() => ModuleAnswers.ReadReceipt(answer));
        Assert.Throws<ModuleAnswers.AnswerException>(() => ModuleAnswers.ReadSignedData(answer));
        Assert.Throws<ModuleAnswers.AnswerException>(() => ModuleAnswers.CheckInit(answer));
    }

    /// <summary>
    /// The module's JSON never repeats a member, but a repeat reads the way
    /// the old hand-written reader read it: once, with its last value.
    /// </summary>
    [Fact]
    public void ARepeatedMemberCountsOnceWithItsLastValue()
    {
        ModuleAnswers.CheckInit("{\"ok\":false,\"ok\":true}");
        VerificationResult<JsonPayload> read = ModuleAnswers.ReadSignedData(
            "{\"verified\":true,\"payload\":\"first\",\"payload\":\"{}\"}");
        Assert.Equal("{}", read.Payload!.Json);
    }

    [Theory]
    [InlineData("\"receipt_creation_date_ms\":1.0")]
    [InlineData("\"receipt_creation_date_ms\":1e3")]
    [InlineData("\"receipt_creation_date_ms\":9223372036854775808")]
    [InlineData("\"receipt_creation_date_ms\":-0.0")]
    [InlineData("\"receipt_creation_date_ms\":true")]
    public void ADateThatIsNotA64BitIntegerLiteralMakesTheAnswerUnreadable(string replacement)
    {
        string patched = ReplaceMember(SyntheticAnswers.Receipt().ToJson(), "receipt_creation_date_ms", replacement);
        Assert.Throws<ModuleAnswers.AnswerException>(
            () => ModuleAnswers.ReadReceipt("{\"verified\":true,\"payload\":" + patched + "}"));
    }

    [Fact]
    public void AStringHoldingALoneSurrogateEscapeMakesTheAnswerUnreadable()
    {
        Assert.Throws<ModuleAnswers.AnswerException>(
            () => ModuleAnswers.ReadSignedData("{\"verified\":true,\"payload\":\"\\ud800\"}"));
    }

    /// <summary>
    /// A verified JWS payload is the module's to judge, at any depth
    /// (DECISIONS.md R40), and it reaches this reader as a string, so its
    /// nesting never meets <see cref="Json.MaxDepth"/>. The conformance runner
    /// once failed on a 65-deep payload because it re-read the payload with
    /// a depth-64 reader; this pins that the wrapper itself never did.
    /// </summary>
    [Fact]
    public void AVerifiedPayloadNestedFarPastTheReadersBoundReadsUnchanged()
    {
        int depth = Json.MaxDepth * 100;
        string payload = new string('[', depth) + new string(']', depth);

        VerificationResult<JsonPayload> read = ModuleAnswers.ReadSignedData(SyntheticAnswers.VerifiedJws(payload));

        Assert.Equal(payload, read.Payload!.Json);
    }

    /// <summary>
    /// The deepest answer the module gives is six levels; the reader's bound
    /// is <see cref="Json.MaxDepth"/>, and the boundary is exact. An answer
    /// that deep is still not one the wire defines, so it is unreadable for
    /// its shape, the same outcome as one past the bound.
    /// </summary>
    [Fact]
    public void TheAnswerReaderTakesNestingUpToItsBoundAndRefusesOneLevelMore()
    {
        Assert.Equal(128, Json.MaxDepth);
        string atBound = "{\"verified\":" + new string('[', Json.MaxDepth - 1) + new string(']', Json.MaxDepth - 1) + "}";
        using (System.Text.Json.JsonDocument document = Json.Parse(atBound))
        {
            Assert.Equal(System.Text.Json.JsonValueKind.Object, document.RootElement.ValueKind);
        }

        ModuleAnswers.AnswerException shape = Assert.Throws<ModuleAnswers.AnswerException>(() => ModuleAnswers.ReadReceipt(atBound));
        Assert.Contains("not a boolean", shape.Message, StringComparison.Ordinal);

        string pastBound = "{\"verified\":" + new string('[', Json.MaxDepth) + new string(']', Json.MaxDepth) + "}";
        ModuleAnswers.AnswerException depth = Assert.Throws<ModuleAnswers.AnswerException>(() => ModuleAnswers.ReadReceipt(pastBound));
        Assert.Contains("not JSON", depth.Message, StringComparison.Ordinal);
    }

    /// <summary>The deepest answer the wire defines, an in-app purchase's unknown attribute, reads.</summary>
    [Fact]
    public void TheDeepestAnswerTheWireDefinesReads()
    {
        ReceiptPayload read = ModuleAnswers.ReadReceipt(SyntheticAnswers.Verified(SyntheticAnswers.Receipt())).Payload!;
        Assert.Equal(new byte[] { 7, 7 }, Assert.Single(read.InApp[0].UnknownAttributes[1799]));
    }
}
