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
        Assert.Equal(AppleEnvironment.Sandbox, read.Environment);
        Assert.Equal(written.Environment, read.Environment);
    }

    /// <summary>
    /// The environment is the module's top-level answer beside the payload
    /// (DECISIONS.md R42), read into the payload as an API field, and never
    /// written by <see cref="ReceiptPayload.ToJson"/>.
    /// </summary>
    [Theory]
    [InlineData("\"Production\"", AppleEnvironment.Production)]
    [InlineData("\"Sandbox\"", AppleEnvironment.Sandbox)]
    [InlineData("null", null)]
    public void TheEnvironmentBesideThePayloadIsReadIntoIt(string stated, AppleEnvironment? expected)
    {
        string json = SyntheticAnswers.Receipt().ToJson();
        ReceiptPayload receipt = ModuleAnswers.ReadReceipt(
            "{\"verified\":true,\"payload\":" + json + ",\"environment\":" + stated + "}").Payload!;
        Assert.Equal(expected, receipt.Environment);
        Assert.Equal(json, receipt.ToJson());
        Assert.DoesNotContain("\"environment\"", receipt.ToJson(), StringComparison.Ordinal);

        JsonPayload jws = ModuleAnswers.ReadSignedData(
            "{\"verified\":true,\"payload\":\"{}\",\"environment\":" + stated + "}").Payload!;
        Assert.Equal(expected, jws.Environment);
        Assert.Equal("{}", jws.Json);
    }

    /// <summary>
    /// A verified answer without the environment, or with a value that is
    /// not one of the three, and a failure that carries one, are not the
    /// wire's answers.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData(",\"environment\":\"Xcode\"")]
    [InlineData(",\"environment\":\"PRODUCTION\"")]
    [InlineData(",\"environment\":\"\"")]
    [InlineData(",\"environment\":1")]
    [InlineData(",\"environment\":false")]
    [InlineData(",\"environment\":{}")]
    public void AVerifiedAnswerWithoutAKnownEnvironmentIsUnreadable(string member)
    {
        string json = SyntheticAnswers.Receipt().ToJson();
        Assert.Throws<ModuleAnswers.AnswerException>(
            () => ModuleAnswers.ReadReceipt("{\"verified\":true,\"payload\":" + json + member + "}"));
        Assert.Throws<ModuleAnswers.AnswerException>(
            () => ModuleAnswers.ReadSignedData("{\"verified\":true,\"payload\":\"{}\"" + member + "}"));
    }

    [Fact]
    public void AFailureCarryingAnEnvironmentIsUnreadable()
    {
        string answer = "{\"verified\":false,\"reason\":\"MALFORMED\",\"message\":\"m\",\"environment\":null}";
        Assert.Throws<ModuleAnswers.AnswerException>(() => ModuleAnswers.ReadReceipt(answer));
        Assert.Throws<ModuleAnswers.AnswerException>(() => ModuleAnswers.ReadSignedData(answer));
    }

    [Fact]
    public void AnEmptyPayloadOfNullsAndNoAttributesReadsBack()
    {
        ReceiptPayload empty = new(
            null, null, null, null, null, null, null, null, null, null,
            new List<InAppPurchase>(), null, null, null, new Dictionary<int, IReadOnlyList<byte[]>>(), null);

        ReceiptPayload read = ModuleAnswers.ReadReceipt(SyntheticAnswers.Verified(empty)).Payload!;

        Assert.Equal(empty.ToJson(), read.ToJson());
        Assert.Empty(read.InApp);
        Assert.Empty(read.UnknownAttributes);
        Assert.Null(read.Environment);
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
            new Dictionary<int, IReadOnlyList<byte[]>>(), null);
        string answer = SyntheticAnswers.Verified(big);
        Assert.True(answer.Length > 8 * 1024 * 1024, "the answer must be big enough to matter: " + answer.Length);

        Assert.Equal(40_000, ModuleAnswers.ReadReceipt(answer).Payload!.InApp.Count);
    }

    [Fact]
    public void InitsAnswersAreOkWithTheInputLengthOrARefusalWithItsMessage()
    {
        Assert.Equal(3_145_729, ModuleAnswers.CheckInit("{\"ok\":true,\"max_input_bytes\":3145729}"));
        Assert.Equal(1, ModuleAnswers.CheckInit("{\"max_input_bytes\":1,\"ok\":true}"));
        ArgumentException refused = Assert.Throws<ArgumentException>(
            () => ModuleAnswers.CheckInit("{\"ok\":false,\"message\":\"root 1: not a certificate\"}"));
        Assert.Contains("root 1: not a certificate", refused.Message, StringComparison.Ordinal);
        Assert.Throws<ModuleAnswers.AnswerException>(
            () => ModuleAnswers.CheckInit("{\"ok\":true,\"max_input_bytes\":3145729,\"message\":\"x\"}"));
        Assert.Throws<ModuleAnswers.AnswerException>(() => ModuleAnswers.CheckInit("{\"ok\":false}"));
        Assert.Throws<ModuleAnswers.AnswerException>(() => ModuleAnswers.CheckInit("ok"));
    }

    /// <summary>
    /// <c>{"ok":true}</c> alone is the answer of a module older than this
    /// wrapper (DECISIONS.md R42): it states no input length, so it is not
    /// init's answer, and neither is a length that is not a positive 32-bit
    /// integer.
    /// </summary>
    [Theory]
    [InlineData("{\"ok\":true}")]
    [InlineData("{\"ok\":true,\"message\":\"x\"}")]
    [InlineData("{\"ok\":true,\"max_input_bytes\":0}")]
    [InlineData("{\"ok\":true,\"max_input_bytes\":-1}")]
    [InlineData("{\"ok\":true,\"max_input_bytes\":\"3145729\"}")]
    [InlineData("{\"ok\":true,\"max_input_bytes\":3145729.0}")]
    [InlineData("{\"ok\":true,\"max_input_bytes\":1.5}")]
    [InlineData("{\"ok\":true,\"max_input_bytes\":2147483648}")]
    [InlineData("{\"ok\":true,\"max_input_bytes\":null}")]
    [InlineData("{\"ok\":true,\"max_input_bytes\":true}")]
    public void AnAcceptingInitAnswerWithoutAPositiveLengthIsNotInitsAnswer(string answer)
    {
        ModuleAnswers.AnswerException error = Assert.Throws<ModuleAnswers.AnswerException>(() => ModuleAnswers.CheckInit(answer));
        Assert.Contains("max_input_bytes", error.Message, StringComparison.Ordinal);
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
            () => ModuleAnswers.ReadReceipt("{\"verified\":true,\"payload\":" + patched + ",\"environment\":null}"));
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
        Assert.Equal(7, ModuleAnswers.CheckInit("{\"ok\":false,\"ok\":true,\"max_input_bytes\":7}"));
        VerificationResult<JsonPayload> read = ModuleAnswers.ReadSignedData(
            "{\"verified\":true,\"payload\":\"first\",\"payload\":\"{}\",\"environment\":\"Sandbox\",\"environment\":null}");
        Assert.Equal("{}", read.Payload!.Json);
        Assert.Null(read.Payload.Environment);
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
            () => ModuleAnswers.ReadReceipt("{\"verified\":true,\"payload\":" + patched + ",\"environment\":null}"));
    }

    [Fact]
    public void AStringHoldingALoneSurrogateEscapeMakesTheAnswerUnreadable()
    {
        Assert.Throws<ModuleAnswers.AnswerException>(
            () => ModuleAnswers.ReadSignedData("{\"verified\":true,\"payload\":\"\\ud800\",\"environment\":null}"));
    }

    /// <summary>
    /// A member name is read the way a string value is: a lone-surrogate
    /// escape in it makes the answer unreadable rather than escaping as an
    /// <see cref="InvalidOperationException"/>, which from <c>init</c> would
    /// reach the caller of <see cref="Verifier.Create"/> as something other
    /// than the module's answer being wrong.
    /// </summary>
    [Theory]
    [InlineData("{\"ok\":true,\"\\ud800\":1}")]
    [InlineData("{\"\\udc00x\":1,\"ok\":true}")]
    public void AnInitMemberNameHoldingALoneSurrogateEscapeMakesTheAnswerUnreadable(string answer)
    {
        Assert.Throws<ModuleAnswers.AnswerException>(() => ModuleAnswers.CheckInit(answer));
    }

    [Theory]
    [InlineData("{\"verified\":true,\"\\ud800\":1}")]
    [InlineData("{\"verified\":false,\"\\ud800\":\"MALFORMED\",\"message\":\"m\"}")]
    public void AVerifyMemberNameHoldingALoneSurrogateEscapeMakesTheAnswerUnreadable(string answer)
    {
        Assert.Throws<ModuleAnswers.AnswerException>(() => ModuleAnswers.ReadReceipt(answer));
        Assert.Throws<ModuleAnswers.AnswerException>(() => ModuleAnswers.ReadSignedData(answer));
    }

    [Fact]
    public void AReceiptPayloadMemberNameHoldingALoneSurrogateEscapeMakesTheAnswerUnreadable()
    {
        string json = SyntheticAnswers.Receipt().ToJson();
        string patched = json.Replace("\"receipt_creation_date_ms\":", "\"\\ud800\":");
        Assert.NotEqual(json, patched);
        Assert.Throws<ModuleAnswers.AnswerException>(
            () => ModuleAnswers.ReadReceipt("{\"verified\":true,\"payload\":" + patched + ",\"environment\":null}"));
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
