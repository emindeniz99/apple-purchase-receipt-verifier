using System;
using System.Collections.Generic;
using System.Globalization;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;
using JsonException = ApplePurchaseReceiptVerifier.Internal.JsonException;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The hand-rolled JSON reader and writer. It exists because
/// <c>System.Text.Json</c> is a package below net8.0 and an assembly compiled
/// against a newer one than the host ships cannot be loaded, so this code path
/// is the same on every target framework — which means its semantics have to be
/// pinned rather than inherited.
/// </summary>
public class JsonTests
{
    [Fact]
    public void ObjectsArraysScalarsAndNullsRoundTrip()
    {
        object? parsed = Json.Parse(
            "{\"a\":1,\"b\":\"two\",\"c\":[1,2,3],\"d\":null,\"e\":true,\"f\":{\"g\":false}}");
        OrderedMap map = Assert.IsType<OrderedMap>(parsed);

        Assert.Equal(1L, map["a"]);
        Assert.Equal("two", map["b"]);
        Assert.Equal(3, ((List<object?>)map["c"]!).Count);
        Assert.Null(map["d"]);
        Assert.Equal(true, map["e"]);
        Assert.Equal(false, ((OrderedMap)map["f"]!)["g"]);
    }

    [Fact]
    public void IntegralNumbersBecomeLongAndOthersBecomeDouble()
    {
        OrderedMap map = Json.ParseObject(
            "{\"i\":1722945600000,\"n\":-7,\"f\":1697679936056.485,\"e\":1e3}");
        Assert.Equal(1722945600000L, map["i"]);
        Assert.Equal(-7L, map["n"]);
        Assert.IsType<double>(map["f"]);
        Assert.IsType<double>(map["e"]);
    }

    [Fact]
    public void TheLastDuplicateKeyWins()
    {
        // JSON.parse, json.loads and Jackson all do this; so must we, or the
        // ports would disagree about what a payload claims.
        OrderedMap map = Json.ParseObject("{\"a\":1,\"a\":2}");
        Assert.Equal(2L, map["a"]);
        Assert.Single(map);
    }

    [Fact]
    public void KeyOrderIsPreserved()
    {
        OrderedMap map = Json.ParseObject("{\"z\":1,\"a\":2,\"m\":3}");
        Assert.Equal(new[] { "z", "a", "m" }, map.Keys);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("{")]
    [InlineData("}")]
    [InlineData("{\"a\"}")]
    [InlineData("{\"a\":}")]
    [InlineData("{\"a\":1,}")]
    [InlineData("[1,]")]
    [InlineData("{'a':1}")]
    [InlineData("nul")]
    [InlineData("truex")]
    [InlineData("01")]
    [InlineData("--1")]
    [InlineData("{\"a\":1} trailing")]
    [InlineData("\"unterminated")]
    [InlineData("\"\\q\"")]
    [InlineData("\"\\u00\"")]
    public void MalformedDocumentsAreRejected(string json)
    {
        Assert.Throws<JsonException>(() => Json.Parse(json));
    }

    [Fact]
    public void RawControlCharactersInStringsAreRejected()
    {
        Assert.Throws<JsonException>(() => Json.Parse("{\"a\":\"line\nbreak\"}"));
    }

    [Fact]
    public void EscapesAreDecoded()
    {
        OrderedMap map = Json.ParseObject(
            "{\"a\":\"q\\\"\\\\\\/\\b\\f\\n\\r\\t\\u00e9\\u0041\"}");
        Assert.Equal("q\"\\/\b\f\n\r\té A".Replace(" ", string.Empty, StringComparison.Ordinal), map["a"]);
    }

    [Fact]
    public void NestingDeeperThanTheBoundIsRejected()
    {
        string shallow = new string('[', Json.MaxDepth) + new string(']', Json.MaxDepth);
        Assert.NotNull(Json.Parse(shallow));

        string deep = new string('[', Json.MaxDepth + 2) + new string(']', Json.MaxDepth + 2);
        Assert.Throws<JsonException>(() => Json.Parse(deep));
    }

    [Fact]
    public void InputLongerThanTheBoundIsRejected()
    {
        Assert.Throws<JsonException>(() => Json.Parse("{\"a\":1}", maxLength: 3));
    }

    [Fact]
    public void ParseObjectRejectsAValueThatIsNotAnObject()
    {
        foreach (string json in new[] { "[]", "1", "\"x\"", "null", "true" })
        {
            Assert.Throws<JsonException>(() => Json.ParseObject(json));
        }
    }

    [Fact]
    public void TheWriterEscapesWhatItMustAndNothingElse()
    {
        OrderedMap map = new();
        map.Set("quote\"", "back\\slash");
        map.Set("control", "\u0001");
        map.Set("unicode", "héllo");
        Assert.Equal(
            "{\"quote\\\"\":\"back\\\\slash\",\"control\":\"\\u0001\",\"unicode\":\"héllo\"}",
            Json.Write(map));
    }

    [Fact]
    public void TheWriterIsCultureIndependent()
    {
        System.Globalization.CultureInfo original = System.Threading.Thread.CurrentThread.CurrentCulture;
        try
        {
            System.Threading.Thread.CurrentThread.CurrentCulture = new CultureInfo("de-DE");
            OrderedMap map = new();
            map.Set("i", 1722945600000L);
            map.Set("d", 1.5d);
            Assert.Equal("{\"i\":1722945600000,\"d\":1.5}", Json.Write(map));
        }
        finally
        {
            System.Threading.Thread.CurrentThread.CurrentCulture = original;
        }
    }

    [Fact]
    public void TheWriterRefusesValuesJsonCannotCarry()
    {
        OrderedMap map = new();
        map.Set("nan", double.NaN);
        Assert.Throws<JsonException>(() => Json.Write(map));
    }

    /// <summary>The reader is the one that reads every conformance vector.</summary>
    [Fact]
    public void TheCasesFileItselfParses()
    {
        Assert.True(Fixtures.Cases.ContainsKey("cases"));
        Assert.True(Fixtures.Cases.ContainsKey("fixtures"));
        Assert.Equal(1L, Fixtures.Cases["schemaVersion"]);
    }

    /// <summary>
    /// RFC 8259 requires exactly four hex digits after <c>\u</c>. .NET's
    /// <c>NumberStyles.HexNumber</c> is <c>AllowLeadingWhite |
    /// AllowTrailingWhite | AllowHexSpecifier</c>, so parsing the four-character
    /// window with it accepts a space, tab, CR or LF among the digits and reads
    /// a one-to-three-digit value — a grammar wider than every other port's
    /// (JSON.parse, json.loads, Jackson all reject these).
    /// </summary>
    [Theory]
    [InlineData("{\"k\":\"\\u 041\"}")]
    [InlineData("{\"k\":\"\\u041 \"}")]
    [InlineData("{\"k\":\"\\u\t041\"}")]
    [InlineData("{\"k\":\"\\u\r\n41\"}")]
    [InlineData("{\"k\":\"\\u  41\"}")]
    [InlineData("{\"k\":\"\\u41  \"}")]
    public void WhitespaceIsNotAHexDigitInAUnicodeEscape(string json)
    {
        Assert.Throws<JsonException>(() => Json.Parse(json));
    }

    [Theory]
    [InlineData("{\"k\":\"\\u0041\"}", "A")]
    [InlineData("{\"k\":\"\\u00e9\"}", "\u00e9")]
    [InlineData("{\"k\":\"\\uD83D\\uDE00\"}", "\U0001F600")]
    public void AWellFormedUnicodeEscapeStillDecodes(string json, string expected)
    {
        Assert.Equal(expected, Json.ParseObject(json)["k"]);
    }

}
