using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The options <c>Internal.Json</c> puts on <c>System.Text.Json</c>. Before
/// 0.8 this package carried a hand-written reader and writer; what callers saw
/// of it, <see cref="ReceiptPayload.ToJson"/>'s bytes, is pinned here so the
/// switch changed none of them.
/// </summary>
public class JsonTests
{
    private static string Write(string value) => Json.Write(json => json.WriteStringValue(value));

    [Fact]
    public void TheWriterEscapesWhatItMustAndNothingElse()
    {
        string written = Json.Write(json =>
        {
            json.WriteStartObject();
            json.WriteString("quote\"", "back\\slash");
            json.WriteString("control", "\u0001");
            json.WriteString("unicode", "héllo");
            json.WriteEndObject();
        });
        Assert.Equal(
            "{\"quote\\\"\":\"back\\\\slash\",\"control\":\"\\u0001\",\"unicode\":\"héllo\"}",
            written);
    }

    /// <summary>
    /// The escapes the old writer produced, character for character: the five
    /// short forms, <c>\u00xx</c> in lower case for the other controls, and
    /// nothing else. Neither encoder <c>System.Text.Json</c> ships gives
    /// this: the default one escapes HTML-sensitive and all non-ASCII text,
    /// and <c>UnsafeRelaxedJsonEscaping</c> writes upper-case hex and escapes
    /// most of the non-ASCII rows here (measured on .NET 8.0.31 and 10.0.12).
    /// </summary>
    [Fact]
    public void TheWriterKeepsTheEscapingToJsonAlwaysHad()
    {
        (string Value, string Expected)[] cases =
        {
            ("\b\f\n\r\t", "\"\\b\\f\\n\\r\\t\""),
            ("\u0000\u001f", "\"\\u0000\\u001f\""),
            ("\u000b\u001b", "\"\\u000b\\u001b\""),
            ("/", "\"/\""),
            ("<script>&'+`", "\"<script>&'+`\""),
            ("\u007f\u0080\u00ad", "\"\u007f\u0080\u00ad\""),
            ("\u2028\u2029", "\"\u2028\u2029\""),
            ("\ue000\ufeff\ufffe\uffff", "\"\ue000\ufeff\ufffe\uffff\""),
            ("\u0378\u0870", "\"\u0378\u0870\""),
            ("caf\u00e9 \U0001F600 \U0010FFFF", "\"caf\u00e9 \U0001F600 \U0010FFFF\""),
        };
        foreach ((string value, string expected) in cases)
        {
            Assert.Equal(expected, Write(value));
        }
    }

    /// <summary>
    /// A lone surrogate has no UTF-8 form. Only a payload built by hand can
    /// hold one (the module's strings are Rust strings); it is written as
    /// U+FFFD rather than making <see cref="ReceiptPayload.ToJson"/> throw.
    /// </summary>
    [Fact]
    public void ALoneSurrogateIsWrittenAsTheReplacementCharacter()
    {
        (string Value, string Expected)[] cases =
        {
            ("\ud800", "\"\ufffd\""),
            ("a\udc00b", "\"a\ufffdb\""),
            ("x\ud83d", "\"x\ufffd\""),
            ("\udc00\ud800", "\"\ufffd\ufffd\""),
        };
        foreach ((string value, string expected) in cases)
        {
            Assert.Equal(expected, Write(value));
        }
    }

    [Fact]
    public void TheWriterIsCultureIndependent()
    {
        CultureInfo original = System.Threading.Thread.CurrentThread.CurrentCulture;
        try
        {
            System.Threading.Thread.CurrentThread.CurrentCulture = new CultureInfo("de-DE");
            string written = Json.Write(json =>
            {
                json.WriteStartObject();
                json.WriteNumber("i", 1722945600000L);
                json.WriteNumber("n", -42L);
                json.WriteNumber("max", long.MaxValue);
                json.WriteEndObject();
            });
            Assert.Equal("{\"i\":1722945600000,\"n\":-42,\"max\":9223372036854775807}", written);
        }
        finally
        {
            System.Threading.Thread.CurrentThread.CurrentCulture = original;
        }
    }

    [Fact]
    public void AMissingValueIsWrittenAsNull()
    {
        string written = Json.Write(json =>
        {
            json.WriteStartObject();
            json.WriteString("s", (string?)null);
            Json.WriteNumberOrNull(json, "n", null);
            Json.WriteBooleanOrNull(json, "b", null);
            Json.WriteNumberOrNull(json, "n2", 0L);
            Json.WriteBooleanOrNull(json, "b2", false);
            json.WriteEndObject();
        });
        Assert.Equal("{\"s\":null,\"n\":null,\"b\":null,\"n2\":0,\"b2\":false}", written);
    }

    /// <summary>
    /// <see cref="ReceiptPayload.ToJson"/> byte for byte: member order, ids as
    /// strings, dates as integers, bytes as base64, unknown attributes by
    /// ascending type, and every string as itself.
    /// </summary>
    [Fact]
    public void ToJsonIsByteForByteWhatItWasBeforeSystemTextJson()
    {
        Assert.Equal(
            "{\"receipt_type\":\"ProductionSandbox\",\"app_item_id\":\"1234567890123456789\",\"bundle_id\":\"com.example.app\","
            + "\"bundle_id_bytes\":\"DA9j\",\"application_version\":\"1.2.3\",\"opaque_value\":\"AQIDBA==\",\"sha1_hash\":\"/wCA\","
            + "\"receipt_creation_date_ms\":1722945600000,\"download_id\":\"-42\",\"version_external_identifier\":\"9007199254740993\","
            + "\"in_app\":[{\"quantity\":2,\"product_id\":\"com.example.coins\",\"transaction_id\":\"1000000123456789\","
            + "\"purchase_date_ms\":1705320000000,\"original_transaction_id\":\"1000000123456789\",\"original_purchase_date_ms\":1705320000000,"
            + "\"expires_date_ms\":1705323600000,\"web_order_line_item_id\":\"9223372036854775807\",\"cancellation_date_ms\":1705330000000,"
            + "\"is_trial_period\":true,\"is_in_intro_offer_period\":false,\"unknown_attributes\":{\"1799\":[\"Bwc=\"]}},"
            + "{\"quantity\":null,\"product_id\":\"caf\u00e9 \U0001F600 \\\"quoted\\\" \\\\ back\",\"transaction_id\":null,\"purchase_date_ms\":null,"
            + "\"original_transaction_id\":null,\"original_purchase_date_ms\":null,\"expires_date_ms\":null,\"web_order_line_item_id\":null,"
            + "\"cancellation_date_ms\":null,\"is_trial_period\":null,\"is_in_intro_offer_period\":null,\"unknown_attributes\":{}}],"
            + "\"original_purchase_date_ms\":1705320000000,\"original_application_version\":\"1.0\",\"expiration_date_ms\":1893456000000,"
            + "\"unknown_attributes\":{\"9999\":[\"AQID\",\"BAU=\"],\"31337\":[\"CQ==\"]}}",
            SyntheticAnswers.Receipt().ToJson());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("{")]
    [InlineData("{\"a\":1,}")]
    [InlineData("[1,]")]
    [InlineData("{'a':1}")]
    [InlineData("01")]
    [InlineData("+1")]
    [InlineData("NaN")]
    [InlineData("{\"a\":1} trailing")]
    [InlineData("{\"a\":1} // comment")]
    [InlineData("\"\\q\"")]
    [InlineData("\"\\u00\"")]
    [InlineData("\"\\u 041\"")]
    [InlineData("{\"a\":\"line\nbreak\"}")]
    public void TheReaderRefusesWhatRfc8259Does(string json)
    {
        Assert.ThrowsAny<JsonException>(() => Json.Parse(json).Dispose());
    }

    /// <summary>The harness's reader is the one that reads every conformance vector.</summary>
    [Fact]
    public void TheCasesFileItselfParses()
    {
        Assert.True(Fixtures070.Cases.ContainsKey("cases"));
        Assert.True(Fixtures070.Cases.ContainsKey("fixtures"));
        Assert.Equal(2L, Fixtures070.Cases["schemaVersion"]);
        Assert.IsType<List<object?>>(Fixtures070.Cases["cases"]);
    }
}
