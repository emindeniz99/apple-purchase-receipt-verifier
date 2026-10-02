using System;
using System.Collections;
using System.Collections.Generic;
using System.Text.Json;
using ApplePurchaseReceiptVerifier.Internal;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>A JSON object as the harness reads it: members in document order, a repeated name keeping its last value.</summary>
internal sealed class JsonMap : Dictionary<string, object?>
{
    internal JsonMap()
        : base(StringComparer.Ordinal)
    {
    }

    internal void Set(string key, object? value) => this[key] = value;
}

/// <summary>
/// The value model the conformance harness compares with, read over
/// <c>System.Text.Json</c>: a <see cref="JsonMap"/> per object, a
/// <c>List&lt;object?&gt;</c> per array, a <see cref="long"/> for an integer
/// that fits one and a <see cref="double"/> for any other number, then
/// <see cref="string"/>, <see cref="bool"/> and <see langword="null"/>.
/// </summary>
internal static class TestJson
{
    private static readonly JsonDocumentOptions Options = new() { MaxDepth = Json.MaxDepth };

    internal static object? Parse(string json)
    {
        using JsonDocument document = JsonDocument.Parse(json, Options);
        return Value(document.RootElement);
    }

    internal static JsonMap ParseObject(string json) =>
        Parse(json) as JsonMap ?? throw new InvalidOperationException("harness error: expected a JSON object");

    /// <summary>Writes the value model back out, with the library's own writer options.</summary>
    internal static string Write(object? value) => Json.Write(writer => WriteValue(writer, value));

    private static object? Value(JsonElement json)
    {
        switch (json.ValueKind)
        {
            case JsonValueKind.Object:
                JsonMap map = new();
                foreach (JsonProperty member in json.EnumerateObject())
                {
                    map[member.Name] = Value(member.Value);
                }

                return map;
            case JsonValueKind.Array:
                List<object?> list = new();
                foreach (JsonElement element in json.EnumerateArray())
                {
                    list.Add(Value(element));
                }

                return list;
            case JsonValueKind.String:
                return json.GetString();
            case JsonValueKind.Number:
                // Two returns, not one conditional: `? long : double` is a double.
                if (json.TryGetInt64(out long integer))
                {
                    return integer;
                }

                return json.GetDouble();
            case JsonValueKind.True:
                return true;
            case JsonValueKind.False:
                return false;
            default:
                return null;
        }
    }

    private static void WriteValue(Utf8JsonWriter writer, object? value)
    {
        switch (value)
        {
            case null:
                writer.WriteNullValue();
                return;
            case string text:
                writer.WriteStringValue(text);
                return;
            case bool flag:
                writer.WriteBooleanValue(flag);
                return;
            case long integer:
                writer.WriteNumberValue(integer);
                return;
            case double number:
                writer.WriteNumberValue(number);
                return;
            case JsonMap map:
                writer.WriteStartObject();
                foreach (KeyValuePair<string, object?> member in map)
                {
                    writer.WritePropertyName(member.Key);
                    WriteValue(writer, member.Value);
                }

                writer.WriteEndObject();
                return;
            case IEnumerable list:
                writer.WriteStartArray();
                foreach (object? element in list)
                {
                    WriteValue(writer, element);
                }

                writer.WriteEndArray();
                return;
            default:
                throw new InvalidOperationException("harness error: no JSON for a " + value.GetType().Name);
        }
    }
}
