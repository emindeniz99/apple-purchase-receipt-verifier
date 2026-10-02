using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using ApplePurchaseReceiptVerifier.Internal;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The fixture registry from <c>fixtures/cases.json</c>: ids to logical
/// bytes, each checked against the SHA-256 the registry records for them.
/// </summary>
internal static class Fixtures070
{
    internal static readonly JsonMap Cases = LoadCases();

    internal static readonly string Root = FindFixturesDirectory();

    private static readonly Dictionary<string, byte[]> Cache = new(StringComparer.Ordinal);

    internal static IEnumerable<string> Ids
    {
        get
        {
            foreach (KeyValuePair<string, object?> entry in Registry)
            {
                yield return entry.Key;
            }
        }
    }

    private static JsonMap Registry =>
        Cases["fixtures"] as JsonMap ?? throw new InvalidOperationException("cases.json has no fixtures map");

    /// <summary>The fixture's logical bytes, per its codec, digest-checked.</summary>
    internal static byte[] Bytes(string id)
    {
        lock (Cache)
        {
            if (Cache.TryGetValue(id, out byte[]? cached))
            {
                return cached;
            }
        }

        if (Registry[id] is not JsonMap entry)
        {
            throw new InvalidOperationException($"harness error: cases.json registers no fixture \"{id}\"");
        }

        string path = Str(entry, "path");
        string codec = Str(entry, "codec");
        string expected = Str(entry, "contentSha256");
        byte[] raw = File.ReadAllBytes(Path.Combine(Root, path.Replace('/', Path.DirectorySeparatorChar)));
        byte[] bytes = codec switch
        {
            "raw" => raw,
            "base64" => Convert.FromBase64String(Strip(Encoding.ASCII.GetString(raw))),
            "utf8" => Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(raw).Trim()),
            "text" => raw,
            _ => throw new InvalidOperationException($"harness error: unknown fixture codec \"{codec}\""),
        };

        string actual = Hex(SHA256.HashData(bytes));
        if (!string.Equals(actual, expected, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"fixture \"{id}\" ({path}, codec {codec}) has drifted: cases.json records "
                + $"contentSha256 {expected}, the decoded bytes hash to {actual}");
        }

        lock (Cache)
        {
            Cache[id] = bytes;
        }

        return bytes;
    }

    /// <summary>As the string handed to <c>verifyReceipt</c> / the endpoint's <c>receipt-data</c>: verbatim for a text fixture, canonical base64 otherwise.</summary>
    internal static string ForReceipt(string id)
    {
        return Codec(id) == "text" ? Encoding.UTF8.GetString(Bytes(id)) : Convert.ToBase64String(Bytes(id));
    }

    /// <summary>As the string handed to <c>verifySignedData</c>: the logical bytes, decoded as UTF-8.</summary>
    internal static string ForSignedData(string id) => Encoding.UTF8.GetString(Bytes(id));

    internal static string Codec(string id)
    {
        if (Registry[id] is not JsonMap entry)
        {
            throw new InvalidOperationException($"harness error: cases.json registers no fixture \"{id}\"");
        }

        return Str(entry, "codec");
    }

    private static string Strip(string text)
    {
        StringBuilder builder = new(text.Length);
        foreach (char c in text)
        {
            if (!char.IsWhiteSpace(c))
            {
                builder.Append(c);
            }
        }

        return builder.ToString();
    }

    private static string Str(JsonMap map, string key) =>
        map[key] as string ?? throw new InvalidOperationException($"harness error: missing \"{key}\"");

    private static string Hex(byte[] value)
    {
        StringBuilder builder = new(value.Length * 2);
        foreach (byte b in value)
        {
            builder.Append(b.ToString("x2", CultureInfo.InvariantCulture));
        }

        return builder.ToString();
    }

    private static JsonMap LoadCases()
    {
        return TestJson.ParseObject(File.ReadAllText(Path.Combine(FindFixturesDirectory(), "cases.json")));
    }

    private static string FindFixturesDirectory()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, "fixtures");
            if (File.Exists(Path.Combine(candidate, "cases.json")))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("harness error: could not locate fixtures/cases.json");
    }
}
