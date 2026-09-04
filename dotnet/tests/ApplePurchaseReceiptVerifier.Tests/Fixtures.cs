using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using ApplePurchaseReceiptVerifier.Internal;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The fixture registry from <c>fixtures/cases.json</c>: ids to logical bytes,
/// each checked against the SHA-256 the registry records for them.
/// </summary>
internal static class Fixtures
{
    /// <summary>The parsed <c>fixtures/cases.json</c> document.</summary>
    internal static readonly OrderedMap Cases = LoadCases();

    /// <summary>The <c>fixtures/</c> directory, found by walking up from the test binary.</summary>
    internal static readonly string Root = FindFixturesDirectory();

    private static readonly Dictionary<string, byte[]> Cache = new(StringComparer.Ordinal);

    /// <summary>Every registered fixture id.</summary>
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

    private static OrderedMap Registry =>
        Cases["fixtures"] as OrderedMap ?? throw new InvalidOperationException("cases.json has no fixtures map");

    /// <summary>
    /// The decoded logical bytes of a registered fixture, verified against the
    /// digest the registry records.
    /// </summary>
    /// <remarks>
    /// <c>contentSha256</c> is the anti-drift guarantee for the vectors: a
    /// fixture that is regenerated, re-encoded or silently edited changes the
    /// bytes every port verifies, and the expected fields would then be pinned
    /// to something no other port ever saw. Checking it here is what makes the
    /// guarantee load-bearing rather than documentary — and the digest is over
    /// the logical bytes, which are the bytes handed to the library.
    /// </remarks>
    internal static byte[] Bytes(string id)
    {
        lock (Cache)
        {
            if (Cache.TryGetValue(id, out byte[]? cached))
            {
                return cached;
            }
        }

        if (Registry[id] is not OrderedMap entry)
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

    /// <summary>The fixture's bytes as UTF-8 text — the JWS transport form.</summary>
    internal static string Text(string id) => Encoding.UTF8.GetString(Bytes(id));

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

    private static string Str(OrderedMap map, string key) =>
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

    private static OrderedMap LoadCases()
    {
        // Parsed with the reader the library itself ships, so the conformance
        // run is also a few hundred more inputs through it.
        return Json.ParseObject(File.ReadAllText(Path.Combine(FindFixturesDirectory(), "cases.json")));
    }

    private static string FindFixturesDirectory()
    {
        // Walk up rather than hardcode "../../..": the relative depth changes
        // the moment the target-framework count does.
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
