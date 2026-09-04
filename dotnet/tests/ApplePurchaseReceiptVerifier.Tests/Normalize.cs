using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// Renders a returned value into the language-neutral shape the conformance
/// field paths are written against, and resolves those paths over it.
/// </summary>
internal static class Normalize
{
    // A path step is either a name (bundleId, length) or a bracket ([9999],
    // [0], [productId=com.example.app.vip]). Bracket contents hold dots — the
    // selector values are bundle ids and product ids — so a plain split on '.'
    // is wrong.
    private static readonly Regex PathStep = new(@"\.?([^.\[\]]+)|\[([^\]]+)\]", RegexOptions.CultureInvariant);

    /// <summary>Dates as ISO-8601 UTC, bytes as lowercase hex, maps as objects.</summary>
    internal static object? Value(object? value)
    {
        switch (value)
        {
            case null:
                return null;
            case string or bool or long or double:
                return value;
            case int i:
                return (long)i;
            case DateTimeOffset date:
                return Iso(date);
            case byte[] bytes:
                return Hex(bytes);
            case IReadOnlyDictionary<string, object?> map:
                return Map(map);
            case IDictionary dictionary:
                return Map(dictionary);
            case IEnumerable enumerable:
                {
                    List<object?> list = new();
                    foreach (object? element in enumerable)
                    {
                        list.Add(Value(element));
                    }

                    return list;
                }

            default:
                return Reflect(value);
        }
    }

    /// <summary>Resolves one field path, or <see langword="null"/> when it is absent.</summary>
    internal static object? Resolve(object? root, string path)
    {
        object? current = root;
        int consumed = 0;
        foreach (Match match in PathStep.Matches(path))
        {
            Assert.True(match.Index == consumed, $"harness error: unparseable field path \"{path}\"");
            consumed += match.Length;
            if (current is null)
            {
                return null;
            }

            current = match.Groups[1].Success
                ? Member(current, match.Groups[1].Value, path)
                : Bracket(current, match.Groups[2].Value, path);
        }

        Assert.True(consumed == path.Length, $"harness error: unparseable field path \"{path}\"");
        return current;
    }

    private static object? Member(object? current, string name, string path)
    {
        if (name == "length" && current is List<object?> list)
        {
            return (long)list.Count;
        }

        if (current is Dictionary<string, object?> map)
        {
            return map.TryGetValue(name, out object? value) ? value : null;
        }

        Assert.Fail($"{path}: \".{name}\" does not select from {Describe(current)}");
        return null;
    }

    private static object? Bracket(object? current, string selector, string path)
    {
        int separator = selector.IndexOf('=', StringComparison.Ordinal);
        if (separator > 0)
        {
            string key = selector.Substring(0, separator);
            string wanted = selector.Substring(separator + 1);
            Assert.True(current is List<object?>, $"{path}: [{selector}] does not select from a list");
            List<object?> matches = new();
            foreach (object? element in (List<object?>)current!)
            {
                if (element is Dictionary<string, object?> entry
                    && entry.TryGetValue(key, out object? value)
                    && value is string text && text == wanted)
                {
                    matches.Add(element);
                }
            }

            Assert.True(
                matches.Count == 1,
                $"{path}: [{selector}] must select exactly one element, selected {matches.Count}");
            return matches[0];
        }

        if (current is List<object?> list)
        {
            int index = int.Parse(selector, CultureInfo.InvariantCulture);
            return index >= 0 && index < list.Count ? list[index] : null;
        }

        if (current is Dictionary<string, object?> map)
        {
            return map.TryGetValue(selector, out object? value) ? value : null;
        }

        Assert.Fail($"{path}: [{selector}] does not select from {Describe(current)}");
        return null;
    }

    private static Dictionary<string, object?> Map(IReadOnlyDictionary<string, object?> source)
    {
        Dictionary<string, object?> map = new(StringComparer.Ordinal);
        foreach (KeyValuePair<string, object?> entry in source)
        {
            map[entry.Key] = Value(entry.Value);
        }

        return map;
    }

    private static Dictionary<string, object?> Map(IDictionary source)
    {
        Dictionary<string, object?> map = new(StringComparer.Ordinal);
        foreach (DictionaryEntry entry in source)
        {
            map[Convert.ToString(entry.Key, CultureInfo.InvariantCulture)!] = Value(entry.Value);
        }

        return map;
    }

    /// <summary>
    /// A returned object as a map of its public properties. A byte field is
    /// mirrored under <c>&lt;name&gt;Hex</c> as well, which is the spelling
    /// cases.json uses for one.
    /// </summary>
    private static Dictionary<string, object?> Reflect(object value)
    {
        Dictionary<string, object?> map = new(StringComparer.Ordinal);
        foreach (PropertyInfo property in value.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (property.GetIndexParameters().Length != 0)
            {
                continue;
            }

            object? raw = property.GetValue(value);
            string name = Camel(property.Name);
            map[name] = Value(raw);
            if (raw is byte[])
            {
                map[name + "Hex"] = map[name];
            }
        }

        return map;
    }

    private static string Camel(string name) =>
        name.Length == 0 ? name : char.ToLowerInvariant(name[0]) + name.Substring(1);

    private static string Iso(DateTimeOffset date)
    {
        DateTimeOffset utc = date.ToUniversalTime();
        return utc.Millisecond == 0
            ? utc.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)
            : utc.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
    }

    private static string Hex(byte[] value)
    {
        StringBuilder builder = new(value.Length * 2);
        foreach (byte b in value)
        {
            builder.Append(b.ToString("x2", CultureInfo.InvariantCulture));
        }

        return builder.ToString();
    }

    private static string Describe(object? value) => value is null ? "null" : value.GetType().Name;
}
