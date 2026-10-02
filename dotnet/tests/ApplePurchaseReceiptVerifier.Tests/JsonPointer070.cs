using System.Collections.Generic;
using System.Globalization;
using System.Text;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// RFC 6901 JSON Pointer over the object model <see cref="TestJson"/> produces,
/// with one extension: a reference token written <c>[key=value]</c> selects
/// the single element of an array whose member key is the JSON string value.
/// </summary>
internal static class JsonPointer070
{
    internal static object? Resolve(object? root, string pointer)
    {
        Assert.True(pointer.Length > 0 && pointer[0] == '/', $"harness error: not a JSON pointer: \"{pointer}\"");
        object? current = root;
        int i = 0;
        while (i < pointer.Length)
        {
            Assert.Equal('/', pointer[i]);
            i++;
            int start = i;
            while (i < pointer.Length && pointer[i] != '/')
            {
                i++;
            }

            string token = Unescape(pointer.Substring(start, i - start));
            if (current is null)
            {
                return null;
            }

            current = Step(current, token, pointer);
        }

        return current;
    }

    /// <summary>The length of the array at <paramref name="pointer"/>.</summary>
    internal static long Length(object? root, string pointer)
    {
        object? value = Resolve(root, pointer);
        return value is List<object?> list
            ? list.Count
            : throw new global::Xunit.Sdk.XunitException($"{pointer}: expected an array, got {Describe(value)}");
    }

    private static object? Step(object? current, string token, string path)
    {
        if (token.Length >= 2 && token[0] == '[' && token[token.Length - 1] == ']' && token.IndexOf('=') > 0)
        {
            string inner = token.Substring(1, token.Length - 2);
            int eq = inner.IndexOf('=');
            string key = inner.Substring(0, eq);
            string wanted = inner.Substring(eq + 1);
            List<object?> list = current as List<object?>
                ?? throw new global::Xunit.Sdk.XunitException($"{path}: [{token}] does not select from {Describe(current)}");
            List<object?> matches = new();
            foreach (object? element in list)
            {
                if (element is IReadOnlyDictionary<string, object?> entry
                    && entry.TryGetValue(key, out object? value)
                    && value is string text
                    && text == wanted)
                {
                    matches.Add(element);
                }
            }

            Assert.True(matches.Count == 1, $"{path}: [{token}] must select exactly one element, selected {matches.Count}");
            return matches[0];
        }

        if (current is List<object?> array)
        {
            if (!int.TryParse(token, NumberStyles.None, CultureInfo.InvariantCulture, out int index))
            {
                throw new global::Xunit.Sdk.XunitException($"{path}: \"{token}\" is not an array index");
            }

            return index >= 0 && index < array.Count ? array[index] : null;
        }

        if (current is IReadOnlyDictionary<string, object?> map)
        {
            return map.TryGetValue(token, out object? value) ? value : null;
        }

        throw new global::Xunit.Sdk.XunitException($"{path}: \"{token}\" does not select from {Describe(current)}");
    }

    private static string Unescape(string token)
    {
        if (token.IndexOf('~') < 0)
        {
            return token;
        }

        StringBuilder builder = new(token.Length);
        for (int i = 0; i < token.Length; i++)
        {
            if (token[i] == '~' && i + 1 < token.Length)
            {
                if (token[i + 1] == '0')
                {
                    builder.Append('~');
                    i++;
                    continue;
                }

                if (token[i + 1] == '1')
                {
                    builder.Append('/');
                    i++;
                    continue;
                }
            }

            builder.Append(token[i]);
        }

        return builder.ToString();
    }

    private static string Describe(object? value) => value is null ? "null" : value.GetType().Name;
}
