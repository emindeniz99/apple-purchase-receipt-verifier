using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>Raised when a JSON document will not parse, or breaks a bound.</summary>
    internal sealed class JsonException : Exception
    {
        internal JsonException(string message)
            : base(message)
        {
        }
    }

    /// <summary>
    /// A bounded, dependency-free JSON reader and writer.
    /// </summary>
    /// <remarks>
    /// <para><c>System.Text.Json</c> is in-box from net8.0 but is a
    /// <em>package</em> on netstandard2.0, and an ns2.0 assembly compiled
    /// against a newer STJ than the host ships cannot be loaded
    /// (<c>CS1705</c>) — the classic .NET Framework / Unity binding-redirect
    /// trap. One hand-rolled reader on every target framework instead: zero
    /// dependencies, one code path, no reflection (so it survives trimming and
    /// IL2CPP), and no <c>System.Text.Json</c> type in the public surface.</para>
    /// <para>Semantics are pinned to match the other ports: last key wins on
    /// duplicates, integral numbers that fit exactly become
    /// <see cref="long"/> and everything else <see cref="double"/>, nesting and
    /// input length are bounded, and no key is special-cased.</para>
    /// </remarks>
    internal static class Json
    {
        internal const int MaxDepth = 32;

        private const int DefaultMaxLength = 16 * 1024 * 1024;

        /// <summary>Parses one JSON document; trailing non-whitespace is an error.</summary>
        internal static object? Parse(string text, int maxLength = DefaultMaxLength)
        {
            if (text is null)
            {
                throw new JsonException("input is null");
            }

            if (text.Length > maxLength)
            {
                throw new JsonException("input exceeds the maximum JSON length");
            }

            Reader reader = new Reader(text);
            reader.SkipWhitespace();
            object? value = reader.ReadValue(0);
            reader.SkipWhitespace();
            if (!reader.AtEnd)
            {
                throw new JsonException("trailing data after the JSON value");
            }

            return value;
        }

        /// <summary>Parses a document that must be a JSON object.</summary>
        internal static OrderedMap ParseObject(string text, int maxLength = DefaultMaxLength)
        {
            return Parse(text, maxLength) as OrderedMap
                ?? throw new JsonException("the JSON value is not an object");
        }

        /// <summary>Serializes the value model this reader produces.</summary>
        internal static string Write(object? value)
        {
            StringBuilder builder = new StringBuilder();
            WriteValue(builder, value, 0);
            return builder.ToString();
        }

        private static void WriteValue(StringBuilder builder, object? value, int depth)
        {
            if (depth > MaxDepth)
            {
                throw new JsonException("value nests deeper than the maximum depth");
            }

            switch (value)
            {
                case null:
                    builder.Append("null");
                    return;
                case bool b:
                    builder.Append(b ? "true" : "false");
                    return;
                case string s:
                    WriteString(builder, s);
                    return;
                case int i:
                    builder.Append(i.ToString(CultureInfo.InvariantCulture));
                    return;
                case long l:
                    builder.Append(l.ToString(CultureInfo.InvariantCulture));
                    return;
                case double d:
                    if (double.IsNaN(d) || double.IsInfinity(d))
                    {
                        throw new JsonException("NaN and infinity are not JSON numbers");
                    }

                    builder.Append(d.ToString("R", CultureInfo.InvariantCulture));
                    return;
                case IReadOnlyDictionary<string, object?> map:
                    {
                        builder.Append('{');
                        bool first = true;
                        foreach (KeyValuePair<string, object?> entry in map)
                        {
                            if (!first)
                            {
                                builder.Append(',');
                            }

                            first = false;
                            WriteString(builder, entry.Key);
                            builder.Append(':');
                            WriteValue(builder, entry.Value, depth + 1);
                        }

                        builder.Append('}');
                        return;
                    }

                case System.Collections.IEnumerable list:
                    {
                        builder.Append('[');
                        bool first = true;
                        foreach (object? element in list)
                        {
                            if (!first)
                            {
                                builder.Append(',');
                            }

                            first = false;
                            WriteValue(builder, element, depth + 1);
                        }

                        builder.Append(']');
                        return;
                    }

                default:
                    throw new JsonException("unsupported JSON value type " + value.GetType().FullName);
            }
        }

        private static void WriteString(StringBuilder builder, string value)
        {
            builder.Append('"');
            foreach (char c in value)
            {
                switch (c)
                {
                    case '"': builder.Append("\\\""); break;
                    case '\\': builder.Append("\\\\"); break;
                    case '\b': builder.Append("\\b"); break;
                    case '\f': builder.Append("\\f"); break;
                    case '\n': builder.Append("\\n"); break;
                    case '\r': builder.Append("\\r"); break;
                    case '\t': builder.Append("\\t"); break;
                    default:
                        if (c < 0x20)
                        {
                            builder.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            builder.Append(c);
                        }

                        break;
                }
            }

            builder.Append('"');
        }

        private struct Reader
        {
            private readonly string _text;
            private int _index;

            internal Reader(string text)
            {
                _text = text;
                _index = 0;
            }

            internal bool AtEnd => _index >= _text.Length;

            internal void SkipWhitespace()
            {
                while (_index < _text.Length)
                {
                    char c = _text[_index];
                    if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
                    {
                        _index++;
                    }
                    else
                    {
                        return;
                    }
                }
            }

            internal object? ReadValue(int depth)
            {
                if (depth > MaxDepth)
                {
                    throw new JsonException("document nests deeper than the maximum depth");
                }

                if (AtEnd)
                {
                    throw new JsonException("unexpected end of input");
                }

                switch (_text[_index])
                {
                    case '{': return ReadObject(depth);
                    case '[': return ReadArray(depth);
                    case '"': return ReadString();
                    case 't': Expect("true"); return true;
                    case 'f': Expect("false"); return false;
                    case 'n': Expect("null"); return null;
                    default: return ReadNumber();
                }
            }

            private OrderedMap ReadObject(int depth)
            {
                OrderedMap map = new OrderedMap();
                _index++;
                SkipWhitespace();
                if (Peek() == '}')
                {
                    _index++;
                    return map;
                }

                while (true)
                {
                    SkipWhitespace();
                    if (Peek() != '"')
                    {
                        throw new JsonException("expected a string key");
                    }

                    string key = ReadString();
                    SkipWhitespace();
                    if (Peek() != ':')
                    {
                        throw new JsonException("expected ':' after a key");
                    }

                    _index++;
                    SkipWhitespace();
                    map.Set(key, ReadValue(depth + 1));
                    SkipWhitespace();
                    char next = Peek();
                    _index++;
                    if (next == ',')
                    {
                        continue;
                    }

                    if (next == '}')
                    {
                        return map;
                    }

                    throw new JsonException("expected ',' or '}' in an object");
                }
            }

            private List<object?> ReadArray(int depth)
            {
                List<object?> list = new List<object?>();
                _index++;
                SkipWhitespace();
                if (Peek() == ']')
                {
                    _index++;
                    return list;
                }

                while (true)
                {
                    SkipWhitespace();
                    list.Add(ReadValue(depth + 1));
                    SkipWhitespace();
                    char next = Peek();
                    _index++;
                    if (next == ',')
                    {
                        continue;
                    }

                    if (next == ']')
                    {
                        return list;
                    }

                    throw new JsonException("expected ',' or ']' in an array");
                }
            }

            private string ReadString()
            {
                _index++;
                StringBuilder builder = new StringBuilder();
                while (true)
                {
                    if (AtEnd)
                    {
                        throw new JsonException("unterminated string");
                    }

                    char c = _text[_index++];
                    if (c == '"')
                    {
                        return builder.ToString();
                    }

                    if (c < 0x20)
                    {
                        throw new JsonException("unescaped control character in a string");
                    }

                    if (c != '\\')
                    {
                        builder.Append(c);
                        continue;
                    }

                    if (AtEnd)
                    {
                        throw new JsonException("unterminated escape");
                    }

                    char escape = _text[_index++];
                    switch (escape)
                    {
                        case '"': builder.Append('"'); break;
                        case '\\': builder.Append('\\'); break;
                        case '/': builder.Append('/'); break;
                        case 'b': builder.Append('\b'); break;
                        case 'f': builder.Append('\f'); break;
                        case 'n': builder.Append('\n'); break;
                        case 'r': builder.Append('\r'); break;
                        case 't': builder.Append('\t'); break;
                        case 'u':
                            if (!TryReadFourHexDigits(out ushort code))
                            {
                                throw new JsonException("malformed \\u escape");
                            }

                            builder.Append((char)code);
                            break;
                        default:
                            throw new JsonException("unknown escape \\" + escape);
                    }
                }
            }

            /// <summary>
            /// RFC 8259 wants exactly four hex digits, so the digits are read
            /// one at a time. <c>NumberStyles.HexNumber</c> is
            /// <c>AllowLeadingWhite | AllowTrailingWhite | AllowHexSpecifier</c>
            /// and would accept a space, tab, CR or LF among them — a grammar
            /// no other port's reader has.
            /// </summary>
            private bool TryReadFourHexDigits(out ushort code)
            {
                code = 0;
                if (_index + 4 > _text.Length)
                {
                    return false;
                }

                int value = 0;
                for (int i = 0; i < 4; i++)
                {
                    int digit = HexDigit(_text[_index + i]);
                    if (digit < 0)
                    {
                        return false;
                    }

                    value = (value << 4) | digit;
                }

                _index += 4;
                code = (ushort)value;
                return true;
            }

            private static int HexDigit(char c)
            {
                if (c >= '0' && c <= '9')
                {
                    return c - '0';
                }

                if (c >= 'a' && c <= 'f')
                {
                    return c - 'a' + 10;
                }

                return c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
            }

            private object ReadNumber()
            {
                // RFC 8259 grammar, not a permissive scan: a leading zero, a
                // bare "-", "1." or ".5" are all malformed, and accepting them
                // would make this reader disagree with every other port's.
                int start = _index;
                if (Peek() == '-')
                {
                    _index++;
                }

                if (!ReadDigits(out bool leadingZero))
                {
                    throw new JsonException("expected a JSON number");
                }

                if (leadingZero && _index - start > (_text[start] == '-' ? 2 : 1))
                {
                    throw new JsonException("a JSON number may not have a leading zero");
                }

                bool integral = true;
                if (!AtEnd && _text[_index] == '.')
                {
                    integral = false;
                    _index++;
                    if (!ReadDigits(out _))
                    {
                        throw new JsonException("expected digits after the decimal point");
                    }
                }

                if (!AtEnd && (_text[_index] == 'e' || _text[_index] == 'E'))
                {
                    integral = false;
                    _index++;
                    if (!AtEnd && (_text[_index] == '+' || _text[_index] == '-'))
                    {
                        _index++;
                    }

                    if (!ReadDigits(out _))
                    {
                        throw new JsonException("expected digits in the exponent");
                    }
                }

                string literal = _text.Substring(start, _index - start);
                if (integral
                    && long.TryParse(literal, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long asLong))
                {
                    return asLong;
                }

                if (double.TryParse(
                        literal,
                        NumberStyles.Float,
                        CultureInfo.InvariantCulture,
                        out double asDouble)
                    && !double.IsNaN(asDouble)
                    && !double.IsInfinity(asDouble))
                {
                    return asDouble;
                }

                throw new JsonException("malformed number " + literal);
            }

            private bool ReadDigits(out bool leadingZero)
            {
                int start = _index;
                leadingZero = !AtEnd && _text[_index] == '0';
                while (!AtEnd && _text[_index] >= '0' && _text[_index] <= '9')
                {
                    _index++;
                }

                return _index > start;
            }

            private char Peek()
            {
                if (AtEnd)
                {
                    throw new JsonException("unexpected end of input");
                }

                return _text[_index];
            }

            private void Expect(string literal)
            {
                if (_index + literal.Length > _text.Length
                    || string.CompareOrdinal(_text, _index, literal, 0, literal.Length) != 0)
                {
                    throw new JsonException("expected " + literal);
                }

                _index += literal.Length;
            }
        }
    }
}
