using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace ApplePurchaseReceiptVerifier.Fuzz.Targets
{
    /// <summary>
    /// The hand-written bounded JSON reader (<c>Internal/Json.cs</c>) on raw
    /// bytes, plus the writer that shares its value model.
    /// </summary>
    /// <remarks>
    /// <para>This reader exists because <c>System.Text.Json</c> is a NuGet
    /// package below net8.0, so it is the one parser in the package with no
    /// upstream fuzzing behind it. Two invariants:</para>
    /// <list type="number">
    ///   <item>a failure is the reader's own <c>JsonException</c> and never a
    ///   stack overflow, an index error or a format exception from
    ///   <c>double.Parse</c>;</item>
    ///   <item>anything the reader accepts, the writer serializes, and the
    ///   reader reads back to an equal value. The endpoint's reply goes
    ///   through <c>Json.Write</c>, so a reader that accepts what the writer
    ///   cannot emit is a way to make the endpoint answer 21009 to a receipt
    ///   it actually verified.</item>
    /// </list>
    /// </remarks>
    internal static class JsonReader
    {
        internal static void Run(ReadOnlySpan<byte> data)
        {
            string text;
            try
            {
                text = new UTF8Encoding(false, true).GetString(data.ToArray());
            }
            catch (DecoderFallbackException)
            {
                // The reader takes a string; the callers that reach it have
                // already decoded one. Feeding it replacement characters would
                // fuzz the decoder instead.
                return;
            }

            object? value;
            try
            {
                value = Internals.JsonParse(text);
            }
            catch (Exception e)
            {
                Invariant.Require(
                    Internals.IsJsonException(e),
                    $"Json.Parse escaped as {e.GetType().FullName}: {e.Message}");
                return;
            }

            string written;
            try
            {
                written = Internals.JsonWrite(value);
            }
            catch (Exception e)
            {
                throw new InvariantException(
                    $"Json.Write refused a value Json.Parse produced ({e.GetType().FullName}: {e.Message})");
            }

            object? reread;
            try
            {
                reread = Internals.JsonParse(written);
            }
            catch (Exception e)
            {
                throw new InvariantException(
                    $"Json.Parse refused what Json.Write emitted ({e.GetType().FullName}: {e.Message})");
            }

            Invariant.Require(Same(value, reread), "the reader and the writer disagree on a value");
        }

        /// <summary>
        /// Numeric equality across the two CLR types the reader produces.
        /// </summary>
        /// <remarks>
        /// The round trip preserves the <em>value</em>, not the CLR type, and
        /// asserting the latter would be asserting something the library never
        /// promised: <c>-2.5e10</c> reads as a <see cref="double"/>, and the
        /// writer's "R" format renders it <c>-25000000000</c>, which reads back
        /// as a <see cref="long"/>. That is the first thing this target found,
        /// and it is correct behaviour — every such rendering is exact, so the
        /// numbers still compare equal here. A reader/writer disagreement that
        /// changes the number would still fail.
        /// </remarks>
        private static bool SameNumber(object left, object right)
        {
            if (left is long a && right is long b)
            {
                return a == b;
            }

            double x = left is long la ? la : (double)left;
            double y = right is long lb ? lb : (double)right;
            return x.Equals(y);
        }

        private static bool Same(object? left, object? right)
        {
            if (left is null || right is null)
            {
                return left is null && right is null;
            }

            if (left is IReadOnlyDictionary<string, object?> leftMap)
            {
                if (right is not IReadOnlyDictionary<string, object?> rightMap
                    || leftMap.Count != rightMap.Count)
                {
                    return false;
                }

                foreach (KeyValuePair<string, object?> entry in leftMap)
                {
                    if (!rightMap.TryGetValue(entry.Key, out object? other) || !Same(entry.Value, other))
                    {
                        return false;
                    }
                }

                return true;
            }

            if (left is long or double || right is long or double)
            {
                return left is (long or double) && right is (long or double) && SameNumber(left, right);
            }

            if (left is string || right is string)
            {
                return left is string a && right is string b && string.Equals(a, b, StringComparison.Ordinal);
            }

            if (left is IEnumerable leftList && right is IEnumerable rightList)
            {
                IEnumerator one = leftList.GetEnumerator();
                IEnumerator two = rightList.GetEnumerator();
                while (true)
                {
                    bool oneMoved = one.MoveNext();
                    if (oneMoved != two.MoveNext())
                    {
                        return false;
                    }

                    if (!oneMoved)
                    {
                        return true;
                    }

                    if (!Same(one.Current, two.Current))
                    {
                        return false;
                    }
                }
            }

            return left.Equals(right);
        }
    }
}
