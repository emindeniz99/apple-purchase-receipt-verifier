using System;
using System.Globalization;
using System.Text;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// <c>ReceiptVerifier.DecodeBase64</c> tries <c>Convert.TryFromBase64String</c>
/// before its own tolerant parser. That shortcut is only safe if it never
/// changes an answer: every string the fast path accepts must be one the
/// tolerant parser accepts too, with the same bytes, and every string it
/// declines must reach the tolerant parser unchanged. If the fast path ever
/// accepted something the documented <c>receipt-data</c> contract rejects (an
/// empty string, a character after the padding, a wrong padding count), a
/// malformed receipt would start verifying in .NET alone and the ports would
/// disagree.
/// </summary>
/// <remarks>
/// <para><c>TryFromBase64String</c> is not strict: it skips whitespace
/// anywhere in the string. That is why this is a differential test rather
/// than an argument, and why it runs on every runtime the suite targets
/// (net8.0, net9.0, net10.0): the decoder's rules belong to the runtime, not
/// to this library.</para>
/// <para>The generator is seeded, so a failure reproduces. It mixes the
/// shapes the contract names: clean standard base64, missing and extra
/// padding, both alphabets, whitespace anywhere, illegal characters (Unicode
/// whitespace among them), characters after the padding, and lengths
/// congruent to 1 mod 4.</para>
/// </remarks>
public class ReceiptBase64FastPathTests
{
    private const int Seed = 0x5EEDB64;
    private const int Cases = 20_000;
    private const string Illegal =
        "!#$%&*.,:;?@[]{}|~\"'\\\u0000\u007f\u00e9\u00ff\u0100\u00a0\u0085\u000b\u000c\u2028\u3000\uff21";
    private const string Whitespace = "\r\n \t";

    [Fact]
    public void DecodeAgreesWithTheTolerantPathOnGeneratedInputs()
    {
        Random random = new Random(Seed);
        int fastAccepted = 0;
        int fastAcceptedWithWhitespace = 0;
        int tolerantOnlyAccepted = 0;
        int rejected = 0;
        for (int i = 0; i < Cases; i++)
        {
            string input = Generate(random);
            AssertAgrees(input);
            if (ReceiptVerifier.DecodeBase64Fast(input) is not null)
            {
                fastAccepted++;
                if (input.IndexOfAny(Whitespace.ToCharArray()) >= 0)
                {
                    fastAcceptedWithWhitespace++;
                }
            }
            else if (Accepts(ReceiptVerifier.DecodeBase64Tolerant, input))
            {
                tolerantOnlyAccepted++;
            }
            else
            {
                rejected++;
            }
        }

        // The comparison proves nothing unless every branch ran many times:
        // the fast path taken (with and without the whitespace it skips), the
        // fallback accepting, and both rejecting.
        Assert.True(fastAccepted > 1_000, "fast path accepted only " + fastAccepted);
        Assert.True(
            fastAcceptedWithWhitespace > 100,
            "fast path accepted whitespace only " + fastAcceptedWithWhitespace);
        Assert.True(tolerantOnlyAccepted > 1_000, "fallback accepted only " + tolerantOnlyAccepted);
        Assert.True(rejected > 1_000, "rejected only " + rejected);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\r\n\t ")]
    [InlineData("=")]
    [InlineData("==")]
    [InlineData("===")]
    [InlineData("====")]
    [InlineData("A")]
    [InlineData("A=")]
    [InlineData("A==")]
    [InlineData("A===")]
    [InlineData("AA")]
    [InlineData("AA=")]
    [InlineData("AA==")]
    [InlineData("AA===")]
    [InlineData("AA= =")]
    [InlineData("AAA")]
    [InlineData("AAA=")]
    [InlineData("AAA==")]
    [InlineData("AAAA")]
    [InlineData("AAAA=")]
    [InlineData("AAAA==")]
    [InlineData("AAAA====")]
    [InlineData("AA==A")]
    [InlineData("AA==\n")]
    [InlineData("AA==AA==")]
    [InlineData("AAAAA")]
    [InlineData("-_")]
    [InlineData("+/")]
    [InlineData("+_")]
    [InlineData("-/")]
    [InlineData("AB-_")]
    [InlineData("AB+/")]
    [InlineData("AB\u00e9=")]
    [InlineData("AB\u0100")]
    [InlineData("AB\u00a0CD")]
    [InlineData("AB\u000bCD")]
    [InlineData("QUJD")]
    [InlineData("QUJ")]
    [InlineData("QUI")]
    [InlineData("QQ")]
    [InlineData("QR")]
    [InlineData("QUK=")]
    [InlineData("QUJD\r\n")]
    [InlineData("Q U J D")]
    public void DecodeAgreesWithTheTolerantPathOnHandPickedEdges(string input)
    {
        AssertAgrees(input);
    }

    /// <summary>
    /// The comparison has teeth: the obvious fast path without the zero-byte
    /// refusal accepts the empty string, and a permissive one that also takes
    /// base64url mixes the alphabets. Both would change answers, and both are
    /// caught by the same seeded run that the real fast path passes.
    /// </summary>
    [Fact]
    public void AFastPathThatChangesAnAnswerFailsTheComparison()
    {
        Func<string, byte[]?> unguarded = s =>
        {
            byte[] buffer = new byte[s.Length];
            return Convert.TryFromBase64String(s, buffer, out int written) ? buffer.AsSpan(0, written).ToArray() : null;
        };
        Func<string, byte[]?> permissive = s =>
        {
            byte[] buffer = new byte[s.Length];
            string translated = s.Replace('-', '+').Replace('_', '/');
            return Convert.TryFromBase64String(translated, buffer, out int written) && written > 0
                ? buffer.AsSpan(0, written).ToArray()
                : null;
        };

        Assert.True(FirstDisagreement(unguarded) is not null, "the unguarded decoder was not caught");
        Assert.True(FirstDisagreement(permissive) is not null, "the permissive decoder was not caught");
        Assert.Null(FirstDisagreement(ReceiptVerifier.DecodeBase64Fast));
    }

    private static string? FirstDisagreement(Func<string, byte[]?> fastPath)
    {
        Random random = new Random(Seed);
        for (int i = 0; i < Cases; i++)
        {
            string input = Generate(random);
            string? problem = Disagreement(s => fastPath(s) ?? ReceiptVerifier.DecodeBase64Tolerant(s), input);
            if (problem is not null)
            {
                return problem;
            }
        }

        return null;
    }

    private static void AssertAgrees(string input)
    {
        string? problem = Disagreement(ReceiptVerifier.DecodeBase64, input);
        Assert.True(problem is null, problem);
    }

    /// <summary>
    /// Null when <paramref name="decode"/> and the tolerant path give the same
    /// answer for <paramref name="input"/> (equal bytes, or the same reason
    /// and message); otherwise what differs.
    /// </summary>
    private static string? Disagreement(Func<string, byte[]> decode, string input)
    {
        byte[]? expected = null;
        VerificationException? expectedError = null;
        try
        {
            expected = ReceiptVerifier.DecodeBase64Tolerant(input);
        }
        catch (VerificationException e)
        {
            expectedError = e;
        }

        byte[]? actual = null;
        VerificationException? actualError = null;
        try
        {
            actual = decode(input);
        }
        catch (VerificationException e)
        {
            actualError = e;
        }

        string shown = Describe(input);
        if (expectedError is not null)
        {
            if (actualError is null)
            {
                return "accepted what the tolerant path rejects: " + shown;
            }

            return expectedError.Reason == actualError.Reason
                && string.Equals(expectedError.Message, actualError.Message, StringComparison.Ordinal)
                ? null
                : "rejected differently: " + shown + ": " + actualError.Message;
        }

        if (actualError is not null)
        {
            return "rejected what the tolerant path accepts: " + shown + ": " + actualError.Message;
        }

        return expected.AsSpan().SequenceEqual(actual) ? null : "decoded different bytes: " + shown;
    }

    private static bool Accepts(Func<string, byte[]> decode, string input)
    {
        try
        {
            decode(input);
            return true;
        }
        catch (VerificationException)
        {
            return false;
        }
    }

    private static string Generate(Random random)
    {
        byte[] bytes = new byte[random.Next(40)];
        random.NextBytes(bytes);
        StringBuilder s = new StringBuilder(Convert.ToBase64String(bytes));

        // About half the inputs stay canonical standard base64 so the fast
        // path is taken often; the rest get one or more defects.
        if (random.Next(2) == 0)
        {
            return s.ToString();
        }

        int mutations = 1 + random.Next(3);
        for (int m = 0; m < mutations; m++)
        {
            switch (random.Next(9))
            {
                case 0: // drop the padding
                    TrimPadding(s);
                    break;
                case 1: // extra padding
                    s.Append(random.Next(2) == 0 ? "=" : "==");
                    break;
                case 2: // base64url alphabet, whole string
                    s.Replace('+', '-').Replace('/', '_');
                    break;
                case 3: // one character of either alphabet's extras
                    Insert(s, random, "+/-_"[random.Next(4)]);
                    break;
                case 4: // whitespace somewhere, including before and after the padding
                    Insert(s, random, Whitespace[random.Next(Whitespace.Length)]);
                    break;
                case 5: // an illegal character
                    Insert(s, random, Illegal[random.Next(Illegal.Length)]);
                    break;
                case 6: // something after the padding
                    s.Append('=').Append((char)('A' + random.Next(26)));
                    break;
                case 7: // length congruent to 1 mod 4 (after stripping padding)
                    TrimPadding(s);
                    while (s.Length % 4 != 1)
                    {
                        s.Append('A');
                    }

                    break;
                default: // whitespace-only or empty, or trailing whitespace
                    if (random.Next(8) == 0)
                    {
                        s.Clear();
                        for (int k = random.Next(3); k > 0; k--)
                        {
                            s.Append(Whitespace[random.Next(Whitespace.Length)]);
                        }
                    }
                    else
                    {
                        s.Append(Whitespace[random.Next(Whitespace.Length)]);
                    }

                    break;
            }
        }

        return s.ToString();
    }

    private static void TrimPadding(StringBuilder s)
    {
        while (s.Length > 0 && s[s.Length - 1] == '=')
        {
            s.Length--;
        }
    }

    private static void Insert(StringBuilder s, Random random, char c)
    {
        s.Insert(random.Next(s.Length + 1), c);
    }

    private static string Describe(string input)
    {
        StringBuilder output = new StringBuilder("\"");
        foreach (char c in input)
        {
            if (c >= 0x20 && c < 0x7f)
            {
                output.Append(c);
            }
            else
            {
                output.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
            }
        }

        return output.Append('"').ToString();
    }
}
