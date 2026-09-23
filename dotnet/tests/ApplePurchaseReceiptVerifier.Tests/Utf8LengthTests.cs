using System;
using System.Text;
using ApplePurchaseReceiptVerifier.Internal;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// Apple's verifyReceipt answers a 3,145,728-byte body and refuses a
/// 3,145,729-byte one, counting UTF-8 bytes rather than characters. A .NET
/// string counts UTF-16 units, so <see cref="Utf8Length"/> is what makes this
/// port's limit Apple's limit. Each test pins one way a units-based or
/// approximate count would move the boundary: two-byte characters,
/// three-byte characters, surrogate pairs (two units, four bytes), lone
/// surrogates, and both shortcuts that skip the walk.
/// </summary>
public class Utf8LengthTests
{
    private const int Cap = VerifyReceiptEndpoint.MaxRequestBytes;
    private const string EAcute = "é"; // 2 bytes, 1 unit
    private const string Euro = "€"; // 3 bytes, 1 unit
    private const string Emoji = "😀"; // 4 bytes, 2 units

    private static string Repeat(string unit, int count)
    {
        StringBuilder text = new(unit.Length * count);
        for (int i = 0; i < count; i++)
        {
            text.Append(unit);
        }

        return text.ToString();
    }

    [Fact]
    public void AsciiIsOneBytePerCharacterRightAtTheCap()
    {
        Assert.False(Utf8Length.Exceeds(new string('a', Cap), Cap));
        Assert.True(Utf8Length.Exceeds(new string('a', Cap + 1), Cap));
    }

    /// <summary>Apple's own measurement: 3,145,729 bytes of U+00E9 is only 1,572,874 characters, and it is over.</summary>
    [Fact]
    public void TwoByteCharactersAreCountedInBytesNotCharacters()
    {
        string atCap = Repeat(EAcute, Cap / 2);
        Assert.False(Utf8Length.Exceeds(atCap, Cap));
        string overCap = "a" + atCap;
        Assert.Equal(Cap + 1, Encoding.UTF8.GetByteCount(overCap));
        Assert.True(overCap.Length < Cap, "a character count would call this one under the cap");
        Assert.True(Utf8Length.Exceeds(overCap, Cap));
    }

    [Fact]
    public void ThreeByteCharactersAtTheBoundary()
    {
        string atCap = Repeat(Euro, Cap / 3); // 1,048,576 characters, 3,145,728 bytes
        Assert.False(Utf8Length.Exceeds(atCap, Cap));
        Assert.True(Utf8Length.Exceeds(atCap + "a", Cap));
    }

    /// <summary>
    /// A surrogate pair is two UTF-16 units and four UTF-8 bytes: counting it
    /// as two (units) or six (three per unit) both move the boundary.
    /// </summary>
    [Fact]
    public void ASurrogatePairIsFourBytes()
    {
        string atCap = Repeat(Emoji, Cap / 4);
        Assert.Equal(Cap, Encoding.UTF8.GetByteCount(atCap));
        Assert.False(Utf8Length.Exceeds(atCap, Cap));
        Assert.True(Utf8Length.Exceeds(atCap + "a", Cap));
        Assert.False(Utf8Length.Exceeds(Emoji, 4));
        Assert.True(Utf8Length.Exceeds(Emoji, 3));
    }

    /// <summary>
    /// A lone surrogate counts three bytes, which is what
    /// <c>Encoding.UTF8</c> writes for it (U+FFFD) and what the Java port counts.
    /// </summary>
    [Fact]
    public void ALoneSurrogateCountsThreeBytesLikeEncodingUtf8()
    {
        foreach (string lone in new[] { "\ud83d", "\ude00" })
        {
            Assert.Equal(3, Encoding.UTF8.GetByteCount(lone));
            Assert.False(Utf8Length.Exceeds(lone, 3));
            Assert.True(Utf8Length.Exceeds(lone, 2));
        }

        Assert.True(Utf8Length.Exceeds("\ud83da", 3), "high surrogate then ASCII is 3 + 1");
        Assert.True(Utf8Length.Exceeds("\ude00\ud83d", 5), "a reversed pair is two lone surrogates");
        Assert.False(Utf8Length.Exceeds("\ude00\ud83d", 6));
    }

    /// <summary>Both shortcuts, at their edges: units over the limit, and three times the units within it.</summary>
    [Fact]
    public void TheShortcutsAgreeWithTheWalkAtTheirEdges()
    {
        Assert.True(Utf8Length.Exceeds(new string('a', 11), 10));
        Assert.False(Utf8Length.Exceeds(Repeat(Euro, 3), 9));
        Assert.True(Utf8Length.Exceeds(Repeat(Euro, 4), 11));
        Assert.False(Utf8Length.Exceeds(string.Empty, 0));
        Assert.True(Utf8Length.Exceeds("a", 0));
    }

    /// <summary>
    /// On generated text, lone surrogates included, the answer is exactly
    /// what <c>Encoding.UTF8.GetByteCount</c> gives.
    /// </summary>
    [Fact]
    public void AgreesWithEncodingUtf8OnGeneratedText()
    {
        string[] alphabet =
        {
            "a", "~", EAcute, "߿", "ࠀ", Euro, "￿", Emoji, "􏿿", "\ud83d", "\ude00",
        };
        Random random = new(0x0C0FFEE);
        for (int i = 0; i < 5000; i++)
        {
            StringBuilder text = new();
            int length = random.Next(40);
            for (int j = 0; j < length; j++)
            {
                text.Append(alphabet[random.Next(alphabet.Length)]);
            }

            string s = text.ToString();
            int bytes = Encoding.UTF8.GetByteCount(s);
            for (int limit = Math.Max(0, bytes - 4); limit <= bytes + 4; limit++)
            {
                Assert.True(bytes > limit == Utf8Length.Exceeds(s, limit), $"case {i} at limit {limit}");
            }
        }
    }
}
