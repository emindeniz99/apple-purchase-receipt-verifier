using System;
using System.Text;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// <c>ReceiptVerifier.DecodeBase64</c> must answer what Apple's verifyReceipt
/// answered on 2026-09-23 for the same spellings of genuine receipts
/// (docs/evidence/2026-09-23-verifyreceipt-base64.md). A spelling Apple
/// decodes must decode here to the same bytes; a spelling Apple answers
/// 21002 must be <c>InvalidReceiptFormat</c> here, or a receipt verifies in
/// .NET that Apple itself refuses. The conformance cases pin the rule on a
/// real receipt; this pins each shape on its own, including the ones
/// <c>Convert.FromBase64String</c> alone would have accepted.
/// </summary>
public class ReceiptBase64Tests
{
    [Theory]
    [InlineData("QUJD", "414243")]
    [InlineData("QUI=", "4142")]
    [InlineData("QQ==", "41")]
    [InlineData("+/8=", "FBFF")]
    // Unused low bits set in the last data character: Apple accepts them.
    [InlineData("QR==", "41")]
    [InlineData("Qf==", "41")]
    [InlineData("QUJ=", "4142")]
    public void CanonicalSpellingsAndTrailingBitsDecode(string text, string hex)
    {
        Assert.Equal(Convert.FromHexString(hex), ReceiptVerifier.DecodeBase64(text));
    }

    [Theory]
    [InlineData("")]
    [InlineData("QQ")] // padding omitted
    [InlineData("QUI")]
    [InlineData("QQ=")] // under-padded
    [InlineData("QQ===")] // extra padding
    [InlineData("QQ====")]
    [InlineData("QUJD=")] // padding after a full group
    [InlineData("QUJD==")]
    [InlineData("QUJD====")]
    [InlineData("====")]
    [InlineData("Q===")] // impossible length
    [InlineData("QUJDR")]
    [InlineData("QQ==QUJD")] // data or junk after the padding
    [InlineData("QQ==!!!!")]
    [InlineData("QQ=A")]
    [InlineData("QU!D")] // junk inside
    [InlineData("QUJD\n")] // whitespace: Convert.FromBase64String alone skips it
    [InlineData("QUJD\r\n")]
    [InlineData("QUJD\nQUJD")]
    [InlineData(" QUJD")]
    [InlineData("QU JD")]
    [InlineData("QU\tJD")]
    [InlineData("  QUJD  ")]
    [InlineData("-_8=")] // base64url, unpadded, mixed
    [InlineData("-_8")]
    [InlineData("+_8=")]
    [InlineData("QUJé")] // outside ASCII
    [InlineData("QU　D")]
    public void EveryOtherSpellingIsInvalidReceiptFormat(string text)
    {
        VerificationException error =
            Assert.Throws<VerificationException>(() => ReceiptVerifier.DecodeBase64(text));
        Assert.Equal(VerificationReason.InvalidReceiptFormat, error.Reason);
    }

    /// <summary>Why the check in front of the decoder exists.</summary>
    [Fact]
    public void ConvertFromBase64StringAloneIsNotTheRule()
    {
        Assert.Equal(Encoding.ASCII.GetBytes("ABC"), Convert.FromBase64String("QU JD\n"));
        Assert.Empty(Convert.FromBase64String(string.Empty));
    }
}
