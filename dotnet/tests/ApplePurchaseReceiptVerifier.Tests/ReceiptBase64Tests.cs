using System;
using System.Text;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The spellings <c>ReceiptVerifier.DecodeBase64</c> and the x5c decoder must
/// accept and refuse are the decodeBase64 groups of <c>fixtures/cases.json</c>,
/// which <see cref="Conformance"/> runs against both. What stays here is the
/// one thing a shared vector cannot say: why the check in front of
/// <c>Convert.FromBase64String</c> exists.
/// </summary>
public class ReceiptBase64Tests
{
    /// <summary>Why the check in front of the decoder exists.</summary>
    [Fact]
    public void ConvertFromBase64StringAloneIsNotTheRule()
    {
        Assert.Equal(Encoding.ASCII.GetBytes("ABC"), Convert.FromBase64String("QU JD\n"));
        Assert.Empty(Convert.FromBase64String(string.Empty));
    }
}
