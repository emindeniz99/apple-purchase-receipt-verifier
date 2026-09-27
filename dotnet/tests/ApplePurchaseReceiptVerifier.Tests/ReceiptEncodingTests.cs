using System.Formats.Asn1;
using System.Linq;
using System.Numerics;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The attribute-set encoding is read before any signature is checked (its
/// creation date picks the chain instant), so it must read exactly what the
/// encoding says and nothing more: anything after the first ASN.1 value is a
/// different encoding, not something to discard. Signed content that breaks
/// the rule is UNREADABLE_PAYLOAD; a known attribute whose own value breaks
/// it is kept raw. Node's <c>der.ts::parse</c> ("trailing bytes after ASN.1
/// value") is the reference.
/// </summary>
public class ReceiptEncodingTests
{
    private static byte[] SetOf(params (BigInteger Type, byte[] Value)[] attributes) =>
        TestPki.AttributeSet(attributes);

    private static byte[] Standard(string bundleId) =>
        SetOf(
            (0, TestPki.Utf8("ProductionSandbox")),
            (2, TestPki.Utf8(bundleId)),
            (3, TestPki.Utf8("1.2.3")),
            (12, TestPki.Ia5("2024-08-06T12:00:00Z")));

    private static byte[] Concat(params byte[][] parts) =>
        parts.SelectMany(p => p).ToArray();

    private static void AssertUnreadable(byte[] payload)
    {
        Assert.Throws<VerificationException>(() => ReceiptAttributes.Parse(payload));
    }

    [Fact]
    public void JunkAfterTheAttributeSetIsUnreadable()
    {
        AssertUnreadable(Concat(Standard("com.real.app"), new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }));
    }

    /// <summary>
    /// The shape that makes the leniency a semantic problem rather than a
    /// cosmetic one: two concatenated SETs, of which a reader that stops after
    /// the first sees only the first bundle id.
    /// </summary>
    [Fact]
    public void TwoConcatenatedAttributeSetsAreUnreadable()
    {
        AssertUnreadable(Concat(Standard("com.real.app"), Standard("com.attacker.app")));
    }

    /// <summary>An empty SET followed by the real one would read as a receipt with every field absent.</summary>
    [Fact]
    public void AnEmptySetFollowedByTheRealOneIsUnreadable()
    {
        AssertUnreadable(Concat(SetOf(), Standard("com.real.app")));
    }

    [Fact]
    public void JunkAfterTheDoubleWrappedOctetStringIsUnreadable()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.WriteOctetString(Standard("com.real.app"));
        AssertUnreadable(Concat(writer.Encode(), new byte[] { 0x31, 0x00 }));
    }

    [Fact]
    public void JunkInsideTheDoubleWrappedOctetStringIsUnreadable()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.WriteOctetString(Concat(Standard("com.real.app"), new byte[] { 0xDE, 0xAD }));
        AssertUnreadable(writer.Encode());
    }

    /// <summary>
    /// The same rule inside an in-app purchase's own attribute set. 0.7 keeps
    /// what Apple signed: the in-app value does not parse, so there is no
    /// purchase for it and its octets are kept raw under 17.
    /// </summary>
    [Fact]
    public void JunkAfterAnInAppAttributeSetKeepsThePurchaseRaw()
    {
        byte[] inApp = Concat(
            SetOf((1702, TestPki.Utf8("com.example.product"))),
            new byte[] { 0xDE, 0xAD });
        ReceiptPayload receipt = ReceiptAttributes.Parse(SetOf(
            (2, TestPki.Utf8("com.real.app")),
            (17, inApp)));

        Assert.Empty(receipt.InApp);
        Assert.Equal(inApp, Assert.Single(receipt.UnknownAttributes[17]));
    }

    /// <summary>
    /// End to end, and the reason it matters: CMS binds the whole encapsulated
    /// content, so a receipt whose eContent carries the junk verifies its own
    /// signature. Without the exhaustion check the port would accept an
    /// encoding every sibling rejects. The signer is trusted, so the refusal
    /// is UNREADABLE_PAYLOAD, with the parser's verdict as the cause.
    /// </summary>
    [Fact]
    public void ASignedReceiptWithTrailingBytesInTheContentIsUnreadable()
    {
        TestPki.ReceiptChain chain = TestPki.SharedReceipt.Value;
        string receipt = chain.SignBase64(Concat(Standard("com.example.app"), new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }));

        Failure failure = chain.Verifier().VerifyReceipt(receipt).Failure!;
        Assert.Equal(VerificationReason.UnreadablePayload, failure.Reason);
        Assert.IsType<VerificationException>(failure.Cause);
    }

    /// <summary>The exhaustion check must not reject the encodings we do accept.</summary>
    [Fact]
    public void TheAcceptedEncodingsStillParse()
    {
        Assert.Equal("com.real.app", ReceiptAttributes.Parse(Standard("com.real.app")).BundleId);

        AsnWriter wrapped = new(AsnEncodingRules.DER);
        wrapped.WriteOctetString(Standard("com.real.app"));
        Assert.Equal("com.real.app", ReceiptAttributes.Parse(wrapped.Encode()).BundleId);
    }
}
