using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Internal;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The attribute-set encoding is the one parser that runs on attacker-supplied
/// bytes before any signature is checked, and its output picks the
/// chain-validity instant. So it must read exactly what the encoding says and
/// nothing more: anything after the first ASN.1 value is a malformed receipt,
/// not something to discard. Node's <c>der.ts::parse</c> ("trailing bytes
/// after ASN.1 value") is the reference.
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

    private static VerificationReason ParseReason(byte[] payload) =>
        Assert.Throws<VerificationException>(() => ReceiptPayload.Parse(payload)).Reason;

    [Fact]
    public void JunkAfterTheAttributeSetIsAMalformedReceipt()
    {
        byte[] payload = Concat(Standard("com.real.app"), new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
        Assert.Equal(VerificationReason.InvalidReceiptFormat, ParseReason(payload));
    }

    /// <summary>
    /// The shape that makes the leniency a semantic problem rather than a
    /// cosmetic one: two concatenated SETs, of which a reader that stops after
    /// the first sees only the first bundle id.
    /// </summary>
    [Fact]
    public void TwoConcatenatedAttributeSetsAreAMalformedReceipt()
    {
        byte[] payload = Concat(Standard("com.real.app"), Standard("com.attacker.app"));
        Assert.Equal(VerificationReason.InvalidReceiptFormat, ParseReason(payload));
    }

    /// <summary>
    /// An empty SET followed by the real one currently parses as an all-null
    /// receipt — every modelled field silently absent.
    /// </summary>
    [Fact]
    public void AnEmptySetFollowedByTheRealOneIsAMalformedReceipt()
    {
        byte[] payload = Concat(SetOf(), Standard("com.real.app"));
        Assert.Equal(VerificationReason.InvalidReceiptFormat, ParseReason(payload));
    }

    [Fact]
    public void JunkAfterTheDoubleWrappedOctetStringIsAMalformedReceipt()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.WriteOctetString(Standard("com.real.app"));
        byte[] payload = Concat(writer.Encode(), new byte[] { 0x31, 0x00 });
        Assert.Equal(VerificationReason.InvalidReceiptFormat, ParseReason(payload));
    }

    [Fact]
    public void JunkInsideTheDoubleWrappedOctetStringIsAMalformedReceipt()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.WriteOctetString(Concat(Standard("com.real.app"), new byte[] { 0xDE, 0xAD }));
        Assert.Equal(VerificationReason.InvalidReceiptFormat, ParseReason(writer.Encode()));
    }

    /// <summary>The same rule inside an in-app purchase's own attribute set.</summary>
    [Fact]
    public void JunkAfterAnInAppAttributeSetIsAMalformedReceipt()
    {
        byte[] inApp = Concat(
            SetOf((1702, TestPki.Utf8("com.example.product"))),
            new byte[] { 0xDE, 0xAD });
        byte[] payload = SetOf(
            (2, TestPki.Utf8("com.real.app")),
            (17, inApp));
        Assert.Equal(VerificationReason.InvalidReceiptFormat, ParseReason(payload));
    }

    /// <summary>
    /// End to end, and the reason it matters: CMS binds the whole encapsulated
    /// content, so a receipt whose eContent carries the junk verifies its own
    /// signature. Without the exhaustion check the structural gate never fires
    /// and the port accepts an encoding every sibling rejects.
    /// </summary>
    [Fact]
    public void ASignedReceiptWithTrailingBytesInTheContentIsRejected()
    {
        X509Certificate2 root = TestPki.RsaRoot();
        X509Certificate2 signer = TestPki.RsaChild(root, "CN=Signer", false, TestPki.LeafOid);
        byte[] receipt = TestPki.SignReceipt(
            Concat(Standard("com.example.app"), new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }),
            signer,
            new[] { root });

        using ReceiptVerifier verifier = new(new[] { TestPki.Public(root) }, "com.example.app");
        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            Assert.Throws<VerificationException>(() => verifier.Verify(receipt)).Reason);
    }

    /// <summary>The exhaustion check must not reject the encodings we do accept.</summary>
    [Fact]
    public void TheAcceptedEncodingsStillParse()
    {
        Assert.Equal("com.real.app", ReceiptPayload.Parse(Standard("com.real.app")).BundleId);

        AsnWriter wrapped = new(AsnEncodingRules.DER);
        wrapped.WriteOctetString(Standard("com.real.app"));
        Assert.Equal("com.real.app", ReceiptPayload.Parse(wrapped.Encode()).BundleId);
    }
}
