using System.Formats.Asn1;
using System.Numerics;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>The receipt path's own rules: the attribute grammar and what the payload hands out.</summary>
public class ReceiptTests
{
    private static ReceiptPayload Verified(byte[] payload)
    {
        TestPki.ReceiptChain chain = TestPki.SharedReceipt.Value;
        VerificationResult<ReceiptPayload> result = chain.Verifier().VerifyReceipt(chain.SignBase64(payload));
        Assert.True(result.Verified, result.Failure?.ToString());
        return result.Payload;
    }

    /// <summary>
    /// The device-hash inputs are handed out as copies: a caller hashing, or
    /// scribbling on, what it was given cannot change what the next reader of
    /// the same payload sees.
    /// </summary>
    [Fact]
    public void ByteFieldsHandedToTheCallerAreCopies()
    {
        ReceiptPayload receipt = TestPki.FixtureVerifier("receipt-root")
            .VerifyReceipt(Fixtures070.ForReceipt("receipt")).Payload!;

        foreach (System.Func<byte[]?> field in new System.Func<byte[]?>[]
                 { () => receipt.OpaqueValue, () => receipt.Sha1Hash, () => receipt.BundleIdBytes })
        {
            byte[] first = field()!;
            byte original = first[0];
            first[0] ^= 0xFF;
            Assert.Equal(original, field()![0]);
        }
    }

    /// <summary>
    /// Nothing Apple signed is lost: attribute types the library does not
    /// model are kept raw, each under its type, every repeat in receipt order.
    /// </summary>
    [Fact]
    public void UnknownAttributesArePreservedInOrderWithTheirRepeats()
    {
        ReceiptPayload parsed = Verified(TestPki.AttributeSet(new (BigInteger, byte[])[]
        {
            (2, TestPki.Utf8("com.example.app")),
            (12, TestPki.Ia5("2024-08-06T12:00:00Z")),
            (9999, new byte[] { 1, 2, 3 }),
            (31337, new byte[] { 9 }),
            (9999, new byte[] { 4, 5 }),
        }));

        Assert.Equal(2, parsed.UnknownAttributes.Count);
        Assert.Equal(new[] { new byte[] { 1, 2, 3 }, new byte[] { 4, 5 } }, parsed.UnknownAttributes[9999]);
        Assert.Equal(new byte[] { 9 }, Assert.Single(parsed.UnknownAttributes[31337]));
        Assert.Contains("\"unknown_attributes\":{\"9999\":[\"AQID\",\"BAU=\"],\"31337\":[\"CQ==\"]}", parsed.ToJson(), System.StringComparison.Ordinal);
    }

    /// <summary>
    /// A date attribute whose string is empty means "not set": the typed field
    /// is null and nothing is kept raw, so Apple's empty 1712 values leave no
    /// trace. An empty string that is not a date is the value "".
    /// </summary>
    [Fact]
    public void AnEmptyDateStringMeansTheAttributeIsAbsent()
    {
        byte[] inApp = TestPki.AttributeSet(new (BigInteger, byte[])[]
        {
            (1702, TestPki.Utf8("com.example.app.pro")),
            (1712, TestPki.Ia5(string.Empty)),
        });
        ReceiptPayload parsed = Verified(TestPki.AttributeSet(new (BigInteger, byte[])[]
        {
            (2, TestPki.Utf8("com.example.app")),
            (12, TestPki.Ia5("2024-08-06T12:00:00Z")),
            (19, TestPki.Utf8(string.Empty)),
            (21, TestPki.Ia5(string.Empty)),
            (17, inApp),
        }));

        Assert.Null(parsed.ExpirationDateMs);
        Assert.Equal(string.Empty, parsed.OriginalApplicationVersion);
        Assert.Empty(parsed.UnknownAttributes);
        InAppPurchase purchase = Assert.Single(parsed.InApp);
        Assert.Null(purchase.CancellationDateMs);
        Assert.Empty(purchase.UnknownAttributes);
    }

    /// <summary>
    /// Xcode receipts wrap the attribute SET in one extra OCTET STRING
    /// (receipt/accept-double-wrapped-payload); exactly one unwrap is taken,
    /// so a payload wrapped twice is Apple-signed content that does not parse.
    /// </summary>
    [Fact]
    public void ADoubleWrappedPayloadIsUnwrappedExactlyOnce()
    {
        AsnWriter once = new(AsnEncodingRules.DER);
        once.WriteOctetString(TestPki.StandardPayload());
        Assert.Equal("com.example.app", Verified(once.Encode()).BundleId);

        AsnWriter twice = new(AsnEncodingRules.DER);
        twice.WriteOctetString(once.Encode());
        TestPki.ReceiptChain chain = TestPki.SharedReceipt.Value;
        Assert.Equal(
            VerificationReason.UnreadablePayload,
            chain.Verifier().VerifyReceipt(chain.SignBase64(twice.Encode())).Failure?.Reason);
    }
}
