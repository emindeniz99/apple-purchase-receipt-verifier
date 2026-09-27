using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Numerics;
using System.Text;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The bounds that keep unverified input from spending the caller's CPU,
/// memory and stack.
/// </summary>
public class ResourceBoundTests
{
    private static IVerifier Receipts() => TestPki.FixtureVerifier("receipt-root");

    /// <summary>
    /// The certificate cap is a bound on <em>parsing</em>, not on the walk:
    /// the obvious port of it — materialising the bag, then counting — is the
    /// attack, since each entry becomes a platform certificate behind a
    /// handle (measured once at 1 045 ms and 6 000 handle-holding objects for
    /// this input). The flood stays under the base64 cap, so the count is what
    /// refuses it, and it does so before anything is decoded.
    /// </summary>
    [Fact]
    public void ACertificateFloodIsRejectedInBoundedTime()
    {
        string flood = Convert.ToBase64String(TestPki.WithCertificateCopies(Fixtures070.Bytes("receipt"), 2_500));
        Assert.True(flood.Length > 1_000_000, $"the flood is only {flood.Length} characters");
        Assert.True(flood.Length <= ReceiptVerifierCore.MaxReceiptBytes, $"the flood is {flood.Length} characters, over the cap");

        IVerifier verifier = Receipts();

        // One untimed call first: the bound is on the parse, not on JIT
        // compilation of the first call, which a busy CI runner stretches.
        verifier.VerifyReceipt(flood);
        Stopwatch stopwatch = Stopwatch.StartNew();
        VerificationResult<ReceiptPayload> result = verifier.VerifyReceipt(flood);
        stopwatch.Stop();

        Assert.Equal(VerificationReason.Malformed, result.Failure?.Reason);
        Assert.True(stopwatch.ElapsedMilliseconds < 250, $"took {stopwatch.ElapsedMilliseconds} ms");
    }

    /// <summary>
    /// A header that claims more content than the input holds is refused from
    /// the header, without allocating what it claims: here 2 MiB of zeros
    /// behind a SEQUENCE that says it is 3 MiB long.
    /// </summary>
    [Fact]
    public void ALengthThatClaimsMoreThanTheInputHoldsIsMalformed()
    {
        byte[] blob = new byte[2 * 1024 * 1024];
        blob[0] = 0x30;
        blob[1] = 0x84;
        blob[2] = 0x00;
        blob[3] = 0x30;
        blob[4] = 0x00;
        blob[5] = 0x00;

        Assert.Equal(VerificationReason.Malformed, Receipts().VerifyReceipt(Convert.ToBase64String(blob)).Failure?.Reason);
    }

    /// <summary>
    /// Nesting far past the 64-level bound, in both length forms, is refused
    /// on depth: the depth scan itself must not recurse once per level, or
    /// this input would take the process down instead of failing.
    /// </summary>
    [Theory]
    [InlineData(1_000)]
    [InlineData(50_000)]
    public void DeeplyNestedAsn1IsRejectedWithoutUnboundedRecursion(int depth)
    {
        IVerifier verifier = Receipts();
        Assert.Equal(
            VerificationReason.Malformed,
            verifier.VerifyReceipt(Convert.ToBase64String(NestedDefinite(depth))).Failure?.Reason);
        Assert.Equal(
            VerificationReason.Malformed,
            verifier.VerifyReceipt(Convert.ToBase64String(NestedIndefinite(depth))).Failure?.Reason);
    }

    /// <summary>
    /// The same bound inside signed content, where the payload parser runs:
    /// deep nesting is Apple-signed content that does not parse, never a
    /// stack overflow.
    /// </summary>
    [Fact]
    public void DeeplyNestedSignedContentIsUnreadableWithoutUnboundedRecursion()
    {
        Assert.Throws<VerificationException>(() => ReceiptAttributes.Parse(NestedDefinite(50_000)));
        Assert.Throws<VerificationException>(() => ReceiptAttributes.Parse(NestedIndefinite(50_000)));
        Assert.Null(ReceiptAttributes.ReadCreationDateMs(NestedIndefinite(50_000)));
    }

    /// <summary>
    /// The double-unwrap is depth-bounded at one, so a nested-OCTET-STRING bomb
    /// cannot recurse: after the single unwrap the value must be a SET.
    /// </summary>
    [Fact]
    public void ANestedOctetStringBombDoesNotRecurse()
    {
        byte[] bomb = { 0x05, 0x00 };
        for (int i = 0; i < 5_000; i++)
        {
            AsnWriter writer = new(AsnEncodingRules.DER);
            writer.WriteOctetString(bomb);
            bomb = writer.Encode();
        }

        Assert.Throws<VerificationException>(() => ReceiptAttributes.Parse(bomb));
        Assert.Null(ReceiptAttributes.ReadCreationDateMs(bomb));
    }

    /// <summary>
    /// An in-app attribute that nests itself is recorded as an unknown
    /// attribute, never recursed into: the parser's depth is a constant no
    /// input can change.
    /// </summary>
    [Fact]
    public void ANestedInAppAttributeIsNotRecursedInto()
    {
        byte[] inner = TestPki.AttributeSet(new (BigInteger, byte[])[]
        {
            (1702, TestPki.Utf8("com.example.app.coins")),
        });
        byte[] selfNesting = TestPki.AttributeSet(new (BigInteger, byte[])[]
        {
            (1702, TestPki.Utf8("com.example.app.pro")),
            (17, inner),
        });
        byte[] payload = TestPki.AttributeSet(new (BigInteger, byte[])[]
        {
            (2, TestPki.Utf8("com.example.app")),
            (12, TestPki.Ia5("2024-08-06T12:00:00Z")),
            (17, selfNesting),
        });

        ReceiptPayload receipt = ReceiptAttributes.Parse(payload);
        InAppPurchase purchase = Assert.Single(receipt.InApp);
        Assert.Equal("com.example.app.pro", purchase.ProductId);
        Assert.Equal(inner, Assert.Single(purchase.UnknownAttributes[17]));
    }

    [Fact]
    public void DeeplyNestedJsonIsRejectedOnDepthNotOnTheStack()
    {
        string json = new string('[', 10_000) + new string(']', 10_000);
        Assert.Throws<JsonException>(() => Json.Parse(json));

        StringBuilder objects = new();
        for (int i = 0; i < 10_000; i++)
        {
            objects.Append("{\"a\":");
        }

        objects.Append('1').Append('}', 10_000);
        Assert.Throws<JsonException>(() => Json.Parse(objects.ToString()));
    }

    /// <summary>A JWS whose header and payload both nest ten thousand deep is contained in both positions.</summary>
    [Fact]
    public void ADeeplyNestedJwsIsContained()
    {
        TestPki.JwsChain chain = TestPki.SharedJws.Value;
        string deep = new string('[', 10_000) + new string(']', 10_000);
        string signedPayload = chain.Sign("{\"signedDate\":1722945600000,\"x\":" + deep + "}");
        string header = TestPki.Base64Url(Encoding.UTF8.GetBytes("{\"alg\":\"ES256\",\"x\":" + deep + "}"));
        string[] parts = signedPayload.Split('.');

        IVerifier verifier = chain.Verifier(TestPki.SignedAtMs);
        Assert.Equal(VerificationReason.UnreadablePayload, verifier.VerifySignedData(signedPayload).Failure?.Reason);
        Assert.Equal(
            VerificationReason.Malformed,
            verifier.VerifySignedData(header + "." + parts[1] + "." + parts[2]).Failure?.Reason);
    }

    // --- helpers -------------------------------------------------------------

    /// <summary>
    /// <paramref name="depth"/> SEQUENCEs in definite-length form around a
    /// NULL, built from the inside out in one pass: re-encoding each level
    /// with a writer would copy the whole value once per level.
    /// </summary>
    private static byte[] NestedDefinite(int depth)
    {
        List<byte[]> headers = new(depth);
        int length = 2;
        for (int i = 0; i < depth; i++)
        {
            byte[] header = length < 0x80
                ? new byte[] { 0x30, (byte)length }
                : length <= 0xFF
                    ? new byte[] { 0x30, 0x81, (byte)length }
                    : length <= 0xFFFF
                        ? new byte[] { 0x30, 0x82, (byte)(length >> 8), (byte)length }
                        : new byte[] { 0x30, 0x83, (byte)(length >> 16), (byte)(length >> 8), (byte)length };
            headers.Add(header);
            length += header.Length;
        }

        List<byte> bytes = new(length);
        for (int i = headers.Count - 1; i >= 0; i--)
        {
            bytes.AddRange(headers[i]);
        }

        bytes.Add(0x05);
        bytes.Add(0x00);
        return bytes.ToArray();
    }

    private static byte[] NestedIndefinite(int depth)
    {
        List<byte> bytes = new();
        for (int i = 0; i < depth; i++)
        {
            bytes.Add(0x30);
            bytes.Add(0x80);
        }

        bytes.Add(0x05);
        bytes.Add(0x00);
        for (int i = 0; i < depth; i++)
        {
            bytes.Add(0x00);
            bytes.Add(0x00);
        }

        return bytes.ToArray();
    }
}
