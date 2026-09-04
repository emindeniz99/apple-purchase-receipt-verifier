using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier.Internal;
using ApplePurchaseReceiptVerifier.Jws;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The bounds that keep an unverified receipt from spending the caller's CPU
/// and memory.
/// </summary>
public class ResourceBoundTests
{
    private static byte[] Receipt => Fixtures.Bytes("receipt");

    private static IReadOnlyList<X509Certificate2> Roots() =>
        new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("receipt-root")) };

    [Fact]
    public void TenEmbeddedCertificatesAreAccepted()
    {
        byte[] padded = WithCertificateCopies(Receipt, 10);
        Assert.Equal(10, Internals.PreScan(padded, 10));
        using ReceiptVerifier verifier = new(Roots(), "com.example.app");
        Assert.Equal("com.example.app", verifier.Verify(padded).BundleId);
    }

    [Fact]
    public void ElevenEmbeddedCertificatesAreRejected()
    {
        byte[] padded = WithCertificateCopies(Receipt, 11);
        using ReceiptVerifier verifier = new(Roots(), "com.example.app");
        Assert.Equal(
            VerificationReason.InvalidChain,
            Assert.Throws<VerificationException>(() => verifier.Verify(padded)).Reason);
    }

    /// <summary>
    /// The bound is on <em>parsing</em>, not on the walk. The obvious port of
    /// it — reading <c>SignedCms.Certificates.Count</c> — is the attack:
    /// touching that property materialises every embedded certificate, which
    /// measured 1 045 ms and 6 000 handle-holding objects for this input,
    /// against 35 µs for the structural pre-scan.
    /// </summary>
    [Fact]
    public void ACertificateFloodIsRejectedInBoundedTime()
    {
        byte[] flood = WithCertificateCopies(Receipt, 6_000);
        Assert.True(flood.Length > 3_000_000, $"the flood is only {flood.Length} bytes");

        using ReceiptVerifier verifier = new(Roots(), "com.example.app");
        Stopwatch stopwatch = Stopwatch.StartNew();
        VerificationException error = Assert.Throws<VerificationException>(() => verifier.Verify(flood));
        stopwatch.Stop();

        Assert.Equal(VerificationReason.InvalidChain, error.Reason);
        Assert.True(stopwatch.ElapsedMilliseconds < 250, $"took {stopwatch.ElapsedMilliseconds} ms");
    }

    [Fact]
    public void AVeryLargeBlobIsRejectedWithoutExhaustingMemory()
    {
        byte[] blob = new byte[50 * 1024 * 1024];
        blob[0] = 0x30;
        blob[1] = 0x84;
        blob[2] = 0x03;
        blob[3] = 0x00;
        blob[4] = 0x00;
        blob[5] = 0x00;

        using ReceiptVerifier verifier = new(Roots(), "com.example.app");
        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            Assert.Throws<VerificationException>(() => verifier.Verify(blob)).Reason);
    }

    [Theory]
    [InlineData(1_000)]
    [InlineData(50_000)]
    public void DeeplyNestedAsn1IsRejectedWithoutUnboundedRecursion(int depth)
    {
        using ReceiptVerifier verifier = new(Roots(), "com.example.app");
        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            Assert.Throws<VerificationException>(() => verifier.Verify(NestedDefinite(depth))).Reason);
        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            Assert.Throws<VerificationException>(() => verifier.Verify(NestedIndefinite(depth))).Reason);
    }

    /// <summary>
    /// The double-unwrap is depth-bounded at one, so a nested-OCTET-STRING bomb
    /// cannot recurse: after the single unwrap the value must be a SET.
    /// </summary>
    [Fact]
    public void ANestedOctetStringBombDoesNotRecurse()
    {
        byte[] bomb = new byte[] { 0x05, 0x00 };
        for (int i = 0; i < 5_000; i++)
        {
            AsnWriter writer = new(AsnEncodingRules.DER);
            writer.WriteOctetString(bomb);
            bomb = writer.Encode();
        }

        Assert.Equal(VerificationReason.InvalidReceiptFormat, PayloadReason(bomb));
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

        AppReceipt receipt = ParsePayload(payload);
        InAppPurchase purchase = Assert.Single(receipt.InAppPurchases);
        Assert.Equal("com.example.app.pro", purchase.ProductId);
        Assert.True(purchase.UnknownAttributes.ContainsKey(17));
        Assert.Single(purchase.UnknownAttributes[17]);
    }

    [Fact]
    public void DeeplyNestedJsonIsRejectedOnDepthNotOnTheStack()
    {
        string json = new string('[', 10_000) + new string(']', 10_000);
        Assert.Throws<ApplePurchaseReceiptVerifier.Internal.JsonException>(() => Json.Parse(json));

        StringBuilder objects = new();
        for (int i = 0; i < 10_000; i++)
        {
            objects.Append("{\"a\":");
        }

        objects.Append("1");
        for (int i = 0; i < 10_000; i++)
        {
            objects.Append('}');
        }

        Assert.Throws<ApplePurchaseReceiptVerifier.Internal.JsonException>(() => Json.Parse(objects.ToString()));
    }

    [Fact]
    public void ADeeplyNestedJwsPayloadIsContained()
    {
        string payload = new string('[', 10_000) + new string(']', 10_000);
        string jws = TestPki.Base64Url(Encoding.UTF8.GetBytes("{\"alg\":\"ES256\",\"x5c\":[\"A\",\"A\",\"A\"]}"))
            + "." + TestPki.Base64Url(Encoding.UTF8.GetBytes(payload))
            + "." + TestPki.Base64Url(new byte[64]);

        using JwsVerifier verifier = new(
            AppleRootCertificates.JwsRoots(), "com.example.app", new[] { AppleEnvironment.Sandbox });
        Assert.IsType<VerificationException>(
            Record.Exception(() => verifier.VerifyTransaction(jws)));
    }

    // --- helpers -------------------------------------------------------------

    private static AppReceipt ParsePayload(byte[] payload) => ReceiptPayload.Parse(payload);

    private static VerificationReason PayloadReason(byte[] payload) =>
        Assert.Throws<VerificationException>(() => ReceiptPayload.Parse(payload)).Reason;

    private static byte[] NestedDefinite(int depth)
    {
        byte[] current = { 0x05, 0x00 };
        for (int i = 0; i < depth; i++)
        {
            AsnWriter writer = new(AsnEncodingRules.BER);
            using (writer.PushSequence())
            {
                writer.WriteEncodedValue(current);
            }

            current = writer.Encode();
        }

        return current;
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

    /// <summary>Rebuilds the CMS blob with the certificate bag repeated.</summary>
    internal static byte[] WithCertificateCopies(byte[] der, int total)
    {
        Asn1Tag explicitTag = new(TagClass.ContextSpecific, 0, true);
        AsnReader contentInfo = new AsnReader(der, AsnEncodingRules.BER).ReadSequence();
        string oid = contentInfo.ReadObjectIdentifier();
        AsnReader signedData = contentInfo.ReadSequence(explicitTag).ReadSequence();

        List<byte[]> before = new();
        List<byte[]> certificates = new();
        List<byte[]> after = new();
        while (signedData.HasData)
        {
            if (signedData.PeekTag() == explicitTag)
            {
                AsnReader bag = signedData.ReadSetOf(skipSortOrderValidation: true, explicitTag);
                while (bag.HasData)
                {
                    certificates.Add(bag.ReadEncodedValue().ToArray());
                }

                continue;
            }

            (certificates.Count == 0 ? before : after).Add(signedData.ReadEncodedValue().ToArray());
        }

        AsnWriter writer = new(AsnEncodingRules.BER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            using (writer.PushSequence(explicitTag))
            {
                using (writer.PushSequence())
                {
                    foreach (byte[] element in before)
                    {
                        writer.WriteEncodedValue(element);
                    }

                    using (writer.PushSetOf(explicitTag))
                    {
                        for (int i = 0; i < total; i++)
                        {
                            writer.WriteEncodedValue(certificates[i % certificates.Count]);
                        }
                    }

                    foreach (byte[] element in after)
                    {
                        writer.WriteEncodedValue(element);
                    }
                }
            }
        }

        return writer.Encode();
    }
}
