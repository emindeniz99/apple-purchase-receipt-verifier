using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier.Internal;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>The receipt path's own rules: the attribute grammar and the device binding.</summary>
public class ReceiptTests
{
    private static IReadOnlyList<X509Certificate2> Roots() =>
        new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("receipt-root")) };

    [Fact]
    public void EveryInputFormIsReachableWithAndWithoutTheDeviceGuid()
    {
        byte[] der = Fixtures.Bytes("receipt");
        string base64 = Convert.ToBase64String(der);
        byte[] guid = Convert.FromHexString("112233445566778899aabbccddeeff00");

        using ReceiptVerifier verifier = new(Roots(), "com.example.app");
        Assert.Equal("com.example.app", verifier.Verify(der).BundleId);
        Assert.Equal("com.example.app", verifier.Verify(der, guid).BundleId);
        Assert.Equal("com.example.app", verifier.Verify(base64).BundleId);
        Assert.Equal("com.example.app", verifier.Verify(base64, guid).BundleId);
    }

    [Fact]
    public void ABase64ReceiptWithWhitespaceIsAccepted()
    {
        string wrapped = string.Join(
            "\n",
            Chunks(Convert.ToBase64String(Fixtures.Bytes("receipt")), 64));
        using ReceiptVerifier verifier = new(Roots(), "com.example.app");
        Assert.Equal("com.example.app", verifier.Verify(wrapped).BundleId);
    }

    [Fact]
    public void TheWrongDeviceGuidIsADeviceHashMismatch()
    {
        using ReceiptVerifier verifier = new(Roots(), "com.example.app");
        Assert.Equal(
            VerificationReason.DeviceHashMismatch,
            Assert.Throws<VerificationException>(
                () => verifier.Verify(Fixtures.Bytes("receipt"), new byte[16])).Reason);
    }

    [Fact]
    public void AReceiptLackingTheDeviceHashAttributesIsADeviceHashMismatch()
    {
        (byte[] receipt, X509Certificate2 root) = Mint(new (BigInteger, byte[])[]
        {
            (2, TestPki.Utf8("com.example.app")),
            (12, TestPki.Ia5("2024-08-06T12:00:00Z")),
        });

        using ReceiptVerifier verifier = new(new[] { root }, "com.example.app");
        Assert.Equal(
            VerificationReason.DeviceHashMismatch,
            Assert.Throws<VerificationException>(() => verifier.Verify(receipt, new byte[16])).Reason);
    }

    [Fact]
    public void TheDeviceHashIsSha1OfGuidThenOpaqueValueThenBundleIdBytes()
    {
        byte[] guid = { 0xAA, 0xBB, 0xCC, 0xDD };
        byte[] opaque = { 1, 2, 3, 4, 5, 6, 7, 8 };
        byte[] bundleIdValue = TestPki.Utf8("com.example.app");
        byte[] expected;
        using (SHA1 sha1 = SHA1.Create())
        {
            expected = sha1.ComputeHash(guid.Concat(opaque).Concat(bundleIdValue).ToArray());
        }

        (byte[] receipt, X509Certificate2 root) = Mint(new (BigInteger, byte[])[]
        {
            (2, bundleIdValue),
            (4, opaque),
            (5, expected),
            (12, TestPki.Ia5("2024-08-06T12:00:00Z")),
        });

        using ReceiptVerifier verifier = new(new[] { root }, "com.example.app");
        Assert.Equal("com.example.app", verifier.Verify(receipt, guid).BundleId);
    }

    [Fact]
    public void ByteFieldsHandedToTheCallerAreCopies()
    {
        using ReceiptVerifier verifier = new(Roots(), "com.example.app");
        AppReceipt receipt = verifier.Verify(Fixtures.Bytes("receipt"));

        byte[] first = receipt.OpaqueValue!;
        first[0] ^= 0xFF;
        Assert.NotEqual(first[0], receipt.OpaqueValue![0]);
    }

    [Fact]
    public void MutatingTheCallersBufferAfterVerificationDoesNotChangeTheReceipt()
    {
        byte[] input = (byte[])Fixtures.Bytes("receipt").Clone();
        using ReceiptVerifier verifier = new(Roots(), "com.example.app");
        AppReceipt receipt = verifier.Verify(input);
        string bundleId = receipt.BundleId!;
        byte[] opaque = receipt.OpaqueValue!;

        Array.Clear(input);

        Assert.Equal(bundleId, receipt.BundleId);
        Assert.Equal(opaque, receipt.OpaqueValue);
    }

    [Fact]
    public void UnknownAttributesArePreservedInOrderWithTheirRepeats()
    {
        (byte[] receipt, X509Certificate2 root) = Mint(new (BigInteger, byte[])[]
        {
            (2, TestPki.Utf8("com.example.app")),
            (12, TestPki.Ia5("2024-08-06T12:00:00Z")),
            (9999, new byte[] { 1, 2, 3 }),
            (9999, new byte[] { 4, 5 }),
            (31337, new byte[] { 9 }),
        });

        using ReceiptVerifier verifier = new(new[] { root }, "com.example.app");
        AppReceipt parsed = verifier.Verify(receipt);

        Assert.Equal(new byte[] { 1, 2, 3 }, parsed.UnknownAttributes[9999][0]);
        Assert.Equal(new byte[] { 4, 5 }, parsed.UnknownAttributes[9999][1]);
        Assert.Equal(new byte[] { 9 }, parsed.UnknownAttributes[31337][0]);
    }

    [Fact]
    public void AnEmptyDateStringMeansTheAttributeIsAbsent()
    {
        (byte[] receipt, X509Certificate2 root) = Mint(new (BigInteger, byte[])[]
        {
            (2, TestPki.Utf8("com.example.app")),
            (12, TestPki.Ia5("2024-08-06T12:00:00Z")),
            (21, TestPki.Ia5(string.Empty)),
        });

        using ReceiptVerifier verifier = new(new[] { root }, "com.example.app");
        Assert.Null(verifier.Verify(receipt).ExpirationDate);
    }

    [Fact]
    public void DatesAreReadAsUtcRegardlessOfTheOffsetTheyCarry()
    {
        (byte[] receipt, X509Certificate2 root) = Mint(new (BigInteger, byte[])[]
        {
            (2, TestPki.Utf8("com.example.app")),
            (12, TestPki.Ia5("2024-08-06T14:00:00+02:00")),
        });

        using ReceiptVerifier verifier = new(new[] { root }, "com.example.app");
        AppReceipt parsed = verifier.Verify(receipt);
        Assert.Equal(new DateTimeOffset(2024, 8, 6, 12, 0, 0, TimeSpan.Zero), parsed.CreationDate);
        Assert.Equal(TimeSpan.Zero, parsed.CreationDate!.Value.Offset);
    }

    [Fact]
    public void AWebOrderLineItemIdWiderThanThirtyTwoBitsIsPreserved()
    {
        byte[] inApp = TestPki.AttributeSet(new (BigInteger, byte[])[]
        {
            (1702, TestPki.Utf8("com.example.app.pro")),
            (1711, TestPki.Integer(1_000_000_000_000L)),
        });
        (byte[] receipt, X509Certificate2 root) = Mint(new (BigInteger, byte[])[]
        {
            (2, TestPki.Utf8("com.example.app")),
            (12, TestPki.Ia5("2024-08-06T12:00:00Z")),
            (17, inApp),
        });

        using ReceiptVerifier verifier = new(new[] { root }, "com.example.app");
        Assert.Equal(1_000_000_000_000L, verifier.Verify(receipt).InAppPurchases[0].WebOrderLineItemId);
    }

    [Fact]
    public void AnIntegerAttributeWiderThanSixtyFourBitsIsRejected()
    {
        byte[] inApp = TestPki.AttributeSet(new (BigInteger, byte[])[]
        {
            (1702, TestPki.Utf8("com.example.app.pro")),
            (1701, TestPki.Integer(BigInteger.Pow(2, 100))),
        });

        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            Assert.Throws<VerificationException>(
                () => ReceiptPayload.Parse(TestPki.AttributeSet(new (BigInteger, byte[])[]
                {
                    (2, TestPki.Utf8("com.example.app")),
                    (17, inApp),
                }))).Reason);
    }

    [Fact]
    public void ANegativeIntegerAttributeIsRejected()
    {
        byte[] inApp = TestPki.AttributeSet(new (BigInteger, byte[])[] { (1701, TestPki.Integer(-1)) });

        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            Assert.Throws<VerificationException>(
                () => ReceiptPayload.Parse(TestPki.AttributeSet(new (BigInteger, byte[])[]
                {
                    (2, TestPki.Utf8("com.example.app")),
                    (17, inApp),
                }))).Reason);
    }

    [Fact]
    public void ADoubleWrappedPayloadIsUnwrappedExactlyOnce()
    {
        // The Xcode shape: the attribute set inside an extra OCTET STRING.
        System.Formats.Asn1.AsnWriter writer = new(System.Formats.Asn1.AsnEncodingRules.DER);
        writer.WriteOctetString(TestPki.StandardPayload());
        AppReceipt parsed = ReceiptPayload.Parse(writer.Encode());
        Assert.Equal("com.example.app", parsed.BundleId);

        System.Formats.Asn1.AsnWriter twice = new(System.Formats.Asn1.AsnEncodingRules.DER);
        twice.WriteOctetString(writer.Encode());
        Assert.Throws<VerificationException>(() => ReceiptPayload.Parse(twice.Encode()));
    }

    [Fact]
    public void AReceiptSignedWithAnUnsupportedDigestIsRejected()
    {
        X509Certificate2 root = TestPki.RsaRoot();
        X509Certificate2 signer = TestPki.RsaChild(root, "CN=Signer", false, TestPki.LeafOid);
        byte[] receipt = TestPki.SignReceipt(
            TestPki.StandardPayload(), signer, new[] { root }, "2.16.840.1.101.3.4.2.3"); // SHA-512

        using ReceiptVerifier verifier = new(new[] { TestPki.Public(root) }, "com.example.app");
        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            Assert.Throws<VerificationException>(() => verifier.Verify(receipt)).Reason);
    }

    [Fact]
    public void ASha1SignedReceiptIsAccepted()
    {
        X509Certificate2 root = TestPki.RsaRoot();
        X509Certificate2 signer = TestPki.RsaChild(root, "CN=Signer", false, TestPki.LeafOid);
        byte[] receipt = TestPki.SignReceipt(
            TestPki.StandardPayload(), signer, new[] { root }, "1.3.14.3.2.26");

        using ReceiptVerifier verifier = new(new[] { TestPki.Public(root) }, "com.example.app");
        Assert.Equal("com.example.app", verifier.Verify(receipt).BundleId);
    }

    [Fact]
    public void AReceiptSignedWithAnEcKeyIsRejected()
    {
        X509Certificate2 root = TestPki.EcRoot();
        X509Certificate2 signer = TestPki.EcChild(root, "CN=Signer", false, TestPki.LeafOid);
        byte[] receipt = TestPki.SignReceipt(TestPki.StandardPayload(), signer, new[] { root });

        using ReceiptVerifier verifier = new(new[] { TestPki.Public(root) }, "com.example.app");
        Assert.Equal(
            VerificationReason.InvalidSignature,
            Assert.Throws<VerificationException>(() => verifier.Verify(receipt)).Reason);
    }

    /// <summary>
    /// The receipt path checks the marker OID <em>after</em> the chain, so a
    /// foreign chain reports INVALID_CHAIN and not INVALID_CERTIFICATE_PURPOSE.
    /// The JWS path is the other way round.
    /// </summary>
    [Fact]
    public void AForeignChainWithoutTheMarkerOidReportsTheChainFailure()
    {
        X509Certificate2 pinned = TestPki.RsaRoot("CN=Pinned");
        X509Certificate2 foreign = TestPki.RsaRoot("CN=Foreign");
        X509Certificate2 signer = TestPki.RsaChild(foreign, "CN=Signer", false);
        byte[] receipt = TestPki.SignReceipt(TestPki.StandardPayload(), signer, new[] { foreign });

        using ReceiptVerifier verifier = new(new[] { TestPki.Public(pinned) }, "com.example.app");
        Assert.Equal(
            VerificationReason.InvalidChain,
            Assert.Throws<VerificationException>(() => verifier.Verify(receipt)).Reason);
    }

    [Fact]
    public void VerifyReceiptCoreSkipsTheBundleIdCheck()
    {
        AppReceipt receipt = ReceiptVerifier.VerifyReceiptCore(Fixtures.Bytes("receipt"), Roots());
        Assert.Equal("com.example.app", receipt.BundleId);

        using ReceiptVerifier verifier = new(Roots(), "com.somebody.else");
        Assert.Equal(
            VerificationReason.WrongBundleId,
            Assert.Throws<VerificationException>(() => verifier.Verify(Fixtures.Bytes("receipt"))).Reason);
    }

    // --- the genuine public receipts ----------------------------------------

    [Fact]
    public void TheGenuineSandboxReceiptVerifiesAgainstTheBundledAppleRoots()
    {
        using ReceiptVerifier verifier = new(
            AppleRootCertificates.ReceiptRoots(), "dev.bonzer.weeka.app");
        AppReceipt receipt = verifier.Verify(Fixtures.Bytes("public-receipt-sandbox-g5"));
        Assert.Equal("ProductionSandbox", receipt.ReceiptType);
        Assert.Equal(2, receipt.InAppPurchases.Count);
    }

    [Fact]
    public void TheGenuineLegacySha1ReceiptVerifiesAgainstTheBundledAppleRoots()
    {
        using ReceiptVerifier verifier = new(
            AppleRootCertificates.ReceiptRoots(), "com.nutcall.alert");
        AppReceipt receipt = verifier.Verify(Fixtures.Bytes("public-receipt-sandbox-legacy"));
        Assert.Equal(187, receipt.InAppPurchases.Count);
        Assert.All(receipt.InAppPurchases, p => Assert.NotNull(p.ProductId));
    }

    [Fact]
    public void AnXcodeSignedReceiptIsNotAppleSigned()
    {
        using ReceiptVerifier verifier = new(AppleRootCertificates.ReceiptRoots(), "*");
        Assert.Equal(
            VerificationReason.InvalidChain,
            Assert.Throws<VerificationException>(
                () => verifier.Verify(Fixtures.Bytes("public-receipt-xcode-with-purchases"))).Reason);
    }

    private static IEnumerable<string> Chunks(string value, int size)
    {
        for (int i = 0; i < value.Length; i += size)
        {
            yield return value.Substring(i, Math.Min(size, value.Length - i));
        }
    }

    private static (byte[] Receipt, X509Certificate2 Root) Mint(
        IEnumerable<(BigInteger Type, byte[] Value)> attributes)
    {
        X509Certificate2 root = TestPki.RsaRoot();
        X509Certificate2 intermediate = TestPki.RsaChild(root, "CN=Fake WWDR", true);
        X509Certificate2 signer = TestPki.RsaChild(
            intermediate, "CN=Fake Receipt Signing", false, TestPki.LeafOid);
        byte[] receipt = TestPki.SignReceipt(
            TestPki.AttributeSet(attributes), signer, new[] { intermediate, root });
        return (receipt, TestPki.Public(root));
    }
}
