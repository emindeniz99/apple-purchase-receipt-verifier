using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using ApplePurchaseReceiptVerifier.Jws;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The parts of this port that no cross-language vector can reach: the ECDSA
/// encoding conversion, the structural pre-scan, thread safety, and disposal.
/// </summary>
public class PlatformTests
{
    private static IReadOnlyList<X509Certificate2> ReceiptRoots() =>
        new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("receipt-root")) };

    private static IReadOnlyList<X509Certificate2> JwsRoots() =>
        new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("jws-root")) };

    // --- DER to IEEE P1363 ---------------------------------------------------

    /// <summary>
    /// The three shapes that break a naive converter: a value with leading
    /// zeros, one whose top bit is set (so DER prepends a 0x00), and one at
    /// full field width.
    /// </summary>
    [Theory]
    [InlineData("01", "01")]
    [InlineData("ff", "ff")]
    [InlineData("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "01")]
    [InlineData("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "80")]
    public void DerSignaturesConvertToFixedWidthP1363(string r, string s)
    {
        byte[] der = Der(Big(r), Big(s));
        byte[]? p1363 = Internals.DerToP1363(der, 32);

        Assert.NotNull(p1363);
        Assert.Equal(64, p1363!.Length);
        Assert.Equal(Big(r), new BigInteger(p1363.AsSpan(0, 32), isUnsigned: true, isBigEndian: true));
        Assert.Equal(Big(s), new BigInteger(p1363.AsSpan(32, 32), isUnsigned: true, isBigEndian: true));
    }

    [Fact]
    public void AValueWiderThanTheFieldIsAFailedConversionNotATruncatedOne()
    {
        byte[] der = Der(
            Big("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), BigInteger.One);
        Assert.Null(Internals.DerToP1363(der, 16));
    }

    [Theory]
    [InlineData("")]
    [InlineData("00")]
    [InlineData("3000")]
    [InlineData("300602010102010101")]
    public void MalformedDerSignaturesConvertToNull(string hex)
    {
        Assert.Null(Internals.DerToP1363(Convert.FromHexString(hex), 32));
    }

    [Fact]
    public void ANonPositiveComponentIsRejected()
    {
        Assert.Null(Internals.DerToP1363(Der(BigInteger.Zero, BigInteger.One), 32));
        Assert.Null(Internals.DerToP1363(Der(BigInteger.MinusOne, BigInteger.One), 32));
    }

    [Fact]
    public void TrailingDataAfterTheSequenceIsRejected()
    {
        byte[] der = Der(BigInteger.One, BigInteger.One);
        byte[] padded = der.Concat(new byte[] { 0x05, 0x00 }).ToArray();
        Assert.Null(Internals.DerToP1363(padded, 32));
    }

    // --- the structural pre-scan --------------------------------------------

    [Fact]
    public void ThePreScanCountsWithoutDecoding()
    {
        Assert.Equal(3, Internals.PreScan(Fixtures.Bytes("receipt"), 10));
        Assert.Equal(1, Internals.PreScan(Fixtures.Bytes("public-receipt-xcode-with-purchases"), 10));
    }

    [Fact]
    public void ThePreScanShortCircuitsAtTheLimit()
    {
        byte[] flood = ResourceBoundTests.WithCertificateCopies(Fixtures.Bytes("receipt"), 500);
        // It stops the moment the bound is exceeded rather than counting to 500.
        Assert.Equal(11, Internals.PreScan(flood, 10));
    }

    [Fact]
    public void ThePreScanRejectsTrailingBytesAndNonCmsInput()
    {
        byte[] padded = Fixtures.Bytes("receipt").Concat(new byte[] { 0 }).ToArray();
        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            Assert.Throws<VerificationException>(() => Internals.PreScan(padded, 10)).Reason);

        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            Assert.Throws<VerificationException>(
                () => Internals.PreScan(new byte[] { 0x05, 0x00 }, 10)).Reason);
    }

    // --- thread safety and lifetime -----------------------------------------

    [Fact]
    public void OneVerifierServesManyThreads()
    {
        using ReceiptVerifier receipts = new(ReceiptRoots(), "com.example.app");
        using JwsVerifier jws = new(JwsRoots(), "com.example.app", new[] { AppleEnvironment.Sandbox });
        byte[] receipt = Fixtures.Bytes("receipt");
        string transaction = Fixtures.Text("transaction");

        ConcurrentBag<string> failures = new();
        Parallel.For(0, 512, _ =>
        {
            try
            {
                Assert.Equal("com.example.app", receipts.Verify(receipt).BundleId);
                Assert.Equal(1722945600000L, jws.VerifyTransaction(transaction).SignedDate);
            }
            catch (Exception e)
            {
                failures.Add(e.ToString());
            }
        });

        Assert.Empty(failures);
    }

    [Fact]
    public void ADisposedVerifierRaisesObjectDisposedNotACryptographicException()
    {
        ReceiptVerifier receipts = new(ReceiptRoots(), "com.example.app");
        receipts.Dispose();
        receipts.Dispose(); // idempotent
        Assert.Throws<ObjectDisposedException>(() => receipts.Verify(Fixtures.Bytes("receipt")));

        JwsVerifier jws = new(JwsRoots(), "com.example.app", new[] { AppleEnvironment.Sandbox });
        jws.Dispose();
        jws.Dispose();
        Assert.Throws<ObjectDisposedException>(() => jws.VerifyTransaction(Fixtures.Text("transaction")));
    }

    /// <summary>
    /// Repeated verification must not grow unboundedly: each call materialises
    /// certificates behind unmanaged handles, and a leak there is invisible
    /// until a server falls over.
    /// </summary>
    [Fact]
    public void RepeatedVerificationDoesNotGrowUnboundedly()
    {
        using ReceiptVerifier verifier = new(ReceiptRoots(), "com.example.app");
        byte[] receipt = Fixtures.Bytes("receipt");
        for (int i = 0; i < 50; i++)
        {
            verifier.Verify(receipt);
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        long before = GC.GetTotalMemory(true);

        for (int i = 0; i < 500; i++)
        {
            verifier.Verify(receipt);
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        long after = GC.GetTotalMemory(true);

        Assert.True(after - before < 16 * 1024 * 1024, $"live set grew by {after - before} bytes");
    }

    // --- the harness itself --------------------------------------------------

    /// <summary>
    /// The conformance adapter's field-path resolver has to be right, or the
    /// whole suite goes green against nothing. These are its own tests.
    /// </summary>
    [Fact]
    public void TheFieldPathResolverSelectsWhatTheGrammarSays()
    {
        object? model = Normalize.Value(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["receipt"] = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["in_app"] = new List<object?>
                {
                    new Dictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["product_id"] = "com.example.app.vip",
                        ["quantity"] = "1",
                    },
                    new Dictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["product_id"] = "com.example.app.coins100",
                        ["quantity"] = "2",
                    },
                },
            },
            ["unknownAttributes"] = new Dictionary<int, IReadOnlyList<byte[]>>
            {
                [9999] = new[] { new byte[] { 1, 2, 3 } },
            },
        });

        Assert.Equal(2L, Normalize.Resolve(model, "receipt.in_app.length"));
        Assert.Equal("1", Normalize.Resolve(model, "receipt.in_app[product_id=com.example.app.vip].quantity"));
        Assert.Equal("010203", Normalize.Resolve(model, "unknownAttributes[9999][0]"));
        Assert.Equal(1L, Normalize.Resolve(model, "unknownAttributes[9999].length"));
        Assert.Null(Normalize.Resolve(model, "receipt.absent"));
        Assert.Null(Normalize.Resolve(model, "receipt.absent.deeper"));
    }

    [Fact]
    public void TheFieldPathResolverFailsWhenASelectorIsNotUnique()
    {
        object? model = Normalize.Value(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["list"] = new List<object?>
            {
                new Dictionary<string, object?>(StringComparer.Ordinal) { ["id"] = "a" },
                new Dictionary<string, object?>(StringComparer.Ordinal) { ["id"] = "a" },
            },
        });

        Assert.ThrowsAny<Exception>(() => Normalize.Resolve(model, "list[id=a]"));
        Assert.ThrowsAny<Exception>(() => Normalize.Resolve(model, "list[id=missing]"));
    }

    [Fact]
    public void TheNormalizerRendersDatesAndBytesTheWayTheVectorsSpellThem()
    {
        Assert.Equal(
            "2024-08-06T12:00:00Z",
            Normalize.Value(new DateTimeOffset(2024, 8, 6, 12, 0, 0, TimeSpan.Zero)));
        Assert.Equal(
            "2024-08-06T12:00:00.250Z",
            Normalize.Value(new DateTimeOffset(2024, 8, 6, 12, 0, 0, 250, TimeSpan.Zero)));
        Assert.Equal(
            "2024-08-06T12:00:00Z",
            Normalize.Value(new DateTimeOffset(2024, 8, 6, 14, 0, 0, TimeSpan.FromHours(2))));
        Assert.Equal("0a0b", Normalize.Value(new byte[] { 0x0A, 0x0B }));
        Assert.Equal(7L, Normalize.Value(7));
    }

    [Fact]
    public void TheHarnessMirrorsByteFieldsUnderAHexSuffix()
    {
        using ReceiptVerifier verifier = new(ReceiptRoots(), "com.example.app");
        object? model = Normalize.Value(verifier.Verify(Fixtures.Bytes("receipt")));
        Assert.Equal("0102030405060708", Normalize.Resolve(model, "opaqueValueHex"));
        Assert.Equal("0102030405060708", Normalize.Resolve(model, "opaqueValue"));
    }

    private static BigInteger Big(string hex) =>
        new(Convert.FromHexString(hex.Length % 2 == 0 ? hex : "0" + hex), isUnsigned: true, isBigEndian: true);

    private static byte[] Der(BigInteger r, BigInteger s)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(r);
            writer.WriteInteger(s);
        }

        return writer.Encode();
    }
}
