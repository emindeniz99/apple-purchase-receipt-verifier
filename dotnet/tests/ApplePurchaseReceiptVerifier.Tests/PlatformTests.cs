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
/// Groups the tests that read process-wide state — the managed live set — so
/// they do not run beside another collection's allocations. xunit's default is
/// one collection per class, all of them in parallel, and
/// <see cref="PlatformTests.RepeatedVerificationDoesNotGrowUnboundedly"/>
/// measures the whole heap, not just its own objects.
/// </summary>
[CollectionDefinition("process-heap", DisableParallelization = true)]
public sealed class ProcessHeapCollection
{
}

/// <summary>
/// The parts of this port that no cross-language vector can reach: the ECDSA
/// encoding conversion, the structural pre-scan, thread safety, and disposal.
/// </summary>
[Collection("process-heap")]
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

    /// <summary>The verifications each measured round performs.</summary>
    private const int LiveSetRoundSize = 500;

    /// <summary>
    /// Measured rounds. The assertion is on the smallest growth of any round:
    /// retention grows the live set in every round, a background allocation
    /// lands in one.
    /// </summary>
    private const int LiveSetRounds = 3;

    /// <summary>
    /// What one verification may leave behind, in bytes. A single retained
    /// <c>X509Certificate2</c> is ~1.5 kB of <c>RawData</c> alone (a measured
    /// leak of one per call read 1,730 B/call), so this is still well under
    /// one leaked object per call. Linux and Windows measure ~2.5 B/call on a
    /// clean run; macOS/arm64 has read up to 110 B/call in every round of a
    /// run with nothing of ours retaining it, so the budget sits above that
    /// platform's noise rather than at the Linux figure.
    /// </summary>
    private const int LiveSetBudgetPerVerification = 256;

    /// <summary>
    /// Repeated verification must not grow unboundedly: each call materialises
    /// certificates behind unmanaged handles, and a leak there is invisible
    /// until a server falls over.
    /// </summary>
    /// <remarks>
    /// The bound is a budget per verification rather than a flat ceiling, so it
    /// scales with the round and fails on retention that is real but small.
    /// It can be that tight only because this class runs in a collection of its
    /// own (<see cref="ProcessHeapCollection"/>): <see cref="GC.GetTotalMemory"/>
    /// reports the whole process's live set, so a sibling collection allocating
    /// on another thread lands in the delta. That is what made this test flaky —
    /// deltas from -7.9 MB to +22 MB against a 16 MB ceiling — while the leak it
    /// looks for was never there.
    /// <para>
    /// A quiet process is still not a silent one: on macOS/arm64 net8.0 a single
    /// round read +262 kB once in three runs with nothing of ours retaining it
    /// (the test host and the runtime allocate on their own threads). So the
    /// round is measured <see cref="LiveSetRounds"/> times and the smallest
    /// growth is judged. Retention of one object per call, the failure this
    /// test exists for, exceeds the budget in every round and still fails.
    /// The same platform later read +55 kB in each of the three rounds
    /// (110 B/call) with Linux and Windows at ~0 on the same commit, which is
    /// why the per-call budget is set above macOS noise and not at the
    /// Linux figure.
    /// </para>
    /// </remarks>
    [Fact]
    public void RepeatedVerificationDoesNotGrowUnboundedly()
    {
        using ReceiptVerifier verifier = new(ReceiptRoots(), "com.example.app");
        byte[] receipt = Fixtures.Bytes("receipt");

        // Warm up: first-call statics, JIT and the ASN.1 reader's pools are a
        // one-off cost, not per-call retention.
        for (int i = 0; i < 50; i++)
        {
            verifier.Verify(receipt);
        }

        long smallestGrowth = long.MaxValue;
        long before = LiveSet();
        for (int round = 0; round < LiveSetRounds; round++)
        {
            for (int i = 0; i < LiveSetRoundSize; i++)
            {
                verifier.Verify(receipt);
            }

            long after = LiveSet();
            smallestGrowth = Math.Min(smallestGrowth, after - before);
            before = after;
        }

        long budget = LiveSetRoundSize * LiveSetBudgetPerVerification;
        Assert.True(
            smallestGrowth < budget,
            $"live set grew by at least {smallestGrowth} bytes in each of {LiveSetRounds} rounds "
            + $"of {LiveSetRoundSize} verifications, which is more than the {budget} bytes budgeted per round");
    }

    /// <summary>The managed live set, with everything collectable collected.</summary>
    private static long LiveSet()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        return GC.GetTotalMemory(true);
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
