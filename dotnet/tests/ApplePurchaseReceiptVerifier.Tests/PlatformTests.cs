using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// Groups the tests that read or write process-wide state — the managed live
/// set, the default thread culture — so they do not run beside another
/// collection. xunit's default is one collection per class, all of them in
/// parallel, and <see cref="PlatformTests.RepeatedVerificationDoesNotGrowUnboundedly"/>
/// measures the whole heap, not just its own objects.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ProcessWideCollection
{
    internal const string Name = "process-wide";
}

/// <summary>
/// The parts of this port that no cross-language vector can reach: the ECDSA
/// encoding conversion, thread safety, retention, and the conformance
/// harness's own resolver.
/// </summary>
[Collection(ProcessWideCollection.Name)]
public class PlatformTests
{
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
        byte[]? p1363 = EcdsaSignatureFormat.DerToP1363(der, 32);

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
        Assert.Null(EcdsaSignatureFormat.DerToP1363(der, 16));
    }

    [Theory]
    [InlineData("")]
    [InlineData("00")]
    [InlineData("3000")]
    [InlineData("300602010102010101")]
    public void MalformedDerSignaturesConvertToNull(string hex)
    {
        Assert.Null(EcdsaSignatureFormat.DerToP1363(Convert.FromHexString(hex), 32));
    }

    [Fact]
    public void ANonPositiveComponentIsRejected()
    {
        Assert.Null(EcdsaSignatureFormat.DerToP1363(Der(BigInteger.Zero, BigInteger.One), 32));
        Assert.Null(EcdsaSignatureFormat.DerToP1363(Der(BigInteger.MinusOne, BigInteger.One), 32));
    }

    [Fact]
    public void TrailingDataAfterTheSequenceIsRejected()
    {
        byte[] der = Der(BigInteger.One, BigInteger.One);
        byte[] padded = der.Concat(new byte[] { 0x05, 0x00 }).ToArray();
        Assert.Null(EcdsaSignatureFormat.DerToP1363(padded, 32));
    }

    // --- thread safety and retention -----------------------------------------

    /// <summary>The design's promise: one verifier is immutable and thread-safe.</summary>
    [Fact]
    public void OneVerifierServesManyThreads()
    {
        IVerifier receipts = TestPki.FixtureVerifier("receipt-root");
        IVerifier jws = TestPki.FixtureVerifier("jws-root");
        string receipt = Fixtures070.ForReceipt("receipt");
        string transaction = Fixtures070.ForSignedData("transaction");
        string expected = receipts.VerifyReceipt(receipt).Payload!.ToJson();
        string expectedJws = jws.VerifySignedData(transaction).Payload!.Json;

        ConcurrentBag<string> failures = new();
        Parallel.For(0, 512, _ =>
        {
            try
            {
                Assert.Equal(expected, receipts.VerifyReceipt(receipt).Payload?.ToJson());
                Assert.Equal(expectedJws, jws.VerifySignedData(transaction).Payload?.Json);
            }
            catch (Exception e)
            {
                failures.Add(e.ToString());
            }
        });

        Assert.Empty(failures);
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
    /// own (<see cref="ProcessWideCollection"/>): <see cref="GC.GetTotalMemory"/>
    /// reports the whole process's live set, so a sibling collection allocating
    /// on another thread lands in the delta. A quiet process is still not a
    /// silent one, so the round is measured <see cref="LiveSetRounds"/> times
    /// and the smallest growth is judged; retention of one object per call,
    /// the failure this test exists for, exceeds the budget in every round.
    /// </remarks>
    [Fact]
    public void RepeatedVerificationDoesNotGrowUnboundedly()
    {
        IVerifier verifier = TestPki.FixtureVerifier("receipt-root");
        string receipt = Fixtures070.ForReceipt("receipt");

        // Warm up: first-call statics, JIT and the ASN.1 reader's pools are a
        // one-off cost, not per-call retention.
        for (int i = 0; i < 50; i++)
        {
            Assert.True(verifier.VerifyReceipt(receipt).Verified);
        }

        long smallestGrowth = long.MaxValue;
        long before = LiveSet();
        for (int round = 0; round < LiveSetRounds; round++)
        {
            for (int i = 0; i < LiveSetRoundSize; i++)
            {
                verifier.VerifyReceipt(receipt);
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
        object? model = Json.Parse(
            "{\"receipt\":{\"in_app\":[{\"product_id\":\"com.example.app.vip\",\"quantity\":\"1\"},"
            + "{\"product_id\":\"com.example.app.coins100\",\"quantity\":\"2\"}]},"
            + "\"unknown_attributes\":{\"9999\":[\"AQID\"]},\"a/b\":{\"c~d\":7}}");

        Assert.Equal(2L, JsonPointer070.Length(model, "/receipt/in_app"));
        Assert.Equal("1", JsonPointer070.Resolve(model, "/receipt/in_app/[product_id=com.example.app.vip]/quantity"));
        Assert.Equal("2", JsonPointer070.Resolve(model, "/receipt/in_app/1/quantity"));
        Assert.Equal("AQID", JsonPointer070.Resolve(model, "/unknown_attributes/9999/0"));
        Assert.Equal(1L, JsonPointer070.Length(model, "/unknown_attributes/9999"));
        Assert.Equal(7L, JsonPointer070.Resolve(model, "/a~1b/c~0d"));
        Assert.Null(JsonPointer070.Resolve(model, "/receipt/absent"));
        Assert.Null(JsonPointer070.Resolve(model, "/receipt/absent/deeper"));
        Assert.Null(JsonPointer070.Resolve(model, "/receipt/in_app/5"));
    }

    [Fact]
    public void TheFieldPathResolverFailsWhenASelectorIsNotUnique()
    {
        object? model = Json.Parse("{\"list\":[{\"id\":\"a\"},{\"id\":\"a\"}]}");

        Assert.ThrowsAny<Exception>(() => JsonPointer070.Resolve(model, "/list/[id=a]"));
        Assert.ThrowsAny<Exception>(() => JsonPointer070.Resolve(model, "/list/[id=missing]"));
        Assert.ThrowsAny<Exception>(() => JsonPointer070.Resolve(model, "list"));
        Assert.ThrowsAny<Exception>(() => JsonPointer070.Length(model, "/list/0"));
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
