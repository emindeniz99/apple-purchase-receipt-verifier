using System;
using System.Text;
using ApplePurchaseReceiptVerifier.Internal;
using Wasmtime;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The canonical ABI, called by hand over the real module's core exports: the
/// contract of the interface, the misuse it traps on, and the hand-rolled
/// host's own discipline (the tests of round 13 that apply to a host with the
/// call in this library). The answers checked are the module's, read as
/// text, so they hold for any module of this ABI version.
/// </summary>
public class AbiTests
{
    private static readonly byte[] None = Array.Empty<byte>();

    private static byte[] G5 => Encoding.UTF8.GetBytes(Fixtures070.ForReceipt("public-receipt-sandbox-g5"));

    private static byte[] Jws => Fixtures070.Bytes("transaction");

    private static byte[] JwsConfig =>
        Encoding.UTF8.GetBytes("{\"roots\":[\"" + Convert.ToBase64String(Fixtures070.Bytes("jws-root")) + "\"]}");

    private static long Now => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    private static AprvInstance Fresh(byte[] config)
    {
        AprvInstance instance = new(AprvRuntime.Shared);
        string answer = instance.Init(config);
        Assert.Equal("{\"ok\":true}", answer);
        return instance;
    }

    private static bool Traps(Func<string> call)
    {
        try
        {
            call();
            return false;
        }
        catch (WasmtimeException)
        {
            return true;
        }
    }

    [Fact]
    public void InitWithNoRootsAndWithAnEmptyObjectAnswersOk()
    {
        using AprvInstance empty = new(AprvRuntime.Shared);
        Assert.Equal("{\"ok\":true}", empty.Init(None));
        using AprvInstance braces = new(AprvRuntime.Shared);
        Assert.Equal("{\"ok\":true}", braces.Init(Encoding.UTF8.GetBytes("{}")));
    }

    [Fact]
    public void AVerifyBeforeInitTraps()
    {
        using AprvInstance instance = new(AprvRuntime.Shared);
        Assert.True(Traps(() => instance.VerifyReceipt(Now, G5)));
    }

    [Fact]
    public void ASecondInitTraps()
    {
        using AprvInstance instance = Fresh(None);
        Assert.True(Traps(() => instance.Init(None)));
    }

    [Fact]
    public void AConfigThatIsNotJsonIsRefusedAndInitCanBeRetried()
    {
        using AprvInstance instance = new(AprvRuntime.Shared);
        string refused = instance.Init(Encoding.UTF8.GetBytes("{not json"));
        Assert.Contains("\"ok\":false", refused, StringComparison.Ordinal);
        Assert.Equal("{\"ok\":true}", instance.Init(None));
    }

    [Fact]
    public void AGenuineReceiptIsAVerdictOfTheModule()
    {
        using AprvInstance instance = Fresh(None);
        string answer = instance.VerifyReceipt(Now, G5);
        Assert.Contains("\"verified\"", answer, StringComparison.Ordinal);
    }

    [Fact]
    public void ASignedDataAnswerIsAVerdictUnderTheConfiguredRoots()
    {
        using AprvInstance instance = Fresh(JwsConfig);
        string answer = instance.VerifySignedData(Now, Jws);
        Assert.Contains("\"verified\"", answer, StringComparison.Ordinal);
    }

    [Fact]
    public void TheEndpointAnswersForBothEnvironments()
    {
        using AprvInstance instance = Fresh(None);
        byte[] request = Encoding.UTF8.GetBytes("{\"receipt-data\":\"" + Encoding.UTF8.GetString(G5) + "\"}");
        Assert.Contains("\"status\":", instance.VerifyReceiptEndpoint(1, Now, request), StringComparison.Ordinal);
        Assert.Contains("\"status\":", instance.VerifyReceiptEndpoint(0, Now, request), StringComparison.Ordinal);
    }

    /// <summary>A JWS that is not UTF-8 reaches the module and is a value, not a host error.</summary>
    [Fact]
    public void AJwsThatIsNotUtf8IsAValue()
    {
        using AprvInstance instance = Fresh(None);
        string answer = instance.VerifySignedData(Now, new byte[] { (byte)'e', (byte)'y', 0xff, 0xfe, (byte)'.', (byte)'x' });
        Assert.Contains("\"verified\":false", answer, StringComparison.Ordinal);
    }

    [Fact]
    public void TheLoweringRefusesTheWrongTypeAndTheWrongCountBeforeAnyCall()
    {
        using AprvInstance instance = Fresh(None);
        Assert.Contains("WIT type is d", Assert.Throws<ArgumentException>(() => instance.Call("verify-receipt", 5u, G5)).Message, StringComparison.Ordinal);
        Assert.Contains("WIT type is w", Assert.Throws<ArgumentException>(() => instance.Call("verify-receipt-endpoint", 1L, Now, G5)).Message, StringComparison.Ordinal);
        Assert.Contains("WIT type is b", Assert.Throws<ArgumentException>(() => instance.Call("verify-receipt", Now, 3.5)).Message, StringComparison.Ordinal);
        Assert.Contains("WIT type is b", Assert.Throws<ArgumentException>(() => instance.Call("verify-receipt", Now, "text")).Message, StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() => instance.Call("verify-receipt", Now));
        Assert.Throws<ArgumentException>(() => instance.Call("no-such-export", Now, G5));
        Assert.NotNull(instance.VerifyReceipt(Now, G5));
    }

    /// <summary>Only 0 and 1 are environments: 2, 255 and 2^32-1 trap in the module, which the generated bindings of other hosts would not catch.</summary>
    [Theory]
    [InlineData(2)]
    [InlineData(255)]
    [InlineData(-1)]
    public void AnEnvironmentOtherThanZeroOrOneTraps(int env)
    {
        using AprvInstance instance = Fresh(None);
        Assert.True(Traps(() => instance.VerifyReceiptEndpoint(env, Now, Encoding.UTF8.GetBytes("{}"))));
    }

    /// <summary>The module asks the host for random bytes to verify an ECDSA signature; a host that answers the wrong length makes it trap.</summary>
    [Fact]
    public void RandomGetAnsweringTheWrongLengthTraps()
    {
        AprvRuntime shortRuntime = new(AprvRuntime.LoadEmbeddedModule(), length => new byte[Math.Max(0, length - 1)]);
        AprvInstance instance = new(shortRuntime);
        try
        {
            Assert.Equal("{\"ok\":true}", instance.Init(JwsConfig));
            Assert.True(Traps(() => instance.VerifySignedData(Now, Jws)));
        }
        finally
        {
            instance.Dispose();
        }
    }

    /// <summary>A trap in one instance leaves another verifying: nothing is shared between two stores.</summary>
    [Fact]
    public void ATrapInOneInstanceLeavesAnotherVerifying()
    {
        using AprvInstance a = Fresh(None);
        using AprvInstance b = Fresh(None);
        string before = b.VerifyReceipt(Now, G5);
        Assert.True(Traps(() => a.VerifyReceiptEndpoint(2, Now, Encoding.UTF8.GetBytes("{}"))));
        Assert.Equal(before, b.VerifyReceipt(Now, G5));
        Assert.Equal(before, b.VerifyReceipt(Now, G5));
    }

    /// <summary>2,000 calls leave the module's memory the size it had after the first: the post-return frees each result.</summary>
    [Fact]
    public void TwoThousandCallsLeaveLinearMemoryTheSameSize()
    {
        using AprvInstance instance = Fresh(None);
        byte[] request = Encoding.UTF8.GetBytes("{\"receipt-data\":\"" + Encoding.UTF8.GetString(G5) + "\"}");
        for (int i = 0; i < 20; i++)
        {
            instance.VerifyReceiptEndpoint(1, Now, request);
        }

        long warm = instance.MemoryBytes;
        for (int i = 0; i < 2000; i++)
        {
            instance.VerifyReceiptEndpoint(1, Now, request);
        }

        Assert.Equal(warm, instance.MemoryBytes);
    }

    /// <summary>The instance's store carries the limits: one instance, and 256 MiB of memory.</summary>
    [Fact]
    public void AnInstanceHoldsAtMostTheMemoryLimit()
    {
        using AprvInstance instance = Fresh(None);
        Assert.True(instance.MemoryBytes < AprvInstance.MemoryLimitBytes);
        Assert.Equal(256L * 1024 * 1024, AprvInstance.MemoryLimitBytes);
    }
}
