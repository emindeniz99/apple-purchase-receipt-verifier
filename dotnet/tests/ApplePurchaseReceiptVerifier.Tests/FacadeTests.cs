using System;
using System.Collections.Generic;
using System.Text;
using ApplePurchaseReceiptVerifier.Internal;
using Wasmtime;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The wrapper's own duties, over a hand-assembled module that speaks the ABI
/// (<see cref="StubModule"/>): the six outcomes of ARCHITECTURE.md §4 kept
/// distinct, trap recovery, the post-return discipline, what reaches the
/// module, and what a hostile module cannot make the wrapper do. Nothing here
/// depends on which core is embedded.
/// </summary>
public class FacadeTests
{
    private static VerifierImpl Over(StubModule stub, Config? config = null) =>
        new(config ?? Config.Defaults(), new AprvRuntime(stub.ToWasm(), null));

    private static long Posts(AprvInstance instance) => (int)instance.Raw.GetFunction("posts")!.Invoke()!;

    // --- 1. verified ----------------------------------------------------------

    [Fact]
    public void AVerifiedReceiptIsThePayloadTheModuleAnswered()
    {
        ReceiptPayload expected = SyntheticAnswers.Receipt();
        VerifierImpl verifier = Over(new StubModule { ReceiptAnswer = SyntheticAnswers.Verified(expected) });

        VerificationResult<ReceiptPayload> result = verifier.VerifyReceipt("anything");

        Assert.True(result.Verified);
        Assert.Null(result.Failure);
        Assert.Equal(expected.ToJson(), result.Payload!.ToJson());
        Assert.Equal(1234567890123456789L, result.Payload.AppItemId);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, result.Payload.OpaqueValue);
        Assert.Equal(new byte[] { 4, 5 }, result.Payload.UnknownAttributes[9999][1]);
        Assert.Equal(9223372036854775807L, result.Payload.InApp[0].WebOrderLineItemId);
        Assert.True(result.Payload.InApp[0].IsTrialPeriod);
        Assert.False(result.Payload.InApp[0].IsInIntroOfferPeriod);
    }

    [Fact]
    public void AVerifiedJwsIsThePayloadStringExactlyAsTheModuleGaveIt()
    {
        string payload = " {\"b\":1,  \"a\":[true,null],\"big\":123456789012345678901234567890}";
        VerifierImpl verifier = Over(new StubModule { SignedDataAnswer = SyntheticAnswers.VerifiedJws(payload) });

        Assert.Equal(payload, verifier.VerifySignedData("x").Payload!.Json);
    }

    [Fact]
    public void TheEndpointAnswerIsTheModulesTextByteForByte()
    {
        string answer = "{\"status\":0,\"receipt\":{\"in_app\":[]},\n  \"odd\" : \"\\u00e9\"}";
        VerifierImpl verifier = Over(new StubModule { EndpointAnswer = answer });

        Assert.Equal(answer, verifier.VerifyReceiptEndpoint(AppleEnvironment.Production, "{}"));
    }

    // --- 2. verification failure ---------------------------------------------

    [Theory]
    [InlineData("MALFORMED", VerificationReason.Malformed)]
    [InlineData("TOO_LARGE", VerificationReason.TooLarge)]
    [InlineData("INVALID_SIGNATURE", VerificationReason.InvalidSignature)]
    [InlineData("UNTRUSTED_CHAIN", VerificationReason.UntrustedChain)]
    [InlineData("INVALID_CERTIFICATE", VerificationReason.InvalidCertificate)]
    [InlineData("INVALID_CERTIFICATE_PURPOSE", VerificationReason.InvalidCertificatePurpose)]
    [InlineData("UNREADABLE_PAYLOAD", VerificationReason.UnreadablePayload)]
    [InlineData("INTERNAL_ERROR", VerificationReason.InternalError)]
    public void EveryReasonTheModuleGivesIsTheVerdictAndCarriesNoCause(string token, VerificationReason reason)
    {
        VerifierImpl verifier = Over(new StubModule
        {
            ReceiptAnswer = SyntheticAnswers.Failed(token, "the module's words"),
            SignedDataAnswer = SyntheticAnswers.Failed(token, "the module's words"),
        });

        Failure receipt = verifier.VerifyReceipt("x").Failure!;
        Assert.Equal(reason, receipt.Reason);
        Assert.Equal("the module's words", receipt.Message);
        Assert.Null(receipt.Cause);
        Failure jws = verifier.VerifySignedData("x").Failure!;
        Assert.Equal(reason, jws.Reason);
        Assert.Null(jws.Cause);
    }

    // --- 3. caller misuse -----------------------------------------------------

    [Fact]
    public void CallerMisuseIsTheLanguagesProgrammerErrorAndNeverAVerdict()
    {
        Assert.Throws<ArgumentNullException>(() => Verifier.Create(null!));
        Assert.Throws<ArgumentException>(() => Config.CreateBuilder().Roots(Array.Empty<System.Security.Cryptography.X509Certificates.X509Certificate2>()).Build());
        VerifierImpl verifier = Over(new StubModule());
        Assert.Throws<ArgumentOutOfRangeException>(() => verifier.VerifyReceiptEndpoint((AppleEnvironment)2, "{}"));
        Assert.Throws<ArgumentOutOfRangeException>(() => verifier.VerifyReceiptEndpoint((AppleEnvironment)(-1), "{}"));
    }

    [Fact]
    public void ARootTheModuleRefusesFailsCreateAsAConfigurationError()
    {
        StubModule stub = new() { InitAnswer = "{\"ok\":false,\"message\":\"root 0 is not a certificate\"}" };
        ArgumentException error = Assert.Throws<ArgumentException>(() => Over(stub));
        Assert.Contains("root 0 is not a certificate", error.Message, StringComparison.Ordinal);
    }

    // --- 4. ABI mismatch ------------------------------------------------------

    [Fact]
    public void AModuleOfAnotherAbiVersionFailsCreateNamingWhatItExports()
    {
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => Over(new StubModule { Version = "2.0.0" }));
        Assert.Contains("aprv:verifier@0.1.0", error.Message, StringComparison.Ordinal);
        Assert.Contains("aprv:verifier/verify@2.0.0#init", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("aprv:verifier/verify@0.1.0#verify-signed-data")]
    [InlineData("cabi_post_aprv:verifier/verify@0.1.0#init")]
    [InlineData("cabi_realloc")]
    public void AModuleLackingAnExportFailsCreate(string missing)
    {
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => Over(new StubModule { DropExport = missing }));
        Assert.Contains(missing, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnyImportButRandomGetIsRefused()
    {
        StubModule stub = new() { ExtraImports = "(import \"wasi_snapshot_preview1\" \"fd_write\" (func (param i32 i32 i32 i32) (result i32)))" };
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => Over(stub));
        Assert.Contains("fd_write", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AModuleWithoutItsOneImportIsRefusedToo()
    {
        byte[] wasm = Module.ConvertText("(module (memory (export \"memory\") 1))");
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => new AprvRuntime(wasm, null));
        Assert.Contains("random-get", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheEmbeddedModuleIsTheOneWhoseHashIsRecorded()
    {
        byte[] wasm = AprvRuntime.LoadEmbeddedModule();
        string hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(wasm)).ToLowerInvariant();
        Assert.Same(wasm, AprvRuntime.CheckedModule(wasm, hash + "  aprv.wasm\n"));
        Assert.Same(wasm, AprvRuntime.CheckedModule(wasm, hash));
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => AprvRuntime.CheckedModule(wasm, new string('0', 64)));
        Assert.Contains("SHA-256", error.Message, StringComparison.Ordinal);
        Assert.Throws<InvalidOperationException>(() => AprvRuntime.CheckedModule(new byte[] { 0, 1, 2 }, hash));
    }

    // --- 5. trap or internal failure -----------------------------------------

    [Fact]
    public void ATrapIsAnInternalErrorNamingTheTrapAndTheInstanceIsReplaced()
    {
        VerifierImpl verifier = Over(new StubModule());

        VerificationResult<ReceiptPayload> trapped = verifier.VerifyReceipt("!");
        Failure failure = trapped.Failure!;
        Assert.Equal(VerificationReason.InternalError, failure.Reason);
        Assert.IsType<WasmtimeException>(failure.Cause, exactMatch: false);

        // The next call takes a fresh instance and answers as before.
        Assert.Equal(VerificationReason.Malformed, verifier.VerifyReceipt("x").Failure!.Reason);
        Assert.Equal("{\"status\":21009}", verifier.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, "!"));
        Assert.Equal("{\"status\":21002}", verifier.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, "x"));
        Assert.Equal(VerificationReason.InternalError, verifier.VerifySignedData("!").Failure!.Reason);
    }

    [Fact]
    public void ATrappedInstanceIsDiscardedAndNeverHandedOutAgain()
    {
        VerifierImpl verifier = Over(new StubModule());
        AprvInstance before = verifier.Pool.Rent();
        verifier.Pool.Return(before);

        verifier.VerifyReceipt("!");
        AprvInstance after = verifier.Pool.Rent();

        Assert.NotSame(before, after);
        verifier.Pool.Return(after);
    }

    [Fact]
    public void ANewInstanceIsInitialisedBeforeAnyoneUsesIt()
    {
        StubModule stub = new();
        AprvRuntime runtime = new(stub.ToWasm(), null);
        InstancePool pool = new(runtime, Encoding.UTF8.GetBytes("{}"));
        AprvInstance instance = pool.Rent();
        Assert.Equal(1, Posts(instance));
        pool.Return(instance);
    }

    /// <summary>The result string is freed exactly once per call, by the post-return, and never a second time.</summary>
    [Fact]
    public void EveryCallPostReturnsItsResultExactlyOnce()
    {
        AprvRuntime runtime = new(new StubModule().ToWasm(), null);
        AprvInstance instance = new(runtime);
        instance.Init(Encoding.UTF8.GetBytes("{}"));
        Assert.Equal(1, Posts(instance));
        for (int i = 1; i <= 5; i++)
        {
            instance.VerifyReceipt(1, Encoding.UTF8.GetBytes("x"));
            Assert.Equal(1 + i, Posts(instance));
        }

        instance.Dispose();
    }

    /// <summary>The input lands in guest memory through the guest's own allocator, once per list.</summary>
    [Fact]
    public void EachInputListIsAllocatedByTheGuest()
    {
        AprvRuntime runtime = new(new StubModule().ToWasm(), null);
        AprvInstance instance = new(runtime);
        int before = (int)instance.Raw.GetFunction("reallocs")!.Invoke()!;
        instance.Init(Encoding.UTF8.GetBytes("{}"));
        instance.VerifyReceiptEndpoint(0, 1, Encoding.UTF8.GetBytes("x"));
        Assert.Equal(before + 2, (int)instance.Raw.GetFunction("reallocs")!.Invoke()!);
        instance.Dispose();
    }

    [Fact]
    public void EnvAndNowReachTheModuleAsTheCallerGaveThem()
    {
        AprvInstance instance = new(new AprvRuntime(new StubModule().ToWasm(), null));
        instance.Init(Encoding.UTF8.GetBytes("{}"));
        instance.VerifyReceiptEndpoint(1, 123456789012345L, Encoding.UTF8.GetBytes("x"));
        Assert.Equal(1, (int)instance.Raw.GetFunction("last_env")!.Invoke()!);
        Assert.Equal(123456789012345L, (long)instance.Raw.GetFunction("last_now")!.Invoke()!);
        instance.VerifyReceiptEndpoint(0, 5L, Encoding.UTF8.GetBytes("x"));
        Assert.Equal(0, (int)instance.Raw.GetFunction("last_env")!.Invoke()!);
        instance.Dispose();
    }

    [Fact]
    public void TheEnvironmentEnumMapsToZeroAndOne()
    {
        VerifierImpl verifier = Over(new StubModule());
        verifier.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, "x");
        AprvInstance instance = verifier.Pool.Rent();
        Assert.Equal(1, (int)instance.Raw.GetFunction("last_env")!.Invoke()!);
        verifier.Pool.Return(instance);
        verifier.VerifyReceiptEndpoint(AppleEnvironment.Production, "x");
        instance = verifier.Pool.Rent();
        Assert.Equal(0, (int)instance.Raw.GetFunction("last_env")!.Invoke()!);
        verifier.Pool.Return(instance);
    }

    /// <summary>random-get from the host reaches the guest as a list of exactly the length it asked for, in guest memory.</summary>
    [Fact]
    public void RandomGetAnswersTheLengthAskedFor()
    {
        VerifierImpl verifier = Over(new StubModule());
        Assert.Equal(VerificationReason.Malformed, verifier.VerifyReceipt("G").Failure!.Reason);
    }

    [Fact]
    public void RandomGetAnsweringTheWrongLengthIsATrapThatBecomesAnInternalError()
    {
        AprvRuntime runtime = new(new StubModule().ToWasm(), length => new byte[length + 1]);
        VerifierImpl verifier = new(Config.Defaults(), runtime);
        Failure failure = verifier.VerifyReceipt("G").Failure!;
        Assert.Equal(VerificationReason.InternalError, failure.Reason);
        Assert.NotNull(failure.Cause);
    }

    // --- a module that misbehaves: answers the wrapper refuses to believe -----

    [Theory]
    [InlineData("P")]
    [InlineData("B")]
    [InlineData("L")]
    [InlineData("N")]
    [InlineData("U")]
    public void AnAnswerOutsideTheMemoryOrNotUtf8IsAnInternalErrorNotAReadOutOfBounds(string input)
    {
        VerifierImpl verifier = Over(new StubModule());
        Failure failure = verifier.VerifyReceipt(input).Failure!;
        Assert.Equal(VerificationReason.InternalError, failure.Reason);
        Assert.NotNull(failure.Cause);
        Assert.Equal("{\"status\":21009}", verifier.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, input));
        Assert.Equal(VerificationReason.Malformed, verifier.VerifyReceipt("x").Failure!.Reason);
    }

    public static IEnumerable<object[]> UnreadableAnswers => new[]
    {
        new object[] { "not json" },
        new object[] { "[]" },
        new object[] { "{}" },
        new object[] { "{\"verified\":1}" },
        new object[] { "{\"verified\":true}" },
        new object[] { "{\"verified\":true,\"payload\":{}}" },
        new object[] { "{\"verified\":false,\"reason\":\"WRONG_BUNDLE_ID\",\"message\":\"x\"}" },
        new object[] { "{\"verified\":false,\"reason\":\"MALFORMED\"}" },
        new object[] { "{\"verified\":false,\"reason\":\"MALFORMED\",\"message\":\"x\",\"extra\":1}" },
        new object[] { "{\"verified\":true,\"payload\":{},\"extra\":1}" },
        new object[] { "{\"verified\":false,\"reason\":7,\"message\":\"x\"}" },
    };

    /// <summary>An answer that is not the wire's shape is never guessed at: INTERNAL_ERROR, the exception as the cause, the instance discarded.</summary>
    [Theory]
    [MemberData(nameof(UnreadableAnswers))]
    public void AnUnreadableAnswerIsAnInternalErrorWithACause(string answer)
    {
        VerifierImpl verifier = Over(new StubModule { ReceiptAnswer = answer, SignedDataAnswer = answer });
        AprvInstance before = verifier.Pool.Rent();
        verifier.Pool.Return(before);

        Failure receipt = verifier.VerifyReceipt("x").Failure!;
        Assert.Equal(VerificationReason.InternalError, receipt.Reason);
        Assert.IsType<ModuleAnswers.AnswerException>(receipt.Cause);
        Assert.Equal(VerificationReason.InternalError, verifier.VerifySignedData("x").Failure!.Reason);
        Assert.NotSame(before, verifier.Pool.Rent());
    }

    [Theory]
    [InlineData("{\"verified\":true,\"payload\":{\"receipt_type\":1}}")]
    public void AReceiptPayloadWithoutTheWiresMembersIsUnreadable(string answer)
    {
        VerifierImpl verifier = Over(new StubModule { ReceiptAnswer = answer });
        Assert.Equal(VerificationReason.InternalError, verifier.VerifyReceipt("x").Failure!.Reason);
    }

    // --- one call at a time per instance, discard on failure ------------------

    [Fact]
    public void AnInstanceThatGrewPastTheRetentionLimitIsNotKept()
    {
        AprvRuntime runtime = new(new StubModule().ToWasm(), null);
        InstancePool pool = new(runtime, Encoding.UTF8.GetBytes("{}"));
        AprvInstance kept = pool.Rent();
        Assert.NotEqual(-1, (int)kept.Raw.GetFunction("grow")!.Invoke(1200)!);
        Assert.True(kept.MemoryBytes > InstancePool.RetainMemoryBytes);
        pool.Return(kept);
        Assert.NotSame(kept, pool.Rent());
    }

    [Fact]
    public void TheStoreRefusesToGrowPastItsMemoryLimit()
    {
        AprvInstance instance = new(new AprvRuntime(new StubModule().ToWasm(), null));
        Assert.NotEqual(-1, (int)instance.Raw.GetFunction("grow")!.Invoke(2048)!);
        Assert.Equal(-1, (int)instance.Raw.GetFunction("grow")!.Invoke(4096)!);
        Assert.True(instance.MemoryBytes <= AprvInstance.MemoryLimitBytes);
        instance.Dispose();
    }
}
