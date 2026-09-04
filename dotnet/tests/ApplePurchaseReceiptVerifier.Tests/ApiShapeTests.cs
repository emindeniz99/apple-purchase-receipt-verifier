using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Internal;
using ApplePurchaseReceiptVerifier.Jws;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The published surface: the reason vocabulary, what a misconfiguration
/// raises, and what types leak into the API.
/// </summary>
public class ApiShapeTests
{
    /// <summary>
    /// The eleven canonical tokens, read out of
    /// <c>fixtures/cases.schema.json</c> rather than retyped — so a drifted
    /// spelling fails here instead of in another port's CI.
    /// </summary>
    public static TheoryData<string> SchemaReasonCodes
    {
        get
        {
            TheoryData<string> codes = new();
            foreach (string code in ReasonCodesFromSchema())
            {
                codes.Add(code);
            }

            return codes;
        }
    }

    [Fact]
    public void ReasonHasExactlyElevenMembers()
    {
        Assert.Equal(11, Enum.GetValues<VerificationReason>().Length);
    }

    [Fact]
    public void EveryReasonHasACodeAndRoundTrips()
    {
        foreach (VerificationReason reason in Enum.GetValues<VerificationReason>())
        {
            string code = VerificationReasonCodes.ToCode(reason);
            Assert.Matches("^[A-Z][A-Z_]*[A-Z]$", code);
            Assert.True(VerificationReasonCodes.TryParse(code, out VerificationReason parsed));
            Assert.Equal(reason, parsed);
        }
    }

    [Theory]
    [MemberData(nameof(SchemaReasonCodes))]
    public void SchemaCodeIsProducedByThisPort(string code)
    {
        Assert.True(VerificationReasonCodes.TryParse(code, out VerificationReason reason));
        Assert.Equal(code, VerificationReasonCodes.ToCode(reason));
    }

    [Fact]
    public void TheVocabularyIsExactlyTheSchemaVocabulary()
    {
        HashSet<string> schema = new(ReasonCodesFromSchema(), StringComparer.Ordinal);
        HashSet<string> ours = new(
            Enum.GetValues<VerificationReason>().Select(VerificationReasonCodes.ToCode),
            StringComparer.Ordinal);
        Assert.Equal(schema, ours);
    }

    [Theory]
    [InlineData("")]
    [InlineData("invalid_chain")]
    [InlineData("SOMETHING_ELSE")]
    [InlineData(null)]
    public void UnknownCodesDoNotParse(string? code)
    {
        Assert.False(VerificationReasonCodes.TryParse(code, out _));
    }

    [Fact]
    public void ExceptionMessageLeadsWithTheCanonicalCode()
    {
        VerificationException error = new(VerificationReason.WrongBundleId, "detail");
        Assert.StartsWith("WRONG_BUNDLE_ID: ", error.Message, StringComparison.Ordinal);
        Assert.Equal("WRONG_BUNDLE_ID", error.ReasonCode);
        Assert.Equal(VerificationReason.WrongBundleId, error.Reason);
    }

    [Fact]
    public void EveryEnvironmentClaimValueRoundTrips()
    {
        foreach (AppleEnvironment environment in Enum.GetValues<AppleEnvironment>())
        {
            string value = AppleEnvironments.ToValue(environment);
            Assert.True(AppleEnvironments.TryParse(value, out AppleEnvironment parsed));
            Assert.Equal(environment, parsed);
        }

        Assert.False(AppleEnvironments.TryParse("production", out _));
        Assert.False(AppleEnvironments.TryParse(null, out _));
    }

    // --- misconfiguration is an argument error, never a verdict --------------

    [Fact]
    public void JwsVerifierRejectsEmptyRoots()
    {
        Assert.Throws<ArgumentException>(
            () => new JwsVerifier(Array.Empty<X509Certificate2>(), "id", new[] { AppleEnvironment.Sandbox }));
    }

    [Fact]
    public void JwsVerifierRejectsAnEmptyBundleId()
    {
        Assert.Throws<ArgumentException>(
            () => new JwsVerifier(Roots(), string.Empty, new[] { AppleEnvironment.Sandbox }));
        Assert.Throws<ArgumentException>(
            () => new JwsVerifier(Roots(), null!, new[] { AppleEnvironment.Sandbox }));
    }

    [Fact]
    public void JwsVerifierRejectsAnEmptyAcceptSet()
    {
        Assert.Throws<ArgumentException>(
            () => new JwsVerifier(Roots(), "id", Array.Empty<AppleEnvironment>()));
        Assert.Throws<ArgumentException>(() => new JwsVerifier(Roots(), "id", null!));
    }

    [Fact]
    public void ReceiptVerifierRejectsMisconfiguration()
    {
        Assert.Throws<ArgumentException>(() => new ReceiptVerifier(Array.Empty<X509Certificate2>(), "id"));
        Assert.Throws<ArgumentException>(() => new ReceiptVerifier(Roots(), string.Empty));
        Assert.Throws<ArgumentException>(() => new ReceiptVerifier(Roots(), null!));
    }

    [Fact]
    public void EndpointRejectsAnEnvironmentApplesEndpointDoesNotHave()
    {
        Assert.Throws<ArgumentException>(
            () => new VerifyReceiptEndpoint(Roots(), AppleEnvironment.Xcode));
        Assert.Throws<ArgumentException>(
            () => new VerifyReceiptEndpoint(Roots(), AppleEnvironment.LocalTesting));
        Assert.Throws<ArgumentException>(
            () => new VerifyReceiptEndpoint(Array.Empty<X509Certificate2>(), AppleEnvironment.Sandbox));
    }

    /// <summary>
    /// <c>ReceiptVerifier</c> must have no clock parameter on any constructor.
    /// Its only "now" is a certificate-validity instant, and an injected clock
    /// must never be able to move one — an option with no legitimate consumer
    /// is an invitation to wire it into the one place it must not reach.
    /// </summary>
    [Fact]
    public void ReceiptVerifierHasNoClockSeam()
    {
        foreach (ConstructorInfo constructor in typeof(ReceiptVerifier).GetConstructors())
        {
            Assert.DoesNotContain(constructor.GetParameters(), p => p.ParameterType == typeof(IClock));
        }

        foreach (MethodInfo method in typeof(ReceiptVerifier).GetMethods(BindingFlags.Public | BindingFlags.Static))
        {
            Assert.DoesNotContain(method.GetParameters(), p => p.ParameterType == typeof(IClock));
        }
    }

    /// <summary>
    /// <c>VerifyReceiptCore</c> is public, so an endpoint never has to build a
    /// verifier around a magic bundle id just to reach the primitive.
    /// </summary>
    [Fact]
    public void VerifyReceiptCoreIsPublic()
    {
        MethodInfo? method = typeof(ReceiptVerifier).GetMethod(
            "VerifyReceiptCore", BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(method);
        Assert.Equal(typeof(AppReceipt), method!.ReturnType);
    }

    /// <summary>
    /// No implementation type reaches the public surface: no
    /// <c>System.Text.Json</c>, no <c>System.Formats.Asn1</c>, no
    /// <c>System.Security.Cryptography.Pkcs</c>. Changing any of them must not
    /// be a breaking change.
    /// </summary>
    [Fact]
    public void NoImplementationTypeEscapesIntoThePublicSurface()
    {
        string[] banned =
        {
            "System.Text.Json", "System.Formats.Asn1", "System.Security.Cryptography.Pkcs",
        };

        foreach (Type type in typeof(JwsVerifier).Assembly.GetExportedTypes())
        {
            foreach (Type used in SurfaceTypes(type))
            {
                foreach (string prefix in banned)
                {
                    Assert.False(
                        used.FullName?.StartsWith(prefix, StringComparison.Ordinal) == true,
                        $"{type.FullName} exposes {used.FullName}");
                }
            }
        }
    }

    /// <summary>
    /// JWS date claims stay epoch-millisecond integers, exactly as Apple ships
    /// them. Converting one to a date type loses the raw claim and is a
    /// cross-port divergence, so the types are asserted rather than assumed.
    /// </summary>
    [Theory]
    [InlineData(typeof(TransactionPayload), "SignedDate")]
    [InlineData(typeof(TransactionPayload), "PurchaseDate")]
    [InlineData(typeof(TransactionPayload), "ExpiresDate")]
    [InlineData(typeof(TransactionPayload), "RevocationDate")]
    [InlineData(typeof(TransactionPayload), "OriginalPurchaseDate")]
    [InlineData(typeof(AppTransactionPayload), "ReceiptCreationDate")]
    [InlineData(typeof(AppTransactionPayload), "PreorderDate")]
    [InlineData(typeof(AppTransactionPayload), "OriginalPurchaseDate")]
    public void JwsDateClaimsAreEpochMillisecondIntegers(Type payload, string property)
    {
        Assert.Equal(typeof(long?), payload.GetProperty(property)!.PropertyType);
    }

    /// <summary>Receipt attribute dates, in contrast, are the platform's date type.</summary>
    [Theory]
    [InlineData(typeof(AppReceipt), "CreationDate")]
    [InlineData(typeof(AppReceipt), "ExpirationDate")]
    [InlineData(typeof(InAppPurchase), "PurchaseDate")]
    [InlineData(typeof(InAppPurchase), "ExpiresDate")]
    public void ReceiptAttributeDatesAreDateTimeOffsets(Type type, string property)
    {
        Assert.Equal(typeof(DateTimeOffset?), type.GetProperty(property)!.PropertyType);
    }

    [Fact]
    public void EntitlementHelperLivesOnThePayload()
    {
        MethodInfo? method = typeof(TransactionPayload).GetMethod(
            "IsActiveAt", new[] { typeof(DateTimeOffset) });
        Assert.NotNull(method);
        Assert.Equal(typeof(bool), method!.ReturnType);
    }

    private static IEnumerable<Type> SurfaceTypes(Type type)
    {
        foreach (PropertyInfo property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
        {
            yield return property.PropertyType;
        }

        foreach (MethodInfo method in type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
        {
            yield return method.ReturnType;
            foreach (ParameterInfo parameter in method.GetParameters())
            {
                yield return parameter.ParameterType;
            }
        }

        foreach (ConstructorInfo constructor in type.GetConstructors())
        {
            foreach (ParameterInfo parameter in constructor.GetParameters())
            {
                yield return parameter.ParameterType;
            }
        }
    }

    private static IEnumerable<string> ReasonCodesFromSchema()
    {
        OrderedMap schema = Json.ParseObject(
            System.IO.File.ReadAllText(System.IO.Path.Combine(Fixtures.Root, "cases.schema.json")));
        OrderedMap defs = (OrderedMap)schema["$defs"]!;
        OrderedMap reason = (OrderedMap)defs["reason"]!;
        foreach (object? code in (List<object?>)reason["enum"]!)
        {
            yield return (string)code!;
        }
    }

    private static IReadOnlyList<X509Certificate2> Roots() => AppleRootCertificates.JwsRoots();
}
