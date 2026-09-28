using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The published surface: the reason vocabulary, what a misconfiguration
/// raises, and what types leak into the API.
/// </summary>
public class ApiShapeTests
{
    /// <summary>
    /// The eight canonical tokens, read out of
    /// <c>fixtures/cases.schema.json</c> rather than retyped — so a
    /// drifted spelling fails here instead of in another port's CI.
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
    public void ReasonHasExactlyTheEightMembersOf07()
    {
        Assert.Equal(8, Enum.GetValues<VerificationReason>().Length);
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
    [InlineData("untrusted_chain")]
    [InlineData("INVALID_CHAIN")]
    [InlineData("WRONG_BUNDLE_ID")]
    [InlineData("SOMETHING_ELSE")]
    [InlineData(null)]
    public void UnknownCodesDoNotParse(string? code)
    {
        Assert.False(VerificationReasonCodes.TryParse(code, out _));
    }

    [Fact]
    public void AReasonOutsideTheEnumHasNoCode()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => VerificationReasonCodes.ToCode((VerificationReason)99));
    }

    [Fact]
    public void MessagesLeadWithTheCanonicalCode()
    {
        VerificationException error = new(VerificationReason.UntrustedChain, "detail");
        Assert.Equal("UNTRUSTED_CHAIN: detail", error.Message);
        Assert.Equal("UNTRUSTED_CHAIN", error.ReasonCode);
        Assert.Equal("detail", error.Detail);

        Failure failure = TestPki.Verifier(TestPki.SharedJws.Value.Root).VerifySignedData("a.b").Failure!;
        Assert.StartsWith("MALFORMED: ", failure.ToString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// <c>fromReceiptType</c> states what Apple's value means and decides
    /// nothing: the four documented spellings, exactly, and nothing else.
    /// </summary>
    [Theory]
    [InlineData("Production", AppleEnvironment.Production)]
    [InlineData("ProductionVPP", AppleEnvironment.Production)]
    [InlineData("ProductionSandbox", AppleEnvironment.Sandbox)]
    [InlineData("ProductionVPPSandbox", AppleEnvironment.Sandbox)]
    [InlineData("production", null)]
    [InlineData("Sandbox", null)]
    [InlineData("Xcode", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void FromReceiptTypeMapsOnlyApplesSpellings(string? receiptType, AppleEnvironment? expected)
    {
        Assert.Equal(expected, AppleEnvironments.FromReceiptType(receiptType));
    }

    [Theory]
    [InlineData("Production", AppleEnvironment.Production)]
    [InlineData("Sandbox", AppleEnvironment.Sandbox)]
    [InlineData("Xcode", null)]
    [InlineData("LocalTesting", null)]
    [InlineData("sandbox", null)]
    [InlineData("ProductionSandbox", null)]
    [InlineData(null, null)]
    public void FromJwsEnvironmentMapsOnlyApplesSpellings(string? claim, AppleEnvironment? expected)
    {
        Assert.Equal(expected, AppleEnvironments.FromJwsEnvironment(claim));
    }

    [Fact]
    public void EveryEnvironmentsWireSpellingRoundTrips()
    {
        Assert.Equal(2, Enum.GetValues<AppleEnvironment>().Length);
        foreach (AppleEnvironment environment in Enum.GetValues<AppleEnvironment>())
        {
            Assert.Equal(environment, AppleEnvironments.FromJwsEnvironment(AppleEnvironments.ToValue(environment)));
        }
    }

    // --- misconfiguration is an argument error, never a verdict --------------

    /// <summary>
    /// A verifier with no roots would answer UNTRUSTED_CHAIN to everything and
    /// nobody would notice until production, so an empty root set fails at
    /// startup, once.
    /// </summary>
    [Fact]
    public void AnEmptyRootSetIsRefusedAtBuildTime()
    {
        Assert.Throws<ArgumentException>(
            () => Config.CreateBuilder().Roots(Array.Empty<X509Certificate2>()).Build());
    }

    [Fact]
    public void NullConfigurationIsAProgrammingError()
    {
        Assert.Throws<ArgumentNullException>(() => Config.CreateBuilder().Roots(null!));
        Assert.Throws<ArgumentNullException>(() => Config.CreateBuilder().Clock(null!));
        Assert.Throws<ArgumentNullException>(() => Verifier.Create(null!));
        Assert.Throws<ArgumentException>(
            () => Config.CreateBuilder().Roots(new X509Certificate2[] { null! }).Build());
    }

    /// <summary>
    /// The .NET spelling of "a null Environment is a programming error": an
    /// enum value that is neither of Apple's two URLs throws, and never turns
    /// into a status a receipt could have caused.
    /// </summary>
    [Fact]
    public void AnEnvironmentApplesEndpointDoesNotHaveIsAProgrammingError()
    {
        IVerifier verifier = TestPki.FixtureVerifier("receipt-root");
        Assert.Throws<ArgumentOutOfRangeException>(
            () => verifier.VerifyReceiptEndpoint((AppleEnvironment)2, "{\"receipt-data\":\"AAAA\"}"));
    }

    [Fact]
    public void TheDefaultsPinTheBundledAppleRootsAndTheSystemClock()
    {
        Config defaults = Config.Defaults();
        Assert.Equal(3, defaults.Roots.Count);
        Assert.True(Math.Abs(defaults.Clock() - DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()) < 60_000);
    }

    /// <summary>
    /// Callers mock <see cref="IVerifier"/> and build payloads by hand in their
    /// own tests, so those are public; the implementation is not.
    /// </summary>
    [Fact]
    public void TheImplementationIsNotPublic()
    {
        Assert.True(typeof(IVerifier).IsInterface);
        Assert.False(typeof(VerifierImpl).IsPublic);
        foreach (Type type in typeof(IVerifier).Assembly.GetExportedTypes())
        {
            Assert.Equal("ApplePurchaseReceiptVerifier", type.Namespace);
        }

        Assert.NotNull(typeof(JsonPayload).GetMethod("Create", BindingFlags.Public | BindingFlags.Static));
        Assert.Single(typeof(ReceiptPayload).GetConstructors());
        Assert.Single(typeof(InAppPurchase).GetConstructors());
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
            "ApplePurchaseReceiptVerifier.Internal",
        };

        foreach (Type type in typeof(IVerifier).Assembly.GetExportedTypes())
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
    /// Receipt dates are epoch milliseconds, UTC, with an <c>Ms</c> suffix
    /// (design, decode rules), not the platform's date type: a date type
    /// carries an offset and a range the wire format does not.
    /// </summary>
    [Theory]
    [InlineData(typeof(ReceiptPayload), "ReceiptCreationDateMs")]
    [InlineData(typeof(ReceiptPayload), "OriginalPurchaseDateMs")]
    [InlineData(typeof(ReceiptPayload), "ExpirationDateMs")]
    [InlineData(typeof(InAppPurchase), "PurchaseDateMs")]
    [InlineData(typeof(InAppPurchase), "OriginalPurchaseDateMs")]
    [InlineData(typeof(InAppPurchase), "ExpiresDateMs")]
    [InlineData(typeof(InAppPurchase), "CancellationDateMs")]
    public void ReceiptDatesAreEpochMillisecondLongs(Type type, string property)
    {
        Assert.Equal(typeof(long?), type.GetProperty(property)!.PropertyType);
    }

    [Fact]
    public void NoPublicPropertyIsADateType()
    {
        foreach (Type type in typeof(IVerifier).Assembly.GetExportedTypes())
        {
            foreach (PropertyInfo property in type.GetProperties())
            {
                Assert.NotEqual(typeof(DateTimeOffset?), property.PropertyType);
                Assert.NotEqual(typeof(DateTimeOffset), property.PropertyType);
                Assert.NotEqual(typeof(DateTime?), property.PropertyType);
                Assert.NotEqual(typeof(DateTime), property.PropertyType);
            }
        }
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
            System.IO.File.ReadAllText(System.IO.Path.Combine(Fixtures070.Root, "cases.schema.json")));
        OrderedMap defs = (OrderedMap)schema["$defs"]!;
        OrderedMap reason = (OrderedMap)defs["reason"]!;
        foreach (object? code in (List<object?>)reason["enum"]!)
        {
            yield return (string)code!;
        }
    }
}
