using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier.Internal;
using ApplePurchaseReceiptVerifier.Jws;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// Runs <c>fixtures/cases.json</c> — the normative cross-language conformance
/// vectors — against this implementation.
/// </summary>
/// <remarks>
/// The adapter knows nothing about any individual case: it loads the file,
/// resolves fixture ids to bytes, verifies each fixture's digest, builds a
/// verifier from the generic config, dispatches on <c>operation</c>, normalizes
/// the result and reads the reason off a failure. A vector that disagrees with
/// the library is a bug report against one of the two; it is never something to
/// special-case here. A case this adapter cannot map is a hard failure, never a
/// skip.
/// </remarks>
public class Conformance
{
    // verifyRaw enforces no claim, so its cases may omit bundleId and
    // acceptedEnvironments — but the constructor still demands both. These
    // stand-ins match nothing any fixture carries, so a claim check that leaked
    // into VerifyRaw surfaces as a failure rather than as a silent pass. An
    // empty string, a wildcard, or "all four environments" would hide it.
    private const string UnmatchableBundleId = "conformance.unset.bundle.id";

    private static readonly AppleEnvironment[] UnmatchableEnvironments = { AppleEnvironment.LocalTesting };

    private static readonly List<object?> CaseList =
        Fixtures.Cases["cases"] as List<object?>
        ?? throw new InvalidOperationException("cases.json has no cases array");

    /// <summary>One entry per case, so a CI log names the vector that broke.</summary>
    public static TheoryData<string> CaseIds
    {
        get
        {
            TheoryData<string> ids = new();
            foreach (object? entry in CaseList)
            {
                ids.Add(Str(AsMap(entry), "id"));
            }

            return ids;
        }
    }

    /// <summary>
    /// Read before any case runs: a fixture no case happens to reference would
    /// otherwise drift unnoticed, and the registry is the thing being guarded.
    /// </summary>
    [Fact]
    public void EveryRegisteredFixtureMatchesItsRecordedDigest()
    {
        int count = 0;
        foreach (string id in Fixtures.Ids)
        {
            Fixtures.Bytes(id);
            count++;
        }

        Assert.True(count > 0, "cases.json must register fixtures");
    }

    /// <summary>
    /// A silently dropped operation cannot hide behind a green run: the number
    /// of discovered cases must equal the number in the file.
    /// </summary>
    [Fact]
    public void EveryCaseInTheFileIsRun()
    {
        Assert.Equal(CaseList.Count, CaseIds.Count);
        HashSet<string> ids = new(StringComparer.Ordinal);
        foreach (object? entry in CaseList)
        {
            Assert.True(ids.Add(Str(AsMap(entry), "id")), "case ids must be unique");
        }

        Assert.Equal(CaseList.Count, ids.Count);
    }

    [Theory]
    [MemberData(nameof(CaseIds))]
    public void Case(string id)
    {
        OrderedMap kase = Find(id);
        string operation = Str(kase, "operation");
        OrderedMap config = AsMap(kase["config"]);
        string fixtureId = Str(AsMap(kase["input"]), "fixture");
        byte[] input = Fixtures.Bytes(fixtureId);
        IClock? clock = Clock(kase);
        OrderedMap expected = AsMap(kase["expected"]);

        object? result;
        try
        {
            result = Run(operation, config, input, fixtureId, clock);
        }
        catch (VerificationException e)
        {
            Assert.True(
                Str(expected, "status") == "error",
                $"expected success but the call threw {e.ReasonCode}");
            Assert.Equal(Str(expected, "reason"), e.ReasonCode);
            return;
        }
        catch (Exception e)
        {
            // Only a VerificationException carries a canonical Reason. Anything
            // else is a defect in the library or in this harness, and must never
            // be read as one of the expected reasons.
            throw new InvalidOperationException(
                $"harness error: {operation} threw {e.GetType().FullName} ({e.Message}), "
                + "which is not a VerificationException", e);
        }

        expected.TryGetValue("reason", out object? expectedReason);
        Assert.True(
            Str(expected, "status") == "ok",
            $"expected {expectedReason} but the call returned a value");

        object? actual = Normalize.Value(result);
        foreach (KeyValuePair<string, object?> field in AsMap(expected["fields"]))
        {
            object? value = Normalize.Resolve(actual, field.Key);
            if (field.Value is null)
            {
                // null means "absent or unset".
                Assert.True(value is null, $"{field.Key}: expected absent, got {value}");
                continue;
            }

            AssertEqual(field.Value, value, field.Key);
        }
    }

    private static object Run(string operation, OrderedMap config, byte[] input, string fixtureId, IClock? clock)
    {
        switch (operation)
        {
            case "verifyTransaction":
                using (JwsVerifier verifier = Jws(config, clock))
                {
                    return verifier.VerifyTransaction(Encoding.UTF8.GetString(input));
                }

            case "verifyAppTransaction":
                using (JwsVerifier verifier = Jws(config, clock))
                {
                    return verifier.VerifyAppTransaction(Encoding.UTF8.GetString(input));
                }

            case "verifyRaw":
                using (JwsVerifier verifier = Jws(config, clock))
                {
                    return verifier.VerifyRaw(Encoding.UTF8.GetString(input));
                }

            case "verifyReceipt":
                {
                    RequireNoClock(clock, operation);
                    using ReceiptVerifier verifier = new(Roots(config), Str(config, "bundleId"));
                    string? guidHex = config.TryGetValue("deviceGuidHex", out object? hex) ? hex as string : null;
                    return verifier.Verify(input, guidHex is null ? null : FromHex(guidHex));
                }

            case "verifyReceiptBase64":
                {
                    RequireNoClock(clock, operation);
                    Assert.True(
                        Fixtures.Codec(fixtureId) == "text",
                        $"harness error: verifyReceiptBase64 fixture \"{fixtureId}\" is not codec \"text\"");
                    using ReceiptVerifier verifier = new(Roots(config), Str(config, "bundleId"));
                    string? guidHex = config.TryGetValue("deviceGuidHex", out object? hex) ? hex as string : null;
                    return verifier.Verify(
                        Encoding.UTF8.GetString(input), guidHex is null ? null : FromHex(guidHex));
                }

            case "verifyReceiptEndpoint":
                {
                    Assert.True(
                        AppleEnvironments.TryParse(Str(config, "environment"), out AppleEnvironment environment),
                        "harness error: unknown endpoint environment");
                    using VerifyReceiptEndpoint endpoint = new(Roots(config), environment, clock);
                    OrderedMap body = new();
                    // A text fixture is what a client actually sent, verbatim;
                    // a raw or base64 fixture is DER this harness re-encodes
                    // as canonical base64, since no port decodes those itself.
                    body.Set(
                        "receipt-data",
                        Fixtures.Codec(fixtureId) == "text"
                            ? Encoding.UTF8.GetString(input)
                            : Convert.ToBase64String(input));
                    return endpoint.VerifyReceipt(body);
                }

            default:
                throw new InvalidOperationException(
                    $"harness error: no adapter for operation \"{operation}\"");
        }
    }

    private static JwsVerifier Jws(OrderedMap config, IClock? clock)
    {
        List<AppleEnvironment> environments = new();
        if (config.TryGetValue("acceptedEnvironments", out object? accepted) && accepted is List<object?> list)
        {
            foreach (object? entry in list)
            {
                Assert.True(
                    AppleEnvironments.TryParse(entry as string, out AppleEnvironment environment),
                    $"harness error: unknown environment \"{entry}\"");
                environments.Add(environment);
            }
        }
        else
        {
            environments.AddRange(UnmatchableEnvironments);
        }

        long? appAppleId = config.TryGetValue("appAppleId", out object? id) ? (long?)id : null;
        TimeSpan? maxSignedAge = config.TryGetValue("maxSignedAgeSeconds", out object? seconds)
            ? TimeSpan.FromSeconds((long)seconds!)
            : null;

        return new JwsVerifier(
            Roots(config),
            config.TryGetValue("bundleId", out object? bundleId) ? (string)bundleId! : UnmatchableBundleId,
            environments,
            appAppleId,
            maxSignedAge,
            clock);
    }

    private static IReadOnlyList<X509Certificate2> Roots(OrderedMap config)
    {
        OrderedMap spec = AsMap(config["trustedRoots"]);
        if (Str(spec, "source") == "builtin")
        {
            return Str(spec, "name") switch
            {
                "apple-jws-roots" => AppleRootCertificates.JwsRoots(),
                "apple-receipt-roots" => AppleRootCertificates.ReceiptRoots(),
                _ => throw new InvalidOperationException(
                    $"harness error: unknown builtin root set \"{spec["name"]}\""),
            };
        }

        List<X509Certificate2> roots = new();
        foreach (object? id in spec["fixtures"] as List<object?>
            ?? throw new InvalidOperationException("harness error: trustedRoots.fixtures is not a list"))
        {
            roots.Add(X509CertificateLoader.LoadCertificate(Fixtures.Bytes((string)id!)));
        }

        return roots;
    }

    /// <summary>
    /// The case's pinned instant as the verifier's clock option, or
    /// <see langword="null"/> when it pins none. No global time is faked: an
    /// operation whose API has no clock seam rejects a case that pins one
    /// rather than silently running on the system clock.
    /// </summary>
    private static IClock? Clock(OrderedMap kase)
    {
        if (!kase.TryGetValue("clock", out object? clock) || clock is not OrderedMap map)
        {
            return null;
        }

        Assert.True(
            DateTimeOffset.TryParse(
                Str(map, "now"),
                CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AdjustToUniversal,
                out DateTimeOffset now),
            $"harness error: unparseable clock \"{map["now"]}\"");
        return new FixedClock(now);
    }

    private static void RequireNoClock(IClock? clock, string operation)
    {
        if (clock is not null)
        {
            throw new InvalidOperationException(
                $"harness error: {operation} has no clock seam, but the case pins one");
        }
    }

    private static void AssertEqual(object expected, object? actual, string path)
    {
        switch (expected)
        {
            case string text:
                Assert.Equal(text, actual as string);
                return;
            case bool flag:
                Assert.Equal(flag, actual);
                return;
            case long number:
                Assert.True(
                    actual is long asLong && asLong == number,
                    $"{path}: expected {number}, got {actual ?? "null"}");
                return;
            case double number:
                Assert.True(
                    actual is double asDouble && Math.Abs(asDouble - number) < 1e-9,
                    $"{path}: expected {number}, got {actual ?? "null"}");
                return;
            default:
                throw new InvalidOperationException(
                    $"harness error: unsupported expected value type for \"{path}\"");
        }
    }

    private static OrderedMap Find(string id)
    {
        foreach (object? entry in CaseList)
        {
            OrderedMap map = AsMap(entry);
            if (Str(map, "id") == id)
            {
                return map;
            }
        }

        throw new InvalidOperationException($"harness error: no case with id \"{id}\"");
    }

    private static byte[] FromHex(string hex)
    {
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = byte.Parse(hex.Substring(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }

        return bytes;
    }

    private static OrderedMap AsMap(object? value) =>
        value as OrderedMap ?? throw new InvalidOperationException("harness error: expected a JSON object");

    private static string Str(OrderedMap map, string key) =>
        map[key] as string ?? throw new InvalidOperationException($"harness error: missing \"{key}\"");
}
