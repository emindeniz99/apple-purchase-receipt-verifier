using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier.Internal;
using ApplePurchaseReceiptVerifier.Jws;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;
using Xunit.Sdk;
using Xunit.v3;

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
public class Conformance : IClassFixture<Conformance.Coverage>
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

    /// <summary>
    /// The download-id vectors expect 2^63-1, a nineteen-digit, eight-byte
    /// integer an IEEE-754 double rounds to 2^63. This harness reads
    /// cases.json with the library's own reader, which keeps an integral
    /// literal that fits as a <see cref="long"/>; a reader that made it a
    /// double would compare against 9223372036854775808 and let a rounding
    /// implementation pass. So the expectation itself is asserted to arrive
    /// with its exact digits, and as an integer — the comparison in
    /// <see cref="AssertEqual"/> is then exact.
    /// </summary>
    [Fact]
    public void TheDownloadIdExpectationIsReadAsAnExactInteger()
    {
        Assert.Equal(
            9223372036854775807L,
            Assert.IsType<long>(Expected("receipt/ids-are-decoded")["downloadId"]));
        Assert.Equal(
            9223372036854775807L,
            Assert.IsType<long>(Expected("endpoint/ids-echo-apples-keys")["receipt.download_id"]));
    }

    [Theory]
    [MemberData(nameof(CaseIds))]
    public void Case(string id)
    {
        Ran[id] = true;
        OrderedMap kase = Find(id);
        string operation = Str(kase, "operation");
        if (operation == "decodeBase64")
        {
            List<string> failures = DecodeBase64Failures(kase);
            Assert.True(failures.Count == 0, string.Join("\n", failures));
            return;
        }

        OrderedMap config = AsMap(kase["config"]);
        OrderedMap inputSpec = AsMap(kase["input"]);
        // A requestBody names a fixture too: the whole raw request body.
        bool rawBody = inputSpec.TryGetValue("requestBody", out _);
        string fixtureId = Str(inputSpec, rawBody ? "requestBody" : "fixture");
        byte[] input = Fixtures.Bytes(fixtureId);
        IClock? clock = Clock(kase);
        OrderedMap expected = AsMap(kase["expected"]);

        object? result;
        try
        {
            result = Run(operation, config, input, fixtureId, rawBody, clock);
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

        if (result is VerifyReceiptResult endpointResult)
        {
            // FailureReason is not on Apple's wire, so an endpoint case pins
            // it beside the wire fields rather than among them.
            if (expected.TryGetValue("failureReason", out object? failureReason))
            {
                Assert.Equal(
                    failureReason as string,
                    endpointResult.FailureReason is VerificationReason reason
                        ? VerificationReasonCodes.ToCode(reason)
                        : null);
            }

            result = endpointResult.ToResponse();
        }

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

    /// <summary>Which case ids actually ran, for <see cref="Coverage"/>.</summary>
    private static readonly ConcurrentDictionary<string, bool> Ran = new(StringComparer.Ordinal);

    /// <summary>
    /// Coverage self-check: every case id in the file ran, compared against
    /// the parsed file and never against a literal count, so a case that was
    /// skipped, or never discovered, fails the run.
    /// </summary>
    /// <remarks>
    /// It runs as the class fixture's cleanup, which xUnit calls once after
    /// every test of this class has finished, whatever order they ran in, and
    /// reports a throw there as a failure of the run. A [Fact] with a test-case
    /// orderer was tried first; the orderer did not hold on net10.0 in CI and
    /// the check ran before any case. An explicit filter on the test process's
    /// command line is the one thing that may leave cases unrun, so the check
    /// stands down for it.
    /// </remarks>
    public sealed class Coverage : IDisposable
    {
        public void Dispose()
        {
            foreach (string argument in Environment.GetCommandLineArgs())
            {
                if (argument.StartsWith("--filter", StringComparison.Ordinal)
                    || argument.StartsWith("--treenode-filter", StringComparison.Ordinal)
                    || argument.StartsWith("-filter", StringComparison.Ordinal)
                    || argument is "-method" or "-class" or "-trait" or "-namespace")
                {
                    return;
                }
            }

            List<string> missing = new();
            foreach (object? entry in CaseList)
            {
                string id = Str(AsMap(entry), "id");
                if (!Ran.ContainsKey(id))
                {
                    missing.Add(id);
                }
            }

            if (missing.Count != 0)
            {
                throw new InvalidOperationException(
                    $"{missing.Count} of {CaseList.Count} cases did not run: {string.Join(", ", missing)}");
            }
        }
    }

    /// <summary>
    /// The decoders a decodeBase64 group can name, called directly, each with
    /// the reason its refusal carries. An error group states
    /// INVALID_RECEIPT_FORMAT, the receipt-data answer; x5c answers
    /// INVALID_CERTIFICATE. <see cref="CanonicalBase64.Decode"/> answers null,
    /// which the x5c path reports as InvalidCertificate, so that translation
    /// happens here.
    /// </summary>
    private static readonly Dictionary<string, (Func<string, byte[]> Decode, string Refusal)> Base64Decoders =
        new(StringComparer.Ordinal)
        {
            ["receipt-data"] = (ReceiptVerifier.DecodeBase64, "INVALID_RECEIPT_FORMAT"),
            ["x5c"] = (
                text => CanonicalBase64.Decode(text) ?? throw new VerificationException(
                    VerificationReason.InvalidCertificate, "x5c entry is not valid base64"),
                "INVALID_CERTIFICATE"),
        };

    /// <summary>
    /// Every text of a decodeBase64 group that got the wrong answer from a
    /// decoder the group names, by case id, decoder, index and escaped text,
    /// rather than stopping at the first.
    /// </summary>
    private static List<string> DecodeBase64Failures(OrderedMap kase)
    {
        string id = Str(kase, "id");
        OrderedMap expected = AsMap(kase["expected"]);
        bool ok = Str(expected, "status") == "ok";
        if (!ok)
        {
            Assert.Equal("INVALID_RECEIPT_FORMAT", Str(expected, "reason"));
        }

        string want = ok ? Str(expected, "bytesHex") : string.Empty;
        List<object?> texts = AsMap(kase["input"])["texts"] as List<object?>
            ?? throw new InvalidOperationException("harness error: input.texts is not a list");
        List<object?> decoders = kase["decoders"] as List<object?>
            ?? throw new InvalidOperationException("harness error: decoders is not a list");
        Assert.True(texts.Count > 0 && decoders.Count > 0, $"harness error: {id}: no texts or no decoders");
        List<string> failures = new();
        foreach (object? decoder in decoders)
        {
            string name = decoder as string ?? throw new InvalidOperationException("harness error: decoder");
            (Func<string, byte[]> decode, string refusal) = Base64Decoders[name];
            for (int index = 0; index < texts.Count; index++)
            {
                string text = texts[index] as string
                    ?? throw new InvalidOperationException("harness error: a text is not a string");
                string where = $"{id}: {name} texts[{index}] {Escape(text)}";
                string decoded;
                try
                {
                    decoded = Convert.ToHexString(decode(text)).ToLowerInvariant();
                }
                catch (VerificationException e)
                {
                    if (ok)
                    {
                        failures.Add($"{where} was refused ({e.ReasonCode}), want {want}");
                    }
                    else if (e.ReasonCode != refusal)
                    {
                        failures.Add($"{where}: reason {e.ReasonCode}, want {refusal}");
                    }

                    continue;
                }
                catch (Exception e)
                {
                    failures.Add($"{where}: harness error: threw {e.GetType().FullName} ({e.Message})");
                    continue;
                }

                if (!ok)
                {
                    failures.Add($"{where} was accepted (decoded to {decoded})");
                }
                else if (decoded != want)
                {
                    failures.Add($"{where} decoded to {decoded}, want {want}");
                }
            }
        }

        return failures;
    }

    /// <summary>A text as a quoted literal with every non-printable-ASCII character escaped.</summary>
    private static string Escape(string text)
    {
        StringBuilder builder = new("\"");
        foreach (char c in text)
        {
            if (c is '"' or '\\')
            {
                builder.Append('\\').Append(c);
            }
            else if (c < 0x20 || c > 0x7e)
            {
                builder.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
            }
            else
            {
                builder.Append(c);
            }
        }

        return builder.Append('"').ToString();
    }

    private static object Run(
        string operation, OrderedMap config, byte[] input, string fixtureId, bool rawBody, IClock? clock)
    {
        if (rawBody && operation != "verifyReceiptEndpoint")
        {
            throw new InvalidOperationException(
                $"harness error: requestBody is only defined for verifyReceiptEndpoint, not \"{operation}\"");
        }

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
                    if (rawBody)
                    {
                        // The whole raw body, verbatim, through the entry
                        // point that parses it.
                        return endpoint.VerifyReceiptResult(Encoding.UTF8.GetString(input));
                    }

                    OrderedMap body = new();
                    // A text fixture is what a client actually sent, verbatim;
                    // a raw or base64 fixture is DER this harness re-encodes
                    // as canonical base64, since no port decodes those itself.
                    body.Set(
                        "receipt-data",
                        Fixtures.Codec(fixtureId) == "text"
                            ? Encoding.UTF8.GetString(input)
                            : Convert.ToBase64String(input));
                    return endpoint.VerifyReceiptResult(body);
                }

            default:
                throw new InvalidOperationException(
                    $"harness error: no adapter for operation \"{operation}\"");
        }
    }

    private static JwsVerifier Jws(OrderedMap config, IClock? clock)
    {
        RequireNoClock(clock, "JwsVerifier");
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

        return new JwsVerifier(
            Roots(config),
            config.TryGetValue("bundleId", out object? bundleId) ? (string)bundleId! : UnmatchableBundleId,
            environments,
            appAppleId);
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

    private static OrderedMap Expected(string id) => AsMap(AsMap(Find(id)["expected"])["fields"]);

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
