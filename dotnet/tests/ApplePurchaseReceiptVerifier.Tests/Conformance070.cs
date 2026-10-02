using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;
using Xunit.v3;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// Runs <c>fixtures/cases.json</c> — the normative cross-language 0.7
/// conformance vectors — against this implementation.
/// </summary>
/// <remarks>
/// The adapter knows nothing about any individual case: it loads the file,
/// resolves fixture ids to bytes, builds a <see cref="Config"/> from the
/// generic config, dispatches on <c>operation</c>, and evaluates the
/// expectation the file states. A vector that disagrees with the library is a
/// bug report against one of the two; it is never something to special-case
/// here. A case this adapter cannot map is a hard failure, never a skip.
/// </remarks>
public class Conformance070 : IClassFixture<Conformance070.Coverage>
{
    private static readonly List<object?> CaseList =
        Fixtures070.Cases["cases"] as List<object?>
        ?? throw new InvalidOperationException("cases.json has no cases array");

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

    [Fact]
    public void EveryRegisteredFixtureMatchesItsRecordedDigest()
    {
        int count = 0;
        foreach (string id in Fixtures070.Ids)
        {
            Fixtures070.Bytes(id);
            count++;
        }

        Assert.True(count > 0, "cases.json must register fixtures");
    }

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
        Ran[id] = true;
        JsonMap kase = Find(id);
        string operation = Str(kase, "operation");

        if (operation == "decodeBase64")
        {
            List<string> failures = DecodeBase64Failures(kase);
            Assert.True(failures.Count == 0, string.Join("\n", failures));
            return;
        }

        long? maxMillis = kase.TryGetValue("maxMillis", out object? mm) ? (long?)mm : null;
        JsonMap expected = AsMap(kase["expected"]);

        if (maxMillis is long budget)
        {
            // One warm-up call of the same case, discarded, then the timed one.
            RunCase(operation, kase);
            Stopwatch stopwatch = Stopwatch.StartNew();
            EvaluateCase(operation, kase, expected);
            stopwatch.Stop();
            Assert.True(
                stopwatch.ElapsedMilliseconds <= budget,
                $"{id}: took {stopwatch.ElapsedMilliseconds} ms, budget {budget} ms");
            return;
        }

        EvaluateCase(operation, kase, expected);
    }

    private static void EvaluateCase(string operation, JsonMap kase, JsonMap expected)
    {
        string id = Str(kase, "id");
        object? outcome = RunCase(operation, kase);

        if (operation == "verifyReceiptEndpoint")
        {
            string responseJson = (string)outcome!;
            object? response = TestJson.Parse(responseJson);
            if (expected.TryGetValue("oneOf", out object? listedStatuses) && listedStatuses is List<object?> allowedStatuses)
            {
                // Port-defined within a list: the response's /status must be
                // listed, and nothing else is pinned.
                object? status = response is JsonMap body && body.TryGetValue("status", out object? value) ? value : null;
                Assert.True(
                    allowedStatuses.Exists(allowed => SameJsonValue(allowed, status)),
                    $"{id}: answered status {Render(status)}, want one of {string.Join(", ", allowedStatuses)}");
                return;
            }

            EvaluateFields(id, response, expected);
            return;
        }

        if (expected.TryGetValue("oneOf", out object? listed) && listed is List<object?> allowed)
        {
            AssertListedOutcome(id, operation, outcome, allowed);
            return;
        }

        bool ok = Str(expected, "status") == "ok";
        (bool verified, object? payloadJsonValue, VerificationReason? reason, string? message) = ReadOutcome(operation, outcome!);

        if (ok)
        {
            Assert.True(verified, $"{id}: expected success but got {reason} ({message})");
            EvaluateFields(id, payloadJsonValue, expected);
            if (expected.TryGetValue("toJson", out object? toJsonExpected) && toJsonExpected is string expectedJson)
            {
                string actualJson = operation == "verifyReceipt"
                    ? ((VerificationResult<ReceiptPayload>)outcome!).Payload!.ToJson()
                    : throw new InvalidOperationException("harness error: toJson is only defined for verifyReceipt");
                // Same value, not same bytes: whitespace, key order and
                // escaping are free (docs/design/0.7-api.md "Our JSON").
                Assert.True(
                    SameJsonValue(TestJson.Parse(expectedJson), TestJson.Parse(actualJson)),
                    $"{id}: toJson value mismatch\n  want: {expectedJson}\n  got:  {actualJson}");
            }
        }
        else
        {
            Assert.False(verified, $"{id}: expected {Str(expected, "reason")} but the call verified");
            string got = reason is VerificationReason r ? VerificationReasonCodes.ToCode(r) : "?";
            Assert.True(Str(expected, "reason") == got, $"{id}: expected {Str(expected, "reason")}, got {got} ({message})");
            if (expected.TryGetValue("messageMustNotContain", out object? forbidden) && forbidden is List<object?> codePoints)
            {
                foreach (object? cp in codePoints)
                {
                    int codePoint = (int)(long)cp!;
                    Assert.False(
                        ContainsCodePoint(message ?? string.Empty, codePoint),
                        $"{id}: message contains forbidden code point U+{codePoint:X4}: {message}");
                }
            }
        }
    }

    /// <summary>
    /// Deep equality over the values <see cref="TestJson.Parse"/> produces:
    /// objects compare by key regardless of order, arrays element by
    /// element, and scalars by type and value, so <c>1</c> never equals
    /// <c>"1"</c> or <c>true</c>.
    /// </summary>
    private static bool SameJsonValue(object? a, object? b)
    {
        switch (a)
        {
            case JsonMap mapA:
                if (b is not JsonMap mapB || mapA.Count != mapB.Count)
                {
                    return false;
                }

                foreach (KeyValuePair<string, object?> entry in mapA)
                {
                    if (!mapB.TryGetValue(entry.Key, out object? other) || !SameJsonValue(entry.Value, other))
                    {
                        return false;
                    }
                }

                return true;
            case List<object?> listA:
                if (b is not List<object?> listB || listA.Count != listB.Count)
                {
                    return false;
                }

                for (int i = 0; i < listA.Count; i++)
                {
                    if (!SameJsonValue(listA[i], listB[i]))
                    {
                        return false;
                    }
                }

                return true;
            default:
                return Equals(a, b);
        }
    }

    private static void AssertListedOutcome(string id, string operation, object? outcome, List<object?> allowed)
    {
        (bool verified, VerificationReason? reason) = ReadVerdict(operation, outcome!);
        string got = verified ? "ok" : reason is VerificationReason r ? VerificationReasonCodes.ToCode(r) : "?";
        Assert.True(allowed.Contains(got), $"{id}: answered {got}, want one of {string.Join(", ", allowed)}");
    }

    /// <summary>
    /// The verdict alone, without reading the payload back. A listed outcome checks no field, and the
    /// harness's reader (<see cref="Json.MaxDepth"/>) would refuse a verified payload nested deeper than that.
    /// </summary>
    private static (bool Verified, VerificationReason? Reason) ReadVerdict(string operation, object outcome)
    {
        switch (outcome)
        {
            case VerificationResult<ReceiptPayload> receiptResult:
                return (receiptResult.Verified, receiptResult.Verified ? null : receiptResult.Failure!.Reason);
            case VerificationResult<JsonPayload> jwsResult:
                return (jwsResult.Verified, jwsResult.Verified ? null : jwsResult.Failure!.Reason);
            default:
                throw new InvalidOperationException($"harness error: unexpected result type for \"{operation}\"");
        }
    }

    /// <summary>The failure's message, and the wrapper's own cause when it has one, for a failing case's report.</summary>
    private static string Describe(Failure failure) =>
        failure.Cause is null ? failure.Message : failure.Message + " <" + failure.Cause.Message + ">";

    private static (bool Verified, object? PayloadJson, VerificationReason? Reason, string? Message) ReadOutcome(
        string operation, object outcome)
    {
        switch (outcome)
        {
            case VerificationResult<ReceiptPayload> receiptResult:
                return receiptResult.Verified
                    ? (true, TestJson.Parse(receiptResult.Payload!.ToJson()), null, null)
                    : (false, null, receiptResult.Failure!.Reason, Describe(receiptResult.Failure!));
            case VerificationResult<JsonPayload> jwsResult:
                return jwsResult.Verified
                    ? (true, TestJson.Parse(jwsResult.Payload!.Json), null, null)
                    : (false, null, jwsResult.Failure!.Reason, Describe(jwsResult.Failure!));
            default:
                throw new InvalidOperationException($"harness error: unexpected result type for \"{operation}\"");
        }
    }

    private static void EvaluateFields(string id, object? root, JsonMap expected)
    {
        if (expected.TryGetValue("fields", out object? fieldsValue) && fieldsValue is JsonMap fields)
        {
            foreach (KeyValuePair<string, object?> field in fields)
            {
                object? actual = JsonPointer070.Resolve(root, field.Key);
                if (field.Value is null)
                {
                    Assert.True(actual is null, $"{id}: {field.Key}: expected absent, got {Render(actual)}");
                    continue;
                }

                AssertFieldEqual(id, field.Key, field.Value, actual);
            }
        }

        if (expected.TryGetValue("lengths", out object? lengthsValue) && lengthsValue is JsonMap lengths)
        {
            foreach (KeyValuePair<string, object?> length in lengths)
            {
                long want = (long)length.Value!;
                long got = JsonPointer070.Length(root, length.Key);
                Assert.True(want == got, $"{id}: {length.Key}: expected length {want}, got {got}");
            }
        }
    }

    private static void AssertFieldEqual(string id, string path, object expected, object? actual)
    {
        switch (expected)
        {
            case string text:
                Assert.True(text == (actual as string), $"{id}: {path}: expected \"{text}\", got {Render(actual)}");
                return;
            case bool flag:
                Assert.True(actual is bool b && b == flag, $"{id}: {path}: expected {flag}, got {Render(actual)}");
                return;
            case long number:
                double actualNumber = actual switch { long l => l, double d => d, _ => double.NaN };
                Assert.True(
                    !double.IsNaN(actualNumber) && actualNumber == number,
                    $"{id}: {path}: expected {number}, got {Render(actual)}");
                return;
            case double number:
                double actualD = actual switch { long l => l, double d => d, _ => double.NaN };
                Assert.True(
                    !double.IsNaN(actualD) && Math.Abs(actualD - number) < 1e-9,
                    $"{id}: {path}: expected {number}, got {Render(actual)}");
                return;
            default:
                throw new InvalidOperationException($"harness error: unsupported expected value type for \"{path}\"");
        }
    }

    private static string Render(object? value) => value switch
    {
        null => "null",
        string s => $"\"{s}\"",
        _ => value.ToString() ?? "null",
    };

    private static bool ContainsCodePoint(string text, int codePoint)
    {
        for (int i = 0; i < text.Length;)
        {
            int cp = char.ConvertToUtf32(text, i);
            if (cp == codePoint)
            {
                return true;
            }

            i += char.IsSurrogatePair(text, i) ? 2 : 1;
        }

        return false;
    }

    private static object RunCase(string operation, JsonMap kase)
    {
        JsonMap configSpec = AsMap(kase["config"]);
        Config.Builder builder = Config.CreateBuilder().Clock(Clock(kase));
        IReadOnlyList<X509Certificate2>? roots = Roots(configSpec);
        if (roots is not null)
        {
            builder.Roots(roots);
        }

        IVerifier verifier = Verifier.Create(builder.Build());

        switch (operation)
        {
            case "verifyReceipt":
                {
                    JsonMap input = AsMap(kase["input"]);
                    string fixtureId = Str(input, "fixture");
                    return verifier.VerifyReceipt(Fixtures070.ForReceipt(fixtureId));
                }

            case "verifySignedData":
                {
                    JsonMap input = AsMap(kase["input"]);
                    string fixtureId = Str(input, "fixture");
                    return verifier.VerifySignedData(Fixtures070.ForSignedData(fixtureId));
                }

            case "verifyReceiptEndpoint":
                {
                    JsonMap input = AsMap(kase["input"]);
                    string environmentToken = Str(configSpec, "environment");
                    AppleEnvironment environment = environmentToken switch
                    {
                        "PRODUCTION" => AppleEnvironment.Production,
                        "SANDBOX" => AppleEnvironment.Sandbox,
                        _ => throw new InvalidOperationException("harness error: unknown endpoint environment"),
                    };

                    string requestJson;
                    if (input.TryGetValue("requestBody", out object? requestBodyId) && requestBodyId is string bodyFixture)
                    {
                        requestJson = Encoding.UTF8.GetString(Fixtures070.Bytes(bodyFixture));
                    }
                    else
                    {
                        string fixtureId = Str(input, "fixture");
                        JsonMap body = new();
                        body.Set("receipt-data", Fixtures070.ForReceipt(fixtureId));
                        requestJson = TestJson.Write(body);
                    }

                    return verifier.VerifyReceiptEndpoint(environment, requestJson);
                }

            default:
                throw new InvalidOperationException($"harness error: no adapter for operation \"{operation}\"");
        }
    }

    /// <summary>The registered trust anchors, or <see langword="null"/> for the defaults (the module's built-in Apple roots).</summary>
    private static IReadOnlyList<X509Certificate2>? Roots(JsonMap config)
    {
        JsonMap spec = AsMap(config["trustedRoots"]);
        if (Str(spec, "source") == "defaults")
        {
            return null;
        }

        List<X509Certificate2> roots = new();
        foreach (object? id in spec["fixtures"] as List<object?>
            ?? throw new InvalidOperationException("harness error: trustedRoots.fixtures is not a list"))
        {
            X509Certificate2? certificate = Certificates.TryLoad(Fixtures070.Bytes((string)id!));
            roots.Add(certificate ?? throw new InvalidOperationException($"harness error: trust-anchor fixture \"{id}\" does not decode"));
        }

        return roots;
    }

    private static Func<long> Clock(JsonMap kase)
    {
        if (!kase.TryGetValue("clock", out object? clock) || clock is not JsonMap map)
        {
            return () => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        Assert.True(
            DateTimeOffset.TryParse(
                Str(map, "now"), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out DateTimeOffset now),
            $"harness error: unparseable clock \"{map["now"]}\"");
        long fixedMs = now.ToUnixTimeMilliseconds();
        return () => fixedMs;
    }

    /// <summary>
    /// A <c>decodeBase64</c> case through the module, which is the only decoder
    /// there is. A host cannot read the decoded bytes, so each text is judged
    /// on which side of the rule it lands: a text the case says decodes must
    /// not be refused as base64, and one it says is refused must come back as
    /// the decoder's refusal (MALFORMED for <c>receipt-data</c>,
    /// INVALID_CERTIFICATE for an <c>x5c</c> entry) with a message that says
    /// base64 (or, for the empty text, says it is empty: the core refuses it
    /// before decoding). The decoded bytes are checked by the core's own tests.
    /// </summary>
    private static List<string> DecodeBase64Failures(JsonMap kase)
    {
        string id = Str(kase, "id");
        JsonMap expected = AsMap(kase["expected"]);
        bool ok = Str(expected, "status") == "ok";
        List<object?> texts = AsMap(kase["input"])["texts"] as List<object?>
            ?? throw new InvalidOperationException("harness error: input.texts is not a list");
        List<object?> decoders = kase["decoders"] as List<object?>
            ?? throw new InvalidOperationException("harness error: decoders is not a list");
        IVerifier verifier = Verifier.Create(Config.Defaults());
        List<string> failures = new();
        foreach (object? decoder in decoders)
        {
            string name = (string)decoder!;
            for (int index = 0; index < texts.Count; index++)
            {
                string text = (string)texts[index]!;
                Failure? failure = name switch
                {
                    "receipt-data" => verifier.VerifyReceipt(text).Failure,
                    "x5c" => verifier.VerifySignedData(JwsCarryingX5c(text)).Failure,
                    _ => throw new InvalidOperationException($"harness error: unknown decoder \"{name}\""),
                };
                string refusal = name == "receipt-data" ? "MALFORMED" : "INVALID_CERTIFICATE";
                bool refused = failure is not null
                    && VerificationReasonCodes.ToCode(failure.Reason) == refusal
                    && (failure.Message.Contains("base64", StringComparison.OrdinalIgnoreCase)
                        || (text.Length == 0 && failure.Message.Contains("empty", StringComparison.OrdinalIgnoreCase)));
                string where = $"{id}: {name} texts[{index}] {Escape(text)}";
                if (ok && refused)
                {
                    failures.Add($"{where} was refused as base64: {failure}");
                }
                else if (!ok && !refused)
                {
                    failures.Add($"{where} was not refused as base64: {(failure is null ? "verified" : failure.ToString())}");
                }
            }
        }

        return failures;
    }

    /// <summary>A JWS whose header carries <paramref name="entry"/> as its first <c>x5c</c> element, then two more.</summary>
    private static string JwsCarryingX5c(string entry)
    {
        JsonMap header = new();
        header.Set("alg", "ES256");
        header.Set("x5c", new List<object?> { entry, "AAAA", "AAAA" });
        string Segment(string json) =>
            Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return Segment(TestJson.Write(header)) + "." + Segment("{}") + ".AAAA";
    }

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

    private static readonly ConcurrentDictionary<string, bool> Ran = new(StringComparer.Ordinal);

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

    private static JsonMap Find(string id)
    {
        foreach (object? entry in CaseList)
        {
            JsonMap map = AsMap(entry);
            if (Str(map, "id") == id)
            {
                return map;
            }
        }

        throw new InvalidOperationException($"harness error: no case with id \"{id}\"");
    }

    private static JsonMap AsMap(object? value) =>
        value as JsonMap ?? throw new InvalidOperationException("harness error: expected a JSON object");

    private static string Str(JsonMap map, string key) =>
        map[key] as string ?? throw new InvalidOperationException($"harness error: missing \"{key}\"");
}
