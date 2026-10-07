using System.Collections.Generic;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// Answers in the shape the wire defines (0.7's canonical JSON), built from a
/// hand-made payload, so the wrapper's reading is tested against the wire and
/// not against whichever module is embedded.
/// </summary>
internal static class SyntheticAnswers
{
    /// <summary>
    /// A payload that uses every field: ids above 2^53 and below zero, dates,
    /// both flags, raw bytes, and unknown attributes with repeats at both levels.
    /// </summary>
    internal static ReceiptPayload Receipt()
    {
        Dictionary<int, IReadOnlyList<byte[]>> topUnknown = new()
        {
            [9999] = new List<byte[]> { new byte[] { 1, 2, 3 }, new byte[] { 4, 5 } },
            [31337] = new List<byte[]> { new byte[] { 9 } },
        };
        Dictionary<int, IReadOnlyList<byte[]>> purchaseUnknown = new()
        {
            [1799] = new List<byte[]> { new byte[] { 7, 7 } },
        };
        List<InAppPurchase> inApp = new()
        {
            new InAppPurchase(
                2, "com.example.coins", "1000000123456789", 1705320000000L, "1000000123456789", 1705320000000L,
                1705323600000L, 9223372036854775807L, 1705330000000L, true, false, purchaseUnknown),
            new InAppPurchase(
                null, "café 😀 \"quoted\" \\ back", null, null, null, null, null, null, null, null, null,
                new Dictionary<int, IReadOnlyList<byte[]>>()),
        };
        return new ReceiptPayload(
            "ProductionSandbox", 1234567890123456789L, "com.example.app", new byte[] { 0x0c, 0x0f, 0x63 },
            "1.2.3", new byte[] { 1, 2, 3, 4 }, new byte[] { 0xff, 0x00, 0x80 }, 1722945600000L,
            -42L, 9007199254740993L, inApp, 1705320000000L, 1719913520000L, "1.0", 1893456000000L, topUnknown,
            AppleEnvironment.Sandbox);
    }

    /// <summary>
    /// A <c>verify-receipt</c> answer that verified <paramref name="payload"/>,
    /// with the payload's <see cref="ReceiptPayload.Environment"/> beside it.
    /// </summary>
    internal static string Verified(ReceiptPayload payload) =>
        "{\"verified\":true,\"payload\":" + payload.ToJson() + ",\"environment\":" + EnvironmentJson(payload.Environment) + "}";

    /// <summary>A <c>verify-signed-data</c> answer that verified <paramref name="payloadJson"/> in <paramref name="environment"/>.</summary>
    internal static string VerifiedJws(string payloadJson, AppleEnvironment? environment = null) =>
        "{\"verified\":true,\"payload\":" + Internal.Json.Write(json => json.WriteStringValue(payloadJson))
        + ",\"environment\":" + EnvironmentJson(environment) + "}";

    /// <summary>The wire's spelling of the environment beside a verified payload (DECISIONS.md R42).</summary>
    internal static string EnvironmentJson(AppleEnvironment? environment) => environment switch
    {
        AppleEnvironment.Production => "\"Production\"",
        AppleEnvironment.Sandbox => "\"Sandbox\"",
        _ => "null",
    };

    /// <summary>A verification failure answer.</summary>
    internal static string Failed(string reason, string message) =>
        "{\"verified\":false,\"reason\":\"" + reason + "\",\"message\":\"" + message + "\"}";
}
