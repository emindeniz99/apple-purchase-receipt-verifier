using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using ApplePurchaseReceiptVerifier;

// Dumps every case's outcome and, for a verified receipt, ToJson() verbatim,
// plus ToJson() of hand-built payloads with awkward strings. One line per item.
static class P
{
    static string fixtures = "";
    static JsonElement registry;

    static byte[] Bytes(string id)
    {
        JsonElement e = registry.GetProperty(id);
        byte[] raw = File.ReadAllBytes(Path.Combine(fixtures, e.GetProperty("path").GetString()!));
        return e.GetProperty("codec").GetString() switch
        {
            "raw" or "text" => raw,
            "base64" => Convert.FromBase64String(new string(Encoding.ASCII.GetString(raw).Where(c => !char.IsWhiteSpace(c)).ToArray())),
            "utf8" => Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(raw).Trim()),
            _ => throw new Exception("codec"),
        };
    }

    static string Codec(string id) => registry.GetProperty(id).GetProperty("codec").GetString()!;

    static string Hex(string s) => string.Concat(s.Select(c => ((int)c).ToString("x4")));

    static int Main(string[] args)
    {
        fixtures = args[0];
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(fixtures, "cases.json")));
        registry = doc.RootElement.GetProperty("fixtures");
        using StreamWriter output = new StreamWriter(args[1], false, new UTF8Encoding(false));
        int receipts = 0, verified = 0;
        foreach (JsonElement kase in doc.RootElement.GetProperty("cases").EnumerateArray())
        {
            string id = kase.GetProperty("id").GetString()!;
            string op = kase.GetProperty("operation").GetString()!;
            if (op == "decodeBase64") continue;
            JsonElement config = kase.GetProperty("config");
            Config.Builder b = Config.CreateBuilder();
            if (kase.TryGetProperty("clock", out JsonElement clock) && clock.ValueKind == JsonValueKind.Object)
            {
                long ms = DateTimeOffset.Parse(clock.GetProperty("now").GetString()!, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal).ToUnixTimeMilliseconds();
                b.Clock(() => ms);
            }
            JsonElement tr = config.GetProperty("trustedRoots");
            if (tr.GetProperty("source").GetString() != "defaults")
            {
                List<X509Certificate2> roots = new();
                foreach (JsonElement f in tr.GetProperty("fixtures").EnumerateArray())
                    roots.Add(ApplePurchaseReceiptVerifier.Internal.Certificates.TryLoad(Bytes(f.GetString()!))!);
                b.Roots(roots);
            }
            IVerifier v = Verifier.Create(b.Build());
            JsonElement input = kase.GetProperty("input");
            switch (op)
            {
                case "verifyReceipt":
                {
                    string fx = input.GetProperty("fixture").GetString()!;
                    string text = Codec(fx) == "text" ? Encoding.UTF8.GetString(Bytes(fx)) : Convert.ToBase64String(Bytes(fx));
                    var r = v.VerifyReceipt(text);
                    receipts++;
                    if (r.Verified) verified++;
                    output.WriteLine(id + "\t" + (r.Verified ? "ok\t" + Hex(r.Payload!.ToJson()) : r.Failure!.Reason.ToString()));
                    break;
                }
                case "verifySignedData":
                {
                    var r = v.VerifySignedData(Encoding.UTF8.GetString(Bytes(input.GetProperty("fixture").GetString()!)));
                    output.WriteLine(id + "\t" + (r.Verified ? "ok\t" + Hex(r.Payload!.Json) : r.Failure!.Reason.ToString()));
                    break;
                }
                case "verifyReceiptEndpoint":
                {
                    string body = input.TryGetProperty("requestBody", out JsonElement rb)
                        ? Encoding.UTF8.GetString(Bytes(rb.GetString()!))
                        : "{\"receipt-data\":\"" + (Codec(input.GetProperty("fixture").GetString()!) == "text" ? Encoding.UTF8.GetString(Bytes(input.GetProperty("fixture").GetString()!)) : Convert.ToBase64String(Bytes(input.GetProperty("fixture").GetString()!))) + "\"}";
                    AppleEnvironment env = config.GetProperty("environment").GetString() == "PRODUCTION" ? AppleEnvironment.Production : AppleEnvironment.Sandbox;
                    output.WriteLine(id + "\t" + Hex(v.VerifyReceiptEndpoint(env, body)));
                    break;
                }
            }
        }

        // Hand-built payloads: every string field carries awkward text.
        string[] awkward =
        {
            "plain", "", "q\"uote back\\slash /slash", "\b\f\n\r\t", "\u0000\u0001\u001f\u007f",
            "caf\u00e9 \u00ff \u0100", "\u2028\u2029", "\ue000 private", "\ufeff bom", "\ufffd \uffff \ufffe",
            "\U0001F600 emoji \U0010FFFF", "\u0378 unassigned \u0870", "<script>&'+`", "\u00ad soft \u200b zw",
        };
        int n = 0;
        foreach (string s in awkward)
        {
            var unknown = new Dictionary<int, IReadOnlyList<byte[]>> { [5] = new List<byte[]> { new byte[] { 1, 2 } }, [-3] = new List<byte[]>(), [100000] = new List<byte[]> { new byte[0] } };
            var purchase = new InAppPurchase(long.MinValue, s, s, long.MaxValue, s, 0, -1, long.MinValue, null, true, false, unknown);
            var p = new ReceiptPayload(s, long.MaxValue, s, new byte[] { 0, 255 }, s, new byte[0], null, -0L, long.MinValue, 0,
                new List<InAppPurchase> { purchase, purchase }, null, s, null, unknown);
            output.WriteLine("synthetic-" + (n++) + "\tok\t" + Hex(p.ToJson()));
        }
        foreach (string s in new[] { "\ud800", "a\udc00b", "x\ud83d" })
        {
            var p = new ReceiptPayload(s, null, null, null, null, null, null, null, null, null, new List<InAppPurchase>(), null, null, null, new Dictionary<int, IReadOnlyList<byte[]>>());
            string res;
            try { res = "ok\t" + Hex(p.ToJson()); } catch (Exception e) { res = "threw " + e.GetType().Name; }
            output.WriteLine("lone-surrogate-" + (n++) + "\t" + res);
        }
        Console.WriteLine($"receipts {receipts}, verified {verified}");
        return 0;
    }
}
