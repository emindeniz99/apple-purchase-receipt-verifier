// Spike only (2026-09-26). The ABI v1 round's 33 mandatory ABI tests
// (js/abi-tests.mjs) on wasmtime-dotnet, plus the facade's contract. Every
// trap is caught, the instance discarded, and a fresh instance must then
// verify g5.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Aprv.Wasm;
using Wasmtime;

static class AbiTests
{
    static int passed, failed;
    static byte[] g5 = Array.Empty<byte>();

    static void Ok(string name, bool cond, string detail = "")
    {
        if (cond) passed++; else failed++;
        Console.WriteLine($"{(cond ? "PASS" : "FAIL")} {name}{(detail.Length == 0 ? "" : ": " + detail)}");
    }

    static (string kind, object? value) Attempt(Func<AprvInstance, object?> f)
    {
        var i = new AprvInstance();
        try { return ("ok", f(i)); }
        catch (TrapException e) { return ("trap", $"TrapException {e.Type}"); }
        catch (Exception e) { return ("error", $"{e.GetType().Name}: {e.Message.Split('\n')[0]}"); }
        finally { i.Dispose(); }
    }

    static JsonNode Dec(byte[] b) => JsonNode.Parse(b)!;

    static bool G5Verifies()
    {
        using var i = new AprvInstance();
        return Dec(i.Invoke(Op.VerifyReceipt, g5))["verified"]!.GetValue<bool>();
    }

    static void TrapsThenRecovers(string name, Func<AprvInstance, object?> f)
    {
        var (kind, msg) = Attempt(f);
        bool after = G5Verifies();
        Ok(name, kind == "trap" && after, $"{kind} ({msg}); fresh instance verifies g5: {after}");
    }

    static Func<int, int, int, int, int> CallFn(AprvInstance i) => i.Instance.GetFunction<int, int, int, int, int>("aprv_call")!;
    static int Alloc(AprvInstance i, int n) => i.Instance.GetFunction<int, int>("aprv_alloc")!(n);
    static int Fn1(AprvInstance i, string name, int a) => i.Instance.GetFunction<int, int>(name)!(a);
    static void Free(AprvInstance i, int h) => i.Instance.GetAction<int>("aprv_result_free")!(h);
    static int WithHandle(AprvInstance i) => CallFn(i)(1, Op.VerifyReceipt, Alloc(i, 4), 4);

    public static int Run(List<JsonElement> calls)
    {
        JsonElement Row(string id) => calls.First(c => c.GetProperty("id").GetString() == id);
        g5 = Convert.FromBase64String(Row("receipt/verify-genuine-sandbox-g5-against-apple-roots").GetProperty("input").GetString()!);
        var jr = Row("transaction/verify-shared-sandbox");
        int jwsOp = jr.GetProperty("op").GetInt32();
        var jws = Convert.FromBase64String(jr.GetProperty("input").GetString()!);
        const int R = Op.VerifyReceipt;

        using (var i = new AprvInstance()) Ok("aprv_abi_version() == 1", i.Instance.GetFunction<int>("aprv_abi_version")!() == 1);
        {
            var (k, v) = Attempt(i => Dec(i.Invoke(R, g5)));
            var b = k == "ok" ? ((JsonNode)v!)["payload"]!["bundleId"]!.GetValue<string>() : null;
            Ok("aprv_call(1, VERIFY_RECEIPT, genuine g5) verifies", k == "ok" && ((JsonNode)v!)["verified"]!.GetValue<bool>() && b == "dev.bonzer.weeka.app", $"bundleId {b}");
        }
        {
            var (k, v) = Attempt(i => Dec(i.Invoke(jwsOp, jws)));
            bool good = false; string detail = $"{v}";
            if (k == "ok")
            {
                var n = (JsonNode)v!;
                var raw = n["payloadJson"]!.GetValue<string>();
                good = n["verified"]!.GetValue<bool>() && JsonNode.DeepEquals(JsonNode.Parse(raw), n["payload"]);
                detail = $"payloadJson {raw.Length} chars";
            }
            Ok("aprv_call(1, VERIFY_SIGNED_DATA (test anchors), shared-sandbox JWS) verifies; payloadJson is the exact signed JSON and parses to payload", good, detail);
        }
        TrapsThenRecovers("aprv_call(0, garbage op, invalid ptr, absurd len) fails hard", i => CallFn(i)(0, 0x7fffffff, -16, 0x7fffffff));
        TrapsThenRecovers("aprv_call(2, garbage op, invalid ptr, absurd len) fails hard", i => CallFn(i)(2, 0x7fffffff, -16, 0x7fffffff));
        {
            var (k, m) = Attempt(i => i.Invoke(R, g5, 2));
            Ok("bridge reports a version mismatch as an ABI error, never verified=false", k == "error" && $"{m}".Contains("APRV Wasm ABI mismatch: module=1, caller=2"), $"{m}");
        }
        {
            var (k, v) = Attempt(i =>
            {
                long before = AprvRuntime.ClockCalls + AprvRuntime.RandomCalls;
                try { CallFn(i)(3, 1, 0, 0); } catch (TrapException) { }
                return AprvRuntime.ClockCalls + AprvRuntime.RandomCalls - before;
            });
            Ok("a version mismatch runs nothing (no host import called)", k == "ok" && (long)v! == 0, $"import calls during the call: {v}");
        }
        foreach (int op in new[] { 0, 5, 99, 255, 256, 261, -1 })
            TrapsThenRecovers($"unknown operation {op} fails hard", i => CallFn(i)(1, op, Alloc(i, 4), 4));
        TrapsThenRecovers("null input pointer with a length fails hard", i => CallFn(i)(1, R, 0, 10));
        TrapsThenRecovers("input beyond linear memory fails hard", i => CallFn(i)(1, R, (int)i.Memory.GetLength() - 4, 16));
        TrapsThenRecovers("input range that overflows u32 fails hard", i => CallFn(i)(1, R, -16, 0x20));
        {
            var (k, v) = Attempt(i => Dec(i.Invoke(R, Array.Empty<byte>())));
            var n = v as JsonNode;
            Ok("empty input is a verification failure value", k == "ok" && !n!["verified"]!.GetValue<bool>() && n["reason"]!.GetValue<string>() == "INVALID_RECEIPT_FORMAT", $"{n?.ToJsonString()}");
        }
        {
            var (k, v) = Attempt(i => new object[] { Alloc(i, 0x7fffffff), Alloc(i, 0x7ffffff0), Dec(i.Invoke(R, g5))["verified"]!.GetValue<bool>() });
            var a = v as object[];
            Ok("absurd aprv_alloc lengths return 0, and the instance keeps working", k == "ok" && (int)a![0] == 0 && (int)a[1] == 0 && (bool)a[2], a == null ? $"{v}" : string.Join(",", a));
        }
        TrapsThenRecovers("invalid handle: aprv_result_ptr(0) fails hard", i => Fn1(i, "aprv_result_ptr", 0));
        TrapsThenRecovers("invalid handle: aprv_result_len(12345) fails hard", i => Fn1(i, "aprv_result_len", 12345));
        TrapsThenRecovers("invalid handle: aprv_result_free(0) fails hard", i => { Free(i, 0); return null; });
        TrapsThenRecovers("invalid handle: aprv_result_free(never issued) fails hard", i => { Free(i, 7); return null; });
        TrapsThenRecovers("double free fails hard", i => { int h = WithHandle(i); Free(i, h); Free(i, h); return null; });
        TrapsThenRecovers("use after free (result_ptr) fails hard", i => { int h = WithHandle(i); Free(i, h); return Fn1(i, "aprv_result_ptr", h); });
        TrapsThenRecovers("use after free (result_len) fails hard", i => { int h = WithHandle(i); Free(i, h); return Fn1(i, "aprv_result_len", h); });
        {
            var (k, v) = Attempt(i => { var hs = new[] { WithHandle(i), WithHandle(i), WithHandle(i) }; Free(i, hs[1]); return new[] { hs[0], hs[1], hs[2], WithHandle(i) }; });
            var a = v as int[];
            Ok("freed handles are reused and live ones stay valid", k == "ok" && a![3] == a[1], a == null ? $"{v}" : string.Join(",", a));
        }
        foreach (var (name, op, input, check) in new (string, int, byte[], Func<JsonNode, bool>)[]
        {
            ("garbage receipt -> verified=false value", R, Encoding.UTF8.GetBytes("not a receipt"), n => !n["verified"]!.GetValue<bool>()),
            ("non-UTF-8 JWS -> verified=false INVALID_JWS_FORMAT", Op.VerifySignedData, new byte[] { 0xff, 0xfe, 0x2e }, n => !n["verified"]!.GetValue<bool>() && n["reason"]!.GetValue<string>() == "INVALID_JWS_FORMAT"),
            ("malformed endpoint request JSON -> Apple status 21002 value", Op.EndpointSandbox, Encoding.UTF8.GetBytes("{\"receipt-data\": "), n => n["status"]!.GetValue<int>() == 21002),
        })
        {
            var (k, v) = Attempt(i => Dec(i.Invoke(op, input)));
            Ok(name, k == "ok" && check((JsonNode)v!), $"{(v as JsonNode)?.ToJsonString() ?? v}");
        }
        string msg = "";
        try { JsonDocument.Parse("{\"verified\":tru"); } catch (JsonException e) { msg = $"{e.GetType().Name}: {e.Message.Split('.')[0]}"; }
        Ok("malformed result JSON is a host decode error (internal failure), not a verdict", msg.Length > 0, msg);
        {
            var (k, v) = Attempt(i =>
            {
                var a = i.Invoke(R, g5);
                var snap = (byte[])a.Clone();
                for (int n = 0; n < 5; n++) i.Invoke(R, Encoding.UTF8.GetBytes(new string('x', n + 1)));
                return snap.SequenceEqual(a);
            });
            Ok("a result is a host-owned copy (unchanged after later calls reuse guest memory)", k == "ok" && (bool)v!);
        }
        {
            var (k, v) = Attempt(i =>
            {
                for (int n = 0; n < 200; n++) i.Invoke(R, g5);
                long m1 = i.Memory.GetLength();
                for (int n = 0; n < 2000; n++) i.Invoke(R, g5);
                return new[] { m1, i.Memory.GetLength() };
            });
            var a = v as long[];
            Ok("no growth of linear memory over 2,000 more calls", k == "ok" && a![0] == a[1], a == null ? $"{v}" : string.Join(",", a));
        }
        var fv = new Verifier();
        try { fv.Call(R, g5, 2); Ok("facade: a version mismatch throws AbiMismatchException", false); }
        catch (AbiMismatchException e) { Ok("facade: a version mismatch throws AbiMismatchException", e.Message.Contains("module=1, caller=2"), e.Message); }
        try { fv.Call(99, Array.Empty<byte>()); Ok("facade: an unknown operation throws WasmTrapException", false); }
        catch (WasmTrapException e) { Ok("facade: an unknown operation throws WasmTrapException (internal failure)", true, e.Message.Split('\n')[0]); }
        using (var again = fv.VerifyReceipt(Encoding.UTF8.GetString(g5)))
            Ok("facade: after a trap the next call runs on a fresh instance and verifies", again.RootElement.GetProperty("verified").GetBoolean() && fv.Traps == 1, $"traps {fv.Traps}");
        using (var bad = fv.VerifyReceipt("not base64!"))
            Ok("facade: a verification failure is a value", !bad.RootElement.GetProperty("verified").GetBoolean() && bad.RootElement.GetProperty("reason").GetString() == "INVALID_RECEIPT_FORMAT", bad.RootElement.GetRawText());
        Console.WriteLine($"summary: {passed} passed, {failed} failed");
        return failed == 0 ? 0 : 1;
    }
}
