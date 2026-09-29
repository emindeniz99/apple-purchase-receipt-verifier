using System;
using System.Text;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// A hand-assembled stand-in for <c>aprv.wasm</c>: the same canonical-ABI
/// exports and the same single import, answering fixed JSON, so the wrapper's
/// own duties (bounds checks, trap recovery, post-return, argument passing,
/// reading answers) are tested without the real module.
/// </summary>
/// <remarks>
/// <para>What each verify export does depends on the first byte of its
/// input, so one module serves every test:</para>
/// <list type="bullet">
/// <item><c>!</c> traps (<c>unreachable</c>);</item>
/// <item><c>G</c> asks the host for 32 random bytes and traps unless it gets
/// 32 back;</item>
/// <item><c>P</c> returns a return-area address outside the memory;</item>
/// <item><c>B</c> returns a pointer and length outside the memory;</item>
/// <item><c>L</c> returns a length over 2 GiB; <c>N</c> a negative one;</item>
/// <item><c>U</c> returns two bytes that are not UTF-8;</item>
/// <item>anything else returns the module's fixed answer for that export.</item>
/// </list>
/// <para>It also exports <c>posts</c> (how many <c>cabi_post</c> calls it has
/// seen), <c>reallocs</c>, <c>last_now</c>, <c>last_env</c> and <c>grow</c>
/// (<c>memory.grow</c>), which the host-level tests read and use.</para>
/// </remarks>
internal sealed class StubModule
{
    private const string Iface = "aprv:verifier/verify@1.0.0#";
    private const int AnswerBase = 1024;
    private const int AnswerStride = 4096;
    private const int NotUtf8 = AnswerBase + (4 * AnswerStride);

    internal string InitAnswer { get; set; } = "{\"ok\":true}";

    internal string ReceiptAnswer { get; set; } = "{\"verified\":false,\"reason\":\"MALFORMED\",\"message\":\"stub receipt\"}";

    internal string SignedDataAnswer { get; set; } = "{\"verified\":false,\"reason\":\"MALFORMED\",\"message\":\"stub jws\"}";

    internal string EndpointAnswer { get; set; } = "{\"status\":21002}";

    /// <summary>Extra WAT items placed in the module, such as another import (which must come first).</summary>
    internal string ExtraImports { get; set; } = string.Empty;

    /// <summary>The version in the export names; the wrapper binds 1.0.0.</summary>
    internal string Version { get; set; } = "1.0.0";

    /// <summary>An export to leave out, by its full name.</summary>
    internal string? DropExport { get; set; }

    /// <summary>The module's memory, allocator, counters and the shared <c>$answer</c> function.</summary>
    private const string Body = """
        (func (export "_initialize"))
        (func (export "posts") (result i32) (global.get $posts))
        (func (export "reallocs") (result i32) (global.get $reallocs))
        (func (export "last_now") (result i64) (global.get $lastNow))
        (func (export "last_env") (result i32) (global.get $lastEnv))
        (func (export "grow") (param i32) (result i32) (memory.grow (local.get 0)))
        (func $answer (param $ptr i32) (param $len i32) (param $off i32) (param $n i32) (result i32)
          (local $c i32)
          (if (i32.gt_u (local.get $len) (i32.const 0))
            (then
              (local.set $c (i32.load8_u (local.get $ptr)))
              (if (i32.eq (local.get $c) (i32.const 33)) (then unreachable))
              (if (i32.eq (local.get $c) (i32.const 71))
                (then
                  (call $random (i32.const 32) (i32.const 520))
                  (if (i32.ne (i32.load (i32.const 524)) (i32.const 32)) (then unreachable))))
              (if (i32.eq (local.get $c) (i32.const 80)) (then (return (i32.const -16))))
              (if (i32.eq (local.get $c) (i32.const 66))
                (then (i32.store (i32.const 512) (i32.const -16)) (i32.store (i32.const 516) (i32.const 16)) (return (i32.const 512))))
              (if (i32.eq (local.get $c) (i32.const 76))
                (then (i32.store (i32.const 512) (local.get $off)) (i32.store (i32.const 516) (i32.const 2147483647)) (return (i32.const 512))))
              (if (i32.eq (local.get $c) (i32.const 78))
                (then (i32.store (i32.const 512) (local.get $off)) (i32.store (i32.const 516) (i32.const -2147483647)) (return (i32.const 512))))
              (if (i32.eq (local.get $c) (i32.const 85))
                (then (i32.store (i32.const 512) (i32.const 17408)) (i32.store (i32.const 516) (i32.const 2)) (return (i32.const 512))))))
          (i32.store (i32.const 512) (local.get $off))
          (i32.store (i32.const 516) (local.get $n))
          (i32.const 512))
        """;

    /// <summary>The module as WebAssembly bytes.</summary>
    internal byte[] ToWasm() => Wasmtime.Module.ConvertText(ToWat());

    internal string ToWat()
    {
        string iface = Iface.Replace("1.0.0", Version, StringComparison.Ordinal);
        StringBuilder wat = new StringBuilder();
        wat.AppendLine("(module");
        wat.AppendLine("  (import \"aprv:verifier/host@1.0.0\" \"random-get\" (func $random (param i32 i32)))");
        wat.AppendLine(ExtraImports);
        wat.AppendLine("  (memory (export \"memory\") 4 65536)");
        wat.AppendLine("  (global $heap (mut i32) (i32.const 65536))");
        wat.AppendLine("  (global $posts (mut i32) (i32.const 0))");
        wat.AppendLine("  (global $reallocs (mut i32) (i32.const 0))");
        wat.AppendLine("  (global $lastNow (mut i64) (i64.const -1))");
        wat.AppendLine("  (global $lastEnv (mut i32) (i32.const -1))");
        Data(wat, AnswerBase, InitAnswer);
        Data(wat, AnswerBase + AnswerStride, ReceiptAnswer);
        Data(wat, AnswerBase + (2 * AnswerStride), SignedDataAnswer);
        Data(wat, AnswerBase + (3 * AnswerStride), EndpointAnswer);
        wat.AppendLine($"  (data (i32.const {NotUtf8}) \"\\ff\\fe\")");
        wat.AppendLine(Body);
        Export(wat, "cabi_realloc", "(param $old i32) (param $osz i32) (param $al i32) (param $n i32) (result i32)",
            "(local $p i32) (global.set $reallocs (i32.add (global.get $reallocs) (i32.const 1))) (local.set $p (global.get $heap)) (global.set $heap (i32.add (global.get $heap) (local.get $n))) (local.get $p)");
        Export(wat, iface + "init", "(param i32 i32) (result i32)",
            $"(call $answer (local.get 0) (local.get 1) (i32.const {AnswerBase}) (i32.const {Bytes(InitAnswer)}))");
        Export(wat, iface + "verify-receipt", "(param i64 i32 i32) (result i32)",
            $"(global.set $lastNow (local.get 0)) (call $answer (local.get 1) (local.get 2) (i32.const {AnswerBase + AnswerStride}) (i32.const {Bytes(ReceiptAnswer)}))");
        Export(wat, iface + "verify-signed-data", "(param i64 i32 i32) (result i32)",
            $"(global.set $lastNow (local.get 0)) (call $answer (local.get 1) (local.get 2) (i32.const {AnswerBase + (2 * AnswerStride)}) (i32.const {Bytes(SignedDataAnswer)}))");
        Export(wat, iface + "verify-receipt-endpoint", "(param i32 i64 i32 i32) (result i32)",
            $"(global.set $lastEnv (local.get 0)) (global.set $lastNow (local.get 1)) (call $answer (local.get 2) (local.get 3) (i32.const {AnswerBase + (3 * AnswerStride)}) (i32.const {Bytes(EndpointAnswer)}))");
        foreach (string operation in new[] { "init", "verify-receipt", "verify-signed-data", "verify-receipt-endpoint" })
        {
            Export(wat, "cabi_post_" + iface + operation, "(param i32)", "(global.set $posts (i32.add (global.get $posts) (i32.const 1)))");
        }

        wat.AppendLine(")");
        return wat.ToString();

        void Export(StringBuilder into, string name, string signature, string body)
        {
            if (name == DropExport)
            {
                return;
            }

            into.AppendLine($"  (func (export \"{name}\") {signature} {body})");
        }
    }

    private static int Bytes(string text) => Encoding.UTF8.GetByteCount(text);

    private static void Data(StringBuilder wat, int offset, string text)
    {
        if (Bytes(text) > AnswerStride)
        {
            throw new ArgumentException("a stub answer must fit in " + AnswerStride + " bytes");
        }

        StringBuilder escaped = new StringBuilder();
        foreach (byte b in Encoding.UTF8.GetBytes(text))
        {
            escaped.Append('\\').Append(b.ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
        }

        wat.AppendLine($"  (data (i32.const {offset}) \"{escaped}\")");
    }
}
