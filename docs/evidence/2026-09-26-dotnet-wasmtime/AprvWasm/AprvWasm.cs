// Spike only (2026-09-26). A minimal .NET facade over aprv.wasm (ABI v1) on
// the official Bytecode Alliance Wasmtime package.
//
//   var v = new Verifier();                     // one per thread; never shared
//   JsonDocument r = v.VerifyReceipt(data);     // verified + payload, or verified=false + reason
//   JsonDocument j = v.VerifySignedData(jws);   // + payloadJson
//   string a = v.VerifyReceiptEndpoint(true, body);   // the verifyReceipt answer, byte for byte
//
// No business policy: the caller compares bundleId, environment and
// appAppleId. A verification failure is a value; AbiMismatchException and
// WasmTrapException are exceptions, and a trap discards the instance.
//
// Engine, compiled Module and a Linker with the two host functions are
// process-wide (AprvRuntime.Shared); each Verifier owns a Store + Instance.
// Lifecycle of Invoke: alloc, copy in, aprv_call, bounds-check, copy out,
// aprv_result_free, dealloc. No guest pointer leaves it.
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using Wasmtime;

namespace Aprv.Wasm
{
    public sealed class AbiMismatchException : Exception
    {
        public AbiMismatchException(int module, int caller) : base($"APRV Wasm ABI mismatch: module={module}, caller={caller}") { }
    }

    public sealed class WasmTrapException : Exception
    {
        public WasmTrapException(string message, Exception? inner = null) : base(message, inner) { }
    }

    public static class Op
    {
        public const int VerifyReceipt = 1, VerifySignedData = 2, EndpointProduction = 3, EndpointSandbox = 4;
    }

    public sealed class AprvRuntime
    {
        public const int AbiVersion = 1;
        public Engine Engine { get; }
        public Module Module { get; }
        public Linker Linker { get; }
        // Host-function calls, process-wide (for the tests).
        public static long ClockCalls, RandomCalls;

        public AprvRuntime(byte[] wasm)
        {
            Engine = new Engine();
            Module = Module.FromBytes(Engine, "aprv", wasm);
            foreach (var i in Module.Imports)
            {
                if (i.ModuleName != "aprv" || (i.Name != "clock_now_ms" && i.Name != "random_get"))
                    throw new InvalidOperationException($"unexpected import {i.ModuleName}.{i.Name}");
            }
            Linker = new Linker(Engine);
            Linker.DefineFunction("aprv", "clock_now_ms", () =>
            {
                Interlocked.Increment(ref ClockCalls);
                return (double)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            });
            Linker.DefineFunction("aprv", "random_get", (Caller caller, int ptr, int len) =>
            {
                Interlocked.Increment(ref RandomCalls);
                var memory = caller.GetMemory("memory") ?? throw new WasmTrapException("no memory");
                long p = (uint)ptr, n = (uint)len;
                if (p + n > memory.GetLength()) throw new WasmTrapException("aprv.random_get out of bounds");
                if (n > 0)
                {
                    var bytes = new byte[n];
                    using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes);
                    bytes.AsSpan().CopyTo(memory.GetSpan(p, (int)n));
                }
                return 0;
            });
        }

        static readonly Lazy<AprvRuntime> shared = new Lazy<AprvRuntime>(() =>
        {
            using var s = typeof(AprvRuntime).Assembly.GetManifestResourceStream("aprv.wasm")
                ?? throw new InvalidOperationException("aprv.wasm missing from the assembly");
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            return new AprvRuntime(ms.ToArray());
        }, LazyThreadSafetyMode.ExecutionAndPublication);

        public static AprvRuntime Shared => shared.Value;
    }

    /// <summary>One Store + Instance. Not thread-safe.</summary>
    public sealed class AprvInstance : IDisposable
    {
        public Store Store { get; }
        public Instance Instance { get; }
        public Memory Memory { get; }
        public int ModuleVersion { get; }
        readonly Func<int, int> alloc;
        readonly Action<int, int> dealloc;
        readonly Func<int, int, int, int, int> call;
        readonly Func<int, int> resultPtr, resultLen;
        readonly Action<int> resultFree;

        public AprvInstance(AprvRuntime? runtime = null)
        {
            runtime ??= AprvRuntime.Shared;
            Store = new Store(runtime.Engine);
            Instance = runtime.Linker.Instantiate(Store, runtime.Module);
            Memory = Instance.GetMemory("memory") ?? throw new InvalidOperationException("no memory");
            alloc = Instance.GetFunction<int, int>("aprv_alloc")!;
            dealloc = Instance.GetAction<int, int>("aprv_dealloc")!;
            call = Instance.GetFunction<int, int, int, int, int>("aprv_call")!;
            resultPtr = Instance.GetFunction<int, int>("aprv_result_ptr")!;
            resultLen = Instance.GetFunction<int, int>("aprv_result_len")!;
            resultFree = Instance.GetAction<int>("aprv_result_free")!;
            Instance.GetAction("_initialize")!();
            ModuleVersion = Instance.GetFunction<int>("aprv_abi_version")!();
            if (ModuleVersion != AprvRuntime.AbiVersion) throw new AbiMismatchException(ModuleVersion, AprvRuntime.AbiVersion);
        }

        /// <summary>The whole lifecycle. <paramref name="abiVersion"/> other than 1 only for the ABI tests.</summary>
        public byte[] Invoke(int operation, byte[] input, int abiVersion = AprvRuntime.AbiVersion)
        {
            int n = input.Length;
            int p = alloc(n);
            if (p == 0) throw new OutOfMemoryException($"aprv_alloc({n}) failed");
            if (n > 0) input.AsSpan().CopyTo(Memory.GetSpan((uint)p, n));
            int h;
            try
            {
                h = call(abiVersion, operation, p, n);
            }
            catch (TrapException) when (abiVersion != ModuleVersion)
            {
                throw new AbiMismatchException(ModuleVersion, abiVersion);
            }
            long rp = (uint)resultPtr(h), rn = (uint)resultLen(h);
            if (rp + rn > Memory.GetLength()) throw new WasmTrapException("result out of bounds");
            byte[] output = Memory.GetSpan(rp, (int)rn).ToArray(); // a copy owned by .NET
            resultFree(h);
            dealloc(p, n);
            return output;
        }

        public void Dispose() => Store.Dispose();
    }

    /// <summary>The facade: one per thread. A trap discards the instance.</summary>
    public sealed class Verifier : IDisposable
    {
        AprvInstance? current;
        public int Traps { get; private set; }

        public Verifier() => current = new AprvInstance();

        public byte[] Call(int operation, byte[] input, int abiVersion = AprvRuntime.AbiVersion)
        {
            current ??= new AprvInstance();
            try
            {
                return current.Invoke(operation, input, abiVersion);
            }
            catch (Exception e) when (e is WasmtimeException || e is WasmTrapException)
            {
                Traps++;
                Discard();
                throw new WasmTrapException(e.Message, e);
            }
            catch (AbiMismatchException)
            {
                Discard();
                throw;
            }
        }

        void Discard()
        {
            current?.Dispose();
            current = null;
        }

        public JsonDocument VerifyReceipt(string receiptData) => JsonDocument.Parse(Call(Op.VerifyReceipt, Encoding.UTF8.GetBytes(receiptData)));

        public JsonDocument VerifySignedData(string jws) => JsonDocument.Parse(Call(Op.VerifySignedData, Encoding.UTF8.GetBytes(jws)));

        public string VerifyReceiptEndpoint(bool production, byte[] body) =>
            Encoding.UTF8.GetString(Call(production ? Op.EndpointProduction : Op.EndpointSandbox, body));

        public void Dispose() => Discard();
    }
}
