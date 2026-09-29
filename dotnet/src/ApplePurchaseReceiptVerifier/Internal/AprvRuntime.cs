using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Wasmtime;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// The process-wide half of the Wasm host: one <see cref="Wasmtime.Engine"/>,
    /// one compiled <see cref="Wasmtime.Module"/> and one <see cref="Wasmtime.Linker"/>
    /// holding the module's single import. A <see cref="Store"/> and an instance
    /// are per <see cref="AprvInstance"/>, never shared.
    /// </summary>
    /// <remarks>
    /// <para>The module is <c>aprv.wasm</c>, embedded in this assembly. Its
    /// SHA-256 is checked against <c>aprv.wasm.sha256</c>, embedded beside it,
    /// the first time the runtime is built; the release overwrites both files
    /// with the build it publishes.</para>
    /// <para>The module must import exactly one function, <c>random-get</c>,
    /// and export the <c>aprv:verifier@1.0.0</c> canonical-ABI operations.
    /// Anything else is refused here, once, as an
    /// <see cref="InvalidOperationException"/> naming what was found: it is
    /// a mismatch between this library and its module, never a verdict.</para>
    /// </remarks>
    internal sealed class AprvRuntime
    {
        /// <summary>The ABI's interface prefix; export names carry the ABI version.</summary>
        internal const string Iface = "aprv:verifier/verify@1.0.0#";

        /// <summary>The module name of the one import.</summary>
        internal const string HostModule = "aprv:verifier/host@1.0.0";

        /// <summary>The name of the one import.</summary>
        internal const string RandomGetName = "random-get";

        /// <summary>The four operations, in the order the WIT lists them.</summary>
        internal static readonly string[] Operations =
        {
            "init", "verify-receipt", "verify-signed-data", "verify-receipt-endpoint",
        };

        /// <summary>The most bytes one <c>random-get</c> may ask for; OpenSSL asks for a few dozen.</summary>
        private const int MaxRandomBytes = 1 << 20;

        private static readonly RandomNumberGenerator SecureRandom = RandomNumberGenerator.Create();

        private static readonly Lazy<AprvRuntime> SharedRuntime = new Lazy<AprvRuntime>(
            () => new AprvRuntime(LoadEmbeddedModule(), null),
            LazyThreadSafetyMode.ExecutionAndPublication);

        private readonly Func<int, byte[]> _random;

        /// <summary>Compiles <paramref name="wasm"/> and defines its one import.</summary>
        /// <param name="wasm">The module's bytes.</param>
        /// <param name="random">
        /// Where <c>random-get</c> draws from; <see langword="null"/> means the
        /// operating system's CSPRNG. A seam for tests that make the host
        /// answer the wrong length.
        /// </param>
        internal AprvRuntime(byte[] wasm, Func<int, byte[]>? random)
        {
            _random = random ?? DrawRandom;
            Engine = new Engine();
            Module = Module.FromBytes(Engine, "aprv", wasm);
            CheckImports(Module);
            CheckExports(Module);
            Linker = new Linker(Engine);
            Linker.DefineFunction(HostModule, RandomGetName, (Caller caller, int length, int retptr) => RandomGet(caller, length, retptr));
        }

        /// <summary>The runtime built from the embedded module, on first use.</summary>
        internal static AprvRuntime Shared => SharedRuntime.Value;

        /// <summary>The engine every store of this runtime belongs to.</summary>
        internal Engine Engine { get; }

        /// <summary>The compiled module.</summary>
        internal Module Module { get; }

        /// <summary>The linker holding <c>random-get</c>.</summary>
        internal Linker Linker { get; }

        /// <summary>The embedded module's bytes, after the SHA-256 check.</summary>
        internal static byte[] LoadEmbeddedModule()
        {
            System.Reflection.Assembly assembly = typeof(AprvRuntime).Assembly;
            return CheckedModule(
                ReadResource(assembly, "aprv.wasm"),
                Encoding.UTF8.GetString(ReadResource(assembly, "aprv.wasm.sha256")));
        }

        /// <summary>
        /// <paramref name="wasm"/> when its SHA-256 is the one <paramref name="recorded"/>
        /// names: the hash alone, or <c>sha256sum</c>'s <c>hash  file</c> line.
        /// </summary>
        /// <exception cref="InvalidOperationException">The module is not the recorded one.</exception>
        internal static byte[] CheckedModule(byte[] wasm, string recorded)
        {
            string trimmed = recorded.Trim();
            int space = trimmed.IndexOfAny(new[] { ' ', '\t' });
            string expected = (space < 0 ? trimmed : trimmed.Substring(0, space)).ToLowerInvariant();
            string actual = Hex(Sha256(wasm));
            if (!string.Equals(expected, actual, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "the embedded aprv.wasm does not match its recorded SHA-256 (recorded "
                    + expected + ", found " + actual + ")");
            }

            return wasm;
        }

        private static byte[] ReadResource(System.Reflection.Assembly assembly, string name)
        {
            using (Stream stream = assembly.GetManifestResourceStream(name)
                ?? throw new InvalidOperationException(name + " is missing from the assembly"))
            using (MemoryStream copy = new MemoryStream())
            {
                stream.CopyTo(copy);
                return copy.ToArray();
            }
        }

        private static byte[] Sha256(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return sha.ComputeHash(data);
            }
        }

        private static string Hex(byte[] value)
        {
            StringBuilder builder = new StringBuilder(value.Length * 2);
            foreach (byte b in value)
            {
                builder.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            }

            return builder.ToString();
        }

        private static byte[] DrawRandom(int length)
        {
            byte[] bytes = new byte[length];
            SecureRandom.GetBytes(bytes);
            return bytes;
        }

        /// <summary>
        /// The one import, <c>random-get: func(len: u32) -> list&lt;u8&gt;</c>,
        /// lowered as <c>(len, retptr)</c>: the list is allocated in guest
        /// memory with the guest's own <c>cabi_realloc</c>, and its address and
        /// length are written at <c>retptr</c>. The guest traps when the length
        /// it gets back is not the one it asked for.
        /// </summary>
        private void RandomGet(Caller caller, int length, int retptr)
        {
            uint requested = unchecked((uint)length);
            if (requested > MaxRandomBytes)
            {
                throw new InvalidOperationException("random-get asked for " + requested.ToString(CultureInfo.InvariantCulture) + " bytes");
            }

            Wasmtime.Memory memory = caller.GetMemory("memory")
                ?? throw new InvalidOperationException("the module exports no memory");
            Function realloc = caller.GetFunction("cabi_realloc")
                ?? throw new InvalidOperationException("the module exports no cabi_realloc");

            byte[] bytes = _random((int)requested);
            object? allocated = realloc.Invoke(0, 0, 1, bytes.Length);
            int address = allocated is int value ? value : throw new InvalidOperationException("cabi_realloc returned no address");
            long size = memory.GetLength();
            long start = unchecked((uint)address);
            long slot = unchecked((uint)retptr);
            if (start + bytes.Length > size || slot + 8 > size)
            {
                throw new InvalidOperationException("random-get wrote outside the module's memory");
            }

            if (bytes.Length > 0)
            {
                bytes.AsSpan().CopyTo(memory.GetSpan(start, bytes.Length));
            }

            memory.WriteInt32(slot, address);
            memory.WriteInt32(slot + 4, bytes.Length);
        }

        private static void CheckImports(Wasmtime.Module module)
        {
            List<string> found = new List<string>();
            foreach (Import import in module.Imports)
            {
                found.Add(import.ModuleName + "." + import.Name);
            }

            string expected = HostModule + "." + RandomGetName;
            if (found.Count != 1 || found[0] != expected)
            {
                throw new InvalidOperationException(
                    "aprv.wasm must import exactly " + expected + "; it imports: "
                    + (found.Count == 0 ? "nothing" : string.Join(", ", found)));
            }
        }

        private static void CheckExports(Wasmtime.Module module)
        {
            HashSet<string> exported = new HashSet<string>(StringComparer.Ordinal);
            foreach (Export export in module.Exports)
            {
                exported.Add(export.Name);
            }

            List<string> missing = new List<string>();
            foreach (string operation in Operations)
            {
                Require(exported, Iface + operation, missing);
                Require(exported, "cabi_post_" + Iface + operation, missing);
            }

            Require(exported, "cabi_realloc", missing);
            Require(exported, "memory", missing);
            if (missing.Count != 0)
            {
                List<string> names = new List<string>(exported);
                names.Sort(StringComparer.Ordinal);
                throw new InvalidOperationException(
                    "aprv.wasm does not export the aprv:verifier@1.0.0 ABI this library binds (missing: "
                    + string.Join(", ", missing) + "); it exports: " + string.Join(", ", names));
            }
        }

        private static void Require(HashSet<string> exported, string name, List<string> missing)
        {
            if (!exported.Contains(name))
            {
                missing.Add(name);
            }
        }
    }
}
