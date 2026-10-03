using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Wasmtime;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// One <see cref="Store"/> and one instance of <c>aprv.wasm</c>: the
    /// canonical ABI called by hand over the core module's exports. Not
    /// thread-safe: one call at a time, which <see cref="InstancePool"/>
    /// guarantees by handing an instance to one caller at a time.
    /// </summary>
    /// <remarks>
    /// <para>A call is: <c>cabi_realloc</c> for the input and a copy in (the
    /// guest owns that buffer and frees it), the export by its
    /// <c>@0.1.0</c> name with the scalars first and then <c>(ptr, len)</c>,
    /// the return area at the returned address read as <c>ptr</c> then
    /// <c>len</c> and bounds-checked against the memory, a copy out, and
    /// <c>cabi_post</c> to free the result. No guest pointer outlives a
    /// call and none is exposed.</para>
    /// <para>After a trap, or any exception out of a call, the instance is
    /// finished: a hand-rolled host must discard it, because the runtime lets
    /// a trapped instance keep answering. <see cref="InstancePool"/> does.</para>
    /// <para>The store is limited to one instance and 256 MiB of linear
    /// memory. A module that grows past that fails its own allocation, which
    /// traps.</para>
    /// </remarks>
    internal sealed class AprvInstance : IDisposable
    {
        /// <summary>The most linear memory one instance may hold.</summary>
        internal const long MemoryLimitBytes = 256L * 1024 * 1024;

        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        /// <summary>Each export's WIT parameters in order: <c>w</c> u32, <c>d</c> u64, <c>b</c> list&lt;u8&gt;.</summary>
        private static readonly Dictionary<string, string> Signatures = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["init"] = "b",
            ["verify-receipt"] = "db",
            ["verify-signed-data"] = "db",
            ["verify-receipt-endpoint"] = "wdb",
        };

        private readonly Store _store;
        private readonly Instance _instance;
        private readonly Wasmtime.Memory _memory;
        private readonly Function _realloc;
        private readonly Dictionary<string, Function> _exports = new Dictionary<string, Function>(StringComparer.Ordinal);
        private readonly Dictionary<string, Function> _posts = new Dictionary<string, Function>(StringComparer.Ordinal);

        /// <summary>Instantiates the module in a fresh store. It has not been given <c>init</c> yet.</summary>
        internal AprvInstance(AprvRuntime runtime)
        {
            _store = new Store(runtime.Engine);
            try
            {
                _store.SetLimits(memorySize: MemoryLimitBytes, instances: 1, memories: 1);
                _instance = runtime.Linker.Instantiate(_store, runtime.Module);
                _memory = _instance.GetMemory("memory") ?? throw new InvalidOperationException("the module exports no memory");
                _realloc = _instance.GetFunction("cabi_realloc") ?? throw new InvalidOperationException("the module exports no cabi_realloc");
                Function? initialize = _instance.GetFunction("_initialize");
                initialize?.Invoke();
                foreach (string operation in AprvRuntime.Operations)
                {
                    _exports[operation] = _instance.GetFunction(AprvRuntime.Iface + operation)
                        ?? throw new InvalidOperationException("the module exports no " + AprvRuntime.Iface + operation);
                    _posts[operation] = _instance.GetFunction("cabi_post_" + AprvRuntime.Iface + operation)
                        ?? throw new InvalidOperationException("the module exports no cabi_post_" + AprvRuntime.Iface + operation);
                    CheckShape(operation);
                }
            }
            catch
            {
                _store.Dispose();
                throw;
            }
        }

        /// <summary>The instance's linear memory in bytes right now.</summary>
        internal long MemoryBytes => _memory.GetLength();

        /// <summary>The raw instance, for the ABI misuse tests only.</summary>
        internal Instance Raw => _instance;

        /// <summary>
        /// The most bytes of a verify input that reaches linear memory: the
        /// <c>max_input_bytes</c> this instance's <c>init</c> answer stated
        /// (docs/rust-core/DECISIONS.md R42), one over the module's largest cap.
        /// The module decides every cap on the length before reading a byte, so
        /// a longer input is passed cut to this and gets the same TOO_LARGE
        /// answer the whole input would. <see langword="null"/> before
        /// <see cref="Start"/>, and an input is then passed whole.
        /// </summary>
        internal int? MaxInputBytes { get; private set; }

        /// <summary>
        /// <c>init</c>, once per instance: <c>{"ok":true,"max_input_bytes":N}</c>
        /// or <c>{"ok":false,"message":"..."}</c>.
        /// </summary>
        internal string Init(byte[] configJson) => Call("init", configJson);

        /// <summary>
        /// <c>init</c>, keeping the input length its answer states.
        /// </summary>
        /// <exception cref="ArgumentException"><c>init</c> refused the roots.</exception>
        /// <exception cref="ModuleAnswers.AnswerException">The answer is not init's, or states no input length.</exception>
        internal void Start(byte[] configJson) => MaxInputBytes = ModuleAnswers.CheckInit(Init(configJson));

        /// <summary><c>verify-receipt</c>: the module's JSON answer.</summary>
        internal string VerifyReceipt(long nowMs, byte[] receiptBase64) => Call("verify-receipt", nowMs, receiptBase64);

        /// <summary><c>verify-signed-data</c>: the module's JSON answer.</summary>
        internal string VerifySignedData(long nowMs, byte[] jws) => Call("verify-signed-data", nowMs, jws);

        /// <summary><c>verify-receipt-endpoint</c>: Apple's response JSON. <paramref name="env"/> is 0 or 1.</summary>
        internal string VerifyReceiptEndpoint(int env, long nowMs, byte[] requestJson) =>
            Call("verify-receipt-endpoint", unchecked((uint)env), nowMs, requestJson);

        /// <summary>
        /// An export whose result is a string: lower, call, lift, post-return.
        /// An <see cref="uint"/> is a u32, a <see cref="long"/> a u64 and a
        /// <see cref="byte"/> array a list&lt;u8&gt;; a wrong count or type is an
        /// <see cref="ArgumentException"/> before anything reaches the module.
        /// </summary>
        internal string Call(string operation, params object[] args)
        {
            ValueBox[] core = Lower(operation, args);
            int returnArea = ToAddress(Export(operation).Invoke(core));
            string answer = Lift(returnArea);
            _posts[operation].Invoke(returnArea);
            return answer;
        }

        /// <summary>
        /// Lowers WIT values to core arguments, checked against the export's
        /// WIT signature. A list is copied into a buffer from
        /// <c>cabi_realloc</c>, which the guest takes over, and passed as
        /// <c>(ptr, len)</c>.
        /// </summary>
        internal ValueBox[] Lower(string operation, params object[] args)
        {
            if (!Signatures.TryGetValue(operation, out string? signature) || signature.Length != args.Length)
            {
                throw new ArgumentException(operation + ": unknown export or wrong argument count");
            }

            for (int i = 0; i < args.Length; i++)
            {
                bool ok = signature[i] switch
                {
                    'w' => args[i] is uint,
                    'd' => args[i] is long,
                    _ => args[i] is byte[],
                };
                if (!ok)
                {
                    throw new ArgumentException(
                        operation + ": argument " + i.ToString(CultureInfo.InvariantCulture) + " is "
                        + (args[i]?.GetType().Name ?? "null") + ", the WIT type is " + signature[i]);
                }
            }

            List<ValueBox> core = new List<ValueBox>(args.Length + 1);
            for (int i = 0; i < args.Length; i++)
            {
                switch (signature[i])
                {
                    case 'w':
                        core.Add(unchecked((int)(uint)args[i]));
                        break;
                    case 'd':
                        core.Add((long)args[i]);
                        break;
                    default:
                        byte[] bytes = (byte[])args[i];
                        int count = bytes.Length;
                        if (operation != "init" && MaxInputBytes is int max && count > max)
                        {
                            count = max;
                        }

                        core.Add(Allocate(bytes, count));
                        core.Add(count);
                        break;
                }
            }

            return core.ToArray();
        }

        /// <summary>Frees the store. The instance is unusable afterwards.</summary>
        public void Dispose() => _store.Dispose();

        private Function Export(string operation) => _exports[operation];

        private int Allocate(byte[] bytes, int count)
        {
            int address = ToAddress(_realloc.Invoke(0, 0, 1, count));
            if (count > 0)
            {
                CheckRange(address, count);
                bytes.AsSpan(0, count).CopyTo(_memory.GetSpan(unchecked((uint)address), count));
            }

            return address;
        }

        /// <summary>
        /// Reads the string the return area at <paramref name="returnArea"/>
        /// holds: <c>ptr</c> then <c>len</c>, little-endian u32, both checked
        /// against the memory before anything is read.
        /// </summary>
        private string Lift(int returnArea)
        {
            CheckRange(returnArea, 8);
            long area = unchecked((uint)returnArea);
            int pointer = _memory.ReadInt32(area);
            int length = _memory.ReadInt32(area + 4);
            if (length < 0)
            {
                throw new InvalidOperationException("the module returned a result longer than 2 GiB");
            }

            CheckRange(pointer, length);
            byte[] copy = length == 0 ? Array.Empty<byte>() : _memory.GetSpan(unchecked((uint)pointer), length).ToArray();
            try
            {
                return StrictUtf8.GetString(copy);
            }
            catch (DecoderFallbackException e)
            {
                throw new InvalidOperationException("the module's answer is not UTF-8", e);
            }
        }

        private void CheckRange(int address, int length)
        {
            long start = unchecked((uint)address);
            if (length < 0 || start + length > _memory.GetLength())
            {
                throw new InvalidOperationException(
                    "the module returned a range outside its memory (address " + start.ToString(CultureInfo.InvariantCulture)
                    + ", length " + length.ToString(CultureInfo.InvariantCulture) + ")");
            }
        }

        private static int ToAddress(object? result) =>
            result is int value ? value : throw new InvalidOperationException("the module returned no address");

        /// <summary>
        /// The canonical ABI's flattening of one export: its core parameters
        /// are the scalars and <c>(ptr, len)</c> pairs the WIT signature
        /// implies, and it returns the return-area address.
        /// </summary>
        private void CheckShape(string operation)
        {
            List<ValueKind> expected = new List<ValueKind>();
            foreach (char type in Signatures[operation])
            {
                switch (type)
                {
                    case 'w':
                        expected.Add(ValueKind.Int32);
                        break;
                    case 'd':
                        expected.Add(ValueKind.Int64);
                        break;
                    default:
                        expected.Add(ValueKind.Int32);
                        expected.Add(ValueKind.Int32);
                        break;
                }
            }

            Function export = _exports[operation];
            if (!SameKinds(export.Parameters, expected) || export.Results.Count != 1 || export.Results[0] != ValueKind.Int32)
            {
                throw new InvalidOperationException(
                    "the module's " + AprvRuntime.Iface + operation + " does not have the canonical-ABI shape this library binds");
            }
        }

        private static bool SameKinds(IReadOnlyList<ValueKind> actual, List<ValueKind> expected)
        {
            if (actual.Count != expected.Count)
            {
                return false;
            }

            for (int i = 0; i < actual.Count; i++)
            {
                if (actual[i] != expected[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
