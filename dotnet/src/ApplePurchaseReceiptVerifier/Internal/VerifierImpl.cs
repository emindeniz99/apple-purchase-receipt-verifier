using System;
using System.Text;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// The one <see cref="IVerifier"/> implementation: a thin host for
    /// <c>aprv.wasm</c>. It reads the configured clock once per call, before
    /// it looks at the input, moves the input in as UTF-8 bytes, reads the
    /// module's JSON answer back into the public types and reports a trap or
    /// an unreadable answer as <see cref="VerificationReason.InternalError"/>.
    /// It parses no receipt, checks no signature and decides no trust.
    /// Immutable, thread-safe, never throws for any input.
    /// </summary>
    internal sealed class VerifierImpl : IVerifier
    {
        /// <summary>What the endpoint answers when the wrapper itself failed (a trap, an unreadable answer, the clock).</summary>
        private const string EndpointInternalError = "{\"status\":21009}";

        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, false);

        private readonly Func<long> _clock;
        private readonly InstancePool _pool;

        internal VerifierImpl(Config config)
            : this(config, AprvRuntime.Shared)
        {
        }

        internal VerifierImpl(Config config, AprvRuntime runtime)
        {
            _clock = config.Clock;
            _pool = new InstancePool(runtime, ConfigJson(config));
        }

        /// <summary>The instances this verifier owns, for tests that look inside one.</summary>
        internal InstancePool Pool => _pool;

        public VerificationResult<ReceiptPayload> VerifyReceipt(string base64)
        {
            return Run(
                (instance, now, input) => instance.VerifyReceipt(now, input),
                base64,
                ModuleAnswers.ReadReceipt,
                (reason, message, cause) => VerificationResult<ReceiptPayload>.Failed(reason, message, cause));
        }

        public VerificationResult<JsonPayload> VerifySignedData(string jws)
        {
            return Run(
                (instance, now, input) => instance.VerifySignedData(now, input),
                jws,
                ModuleAnswers.ReadSignedData,
                (reason, message, cause) => VerificationResult<JsonPayload>.Failed(reason, message, cause));
        }

        public string VerifyReceiptEndpoint(AppleEnvironment environment, string requestJson)
        {
            if (environment != AppleEnvironment.Production && environment != AppleEnvironment.Sandbox)
            {
                throw new ArgumentOutOfRangeException(nameof(environment));
            }

            int env = environment == AppleEnvironment.Production ? 0 : 1;
            return Run(
                (instance, now, input) => instance.VerifyReceiptEndpoint(env, now, input),
                requestJson,
                answer => answer,
                (_, _, _) => EndpointInternalError);
        }

        /// <summary>The <c>init</c> configuration: <c>{}</c> for the module's built-in roots, else each root's DER as base64.</summary>
        internal static byte[] ConfigJson(Config config)
        {
            System.Collections.Generic.IReadOnlyList<byte[]>? roots = config.RootDer;
            if (roots is null)
            {
                return Utf8.GetBytes("{}");
            }

            StringBuilder json = new StringBuilder("{\"roots\":[");
            for (int i = 0; i < roots.Count; i++)
            {
                json.Append(i == 0 ? "\"" : ",\"").Append(Convert.ToBase64String(roots[i])).Append('"');
            }

            return Utf8.GetBytes(json.Append("]}").ToString());
        }

        private TResult Run<TResult>(
            Func<AprvInstance, long, byte[], string> call,
            string? input,
            Func<string, TResult> read,
            Func<VerificationReason, string, Exception, TResult> failed)
        {
            long now;
            try
            {
                now = CallClock.Read(_clock);
                if (now < 0)
                {
                    throw new VerificationException(
                        VerificationReason.InternalError, "the configured clock answered a negative time");
                }
            }
            catch (VerificationException e)
            {
                return failed(e.Reason, e.Detail, e.InnerException ?? e);
            }

            AprvInstance instance;
            try
            {
                instance = _pool.Rent();
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                return failed(VerificationReason.InternalError, "the verification module could not be started", e);
            }

            string answer;
            try
            {
                answer = call(instance, now, Utf8.GetBytes(input ?? string.Empty));
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                _pool.Discard(instance);
                return failed(VerificationReason.InternalError, "the verification module failed", e);
            }

            try
            {
                TResult result = read(answer);
                _pool.Return(instance);
                return result;
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                _pool.Discard(instance);
                return failed(VerificationReason.InternalError, "the verification module's answer is unreadable", e);
            }
        }
    }
}
