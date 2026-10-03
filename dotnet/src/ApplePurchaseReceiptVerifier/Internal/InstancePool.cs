using System;
using System.Collections.Concurrent;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// The instances one <see cref="IVerifier"/> owns. A caller takes an idle
    /// instance or gets a fresh one, uses it alone, and hands it back; an
    /// instance that trapped, or that failed in any other way, is disposed
    /// instead, with everything in it.
    /// </summary>
    /// <remarks>
    /// Every instance is given <c>init</c> once, with the verifier's roots,
    /// before anybody uses it. There is nothing to close: instances die with
    /// the verifier, and an abandoned store is released by its finalizer.
    /// </remarks>
    internal sealed class InstancePool
    {
        /// <summary>An instance that grew past this much memory is not kept: a hostile input inflated it.</summary>
        internal const long RetainMemoryBytes = 64L * 1024 * 1024;

        private readonly AprvRuntime _runtime;
        private readonly byte[] _configJson;
        private readonly ConcurrentStack<AprvInstance> _idle = new ConcurrentStack<AprvInstance>();
        private readonly int _maxIdle = Math.Max(2, Environment.ProcessorCount);
        private int _idleCount;

        /// <summary>
        /// Builds the pool and its first instance, so a module that does not
        /// fit this library, or a root <c>init</c> refuses, fails here.
        /// </summary>
        /// <exception cref="ArgumentException"><c>init</c> refused the roots.</exception>
        /// <exception cref="InvalidOperationException">The module cannot be hosted.</exception>
        internal InstancePool(AprvRuntime runtime, byte[] configJson)
        {
            _runtime = runtime;
            _configJson = configJson;
            Return(Create());
        }

        /// <summary>An idle instance, or a new one.</summary>
        internal AprvInstance Rent()
        {
            if (_idle.TryPop(out AprvInstance? instance))
            {
                System.Threading.Interlocked.Decrement(ref _idleCount);
                return instance;
            }

            return Create();
        }

        /// <summary>Hands back an instance that finished its call without a failure.</summary>
        internal void Return(AprvInstance instance)
        {
            if (instance.MemoryBytes <= RetainMemoryBytes)
            {
                if (System.Threading.Interlocked.Increment(ref _idleCount) <= _maxIdle)
                {
                    _idle.Push(instance);
                    return;
                }

                System.Threading.Interlocked.Decrement(ref _idleCount);
            }

            instance.Dispose();
        }

        /// <summary>Throws away an instance that trapped or otherwise failed.</summary>
        internal void Discard(AprvInstance instance) => instance.Dispose();

        private AprvInstance Create()
        {
            AprvInstance instance = new AprvInstance(_runtime);
            try
            {
                instance.Start(_configJson);
                return instance;
            }
            catch
            {
                instance.Dispose();
                throw;
            }
        }
    }
}
