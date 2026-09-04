using System;
using System.Collections;
using System.Collections.Generic;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>
    /// An insertion-ordered string-keyed map. JSON key order is not part of any
    /// contract here, but a deterministic order makes equal inputs serialize to
    /// equal bytes, which the endpoint's callers rely on for caching and
    /// diffing. <c>Dictionary&lt;,&gt;</c> does not promise that.
    /// </summary>
    internal sealed class OrderedMap : IReadOnlyDictionary<string, object?>
    {
        private readonly List<string> _order = new List<string>();
        private readonly Dictionary<string, object?> _values = new Dictionary<string, object?>(StringComparer.Ordinal);

        /// <inheritdoc/>
        public int Count => _order.Count;

        /// <inheritdoc/>
        public IEnumerable<string> Keys => _order;

        /// <inheritdoc/>
        public IEnumerable<object?> Values
        {
            get
            {
                foreach (string key in _order)
                {
                    yield return _values[key];
                }
            }
        }

        /// <inheritdoc/>
        public object? this[string key] => _values[key];

        /// <summary>Adds or replaces <paramref name="key"/>, keeping its original position.</summary>
        internal void Set(string key, object? value)
        {
            if (!_values.ContainsKey(key))
            {
                _order.Add(key);
            }

            _values[key] = value;
        }

        /// <summary>Adds <paramref name="key"/> only when <paramref name="value"/> is not null.</summary>
        internal void SetIfPresent(string key, object? value)
        {
            if (value is not null)
            {
                Set(key, value);
            }
        }

        /// <inheritdoc/>
        public bool ContainsKey(string key) => _values.ContainsKey(key);

        /// <inheritdoc/>
        public bool TryGetValue(string key, out object? value) => _values.TryGetValue(key, out value);

        /// <inheritdoc/>
        public IEnumerator<KeyValuePair<string, object?>> GetEnumerator()
        {
            foreach (string key in _order)
            {
                yield return new KeyValuePair<string, object?>(key, _values[key]);
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
