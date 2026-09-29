using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>Byte helpers that must behave identically on every target framework.</summary>
    internal static class ByteOps
    {
        /// <summary>A defensive copy; <see langword="null"/> stays <see langword="null"/>.</summary>
        internal static byte[]? Copy(byte[]? value)
        {
            if (value is null)
            {
                return null;
            }

            byte[] copy = new byte[value.Length];
            Buffer.BlockCopy(value, 0, copy, 0, value.Length);
            return copy;
        }

        /// <summary>
        /// A read-only deep copy of raw attributes: a fresh dictionary, fresh
        /// lists and fresh arrays, so nothing the caller still holds can change
        /// a payload built from it.
        /// </summary>
        internal static IReadOnlyDictionary<int, IReadOnlyList<byte[]>> CopyAttributes(
            IReadOnlyDictionary<int, IReadOnlyList<byte[]>> attributes,
            string parameterName)
        {
            if (attributes is null)
            {
                throw new ArgumentNullException(parameterName);
            }

            Dictionary<int, IReadOnlyList<byte[]>> copy = new Dictionary<int, IReadOnlyList<byte[]>>(attributes.Count);
            foreach (KeyValuePair<int, IReadOnlyList<byte[]>> entry in attributes)
            {
                byte[][] values = new byte[entry.Value.Count][];
                for (int i = 0; i < values.Length; i++)
                {
                    values[i] = Copy(entry.Value[i]) ?? throw new ArgumentNullException(parameterName, "an attribute value is null");
                }

                copy.Add(entry.Key, Array.AsReadOnly(values));
            }

            return new ReadOnlyDictionary<int, IReadOnlyList<byte[]>>(copy);
        }
    }
}
