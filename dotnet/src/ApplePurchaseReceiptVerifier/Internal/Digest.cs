using System;
using System.Security.Cryptography;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>Computes a message digest by name, on both target frameworks.</summary>
    internal static class Digest
    {
        internal static byte[] Compute(HashAlgorithmName name, byte[] data)
        {
            using (HashAlgorithm algorithm = Create(name))
            {
                return algorithm.ComputeHash(data);
            }
        }

        private static HashAlgorithm Create(HashAlgorithmName name)
        {
            if (name == HashAlgorithmName.MD5)
            {
                return MD5.Create();
            }

            if (name == HashAlgorithmName.SHA1)
            {
                return SHA1.Create();
            }

            if (name == HashAlgorithmName.SHA256)
            {
                return SHA256.Create();
            }

            if (name == HashAlgorithmName.SHA384)
            {
                return SHA384.Create();
            }

            if (name == HashAlgorithmName.SHA512)
            {
                return SHA512.Create();
            }

            throw new NotSupportedException("unsupported digest algorithm " + name);
        }
    }
}
