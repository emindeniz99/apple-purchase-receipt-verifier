using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ApplePurchaseReceiptVerifier.Internal
{
    /// <summary>Certificate loading, in one place so both TFMs use one code path.</summary>
    internal static class Certificates
    {
        /// <summary>
        /// Loads a DER certificate, or returns <see langword="null"/> when the
        /// bytes are not one.
        /// </summary>
        /// <remarks>
        /// The <c>X509Certificate2(byte[])</c> constructor is the only spelling
        /// available on the netstandard2.0 floor, so it is used on both targets
        /// rather than forking behaviour per framework.
        /// </remarks>
        internal static X509Certificate2? TryLoad(byte[] der)
        {
            if (der is null || der.Length == 0)
            {
                return null;
            }

            try
            {
#pragma warning disable SYSLIB0057
                return new X509Certificate2(der);
#pragma warning restore SYSLIB0057
            }
            catch (CryptographicException)
            {
                return null;
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        /// <summary>Snapshots caller-supplied anchors so the caller may dispose theirs.</summary>
        /// <exception cref="ArgumentException">The set is null or empty.</exception>
        internal static List<X509Certificate2> CopyAnchors(
            IEnumerable<X509Certificate2>? trustedRoots, string parameterName)
        {
            if (trustedRoots is null)
            {
                throw new ArgumentException("trustedRoots must not be empty", parameterName);
            }

            List<X509Certificate2> anchors = new List<X509Certificate2>();
            foreach (X509Certificate2 root in trustedRoots)
            {
                if (root is null)
                {
                    throw new ArgumentException("trustedRoots must not contain null", parameterName);
                }

                X509Certificate2? copy = TryLoad(root.RawData);
                if (copy is null)
                {
                    throw new ArgumentException("trustedRoots contains an unreadable certificate", parameterName);
                }

                anchors.Add(copy);
            }

            if (anchors.Count == 0)
            {
                throw new ArgumentException("trustedRoots must not be empty", parameterName);
            }

            return anchors;
        }
    }
}
