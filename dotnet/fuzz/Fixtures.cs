using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace ApplePurchaseReceiptVerifier.Fuzz
{
    /// <summary>
    /// The two generated fixture roots the anchor-set invariants need, loaded
    /// from <c>fixtures/</c> at startup.
    /// </summary>
    /// <remarks>
    /// Read from the shared directory rather than embedded, so nothing under
    /// <c>fixtures/</c> is copied into <c>dotnet/</c> and a regenerated
    /// fixture cannot go stale here. <c>APRV_FIXTURES</c> overrides the search
    /// for a caller running the binary from somewhere unusual.
    /// </remarks>
    internal static class Fixtures
    {
        /// <summary>The <c>fixtures/</c> directory.</summary>
        internal static readonly string Root = Find();

        /// <summary>The generated fake-Apple receipt root.</summary>
        internal static X509Certificate2 ReceiptRoot() => Load("generated/receipt-root.der");

        /// <summary>The generated fake-Apple JWS root.</summary>
        internal static X509Certificate2 JwsRoot() => Load("generated/jws-root.der");

        private static X509Certificate2 Load(string relative)
        {
            string path = Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar));
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadCertificate(File.ReadAllBytes(path));
#else
            return new X509Certificate2(File.ReadAllBytes(path));
#endif
        }

        private static string Find()
        {
            string? configured = Environment.GetEnvironmentVariable("APRV_FIXTURES");
            if (!string.IsNullOrEmpty(configured))
            {
                return configured!;
            }

            // Walk up rather than hardcode a depth, exactly as the test suite's
            // Fixtures does: the relative depth moves with the output layout.
            DirectoryInfo? directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory is not null)
            {
                string candidate = Path.Combine(directory.FullName, "fixtures");
                if (File.Exists(Path.Combine(candidate, "cases.json")))
                {
                    return candidate;
                }

                directory = directory.Parent;
            }

            throw new InvalidOperationException(
                "could not find the fixtures directory; set APRV_FIXTURES");
        }
    }
}
