using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier;
using ApplePurchaseReceiptVerifier.Receipt;

internal static class Program
{
    private static int Main(string[] args)
    {
        string fixtures = args.Length > 0 ? args[0] : FindFixtures();
        byte[] der = File.ReadAllBytes(Path.Combine(fixtures, "generated", "receipt.der"));
        X509Certificate2 root = X509CertificateLoader.LoadCertificate(
            File.ReadAllBytes(Path.Combine(fixtures, "generated", "receipt-root.der")));

        using ReceiptVerifier verifier = new(new[] { root }, "com.example.app");
        AppReceipt receipt = verifier.Verify(der);
        if (receipt.BundleId != "com.example.app" || receipt.InAppPurchases.Count != 2)
        {
            Console.Error.WriteLine("trimmed verification returned the wrong receipt");
            return 1;
        }

        using ReceiptVerifier pinned = new(AppleRootCertificates.ReceiptRoots(), "com.example.app");
        try
        {
            pinned.Verify(der);
            Console.Error.WriteLine("a foreign chain was accepted after trimming");
            return 1;
        }
        catch (VerificationException e) when (e.Reason == VerificationReason.InvalidChain)
        {
        }

        Console.WriteLine("trimmed smoke ok: " + receipt.BundleId);
        return 0;
    }

    private static string FindFixtures()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, "fixtures");
            if (File.Exists(Path.Combine(candidate, "cases.json")))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("could not locate fixtures/");
    }
}
