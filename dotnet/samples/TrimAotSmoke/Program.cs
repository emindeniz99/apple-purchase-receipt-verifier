using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier;

internal static class Program
{
    private static int Main(string[] args)
    {
        string fixtures = args.Length > 0 ? args[0] : FindFixtures();
        byte[] der = File.ReadAllBytes(Path.Combine(fixtures, "generated-0.7", "receipt.der"));
        X509Certificate2 root = X509CertificateLoader.LoadCertificate(
            File.ReadAllBytes(Path.Combine(fixtures, "generated-0.7", "receipt-root.der")));
        string base64 = Convert.ToBase64String(der);

        // The module answers inside Wasmtime; a trimmed build must still load
        // it, run it, and pass its text through. The verdicts are read from
        // the endpoint's status, which is the module's own text.
        IVerifier verifier = Verifier.Create(new Config(roots: new[] { root }));
        string request = "{\"receipt-data\":\"" + base64 + "\"}";
        string sandboxResponse = verifier.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, request);
        string productionResponse = verifier.VerifyReceiptEndpoint(AppleEnvironment.Production, request);
        if (!sandboxResponse.Contains("\"status\":0", StringComparison.Ordinal)
            || productionResponse != "{\"status\":21007}")
        {
            Console.Error.WriteLine("trimmed endpoint returned the wrong result");
            return 1;
        }

        IVerifier pinned = Verifier.Create(new Config());
        if (pinned.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, request) != "{\"status\":21003}")
        {
            Console.Error.WriteLine("a foreign chain was accepted after trimming");
            return 1;
        }

        VerificationResult<ReceiptPayload> result = verifier.VerifyReceipt(base64);
        if (result.Verified == (result.Failure is not null))
        {
            Console.Error.WriteLine("trimmed verification broke the result invariant");
            return 1;
        }

        Console.WriteLine("trimmed smoke ok");
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
