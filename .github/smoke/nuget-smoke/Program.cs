// Smoke-tests the package as published to nuget.org. Everything it touches —
// the verifier, the result types, the bundled root certificates — comes from
// the restored package, so a nupkg missing an asset or its embedded certs fails
// here rather than in a user's build.
using ApplePurchaseReceiptVerifier;

string receiptB64 = File.ReadAllText("receipt-sandbox-g5.b64").Trim();

// Config.Defaults() throws if the bundled roots are missing or unreadable; the
// count catches a package that lost one of them.
Config config = Config.Defaults();
if (config.Roots.Count != 3)
{
    throw new Exception($"expected three bundled Apple roots, got {config.Roots.Count}");
}
IVerifier verifier = Verifier.Create(config);

// A real Apple-signed receipt against the real pinned root: exercises the
// packaged certs, the DER reader, the chain build and the signature check.
VerificationResult<ReceiptPayload> result = verifier.VerifyReceipt(receiptB64);
ReceiptPayload receipt = result.Payload
    ?? throw new Exception($"verification failed: {result.Failure}");
if (receipt.ReceiptType != "ProductionSandbox")
{
    throw new Exception($"ReceiptType was {receipt.ReceiptType}, expected ProductionSandbox");
}
if (receipt.BundleId != "dev.bonzer.weeka.app")
{
    throw new Exception($"BundleId was {receipt.BundleId}");
}

// And the negative direction, so a verifier that accepted everything would fail
// here too: the same receipt with one bit flipped in its signature, the byte
// 128 from the end of the DER (BENCHMARKS.md).
byte[] der = Convert.FromBase64String(receiptB64);
der[der.Length - 128] ^= 0x01;
Failure? failure = verifier.VerifyReceipt(Convert.ToBase64String(der)).Failure;
if (failure?.Reason != VerificationReason.InvalidSignature)
{
    throw new Exception(
        $"a tampered signature was not rejected as InvalidSignature: {failure?.ToString() ?? "verified"}");
}

Console.WriteLine(
    $"nuget: published package verified a genuine Apple receipt ({receipt.BundleId}, "
    + $"{receipt.InApp.Count} purchases) and rejected a tampered signature");
