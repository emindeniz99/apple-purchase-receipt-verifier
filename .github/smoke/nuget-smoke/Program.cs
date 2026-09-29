// Smoke-tests the package as published to nuget.org. Everything it touches —
// the verifier, the result types, aprv.wasm and Wasmtime's native library —
// comes from the restored package, so a nupkg missing an asset fails here
// rather than in a user's build.
using ApplePurchaseReceiptVerifier;

string receiptB64 = File.ReadAllText("receipt-sandbox-g5.b64").Trim();

// The defaults trust the module's built-in Apple roots, so Config.Roots is
// empty; the package ships no copy of them.
Config config = Config.Defaults();
if (config.Roots.Count != 0)
{
    throw new Exception($"expected the defaults to use the module's roots, got {config.Roots.Count} configured");
}
IVerifier verifier = Verifier.Create(config);

// A real Apple-signed receipt against the real pinned root: exercises the
// packaged module, the chain build and the signature check inside it.
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
