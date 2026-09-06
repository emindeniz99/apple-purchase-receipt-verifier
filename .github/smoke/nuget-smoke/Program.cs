// Smoke-tests the package as published to nuget.org. Everything it touches —
// the verifier, the exception type, the bundled root certificates — comes from
// the restored package, so a nupkg missing an asset or its embedded certs fails
// here rather than in a user's build.
using ApplePurchaseReceiptVerifier;
using ApplePurchaseReceiptVerifier.Receipt;

string receiptB64 = File.ReadAllText("receipt-sandbox-g5.b64").Trim();

var roots = AppleRootCertificates.ReceiptRoots();
if (roots.Count != 3)
{
    throw new Exception($"expected three bundled Apple roots, got {roots.Count}");
}

// A real Apple-signed receipt against the real pinned root: exercises the
// packaged certs, the DER reader, the chain build and the signature check.
using var verifier = new ReceiptVerifier(roots, "dev.bonzer.weeka.app");
AppReceipt receipt = verifier.Verify(receiptB64);
if (receipt.ReceiptType != "ProductionSandbox")
{
    throw new Exception($"ReceiptType was {receipt.ReceiptType}, expected ProductionSandbox");
}
if (receipt.BundleId != "dev.bonzer.weeka.app")
{
    throw new Exception($"BundleId was {receipt.BundleId}");
}

// And the negative direction, so a verifier that accepted everything would fail
// here too.
bool rejected = false;
using (var other = new ReceiptVerifier(roots, "com.other.app"))
{
    try
    {
        other.Verify(receiptB64);
    }
    catch (VerificationException error)
    {
        rejected = error.Reason == VerificationReason.WrongBundleId;
    }
}
if (!rejected)
{
    throw new Exception("a receipt for another bundle id was not rejected");
}

Console.WriteLine(
    $"nuget: published package verified a genuine Apple receipt ({receipt.BundleId}, "
    + $"{receipt.InAppPurchases.Count} purchases) and rejected a foreign bundle id");
