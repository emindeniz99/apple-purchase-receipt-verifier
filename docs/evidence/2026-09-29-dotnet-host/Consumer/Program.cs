// Verifies the sandbox receipt whose base64 text is in the file named by the
// first argument, through the public API of the restored package, and prints
// what came back: the typed result, and the endpoint's status (the module's
// own text), which does not depend on the payload shape of the embedded module.
using System;
using System.IO;
using System.Text.RegularExpressions;
using ApplePurchaseReceiptVerifier;

string base64 = File.ReadAllText(args[0]).Trim();
IVerifier verifier = Verifier.Create(Config.Defaults());

VerificationResult<ReceiptPayload> typed = verifier.VerifyReceipt(base64);
string endpoint = verifier.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, "{\"receipt-data\":\"" + base64 + "\"}");
string status = Regex.Match(endpoint, "\"status\":\\d+").Value;

Console.WriteLine(
    "typed: " + (typed.Verified ? "verified, bundle " + typed.Payload!.BundleId : "not verified: " + typed.Failure));
Console.WriteLine("endpoint: " + status);
Console.WriteLine("runtime: " + System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription);
Console.WriteLine("library: " + typeof(IVerifier).Assembly.GetName().Version);
