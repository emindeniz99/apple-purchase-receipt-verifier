// Spike only (2026-09-26). Verifies the receipt-data string given as the
// first argument and prints the verdict and bundle id.
using Aprv.Wasm;

using var v = new Verifier();
using var r = v.VerifyReceipt(args[0]);
var root = r.RootElement;
System.Console.WriteLine($"{{\"verified\":{(root.GetProperty("verified").GetBoolean() ? "true" : "false")},\"bundleId\":\"{root.GetProperty("payload").GetProperty("bundleId").GetString()}\",\"runtime\":\"{System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}\"}}");
