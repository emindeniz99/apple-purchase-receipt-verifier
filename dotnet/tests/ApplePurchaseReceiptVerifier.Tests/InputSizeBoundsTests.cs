using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using ApplePurchaseReceiptVerifier.Internal;
using ApplePurchaseReceiptVerifier.Jws;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The size caps every port applies before it decodes or parses anything.
/// Unbounded input is decoded and parsed in full before any signature is
/// checked, so each cap is a denial-of-service bound. The request and receipt
/// caps are Apple's: its verifyReceipt answers a 3,145,728-byte request body
/// and refuses a 3,145,729-byte one (measured 2026-09-23), counting UTF-8
/// bytes, and every port holds the same fixed numbers.
/// </summary>
/// <remarks>
/// Each cap is pinned from both sides with the same content: an input at the
/// cap that verifies proves the cap does not refuse it, and the same input
/// one character over, refused with the cap's own message, proves the cap
/// fired before the step that would otherwise have answered differently.
/// </remarks>
public class InputSizeBoundsTests
{
    private const string ReceiptCapMessage = "INVALID_RECEIPT_FORMAT: receipt exceeds the maximum accepted size of 3145728 bytes";
    private const string DerCapMessage = ReceiptCapMessage;
    private const string JwsCapMessage = "INVALID_JWS_FORMAT: jws exceeds the maximum accepted size of 262144 characters";

    private static readonly DateTimeOffset Now = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static IReadOnlyList<X509Certificate2> Roots(string fixture = "receipt-root") =>
        new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes(fixture)) };

    private static string B64(string fixture) => Convert.ToBase64String(Fixtures.Bytes(fixture));

    /// <summary>
    /// A genuine receipt's base64 padded with trailing line feeds to exactly
    /// <paramref name="length"/>. receipt-data is canonical base64 only, so
    /// the decoder would refuse the line feeds too: an over-cap test shows the
    /// cap answered by its message, not by the verdict.
    /// </summary>
    private static string PaddedReceipt(int length)
    {
        string base64 = B64("receipt");
        return base64 + new string('\n', length - base64.Length);
    }

    /// <summary>
    /// Canonical base64 admits nothing around the data, so the string AT the
    /// cap is a genuinely signed receipt whose base64 is exactly the cap
    /// (ReceiptBase64CapFixture), verified under a root of its own.
    /// </summary>
    private static string AtCapReceipt() => Fixtures.Text("limit-receipt-b64-at-cap");

    private static IReadOnlyList<X509Certificate2> AtCapRoots() => Roots("receipt-b64-cap-root");

    [Fact]
    public void TheCapsAreTheCrossPortNumbers()
    {
        Assert.Equal(3145728, ReceiptVerifier.MaxReceiptBytes);
        Assert.Equal(3145728, VerifyReceiptEndpoint.MaxRequestBytes);
        Assert.Equal(262144, JwsVerifier.MaxJwsBytes);
        Assert.Equal(64, Json.MaxDepth);
    }

    // --- receipt base64 --------------------------------------------------

    [Fact]
    public void AReceiptStringAtTheCapIsNotRefusedByIt()
    {
        string atCap = AtCapReceipt();
        Assert.Equal(ReceiptVerifier.MaxReceiptBytes, atCap.Length);

        using ReceiptVerifier verifier = new(AtCapRoots(), "com.example.app");
        Assert.Equal("com.example.app", verifier.Verify(atCap).BundleId);
    }

    [Fact]
    public void AReceiptStringOneOverTheCapIsRefusedBeforeDecoding()
    {
        // Its message is not one the decoder or the CMS parse emits, so the
        // cap is what answered.
        string overCap = PaddedReceipt(ReceiptVerifier.MaxReceiptBytes + 1);

        using ReceiptVerifier verifier = new(Roots(), "com.example.app");
        VerificationException error = Assert.Throws<VerificationException>(() => verifier.Verify(overCap));
        Assert.Equal(VerificationReason.InvalidReceiptFormat, error.Reason);
        Assert.Equal(ReceiptCapMessage, error.Message);
    }

    [Fact]
    public void AnOversizedReceiptStringThatIsNotBase64IsStillAnsweredByTheCap()
    {
        // The decoder would object to the first character. It never sees it.
        string overCap = "!" + new string('A', ReceiptVerifier.MaxReceiptBytes);

        using ReceiptVerifier verifier = new(Roots(), "com.example.app");
        Assert.Equal(
            ReceiptCapMessage,
            Assert.Throws<VerificationException>(() => verifier.Verify(overCap)).Message);
    }

    [Fact]
    public void AReceiptStringIsMeasuredInUtf8BytesNotCharacters()
    {
        // Half the cap in characters, one byte over it in UTF-8. A character
        // count would hand it to the decoder, which would answer with its own
        // message instead of the cap's.
        string overCap = "a" + new string('\u00e9', ReceiptVerifier.MaxReceiptBytes / 2);
        Assert.Equal(ReceiptVerifier.MaxReceiptBytes + 1, Encoding.UTF8.GetByteCount(overCap));

        using ReceiptVerifier verifier = new(Roots(), "com.example.app");
        Assert.Equal(
            ReceiptCapMessage,
            Assert.Throws<VerificationException>(() => verifier.Verify(overCap)).Message);
    }

    // --- receipt DER -----------------------------------------------------

    [Fact]
    public void ReceiptDerAtTheCapIsNotRefusedByIt()
    {
        byte[] atCap = new byte[ReceiptVerifier.MaxReceiptBytes];

        using ReceiptVerifier verifier = new(Roots(), "com.example.app");
        VerificationException error = Assert.Throws<VerificationException>(() => verifier.Verify(atCap));
        Assert.Equal(VerificationReason.InvalidReceiptFormat, error.Reason);
        Assert.NotEqual(DerCapMessage, error.Message);
    }

    [Fact]
    public void ReceiptDerOneOverTheCapIsRefusedBeforeParsing()
    {
        byte[] overCap = new byte[ReceiptVerifier.MaxReceiptBytes + 1];

        using ReceiptVerifier verifier = new(Roots(), "com.example.app");
        VerificationException viaVerifier = Assert.Throws<VerificationException>(() => verifier.Verify(overCap));
        Assert.Equal(VerificationReason.InvalidReceiptFormat, viaVerifier.Reason);
        Assert.Equal(DerCapMessage, viaVerifier.Message);

        // The public primitive the endpoint uses carries the same cap.
        VerificationException viaCore = Assert.Throws<VerificationException>(
            () => ReceiptVerifier.VerifyReceiptCore(overCap, Roots()));
        Assert.Equal(VerificationReason.InvalidReceiptFormat, viaCore.Reason);
        Assert.Equal(DerCapMessage, viaCore.Message);
    }

    // --- endpoint receipt-data -------------------------------------------

    [Fact]
    public void ReceiptDataAtTheCapVerifiesAtTheEndpoint()
    {
        using VerifyReceiptEndpoint endpoint = new(AtCapRoots(), AppleEnvironment.Sandbox);
        string atCap = AtCapReceipt();

        Assert.Equal(0, endpoint.VerifyReceiptData(atCap, Now).Status);
        Dictionary<string, object?> body = new(StringComparer.Ordinal) { ["receipt-data"] = atCap };
        Assert.Equal(0, endpoint.VerifyReceiptResult(body, Now).Status);
    }

    [Fact]
    public void ReceiptDataOneOverTheCapAnswers21002InvalidReceiptFormat()
    {
        using VerifyReceiptEndpoint endpoint = new(Roots(), AppleEnvironment.Sandbox);
        string overCap = PaddedReceipt(ReceiptVerifier.MaxReceiptBytes + 1);
        Dictionary<string, object?> body = new(StringComparer.Ordinal) { ["receipt-data"] = overCap };

        foreach (VerifyReceiptResult result in new[]
                 {
                     endpoint.VerifyReceiptData(overCap, Now),
                     endpoint.VerifyReceiptResult(body, Now),
                 })
        {
            Assert.Equal(21002, result.Status);
            Assert.Equal(VerificationReason.InvalidReceiptFormat, result.FailureReason);
            Assert.Equal("{\"status\":21002}", result.ToJson());
        }
    }

    // --- endpoint request body -------------------------------------------

    private static string RequestBody(int length)
    {
        string body = "{\"receipt-data\":\"" + B64("receipt") + "\"}";
        return body + new string(' ', length - body.Length);
    }

    [Fact]
    public void ARequestBodyAtTheCapVerifies()
    {
        using VerifyReceiptEndpoint endpoint = new(Roots(), AppleEnvironment.Sandbox);
        string atCap = RequestBody(VerifyReceiptEndpoint.MaxRequestBytes);
        Assert.Equal(VerifyReceiptEndpoint.MaxRequestBytes, atCap.Length);

        Assert.Equal(0, endpoint.VerifyReceiptResult(atCap, Now).Status);
    }

    [Fact]
    public void ARequestBodyOneOverTheCapIsRefusedBeforeParsing()
    {
        // The body that verifies at the cap plus one space: a parser would
        // have accepted it, so a 21002 here can only come from the cap. The
        // reason is RequestTooLarge, the one an HTTP layer maps to 413 as
        // Apple does.
        using VerifyReceiptEndpoint endpoint = new(Roots(), AppleEnvironment.Sandbox);
        string overCap = RequestBody(VerifyReceiptEndpoint.MaxRequestBytes + 1);

        VerifyReceiptResult result = endpoint.VerifyReceiptResult(overCap, Now);
        Assert.Equal(21002, result.Status);
        Assert.Equal(VerificationReason.RequestTooLarge, result.FailureReason);
        Assert.Equal("{\"status\":21002}", result.ToJson());
        Assert.Equal("{\"status\":21002}", endpoint.VerifyReceiptJson(overCap));
    }

    /// <summary>
    /// Apple's limit counts UTF-8 bytes. A body padded with U+00E9 to one byte
    /// over the limit is barely half the limit in characters, so a character
    /// count lets it through; the same shape one byte shorter verifies.
    /// </summary>
    [Fact]
    public void ARequestBodyIsMeasuredInUtf8BytesNotCharacters()
    {
        int limit = VerifyReceiptEndpoint.MaxRequestBytes;
        string prefix = "{\"receipt-data\":\"" + B64("receipt") + "\",\"password\":\"";
        const string Suffix = "\"}";
        int fixedBytes = prefix.Length + Suffix.Length;
        string Body(int paddingBytes) =>
            prefix + new string('\u00e9', paddingBytes / 2) + (paddingBytes % 2 == 1 ? "a" : string.Empty) + Suffix;

        using VerifyReceiptEndpoint endpoint = new(Roots(), AppleEnvironment.Sandbox);

        string overBody = Body(limit + 1 - fixedBytes);
        Assert.Equal(limit + 1, Encoding.UTF8.GetByteCount(overBody));
        Assert.True(overBody.Length < (limit / 2) + fixedBytes, "a character count calls this one far under the limit");
        Assert.Equal(VerificationReason.RequestTooLarge, endpoint.VerifyReceiptResult(overBody, Now).FailureReason);

        string atBody = Body(limit - fixedBytes);
        Assert.Equal(limit, Encoding.UTF8.GetByteCount(atBody));
        Assert.Equal(0, endpoint.VerifyReceiptResult(atBody, Now).Status);
    }

    /// <summary>
    /// The size check comes before the parse and the depth scan: a body that
    /// is both too large and malformed is answered as too large.
    /// </summary>
    [Fact]
    public void AnOversizedMalformedBodyIsRequestTooLargeNotMalformedRequest()
    {
        using VerifyReceiptEndpoint endpoint = new(Roots(), AppleEnvironment.Sandbox);
        string deep = new('[', VerifyReceiptEndpoint.MaxRequestBytes + 1);
        Assert.Equal(VerificationReason.RequestTooLarge, endpoint.VerifyReceiptResult(deep, Now).FailureReason);
    }

    // --- endpoint nesting depth ------------------------------------------

    /// <summary>
    /// A genuine request whose extra, unread property nests arrays so that
    /// the body as a whole holds <paramref name="levels"/> open containers,
    /// the outer object included.
    /// </summary>
    private static string NestedRequestBody(int levels)
    {
        int arrays = levels - 1;
        return "{\"receipt-data\":\"" + B64("receipt") + "\",\"x\":"
            + new string('[', arrays) + new string(']', arrays) + "}";
    }

    [Fact]
    public void ARequestBodyNestedToTheBoundVerifies()
    {
        using VerifyReceiptEndpoint endpoint = new(Roots(), AppleEnvironment.Sandbox);
        Assert.Equal(0, endpoint.VerifyReceiptResult(NestedRequestBody(64), Now).Status);
    }

    [Fact]
    public void ARequestBodyNestedOnePastTheBoundAnswers21002MalformedRequest()
    {
        using VerifyReceiptEndpoint endpoint = new(Roots(), AppleEnvironment.Sandbox);
        VerifyReceiptResult result = endpoint.VerifyReceiptResult(NestedRequestBody(65), Now);
        Assert.Equal(21002, result.Status);
        Assert.Equal(VerificationReason.MalformedRequest, result.FailureReason);
        Assert.Equal("{\"status\":21002}", result.ToJson());
    }

    /// <summary>
    /// The reader recurses, so the bound is also its stack budget. A document
    /// at the bound, of both container kinds, parses on a 256 KiB thread, the
    /// smallest default stack a supported host hands a worker thread (IIS on
    /// 32-bit Windows).
    /// </summary>
    [Fact]
    public void TheDepthBoundFitsASmallThreadStack()
    {
        StringBuilder objects = new();
        for (int i = 0; i < Json.MaxDepth; i++)
        {
            objects.Append("{\"a\":");
        }

        objects.Append('1').Append('}', Json.MaxDepth);
        string arrays = new string('[', Json.MaxDepth) + new string(']', Json.MaxDepth);

        Exception? failure = null;
        Thread thread = new(
            () =>
            {
                try
                {
                    Assert.NotNull(Json.Parse(arrays));
                    Assert.NotNull(Json.Parse(objects.ToString()));
                }
                catch (Exception e)
                {
                    failure = e;
                }
            },
            256 * 1024);
        thread.Start();
        thread.Join();
        Assert.Null(failure);
    }

    // --- JWS -------------------------------------------------------------

    private const string Claims =
        "\"bundleId\":\"com.example.app\",\"environment\":\"Sandbox\",\"signedDate\":1722945600000";

    private static readonly Lazy<(X509Certificate2 Root, X509Certificate2 Intermediate, X509Certificate2 Leaf)> Pki =
        new(() =>
        {
            X509Certificate2 root = TestPki.EcRoot();
            X509Certificate2 intermediate = TestPki.EcChild(root, "CN=WWDR", true, TestPki.IntermediateOid);
            X509Certificate2 leaf = TestPki.EcChild(intermediate, "CN=Signing", false, TestPki.LeafOid);
            return (root, intermediate, leaf);
        });

    private static JwsVerifier NewJwsVerifier() =>
        new(new[] { TestPki.Public(Pki.Value.Root) }, "com.example.app", new[] { AppleEnvironment.Sandbox });

    private static string SignedJws(string headerJson, string payloadJson)
    {
        string signingInput = TestPki.Base64Url(Encoding.UTF8.GetBytes(headerJson))
            + "." + TestPki.Base64Url(Encoding.UTF8.GetBytes(payloadJson));
        using ECDsa key = Pki.Value.Leaf.GetECDsaPrivateKey()!;
        byte[] signature = key.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256);
        return signingInput + "." + TestPki.Base64Url(signature);
    }

    /// <summary>
    /// A genuinely signed JWS of exactly <paramref name="length"/> characters,
    /// grown with JSON whitespace inside the signed segments. Unpadded
    /// base64url cannot be 1 modulo 4 characters long, so the header takes up
    /// to two spaces as well when the payload alone cannot land on the length.
    /// </summary>
    private static string SignedJwsOfLength(int length)
    {
        (X509Certificate2 _, X509Certificate2 intermediate, X509Certificate2 leaf) = Pki.Value;
        X509Certificate2 root = Pki.Value.Root;
        string header = "{\"alg\":\"ES256\",\"x5c\":[\""
            + Convert.ToBase64String(leaf.RawData) + "\",\""
            + Convert.ToBase64String(intermediate.RawData) + "\",\""
            + Convert.ToBase64String(root.RawData) + "\"]}";
        const int SignatureChars = 86;
        for (int headerPad = 0; headerPad < 3; headerPad++)
        {
            int headerChars = Base64UrlLength(header.Length + headerPad);
            int payloadBytes = (length - headerChars - 2 - SignatureChars) * 3 / 4;
            for (int bytes = payloadBytes - 2; bytes <= payloadBytes + 2; bytes++)
            {
                if (headerChars + 2 + SignatureChars + Base64UrlLength(bytes) == length)
                {
                    string payload = "{" + Claims + "}";
                    string jws = SignedJws(
                        header + new string(' ', headerPad),
                        payload + new string(' ', bytes - payload.Length));
                    Assert.Equal(length, jws.Length);
                    return jws;
                }
            }
        }

        throw new InvalidOperationException("no padding reaches " + length);
    }

    private static int Base64UrlLength(int bytes) => ((bytes * 4) + 2) / 3;

    [Fact]
    public void AJwsAtTheCapVerifies()
    {
        string atCap = SignedJwsOfLength(JwsVerifier.MaxJwsBytes);

        using JwsVerifier verifier = NewJwsVerifier();
        Assert.Equal("com.example.app", verifier.VerifyTransaction(atCap).BundleId);
    }

    [Fact]
    public void AJwsOneOverTheCapIsRefusedBeforeItIsSplit()
    {
        // The JWS that verifies at the cap, one character longer. Past the
        // cap the signature segment would decode to the wrong length and
        // answer INVALID_SIGNATURE; the cap answers first.
        string overCap = SignedJwsOfLength(JwsVerifier.MaxJwsBytes) + "A";

        using JwsVerifier verifier = NewJwsVerifier();
        foreach (Action call in new Action[]
                 {
                     () => verifier.VerifyTransaction(overCap),
                     () => verifier.VerifyAppTransaction(overCap),
                     () => verifier.VerifyRaw(overCap),
                 })
        {
            VerificationException error = Assert.Throws<VerificationException>(call);
            Assert.Equal(VerificationReason.InvalidJwsFormat, error.Reason);
            Assert.Equal(JwsCapMessage, error.Message);
        }

        // No dots at all: a split would have reported one segment.
        Assert.Equal(
            JwsCapMessage,
            Assert.Throws<VerificationException>(
                () => verifier.VerifyRaw(new string('A', JwsVerifier.MaxJwsBytes + 1))).Message);
    }

    [Fact]
    public void AJwsPayloadNestedToTheBoundVerifies()
    {
        string payload = "{" + Claims + ",\"x\":" + new string('[', 63) + new string(']', 63) + "}";
        (X509Certificate2 root, X509Certificate2 intermediate, X509Certificate2 leaf) = Pki.Value;

        using JwsVerifier verifier = NewJwsVerifier();
        string jws = TestPki.SignJws(leaf, new[] { leaf, intermediate, root }, payload);
        Assert.Equal("com.example.app", verifier.VerifyTransaction(jws).BundleId);
    }

    [Fact]
    public void AJwsPayloadNestedOnePastTheBoundIsInvalidJwsFormat()
    {
        string payload = "{" + Claims + ",\"x\":" + new string('[', 64) + new string(']', 64) + "}";
        (X509Certificate2 root, X509Certificate2 intermediate, X509Certificate2 leaf) = Pki.Value;

        using JwsVerifier verifier = NewJwsVerifier();
        string jws = TestPki.SignJws(leaf, new[] { leaf, intermediate, root }, payload);
        VerificationException error = Assert.Throws<VerificationException>(() => verifier.VerifyTransaction(jws));
        Assert.Equal(VerificationReason.InvalidJwsFormat, error.Reason);
        Assert.Equal("INVALID_JWS_FORMAT: payload is not valid JSON", error.Message);
    }

    [Fact]
    public void AJwsHeaderNestedOnePastTheBoundIsInvalidJwsFormat()
    {
        (X509Certificate2 root, X509Certificate2 intermediate, X509Certificate2 leaf) = Pki.Value;
        string header = "{\"alg\":\"ES256\",\"x\":" + new string('[', 64) + new string(']', 64) + ",\"x5c\":[\""
            + Convert.ToBase64String(leaf.RawData) + "\",\""
            + Convert.ToBase64String(intermediate.RawData) + "\",\""
            + Convert.ToBase64String(root.RawData) + "\"]}";

        using JwsVerifier verifier = NewJwsVerifier();
        VerificationException error = Assert.Throws<VerificationException>(
            () => verifier.VerifyTransaction(SignedJws(header, "{" + Claims + "}")));
        Assert.Equal(VerificationReason.InvalidJwsFormat, error.Reason);
        Assert.Equal("INVALID_JWS_FORMAT: header is not valid JSON", error.Message);
    }

    // --- the byte floor --------------------------------------------------

    /// <summary>
    /// The normative 1 MiB receipt floor sits under both caps: its base64 is
    /// about 1.38 MB, so it verifies at every verifier entry point and as a
    /// raw JSON request body.
    /// </summary>
    [Fact]
    public void TheByteFloorReceiptVerifiesEverywhere()
    {
        byte[] der = Fixtures.Bytes("receipt-byte-floor");
        string base64 = Convert.ToBase64String(der);
        Assert.True(base64.Length < VerifyReceiptEndpoint.MaxRequestBytes / 2);

        using ReceiptVerifier verifier = new(Roots("large-receipt-root"), "com.example.app");
        Assert.Equal(2300, verifier.Verify(der).InAppPurchases.Count);
        Assert.Equal(2300, verifier.Verify(base64).InAppPurchases.Count);

        using VerifyReceiptEndpoint endpoint = new(Roots("large-receipt-root"), AppleEnvironment.Sandbox);
        Assert.Equal(0, endpoint.VerifyReceiptData(base64, Now).Status);

        VerifyReceiptResult asBody = endpoint.VerifyReceiptResult("{\"receipt-data\":\"" + base64 + "\"}", Now);
        Assert.Equal(0, asBody.Status);
        Assert.Equal(2300, asBody.Receipt!.InAppPurchases.Count);
    }
}
