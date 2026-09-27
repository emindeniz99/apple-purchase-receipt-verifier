using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The size caps every port applies before it decodes or parses anything.
/// Unbounded input is decoded and parsed in full before any signature is
/// checked, so each cap is a denial-of-service bound. The request and receipt
/// caps are Apple's: its verifyReceipt answers a 3,145,728-byte request body
/// and refuses a 3,145,729-byte one (measured 2026-09-23), counting UTF-8
/// bytes. The boundaries themselves are pinned by shared cases; what stays
/// here is what a shared case cannot say.
/// </summary>
public class InputSizeBoundsTests
{
    /// <summary>The cross-port numbers of the design's Bounds table, none configurable.</summary>
    [Fact]
    public void TheCapsAreTheCrossPortNumbers()
    {
        Assert.Equal(3145728, ReceiptVerifierCore.MaxReceiptBytes);
        Assert.Equal(3145728, EndpointCore.MaxRequestBytes);
        Assert.Equal(262144, JwsVerifierCore.MaxJwsBytes);
        Assert.Equal(64, Json.MaxDepth);
        Assert.Equal(50000, Json.MaxMemberNameLength);
        Assert.Equal(1000, Json.MaxNumberDigits);
        Assert.Equal(64, Asn1Depth.MaxDepth);
        Assert.Equal(10, Cms.MaxEmbeddedCertificates);
        Assert.Equal(4, Cms.MaxSignerInfos);
        Assert.Equal(6, Chain.MaxPathLength);
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

    /// <summary>
    /// The same small stack runs a whole verification of a JWS whose header
    /// and payload are both nested to the bound, and of the deepest signed
    /// content the ASN.1 bound admits.
    /// </summary>
    [Fact]
    public void AVerificationAtTheDepthBoundsFitsASmallThreadStack()
    {
        TestPki.JwsChain chain = TestPki.SharedJws.Value;
        string payload = "{\"signedDate\":1722945600000,\"x\":" + new string('[', 63) + new string(']', 63) + "}";
        string jws = chain.Sign(payload);
        string deepReceipt = Fixtures070.ForReceipt("owner-receipt-content-depth-64");
        IVerifier receipts = TestPki.FixtureVerifier("owner-receipt-root", 1735689600000L);

        bool jwsVerified = false;
        bool receiptVerified = false;
        Exception? failure = null;
        Thread thread = new(
            () =>
            {
                try
                {
                    jwsVerified = chain.Verifier().VerifySignedData(jws).Verified;
                    receiptVerified = receipts.VerifyReceipt(deepReceipt).Verified;
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
        Assert.True(jwsVerified);
        Assert.True(receiptVerified);
    }

    // --- JWS -------------------------------------------------------------

    /// <summary>
    /// A genuinely signed JWS of exactly <paramref name="length"/> characters,
    /// grown with JSON whitespace inside the signed segments. Unpadded
    /// base64url cannot be 1 modulo 4 characters long, so the header takes up
    /// to two spaces as well when the payload alone cannot land on the length.
    /// </summary>
    private static string SignedJwsOfLength(TestPki.JwsChain chain, int length)
    {
        string header = "{\"alg\":\"ES256\",\"x5c\":[\""
            + Convert.ToBase64String(chain.Leaf.RawData) + "\",\""
            + Convert.ToBase64String(chain.Intermediate.RawData) + "\",\""
            + Convert.ToBase64String(chain.Root.RawData) + "\"]}";
        const int SignatureChars = 86;
        for (int headerPad = 0; headerPad < 3; headerPad++)
        {
            int headerChars = Base64UrlLength(header.Length + headerPad);
            int payloadBytes = (length - headerChars - 2 - SignatureChars) * 3 / 4;
            for (int bytes = payloadBytes - 2; bytes <= payloadBytes + 2; bytes++)
            {
                if (headerChars + 2 + SignatureChars + Base64UrlLength(bytes) == length)
                {
                    string jws = Sign(
                        chain,
                        header + new string(' ', headerPad),
                        TestPki.Payload + new string(' ', bytes - TestPki.Payload.Length));
                    Assert.Equal(length, jws.Length);
                    return jws;
                }
            }
        }

        throw new InvalidOperationException("no padding reaches " + length);
    }

    private static string Sign(TestPki.JwsChain chain, string headerJson, string payloadJson)
    {
        string signingInput = TestPki.Base64Url(Encoding.UTF8.GetBytes(headerJson))
            + "." + TestPki.Base64Url(Encoding.UTF8.GetBytes(payloadJson));
        using ECDsa key = chain.Leaf.GetECDsaPrivateKey()!;
        byte[] signature = key.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256);
        return signingInput + "." + TestPki.Base64Url(signature);
    }

    private static int Base64UrlLength(int bytes) => ((bytes * 4) + 2) / 3;

    /// <summary>
    /// The cap refuses nothing at the cap: a genuinely signed JWS of exactly
    /// 262,144 bytes verifies, its payload whitespace and all returned as
    /// signed. (The shared at-cap vector carries a broken signature, so it
    /// can only show that the cap let it through to the signature check.)
    /// </summary>
    [Fact]
    public void AGenuinelySignedJwsAtTheCapVerifies()
    {
        TestPki.JwsChain chain = TestPki.SharedJws.Value;
        string atCap = SignedJwsOfLength(chain, JwsVerifierCore.MaxJwsBytes);

        VerificationResult<JsonPayload> result = chain.Verifier().VerifySignedData(atCap);
        Assert.True(result.Verified, result.Failure?.ToString());
        Assert.StartsWith(TestPki.Payload, result.Payload.Json, StringComparison.Ordinal);

        Assert.Equal(VerificationReason.TooLarge, chain.Verifier().VerifySignedData(atCap + "A").Failure?.Reason);
    }
}
