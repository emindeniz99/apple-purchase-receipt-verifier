using System;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Jws;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// Which certificate signatureAlgorithm OIDs the path walk will verify under.
/// SHA-1 with RSA (<c>1.2.840.113549.1.1.5</c>) is on the list because Apple's
/// own legacy receipt chain is SHA-1/RSA end to end and dropping it would drop
/// legacy receipts. <c>ecdsa-with-SHA1</c> is not: no Apple chain has ever
/// used it, so admitting it only widens the accept set past what node
/// (<c>CERT_SIGNATURE_ALGORITHMS</c>) and python (RSA-only SHA-1 fallback)
/// allow.
/// </summary>
public class SignatureAlgorithmTests
{
    [Fact]
    public void AnEcdsaWithSha1CertificateIsNotAcceptedAsIssued()
    {
        using X509Certificate2 root = TestPki.EcRoot();
        using X509Certificate2 child = TestPki.EcChildSha1(root, "CN=SHA-1 EC child", true);

        Assert.Equal("1.2.840.10045.4.1", child.SignatureAlgorithm.Value);
        Assert.False(Internals.IssuedBy(child, root));
    }

    [Fact]
    public void ARsaWithSha1CertificateIsStillAcceptedAsIssued()
    {
        using X509Certificate2 root = TestPki.RsaRoot();
        using X509Certificate2 child = TestPki.RsaChildSha1(root, "CN=SHA-1 RSA child", true);

        Assert.Equal("1.2.840.113549.1.1.5", child.SignatureAlgorithm.Value);
        Assert.True(Internals.IssuedBy(child, root));
    }

    /// <summary>
    /// End to end: a JWS whose leaf is signed by the intermediate with
    /// ecdsa-with-SHA1 must not verify, however genuine the rest of the chain.
    /// </summary>
    [Fact]
    public void AJwsLeafSignedWithEcdsaSha1IsRejected()
    {
        X509Certificate2 root = TestPki.EcRoot();
        X509Certificate2 intermediate = TestPki.EcChild(root, "CN=WWDR", true, TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.EcChildSha1(
            intermediate, "CN=Signing", false, TestPki.LeafOid);
        string jws = TestPki.SignJws(
            leaf,
            new[] { leaf, intermediate, root },
            "{\"bundleId\":\"com.example.app\",\"environment\":\"Sandbox\",\"signedDate\":1722945600000}");

        using JwsVerifier verifier = new(
            new[] { TestPki.Public(root) }, "com.example.app", new[] { AppleEnvironment.Sandbox });
        Assert.Equal(
            VerificationReason.InvalidChain,
            Assert.Throws<VerificationException>(() => verifier.VerifyTransaction(jws)).Reason);
    }
}
