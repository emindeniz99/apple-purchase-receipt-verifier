using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// Which certificate signature algorithms the path walk verifies under. 0.6
/// kept an allowlist that refused <c>ecdsa-with-SHA1</c>; 0.7 removes it
/// (docs/design/0.7-hardening-parity.md, Q14): whatever the platform verifies
/// under the pinned chain is accepted, as Java does. A certificate signed
/// that way is accepted only because a pinned key really signed it — a
/// relabelled signature is still a failed check
/// (<see cref="ChainSecurityTests.ACertificateSignatureRelabelledAsMd5IsAFailedCheck"/>).
/// </summary>
public class SignatureAlgorithmTests
{
    /// <summary>
    /// End to end: a JWS whose leaf the intermediate genuinely signed with
    /// ecdsa-with-SHA1 verifies, and the certificate really is labelled so.
    /// </summary>
    [Fact]
    public void AJwsLeafGenuinelySignedWithEcdsaSha1Verifies()
    {
        TestPki.JwsChain chain = TestPki.SharedJws.Value;
        X509Certificate2 leaf = TestPki.EcChildSha1(chain.Intermediate, "CN=Signing", false, TestPki.LeafOid);
        string jws = TestPki.SignJws(leaf, new[] { leaf, chain.Intermediate, chain.Root }, TestPki.Payload);

        Assert.Equal("1.2.840.10045.4.1", leaf.SignatureAlgorithm.Value);
        VerificationResult<JsonPayload> result = chain.Verifier().VerifySignedData(jws);
        Assert.True(result.Verified, result.Failure?.ToString());
    }

    /// <summary>The same one level up: the pinned root signed the intermediate with ecdsa-with-SHA1.</summary>
    [Fact]
    public void AJwsIntermediateGenuinelySignedWithEcdsaSha1Verifies()
    {
        X509Certificate2 root = TestPki.EcRoot();
        X509Certificate2 intermediate = TestPki.EcChildSha1(root, "CN=WWDR", true, TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.EcChild(intermediate, "CN=Signing", false, TestPki.LeafOid);
        string jws = TestPki.SignJws(leaf, new[] { leaf, intermediate, root }, TestPki.Payload);

        Assert.Equal("1.2.840.10045.4.1", intermediate.SignatureAlgorithm.Value);
        VerificationResult<JsonPayload> result = TestPki.Verifier(root).VerifySignedData(jws);
        Assert.True(result.Verified, result.Failure?.ToString());
    }
}
