using System;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>The JWS path's own rules, beyond what the shared vectors reach.</summary>
public class JwsTests
{
    private static IVerifier Verifier() => TestPki.FixtureVerifier("jws-root");

    private static string[] Parts() => Fixtures070.ForSignedData("transaction").Split('.');

    [Theory]
    [InlineData(63)]
    [InlineData(65)]
    [InlineData(0)]
    [InlineData(128)]
    public void ASignatureThatIsNotSixtyFourBytesIsAnInvalidSignature(int length)
    {
        string[] parts = Parts();
        string jws = parts[0] + "." + parts[1] + "." + TestPki.Base64Url(new byte[length]);

        Assert.Equal(VerificationReason.InvalidSignature, Verifier().VerifySignedData(jws).Failure?.Reason);
    }

    /// <summary>
    /// The format trap, asserted in the direction that would have silently
    /// "worked" if the conversion were reversed: .NET's three-argument
    /// <c>VerifyData</c> wants IEEE P1363, and a JWS signature already is one.
    /// A DER re-encoding of the same signature must fail.
    /// </summary>
    [Fact]
    public void AnEs256SignatureReEncodedAsDerIsAnInvalidSignature()
    {
        string[] parts = Parts();
        byte[] p1363 = Base64Url(parts[2]);

        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(new BigInteger(p1363.AsSpan(0, 32), isUnsigned: true, isBigEndian: true));
            writer.WriteInteger(new BigInteger(p1363.AsSpan(32, 32), isUnsigned: true, isBigEndian: true));
        }

        string jws = parts[0] + "." + parts[1] + "." + TestPki.Base64Url(writer.Encode());
        Assert.True(Verifier().VerifySignedData(parts[0] + "." + parts[1] + "." + parts[2]).Verified);
        Assert.Equal(VerificationReason.InvalidSignature, Verifier().VerifySignedData(jws).Failure?.Reason);
    }

    /// <summary>
    /// ES256 means an EC P-256 leaf. A leaf with an RSA key, genuinely under
    /// the pinned chain and correctly marked, cannot make an ES256 signature,
    /// so the signature check fails; it is not a certificate defect.
    /// </summary>
    [Fact]
    public void ALeafWithAnRsaKeyIsAnInvalidSignature()
    {
        TestPki.JwsChain chain = TestPki.SharedJws.Value;
        X509Certificate2 leaf = TestPki.RsaChild(chain.Intermediate, "CN=Signing", false, TestPki.LeafOid);
        string jws = TestPki.SignJws(leaf, new[] { leaf, chain.Intermediate, chain.Root }, TestPki.Payload);

        Assert.Equal(VerificationReason.InvalidSignature, chain.Verifier().VerifySignedData(jws).Failure?.Reason);
    }

    private static byte[] Base64Url(string segment)
    {
        string standard = segment.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(standard.PadRight(standard.Length + ((4 - (standard.Length % 4)) % 4), '='));
    }
}
