using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Jws;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The anti-forgery properties of the path walk. Every case here mints the
/// certificate a real attacker would need and asserts the library refuses it.
/// </summary>
public class ChainSecurityTests
{
    private const string Payload =
        "{\"bundleId\":\"com.example.app\",\"environment\":\"Sandbox\",\"signedDate\":1722945600000}";

    private static JwsVerifier Verifier(params X509Certificate2[] anchors) =>
        new(anchors, "com.example.app", new[] { AppleEnvironment.Sandbox });

    private static VerificationReason ReasonOf(Action action) =>
        Assert.Throws<VerificationException>(action).Reason;

    [Fact]
    public void GenuineFakeAppleChainVerifies()
    {
        X509Certificate2 root = TestPki.EcRoot();
        X509Certificate2 intermediate = TestPki.EcChild(root, "CN=WWDR", true, TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.EcChild(intermediate, "CN=Signing", false, TestPki.LeafOid);
        string jws = TestPki.SignJws(leaf, new[] { leaf, intermediate, root }, Payload);

        using JwsVerifier verifier = Verifier(TestPki.Public(root));
        Assert.Equal("com.example.app", verifier.VerifyTransaction(jws).BundleId);
    }

    [Fact]
    public void LeafWithoutTheAppleMarkerOidIsRejected()
    {
        X509Certificate2 root = TestPki.EcRoot();
        X509Certificate2 intermediate = TestPki.EcChild(root, "CN=WWDR", true, TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.EcChild(intermediate, "CN=Signing", false);
        string jws = TestPki.SignJws(leaf, new[] { leaf, intermediate, root }, Payload);

        using JwsVerifier verifier = Verifier(TestPki.Public(root));
        Assert.Equal(
            VerificationReason.InvalidCertificatePurpose,
            ReasonOf(() => verifier.VerifyTransaction(jws)));
    }

    [Fact]
    public void IntermediateWithoutTheWwdrMarkerOidIsRejected()
    {
        X509Certificate2 root = TestPki.EcRoot();
        X509Certificate2 intermediate = TestPki.EcChild(root, "CN=WWDR", true);
        X509Certificate2 leaf = TestPki.EcChild(intermediate, "CN=Signing", false, TestPki.LeafOid);
        string jws = TestPki.SignJws(leaf, new[] { leaf, intermediate, root }, Payload);

        using JwsVerifier verifier = Verifier(TestPki.Public(root));
        Assert.Equal(
            VerificationReason.InvalidCertificatePurpose,
            ReasonOf(() => verifier.VerifyTransaction(jws)));
    }

    /// <summary>
    /// The D13 hole in its JWS form: a developer certificate under the same
    /// WWDR intermediate, chaining to the same pinned root, must not be able to
    /// sign an accepted payload.
    /// </summary>
    [Fact]
    public void DeveloperStyleLeafUnderTheSameIntermediateIsRejected()
    {
        X509Certificate2 root = TestPki.EcRoot();
        X509Certificate2 intermediate = TestPki.EcChild(root, "CN=WWDR", true, TestPki.IntermediateOid);
        X509Certificate2 developer = TestPki.EcChild(
            intermediate, "CN=Apple Distribution: Someone Else", false, "1.2.840.113635.100.6.1.13");
        string jws = TestPki.SignJws(developer, new[] { developer, intermediate, root }, Payload);

        using JwsVerifier verifier = Verifier(TestPki.Public(root));
        Assert.Equal(
            VerificationReason.InvalidCertificatePurpose,
            ReasonOf(() => verifier.VerifyTransaction(jws)));
    }

    /// <summary>
    /// x5c[2] is never consulted, so replacing it with an attacker's own root
    /// changes nothing about the verdict.
    /// </summary>
    [Fact]
    public void ThirdX5cElementIsIgnored()
    {
        X509Certificate2 root = TestPki.EcRoot();
        X509Certificate2 intermediate = TestPki.EcChild(root, "CN=WWDR", true, TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.EcChild(intermediate, "CN=Signing", false, TestPki.LeafOid);
        X509Certificate2 attacker = TestPki.EcRoot("CN=Attacker Root");
        string jws = TestPki.SignJws(leaf, new[] { leaf, intermediate, attacker }, Payload);

        using JwsVerifier verifier = Verifier(TestPki.Public(root));
        Assert.Equal("com.example.app", verifier.VerifyTransaction(jws).BundleId);
    }

    /// <summary>The other direction: swapping x5c[2] does not buy an attacker trust either.</summary>
    [Fact]
    public void ThirdX5cElementCannotSupplyTrust()
    {
        X509Certificate2 pinned = TestPki.EcRoot("CN=Pinned Root");
        X509Certificate2 attackerRoot = TestPki.EcRoot("CN=Attacker Root");
        X509Certificate2 intermediate = TestPki.EcChild(
            attackerRoot, "CN=WWDR", true, TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.EcChild(intermediate, "CN=Signing", false, TestPki.LeafOid);
        string jws = TestPki.SignJws(leaf, new[] { leaf, intermediate, attackerRoot }, Payload);

        using JwsVerifier verifier = Verifier(TestPki.Public(pinned));
        Assert.Equal(VerificationReason.InvalidChain, ReasonOf(() => verifier.VerifyTransaction(jws)));
    }

    [Fact]
    public void IntermediateWithoutTheCaFlagIsRejected()
    {
        // The platform refuses to issue from a non-CA certificate, so the
        // intermediate signs the leaf as a CA and is then re-issued for the
        // same key with CA:false — exactly the shape an attacker would present.
        X509Certificate2 root = TestPki.EcRoot();
        X509Certificate2 intermediate = TestPki.EcChild(root, "CN=WWDR", true, TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.EcChild(intermediate, "CN=Signing", false, TestPki.LeafOid);
        X509Certificate2 notACa = TestPki.EcReissue(root, intermediate, false, TestPki.IntermediateOid);
        string jws = TestPki.SignJws(leaf, new[] { leaf, notACa, root }, Payload);

        using JwsVerifier verifier = Verifier(TestPki.Public(root));
        Assert.Equal(VerificationReason.InvalidChain, ReasonOf(() => verifier.VerifyTransaction(jws)));
    }

    [Fact]
    public void SelfSignedLeafClaimingToBeItsOwnIssuerIsRejected()
    {
        X509Certificate2 pinned = TestPki.EcRoot("CN=Pinned Root");
        X509Certificate2 rogue = TestPki.EcRoot("CN=Rogue", markerOid: TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.EcChild(rogue, "CN=Rogue", false, TestPki.LeafOid);
        string jws = TestPki.SignJws(leaf, new[] { leaf, rogue, rogue }, Payload);

        using JwsVerifier verifier = Verifier(TestPki.Public(pinned));
        Assert.Equal(VerificationReason.InvalidChain, ReasonOf(() => verifier.VerifyTransaction(jws)));
    }

    /// <summary>
    /// Names are compared as bytes. A subject whose printable form matches but
    /// whose DER differs is a different name.
    /// </summary>
    [Fact]
    public void IssuerNameIsComparedAsBytesNotAsAString()
    {
        X509Certificate2 root = TestPki.EcRoot("CN=Fake Apple Root CA");
        X509Certificate2 lookalike = TestPki.EcRoot("CN=fake apple root ca");
        X509Certificate2 intermediate = TestPki.EcChild(root, "CN=WWDR", true, TestPki.IntermediateOid);

        Assert.False(Internals.IssuedBy(intermediate, lookalike));
        Assert.True(Internals.IssuedBy(intermediate, root));
    }

    /// <summary>
    /// Trust anchors are trusted by fiat: an anchor's own expiry is not
    /// checked, which is what lets a historical payload keep verifying.
    /// </summary>
    [Fact]
    public void AnchorExpiryIsNotChecked()
    {
        DateTimeOffset from = new(2019, 1, 1, 0, 0, 0, TimeSpan.Zero);
        DateTimeOffset to = new(2021, 1, 1, 0, 0, 0, TimeSpan.Zero);
        X509Certificate2 root = TestPki.EcRoot("CN=Expired Root", from, to);
        X509Certificate2 intermediate = TestPki.EcChild(
            root, "CN=WWDR", true, TestPki.IntermediateOid, from, to);
        X509Certificate2 leaf = TestPki.EcChild(
            intermediate, "CN=Signing", false, TestPki.LeafOid, from, to);

        // signedDate 2020-06-01, inside the leaf/intermediate window and long
        // past nothing — the anchor is expired today and that is irrelevant.
        string jws = TestPki.SignJws(
            leaf,
            new[] { leaf, intermediate, root },
            "{\"bundleId\":\"com.example.app\",\"environment\":\"Sandbox\",\"signedDate\":1590969600000}");

        using JwsVerifier verifier = Verifier(TestPki.Public(root));
        Assert.Equal("com.example.app", verifier.VerifyTransaction(jws).BundleId);
    }

    [Theory]
    [InlineData("2024-01-01T00:00:00Z", true)]
    [InlineData("2023-12-31T23:59:59Z", false)]
    [InlineData("2050-01-01T00:00:00Z", true)]
    [InlineData("2050-01-01T00:00:01Z", false)]
    public void ValidityWindowIsInclusiveAtBothEnds(string signedAt, bool accepted)
    {
        X509Certificate2 root = TestPki.EcRoot();
        X509Certificate2 intermediate = TestPki.EcChild(root, "CN=WWDR", true, TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.EcChild(intermediate, "CN=Signing", false, TestPki.LeafOid);
        long millis = DateTimeOffset.Parse(signedAt, System.Globalization.CultureInfo.InvariantCulture)
            .ToUnixTimeMilliseconds();
        string jws = TestPki.SignJws(
            leaf,
            new[] { leaf, intermediate, root },
            "{\"bundleId\":\"com.example.app\",\"environment\":\"Sandbox\",\"signedDate\":" + millis + "}");

        using JwsVerifier verifier = Verifier(TestPki.Public(root));
        if (accepted)
        {
            Assert.Equal("com.example.app", verifier.VerifyTransaction(jws).BundleId);
        }
        else
        {
            Assert.Equal(VerificationReason.InvalidChain, ReasonOf(() => verifier.VerifyTransaction(jws)));
        }
    }

    /// <summary>
    /// An unrecognised signature algorithm is a <em>failed</em> check, not a
    /// skipped one. MD5-RSA is the classic way that distinction gets exploited.
    /// </summary>
    [Fact]
    public void CertificateSignedWithAnAlgorithmOutsideTheAllowlistIsRejected()
    {
        X509Certificate2 root = TestPki.RsaRoot();
        X509Certificate2 child = TestPki.RsaChild(root, "CN=Child", true, TestPki.IntermediateOid);
        byte[] retagged = Retag(child.RawData, "1.2.840.113549.1.1.4"); // md5WithRSAEncryption
        X509Certificate2 forged = X509CertificateLoader.LoadCertificate(retagged);

        Assert.False(Internals.IssuedBy(forged, root));
    }

    /// <summary>
    /// The algorithm named inside the TBS must match the outer one, or the
    /// signature does not commit to the algorithm it was made with.
    /// </summary>
    [Fact]
    public void OuterAndInnerSignatureAlgorithmMustAgree()
    {
        X509Certificate2 root = TestPki.RsaRoot();
        X509Certificate2 child = TestPki.RsaChild(root, "CN=Child", true, TestPki.IntermediateOid);
        byte[] outerOnly = RetagOuterOnly(child.RawData, "1.2.840.113549.1.1.12");
        X509Certificate2 forged = X509CertificateLoader.LoadCertificate(outerOnly);

        Assert.False(Internals.IssuedBy(forged, root));
    }

    /// <summary>
    /// The receipt path bounds its walk, so a mesh of cross-signed certificates
    /// cannot make it backtrack exponentially.
    /// </summary>
    [Fact]
    public void ReceiptChainDeeperThanTheBoundIsRejectedQuickly()
    {
        X509Certificate2 root = TestPki.RsaRoot();
        X509Certificate2 current = root;
        List<X509Certificate2> chain = new();
        for (int depth = 0; depth < 8; depth++)
        {
            current = TestPki.RsaChild(current, "CN=Hop " + depth, true, TestPki.IntermediateOid);
            chain.Add(current);
        }

        X509Certificate2 signer = TestPki.RsaChild(current, "CN=Signer", false, TestPki.LeafOid);
        chain.Add(signer);
        byte[] receipt = TestPki.SignReceipt(TestPki.StandardPayload(), signer, chain);

        Stopwatch stopwatch = Stopwatch.StartNew();
        VerificationException error = Assert.Throws<VerificationException>(
            () => ReceiptVerifier.VerifyReceiptCore(receipt, new[] { TestPki.Public(root) }));
        stopwatch.Stop();

        Assert.Equal(VerificationReason.InvalidChain, error.Reason);
        Assert.True(stopwatch.ElapsedMilliseconds < 5_000, $"took {stopwatch.ElapsedMilliseconds} ms");
    }

    /// <summary>
    /// Belt to the analyzer's braces: the shipped IL must not reference
    /// <c>X509Chain</c>, whose defaults are the OS trust store plus online
    /// revocation and AIA fetching.
    /// </summary>
    [Fact]
    public void ShippedAssemblyNeverReferencesX509Chain()
    {
        Assembly library = typeof(JwsVerifier).Assembly;
        byte[] il = System.IO.File.ReadAllBytes(library.Location);
        string text = System.Text.Encoding.ASCII.GetString(il);

        foreach (string banned in new[] { "X509Chain", "X509ChainPolicy", "SystemCertPool", "HttpClient" })
        {
            Assert.DoesNotContain(banned, text, StringComparison.Ordinal);
        }
    }

    /// <summary>A chain to a genuine public CA must fail: only pinned anchors count.</summary>
    [Fact]
    public void ChainToAPublicCertificateAuthorityIsRejected()
    {
        // The genuine Apple receipt chains to the Apple Inc. Root CA, which is
        // in the OS trust store on macOS and Windows. Verified against the
        // Apple *JWS* roots — a different, equally genuine public CA set — it
        // must still fail, because trust comes from the argument and from
        // nowhere else.
        byte[] receipt = Fixtures.Bytes("public-receipt-sandbox-g5");
        X509Certificate2 unrelated = TestPki.Public(TestPki.RsaRoot("CN=Not Apple"));

        Assert.Equal(
            VerificationReason.InvalidChain,
            ReasonOf(() => ReceiptVerifier.VerifyReceiptCore(receipt, new[] { unrelated })));
    }

    private static byte[] Retag(byte[] certificate, string algorithmOid)
    {
        byte[] outer = RetagOuterOnly(certificate, algorithmOid);
        return RetagTbsOnly(outer, algorithmOid);
    }

    private static byte[] RetagOuterOnly(byte[] certificate, string algorithmOid)
    {
        System.Formats.Asn1.AsnReader reader =
            new(certificate, System.Formats.Asn1.AsnEncodingRules.DER);
        System.Formats.Asn1.AsnReader sequence = reader.ReadSequence();
        byte[] tbs = sequence.ReadEncodedValue().ToArray();
        sequence.ReadEncodedValue();
        byte[] signature = sequence.ReadEncodedValue().ToArray();

        System.Formats.Asn1.AsnWriter writer = new(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteEncodedValue(tbs);
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(algorithmOid);
                writer.WriteNull();
            }

            writer.WriteEncodedValue(signature);
        }

        return writer.Encode();
    }

    private static byte[] RetagTbsOnly(byte[] certificate, string algorithmOid)
    {
        System.Formats.Asn1.AsnReader reader =
            new(certificate, System.Formats.Asn1.AsnEncodingRules.DER);
        System.Formats.Asn1.AsnReader sequence = reader.ReadSequence();
        System.Formats.Asn1.AsnReader tbs = sequence.ReadSequence();
        byte[] outerAlgorithm = sequence.ReadEncodedValue().ToArray();
        byte[] signature = sequence.ReadEncodedValue().ToArray();

        List<byte[]> fields = new();
        byte[] version = tbs.ReadEncodedValue().ToArray();
        byte[] serial = tbs.ReadEncodedValue().ToArray();
        tbs.ReadEncodedValue(); // the algorithm being replaced
        fields.Add(version);
        fields.Add(serial);
        while (tbs.HasData)
        {
            fields.Add(tbs.ReadEncodedValue().ToArray());
        }

        System.Formats.Asn1.AsnWriter writer = new(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteEncodedValue(fields[0]);
                writer.WriteEncodedValue(fields[1]);
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(algorithmOid);
                    writer.WriteNull();
                }

                for (int i = 2; i < fields.Count; i++)
                {
                    writer.WriteEncodedValue(fields[i]);
                }
            }

            writer.WriteEncodedValue(outerAlgorithm);
            writer.WriteEncodedValue(signature);
        }

        return writer.Encode();
    }
}
