using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The anti-forgery properties of the path walk. Every case here mints the
/// certificate a real attacker would need and asserts the library refuses it.
/// </summary>
public class ChainSecurityTests
{
    private static VerificationReason? ReasonOf<T>(VerificationResult<T> result)
        where T : class => result.Failure?.Reason;

    [Fact]
    public void GenuineFakeAppleChainVerifies()
    {
        TestPki.JwsChain chain = TestPki.SharedJws.Value;
        VerificationResult<JsonPayload> result = chain.Verifier().VerifySignedData(chain.Sign());

        Assert.True(result.Verified, result.Failure?.ToString());
        Assert.Equal(TestPki.Payload, result.Payload.Json);
    }

    /// <summary>
    /// The D13 hole in its JWS form: a developer certificate under the same
    /// WWDR intermediate, chaining to the same pinned root and carrying a
    /// different Apple marker, must not be able to sign an accepted payload.
    /// </summary>
    [Fact]
    public void DeveloperStyleLeafUnderTheSameIntermediateIsRejected()
    {
        TestPki.JwsChain chain = TestPki.SharedJws.Value;
        X509Certificate2 developer = TestPki.EcChild(
            chain.Intermediate, "CN=Apple Distribution: Someone Else", false, "1.2.840.113635.100.6.1.13");
        string jws = TestPki.SignJws(developer, new[] { developer, chain.Intermediate, chain.Root }, TestPki.Payload);

        Assert.Equal(VerificationReason.InvalidCertificatePurpose, ReasonOf(chain.Verifier().VerifySignedData(jws)));
    }

    /// <summary>
    /// x5c[2] is never consulted, so replacing it with an attacker's own root
    /// changes nothing about the verdict.
    /// </summary>
    [Fact]
    public void ThirdX5cElementIsIgnored()
    {
        TestPki.JwsChain chain = TestPki.SharedJws.Value;
        X509Certificate2 attacker = TestPki.EcRoot("CN=Attacker Root");
        string jws = TestPki.SignJws(chain.Leaf, new[] { chain.Leaf, chain.Intermediate, attacker }, TestPki.Payload);

        Assert.True(chain.Verifier().VerifySignedData(jws).Verified);
    }

    /// <summary>The other direction: swapping x5c[2] does not buy an attacker trust either.</summary>
    [Fact]
    public void ThirdX5cElementCannotSupplyTrust()
    {
        X509Certificate2 pinned = TestPki.EcRoot("CN=Pinned Root");
        TestPki.JwsChain attacker = TestPki.NewJwsChain(rootSubject: "CN=Attacker Root");

        Assert.Equal(
            VerificationReason.UntrustedChain,
            ReasonOf(TestPki.Verifier(pinned).VerifySignedData(attacker.Sign())));
    }

    [Fact]
    public void IntermediateWithoutTheCaFlagIsRejected()
    {
        // The platform refuses to issue from a non-CA certificate, so the
        // intermediate signs the leaf as a CA and is then re-issued for the
        // same key with CA:false — exactly the shape an attacker would present.
        TestPki.JwsChain chain = TestPki.SharedJws.Value;
        X509Certificate2 notACa = TestPki.EcReissue(chain.Root, chain.Intermediate, false, TestPki.IntermediateOid);
        string jws = TestPki.SignJws(chain.Leaf, new[] { chain.Leaf, notACa, chain.Root }, TestPki.Payload);

        Assert.Equal(VerificationReason.UntrustedChain, ReasonOf(chain.Verifier().VerifySignedData(jws)));
    }

    [Fact]
    public void SelfSignedLeafClaimingToBeItsOwnIssuerIsRejected()
    {
        X509Certificate2 pinned = TestPki.EcRoot("CN=Pinned Root");
        X509Certificate2 rogue = TestPki.EcRoot("CN=Rogue", markerOid: TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.EcChild(rogue, "CN=Rogue", false, TestPki.LeafOid);
        string jws = TestPki.SignJws(leaf, new[] { leaf, rogue, rogue }, TestPki.Payload);

        Assert.Equal(VerificationReason.UntrustedChain, ReasonOf(TestPki.Verifier(pinned).VerifySignedData(jws)));
    }

    /// <summary>
    /// Names are compared as bytes. Two roots share one key and differ only in
    /// the letter case of their subject, so the intermediate's signature
    /// verifies under either; only the byte comparison of the issuer name can
    /// tell them apart, and it must.
    /// </summary>
    [Fact]
    public void IssuerNameIsComparedAsBytesNotAsAString()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 root = SelfSigned(key, "CN=Fake Apple Root CA");
        X509Certificate2 lookalike = SelfSigned(key, "CN=fake apple root ca");
        X509Certificate2 intermediate = TestPki.EcChild(root, "CN=WWDR", true, TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.EcChild(intermediate, "CN=Signing", false, TestPki.LeafOid);
        string jws = TestPki.SignJws(leaf, new[] { leaf, intermediate, root }, TestPki.Payload);

        Assert.True(TestPki.Verifier(root).VerifySignedData(jws).Verified);
        Assert.Equal(VerificationReason.UntrustedChain, ReasonOf(TestPki.Verifier(lookalike).VerifySignedData(jws)));
    }

    [Theory]
    [InlineData("2024-01-01T00:00:00Z", true)]
    [InlineData("2023-12-31T23:59:59Z", false)]
    [InlineData("2050-01-01T00:00:00Z", true)]
    [InlineData("2050-01-01T00:00:01Z", false)]
    public void ValidityWindowIsInclusiveAtBothEnds(string signedAt, bool accepted)
    {
        TestPki.JwsChain chain = TestPki.SharedJws.Value;
        long millis = DateTimeOffset.Parse(signedAt, CultureInfo.InvariantCulture).ToUnixTimeMilliseconds();
        string jws = chain.Sign(
            "{\"bundleId\":\"com.example.app\",\"signedDate\":" + millis.ToString(CultureInfo.InvariantCulture) + "}");

        VerificationResult<JsonPayload> result = chain.Verifier().VerifySignedData(jws);
        if (accepted)
        {
            Assert.True(result.Verified, result.Failure?.ToString());
        }
        else
        {
            Assert.Equal(VerificationReason.InvalidCertificate, ReasonOf(result));
        }
    }

    /// <summary>
    /// A relabelled signature algorithm is a <em>failed</em> check, not a
    /// skipped one: the intermediate's signature was made with SHA-256 and is
    /// relabelled md5WithRSAEncryption, the classic way that distinction gets
    /// exploited. 0.7 has no allowlist (Q14), so this is about the check
    /// running under the label, not about MD5 being refused.
    /// </summary>
    [Fact]
    public void ACertificateSignatureRelabelledAsMd5IsAFailedCheck()
    {
        X509Certificate2 root = TestPki.RsaRoot();
        X509Certificate2 intermediate = TestPki.RsaChild(root, "CN=WWDR", true, TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.EcChild(intermediate, "CN=Signing", false, TestPki.LeafOid);
        byte[] relabelled = Retag(intermediate.RawData, "1.2.840.113549.1.1.4");

        string genuine = TestPki.SignJws(leaf, new[] { leaf, intermediate, root }, TestPki.Payload);
        string forged = TestPki.SignJwsRaw(leaf, new[] { leaf.RawData, relabelled, root.RawData }, TestPki.Payload);

        IVerifier verifier = TestPki.Verifier(root);
        Assert.True(verifier.VerifySignedData(genuine).Verified);
        Assert.Equal(VerificationReason.UntrustedChain, ReasonOf(verifier.VerifySignedData(forged)));
    }

    /// <summary>
    /// Belt to the analyzer's braces: the shipped IL must not reference
    /// <c>X509Chain</c>, whose defaults are the OS trust store plus online
    /// revocation and AIA fetching.
    /// </summary>
    [Fact]
    public void ShippedAssemblyNeverReferencesX509Chain()
    {
        Assembly library = typeof(IVerifier).Assembly;
        byte[] il = System.IO.File.ReadAllBytes(library.Location);
        string text = System.Text.Encoding.ASCII.GetString(il);

        foreach (string banned in new[] { "X509Chain", "X509ChainPolicy", "SystemCertPool", "HttpClient", "X509Store" })
        {
            Assert.DoesNotContain(banned, text, StringComparison.Ordinal);
        }
    }

    // --- trust isolation: only the configured roots confer trust -------------

    /// <summary>
    /// The genuine Apple receipt chains to the Apple Inc. Root CA, which is in
    /// the OS trust store on macOS and Windows and among the bundled roots.
    /// Under a config that pins some other root it must fail: custom roots
    /// replace the defaults rather than joining them, and trust comes from
    /// the config and from nowhere else.
    /// </summary>
    [Fact]
    public void AGenuineAppleReceiptIsUntrustedUnderACustomRootSet()
    {
        string receipt = Fixtures070.ForReceipt("public-receipt-sandbox-g5");
        X509Certificate2 unrelated = TestPki.RsaRoot("CN=Not Apple");

        Assert.True(Verifier.Create(Config.Defaults()).VerifyReceipt(receipt).Verified);
        Assert.Equal(VerificationReason.UntrustedChain, ReasonOf(TestPki.Verifier(unrelated).VerifyReceipt(receipt)));
    }

    [Fact]
    public void AGenuineAppleJwsIsUntrustedUnderTheDefaultRootsAndUnderAnUnrelatedOne()
    {
        // Apple's own mock is signed under Apple's test CA, which is not a
        // production root: it verifies only when that CA is configured.
        string jws = Fixtures070.ForSignedData("apple-transaction-info");

        Assert.True(TestPki.FixtureVerifier("apple-test-ca").VerifySignedData(jws).Verified);
        Assert.Equal(VerificationReason.UntrustedChain, ReasonOf(Verifier.Create(Config.Defaults()).VerifySignedData(jws)));
        Assert.Equal(
            VerificationReason.UntrustedChain,
            ReasonOf(TestPki.Verifier(TestPki.SharedJws.Value.Root).VerifySignedData(jws)));
    }

    [Fact]
    public void EachConfiguredRootConfersTrustAndNoOtherDoes()
    {
        TestPki.JwsChain a = TestPki.SharedJws.Value;
        TestPki.JwsChain b = TestPki.NewJwsChain(rootSubject: "CN=Second Root");
        string signedUnderA = a.Sign();
        string signedUnderB = b.Sign();

        IVerifier onlyA = TestPki.Verifier(a.Root);
        Assert.True(onlyA.VerifySignedData(signedUnderA).Verified);
        Assert.Equal(VerificationReason.UntrustedChain, ReasonOf(onlyA.VerifySignedData(signedUnderB)));

        IVerifier both = TestPki.Verifier(new[] { TestPki.Public(a.Root), TestPki.Public(b.Root) });
        Assert.True(both.VerifySignedData(signedUnderA).Verified);
        Assert.True(both.VerifySignedData(signedUnderB).Verified);
    }

    /// <summary>
    /// An attacker root that copies the pinned root's subject name, with its
    /// own key, and travels inside the input: in the receipt's certificate bag
    /// and as x5c[2]. The embedded copy is only an anchor when it is
    /// byte-identical to a configured one.
    /// </summary>
    [Fact]
    public void AnImpostorOfThePinnedRootCarriedInTheInputConfersNothing()
    {
        TestPki.ReceiptChain genuine = TestPki.SharedReceipt.Value;
        TestPki.ReceiptChain impostor = TestPki.NewReceiptChain(genuine.Root.Subject);
        byte[] receipt = TestPki.SignReceipt(
            TestPki.StandardPayload(), impostor.Signer, new[] { impostor.Intermediate, impostor.Root });
        Assert.Equal(
            VerificationReason.UntrustedChain,
            ReasonOf(genuine.Verifier().VerifyReceipt(Convert.ToBase64String(receipt))));

        TestPki.JwsChain pinned = TestPki.SharedJws.Value;
        TestPki.JwsChain lookalike = TestPki.NewJwsChain(rootSubject: pinned.Root.Subject);
        Assert.Equal(VerificationReason.UntrustedChain, ReasonOf(pinned.Verifier().VerifySignedData(lookalike.Sign())));
    }

    // --- an unvouched key is never used (0.7 hardening change 1) -------------
    //
    // Proved behaviourally rather than by counting calls: each certificate
    // below is genuinely signed by an issuer nobody pins, and carries key bits
    // that are not a key. A verifier that decoded or used that key before a
    // pinned root vouched for the certificate would answer with the key's
    // defect (INVALID_CERTIFICATE, MALFORMED); one that walks top-down never
    // reaches it, so the chain answers, or the stranger is simply ignored.

    [Fact]
    public void AnUnvouchedX5cIntermediateWithAGarbageKeyIsUntrustedChain()
    {
        TestPki.JwsChain chain = TestPki.SharedJws.Value;
        X509Certificate2 stranger = TestPki.EcRoot("CN=Stranger Root");
        byte[] garbage = TestPki.GarbageKeyCertificate(stranger, "CN=WWDR", true, TestPki.IntermediateOid);
        string jws = TestPki.SignJwsRaw(
            chain.Leaf, new[] { chain.Leaf.RawData, garbage, chain.Root.RawData }, TestPki.Payload);

        Assert.Equal(VerificationReason.UntrustedChain, ReasonOf(chain.Verifier().VerifySignedData(jws)));
    }

    /// <summary>
    /// The control for the test above: the same kind of certificate, issued
    /// by the pinned root this time, is vouched for, so its key is about to
    /// check the leaf and its defect is now the verdict. The only difference
    /// between the two inputs is who signed x5c[1].
    /// </summary>
    [Fact]
    public void AVouchedX5cIntermediateWithAGarbageKeyIsInvalidCertificate()
    {
        TestPki.JwsChain chain = TestPki.SharedJws.Value;
        byte[] garbage = TestPki.GarbageKeyCertificate(chain.Root, "CN=WWDR", true, TestPki.IntermediateOid);
        string jws = TestPki.SignJwsRaw(
            chain.Leaf, new[] { chain.Leaf.RawData, garbage, chain.Root.RawData }, TestPki.Payload);

        Assert.Equal(VerificationReason.InvalidCertificate, ReasonOf(chain.Verifier().VerifySignedData(jws)));
    }

    [Fact]
    public void AGarbageKeyInTheIgnoredThirdX5cEntryChangesNothing()
    {
        TestPki.JwsChain chain = TestPki.SharedJws.Value;
        X509Certificate2 stranger = TestPki.EcRoot("CN=Stranger Root");
        byte[] garbage = TestPki.GarbageKeyCertificate(stranger, "CN=Stranger", true);
        string jws = TestPki.SignJwsRaw(
            chain.Leaf, new[] { chain.Leaf.RawData, chain.Intermediate.RawData, garbage }, TestPki.Payload);

        Assert.True(chain.Verifier().VerifySignedData(jws).Verified);
    }

    [Fact]
    public void AnUnvouchedReceiptIntermediateWithAGarbageKeyIsUntrustedChain()
    {
        // The signer names "CN=Fake WWDR" as its issuer, and the only
        // certificate in the bag with that subject is signed by a root nobody
        // pins and carries a key that is not a key.
        TestPki.ReceiptChain chain = TestPki.SharedReceipt.Value;
        X509Certificate2 stranger = TestPki.RsaRoot("CN=Stranger Root");
        byte[] garbage = TestPki.GarbageKeyCertificate(stranger, chain.Intermediate.Subject, true, TestPki.IntermediateOid);
        byte[] receipt = TestPki.WithCertificateBag(
            chain.Sign(TestPki.StandardPayload()),
            _ => new List<byte[]> { chain.Signer.RawData, garbage });

        Assert.Equal(
            VerificationReason.UntrustedChain,
            ReasonOf(chain.Verifier().VerifyReceipt(Convert.ToBase64String(receipt))));
    }

    /// <summary>
    /// Q16: the certificate bag is not signed, so a certificate no pinned root
    /// vouches for is ignored rather than fatal, whatever its key holds.
    /// </summary>
    [Fact]
    public void AGenuineReceiptPaddedWithGarbageKeyStrangersVerifies()
    {
        TestPki.ReceiptChain chain = TestPki.SharedReceipt.Value;
        X509Certificate2 stranger = TestPki.RsaRoot("CN=Stranger Root");
        byte[][] strangers =
        {
            TestPki.GarbageKeyCertificate(stranger, chain.Intermediate.Subject, true, TestPki.IntermediateOid),
            TestPki.GarbageKeyCertificate(stranger, chain.Signer.Subject, false, TestPki.LeafOid),
            TestPki.GarbageKeyCertificate(chain.Signer, "CN=Below The Signer", false),
        };
        byte[] receipt = TestPki.WithExtraCertificates(chain.Sign(TestPki.StandardPayload()), strangers);

        VerificationResult<ReceiptPayload> result = chain.Verifier().VerifyReceipt(Convert.ToBase64String(receipt));
        Assert.True(result.Verified, result.Failure?.ToString());
        Assert.Equal("com.example.app", result.Payload.BundleId);
    }

    /// <summary>The same padding around a genuine Apple receipt, under the bundled roots.</summary>
    [Fact]
    public void AGenuineAppleReceiptPaddedWithGarbageKeyStrangersVerifies()
    {
        X509Certificate2 stranger = TestPki.RsaRoot("CN=Apple Worldwide Developer Relations Certification Authority");
        byte[] genuine = Fixtures070.Bytes("public-receipt-sandbox-g5");
        byte[] padded = TestPki.WithExtraCertificates(
            genuine,
            TestPki.GarbageKeyCertificate(stranger, "CN=Stranger", true, TestPki.IntermediateOid),
            TestPki.GarbageKeyCertificate(stranger, "CN=Another Stranger", false, TestPki.LeafOid));

        IVerifier verifier = Verifier.Create(Config.Defaults());
        VerificationResult<ReceiptPayload> result = verifier.VerifyReceipt(Convert.ToBase64String(padded));
        Assert.True(result.Verified, result.Failure?.ToString());
        Assert.Equal(
            verifier.VerifyReceipt(Convert.ToBase64String(genuine)).Payload!.ToJson(),
            result.Payload.ToJson());
    }

    // --- helpers -------------------------------------------------------------

    private static X509Certificate2 SelfSigned(ECDsa key, string subject)
    {
        CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        return request.CreateSelfSigned(
            new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2050, 1, 1, 0, 0, 0, TimeSpan.Zero));
    }

    private static byte[] Retag(byte[] certificate, string algorithmOid)
    {
        byte[] outer = RetagOuterOnly(certificate, algorithmOid);
        return RetagTbsOnly(outer, algorithmOid);
    }

    private static byte[] RetagOuterOnly(byte[] certificate, string algorithmOid)
    {
        AsnReader sequence = new AsnReader(certificate, AsnEncodingRules.DER).ReadSequence();
        byte[] tbs = sequence.ReadEncodedValue().ToArray();
        sequence.ReadEncodedValue();
        byte[] signature = sequence.ReadEncodedValue().ToArray();

        AsnWriter writer = new(AsnEncodingRules.DER);
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
        AsnReader sequence = new AsnReader(certificate, AsnEncodingRules.DER).ReadSequence();
        AsnReader tbs = sequence.ReadSequence();
        byte[] outerAlgorithm = sequence.ReadEncodedValue().ToArray();
        byte[] signature = sequence.ReadEncodedValue().ToArray();

        List<byte[]> fields = new();
        while (tbs.HasData)
        {
            fields.Add(tbs.ReadEncodedValue().ToArray());
        }

        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteEncodedValue(fields[0]);  // version
                writer.WriteEncodedValue(fields[1]);  // serial
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(algorithmOid);
                    writer.WriteNull();
                }

                for (int i = 3; i < fields.Count; i++)
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
