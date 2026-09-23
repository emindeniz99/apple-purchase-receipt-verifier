using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier.Jws;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>The JWS path's own rules, beyond what the shared vectors reach.</summary>
public class JwsTests
{
    private static IReadOnlyList<X509Certificate2> Roots() =>
        new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("jws-root")) };

    private static JwsVerifier Verifier(
        string bundleId = "com.example.app",
        AppleEnvironment environment = AppleEnvironment.Sandbox,
        long? appAppleId = null) =>
        new(Roots(), bundleId, new[] { environment }, appAppleId);

    [Fact]
    public void ATamperedPayloadSegmentFailsTheSignature()
    {
        string[] parts = Fixtures.Text("transaction").Split('.');
        string payload = Encoding.UTF8.GetString(Base64Url(parts[1]))
            .Replace("\"quantity\":1", "\"quantity\":9", StringComparison.Ordinal);
        string tampered = parts[0] + "." + TestPki.Base64Url(Encoding.UTF8.GetBytes(payload)) + "." + parts[2];

        using JwsVerifier verifier = Verifier();
        Assert.Equal(
            VerificationReason.InvalidSignature,
            Assert.Throws<VerificationException>(() => verifier.VerifyTransaction(tampered)).Reason);
    }

    [Theory]
    [InlineData(63)]
    [InlineData(65)]
    [InlineData(0)]
    [InlineData(128)]
    public void ASignatureThatIsNotSixtyFourBytesIsRejected(int length)
    {
        string[] parts = Fixtures.Text("transaction").Split('.');
        string jws = parts[0] + "." + parts[1] + "." + TestPki.Base64Url(new byte[length]);

        using JwsVerifier verifier = Verifier();
        Assert.Equal(
            VerificationReason.InvalidSignature,
            Assert.Throws<VerificationException>(() => verifier.VerifyTransaction(jws)).Reason);
    }

    /// <summary>
    /// The format trap, asserted in the direction that would have silently
    /// "worked" if the conversion were reversed: .NET's three-argument
    /// <c>VerifyData</c> wants IEEE P1363, and a JWS signature already is one.
    /// A DER re-encoding of the same signature must fail.
    /// </summary>
    [Fact]
    public void AnEs256SignatureReEncodedAsDerIsRejected()
    {
        string[] parts = Fixtures.Text("transaction").Split('.');
        byte[] p1363 = Base64Url(parts[2]);

        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(new BigInteger(p1363.AsSpan(0, 32), isUnsigned: true, isBigEndian: true));
            writer.WriteInteger(new BigInteger(p1363.AsSpan(32, 32), isUnsigned: true, isBigEndian: true));
        }

        string jws = parts[0] + "." + parts[1] + "." + TestPki.Base64Url(writer.Encode());
        using JwsVerifier verifier = Verifier();
        Assert.Equal(
            VerificationReason.InvalidSignature,
            Assert.Throws<VerificationException>(() => verifier.VerifyTransaction(jws)).Reason);
    }

    [Fact]
    public void ALeafWithAnRsaKeyIsRejected()
    {
        X509Certificate2 root = TestPki.EcRoot();
        X509Certificate2 intermediate = TestPki.EcChild(root, "CN=WWDR", true, TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.RsaChild(intermediate, "CN=Signing", false, TestPki.LeafOid);
        string jws = TestPki.SignJws(
            leaf,
            new[] { leaf, intermediate, root },
            "{\"bundleId\":\"com.example.app\",\"environment\":\"Sandbox\"}");

        using JwsVerifier verifier = new(
            new[] { TestPki.Public(root) }, "com.example.app", new[] { AppleEnvironment.Sandbox });
        Assert.Equal(
            VerificationReason.InvalidSignature,
            Assert.Throws<VerificationException>(() => verifier.VerifyTransaction(jws)).Reason);
    }

    /// <summary>
    /// An AppTransaction states its signing time as <c>receiptCreationDate</c>,
    /// so the chain-validity instant falls back to it.
    /// </summary>
    [Fact]
    public void ReceiptCreationDateStandsInForASignedDate()
    {
        using JwsVerifier verifier = new(
            Roots(), "com.example.app", new[] { AppleEnvironment.Sandbox }, 123456789L);
        AppTransactionPayload payload =
            verifier.VerifyAppTransaction(Fixtures.Text("app-transaction"));
        Assert.Equal(1722945600000L, payload.ReceiptCreationDate);
    }

    [Fact]
    public void VerifyRawIgnoresEveryClaimButNotTheSignature()
    {
        using JwsVerifier verifier = new(
            Roots(), "com.nothing.matches.this", new[] { AppleEnvironment.LocalTesting });
        IReadOnlyDictionary<string, object?> claims =
            verifier.VerifyRaw(Fixtures.Text("transaction"));
        Assert.Equal("com.example.app", claims["bundleId"]);
        Assert.Equal("Sandbox", claims["environment"]);

        string[] parts = Fixtures.Text("transaction").Split('.');
        string broken = parts[0] + "." + parts[1] + "." + TestPki.Base64Url(new byte[64]);
        Assert.Equal(
            VerificationReason.InvalidSignature,
            Assert.Throws<VerificationException>(() => verifier.VerifyRaw(broken)).Reason);
    }

    [Fact]
    public void ProductionAppTransactionsRequireTheConfiguredAppleId()
    {
        using JwsVerifier unset = new(
            Roots(), "com.example.app", new[] { AppleEnvironment.Production });
        Assert.Equal(
            VerificationReason.WrongAppAppleId,
            Assert.Throws<VerificationException>(
                () => unset.VerifyAppTransaction(Fixtures.Text("app-transaction-production"))).Reason);

        using JwsVerifier matching = new(
            Roots(), "com.example.app", new[] { AppleEnvironment.Production }, 123456789L);
        Assert.Equal(
            123456789L,
            matching.VerifyAppTransaction(Fixtures.Text("app-transaction-production")).AppAppleId);
    }

    [Fact]
    public void SandboxAppTransactionsIgnoreTheAppleId()
    {
        using JwsVerifier verifier = new(
            Roots(), "com.example.app", new[] { AppleEnvironment.Sandbox }, 999L);
        Assert.Equal(
            "Sandbox", verifier.VerifyAppTransaction(Fixtures.Text("app-transaction")).ReceiptType);
    }

    [Fact]
    public void UnmodelledClaimsSurviveOntoTheTypedPayload()
    {
        using JwsVerifier verifier = Verifier();
        TransactionPayload payload = verifier.VerifyTransaction(Fixtures.Text("transaction"));
        Assert.Equal("Non-Consumable", payload.Type);
        Assert.Equal("PURCHASED", payload.InAppOwnershipType);
        Assert.Equal("com.example.app.pro", payload.ClaimsMap["productId"]);
        Assert.Equal(1722945600000L, payload.ClaimsMap["purchaseDate"]);
    }

    [Fact]
    public void BundleIdIsCheckedBeforeEnvironment()
    {
        using JwsVerifier verifier = new(
            Roots(), "com.other.app", new[] { AppleEnvironment.Production });
        Assert.Equal(
            VerificationReason.WrongBundleId,
            Assert.Throws<VerificationException>(
                () => verifier.VerifyTransaction(Fixtures.Text("transaction"))).Reason);
    }

    // --- the typed read -----------------------------------------------------

    /// <summary>
    /// A modelled claim the typed payload cannot hold is INTERNAL_ERROR, not a
    /// silently absent property: a <c>null</c> <see cref="TransactionPayload.RevocationDate"/>
    /// would make <see cref="TransactionPayload.IsActiveAt"/> grant a revoked
    /// purchase. The shared vectors cover the type mismatches; these are the
    /// fixed-width and boolean edges they do not.
    /// </summary>
    [Theory]
    [InlineData("{\"quantity\":2147483648}")]
    [InlineData("{\"offerType\":-2147483649}")]
    [InlineData("{\"revocationDate\":9223372036854775808}")]
    [InlineData("{\"revocationDate\":1000.5}")]
    [InlineData("{\"revocationDate\":true}")]
    [InlineData("{\"productId\":false}")]
    public void AModelledClaimOfTheWrongTypeIsAnInternalError(string json)
    {
        Assert.Equal(
            VerificationReason.InternalError,
            Assert.Throws<VerificationException>(() => Payload(json)).Reason);
    }

    [Fact]
    public void AWholeNumberDoubleAndANullAreAccepted()
    {
        TransactionPayload payload = Payload(
            "{\"quantity\":2147483647.0,\"revocationDate\":1e3,\"productId\":null,\"unmodelled\":true}");
        Assert.Equal(int.MaxValue, payload.Quantity);
        Assert.Equal(1000L, payload.RevocationDate);
        Assert.Null(payload.ProductId);
        Assert.Equal(true, payload.ClaimsMap["unmodelled"]);
    }

    // --- the entitlement helper ---------------------------------------------

    [Fact]
    public void IsActiveAtReadsRevocationBeforeExpiry()
    {
        TransactionPayload payload = Payload(
            "{\"expiresDate\":2000,\"revocationDate\":1000}");
        Assert.True(payload.IsActiveAt(FromMillis(999)));
        Assert.False(payload.IsActiveAt(FromMillis(1000)));
        Assert.False(payload.IsActiveAt(FromMillis(1500)));
    }

    [Fact]
    public void IsActiveAtTreatsAnAbsentExpiryAsPerpetual()
    {
        TransactionPayload payload = Payload("{\"productId\":\"x\"}");
        Assert.True(payload.IsActiveAt(FromMillis(0)));
        Assert.True(payload.IsActiveAt(DateTimeOffset.UtcNow.AddYears(50)));
    }

    [Fact]
    public void IsActiveAtIsExclusiveAtTheExpiryInstant()
    {
        TransactionPayload payload = Payload("{\"expiresDate\":2000}");
        Assert.True(payload.IsActiveAt(FromMillis(1999)));
        Assert.False(payload.IsActiveAt(FromMillis(2000)));
    }

    private static DateTimeOffset FromMillis(long millis) =>
        DateTimeOffset.FromUnixTimeMilliseconds(millis);

    private static TransactionPayload Payload(string json)
    {
        X509Certificate2 root = TestPki.EcRoot();
        X509Certificate2 intermediate = TestPki.EcChild(root, "CN=WWDR", true, TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.EcChild(intermediate, "CN=Signing", false, TestPki.LeafOid);
        string body = json.Insert(1, "\"bundleId\":\"com.example.app\",\"environment\":\"Sandbox\",");
        string jws = TestPki.SignJws(leaf, new[] { leaf, intermediate, root }, body);

        using JwsVerifier verifier = new(
            new[] { TestPki.Public(root) }, "com.example.app", new[] { AppleEnvironment.Sandbox });
        return verifier.VerifyTransaction(jws);
    }

    private static byte[] Base64Url(string segment)
    {
        string standard = segment.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(standard.PadRight(standard.Length + ((4 - (standard.Length % 4)) % 4), '='));
    }
}
