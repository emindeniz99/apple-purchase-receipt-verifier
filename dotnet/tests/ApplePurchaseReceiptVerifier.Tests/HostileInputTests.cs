using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier.Jws;
using ApplePurchaseReceiptVerifier.Receipt;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The mutation sweep. Hostile bytes go into every public entry point and the
/// assertion is categorical: only <see cref="VerificationException"/> may
/// escape, and the endpoint may not throw at all.
/// </summary>
/// <remarks>
/// Containment has to be categorical because the platform's failure surface is
/// not: <c>AsnContentException</c> derives from <see cref="Exception"/> and not
/// from <c>CryptographicException</c>, and which types <c>SignedCms</c> raises
/// is undocumented and varies by platform. Enumerating them is exactly how an
/// unexpected type escapes a declared contract.
/// </remarks>
public class HostileInputTests
{
    private const string ReceiptBundleId = "com.example.app";

    private static byte[] Receipt => Fixtures.Bytes("receipt");

    private static byte[] GenuineReceipt => Fixtures.Bytes("public-receipt-sandbox-g5");

    private static string Jws => Fixtures.Text("transaction");

    private static IReadOnlyList<X509Certificate2> ReceiptRoots() =>
        new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("receipt-root")) };

    private static IReadOnlyList<X509Certificate2> JwsRoots() =>
        new[] { X509CertificateLoader.LoadCertificate(Fixtures.Bytes("jws-root")) };

    // --- receipt sweeps ------------------------------------------------------

    [Fact]
    public void EveryTruncationOfTheReceiptIsRejected()
    {
        int checkedInputs = 0;
        for (int length = 0; length < Receipt.Length; length += 13)
        {
            byte[] truncated = new byte[length];
            Buffer.BlockCopy(Receipt, 0, truncated, 0, length);
            Assert.False(Accepts(truncated), $"a {length}-byte truncation was accepted");
            checkedInputs++;
        }

        Assert.True(checkedInputs >= 250, $"only {checkedInputs} truncations were exercised");
    }

    /// <summary>
    /// No byte flip can change what a receipt <em>says</em> and still be
    /// accepted.
    /// </summary>
    /// <remarks>
    /// A blanket "every flip is rejected" would be false, and falsely so: some
    /// bytes of a CMS blob are load-bearing for nobody. The receipt's own copy
    /// of a root certificate is a candidate issuer the walk never needs,
    /// because trust comes from the caller's anchor; the SignerInfo version
    /// field, the SignedData <c>digestAlgorithms</c> set and a certificate's
    /// outer algorithm <em>parameters</em> are likewise read by no check here
    /// or in any other port. What must hold is the property that matters: an
    /// accepted mutation still reports exactly the genuine receipt's content.
    /// </remarks>
    [Fact]
    public void NoByteFlipCanChangeWhatAnAcceptedReceiptSays()
    {
        AppReceipt genuine = Verify(Receipt);
        int checkedInputs = 0;
        int rejected = 0;
        for (int index = 0; index < Receipt.Length; index += 7)
        {
            byte[] mutated = (byte[])Receipt.Clone();
            mutated[index] ^= 0xFF;

            AppReceipt? result;
            try
            {
                result = Verify(mutated);
            }
            catch (VerificationException)
            {
                rejected++;
                checkedInputs++;
                continue;
            }
            catch (Exception e)
            {
                throw new InvalidOperationException(
                    $"{e.GetType().FullName} escaped for a flip at offset {index}", e);
            }

            AssertSameContent(genuine, result, index);
            checkedInputs++;
        }

        Assert.True(checkedInputs >= 450, $"only {checkedInputs} byte flips were exercised");
        Assert.True(rejected > checkedInputs / 2, $"only {rejected} of {checkedInputs} flips were rejected");
    }

    private static void AssertSameContent(AppReceipt expected, AppReceipt actual, int offset)
    {
        Assert.Equal(expected.ReceiptType, actual.ReceiptType);
        Assert.Equal(expected.BundleId, actual.BundleId);
        Assert.Equal(expected.AppVersion, actual.AppVersion);
        Assert.Equal(expected.OriginalAppVersion, actual.OriginalAppVersion);
        Assert.Equal(expected.CreationDate, actual.CreationDate);
        Assert.Equal(expected.ExpirationDate, actual.ExpirationDate);
        Assert.Equal(expected.InAppPurchases.Count, actual.InAppPurchases.Count);
        Assert.True(
            expected.OpaqueValue.AsSpan().SequenceEqual(actual.OpaqueValue),
            $"a flip at offset {offset} was accepted with a different opaque value");
    }

    private static AppReceipt Verify(byte[] blob)
    {
        using ReceiptVerifier verifier = new(ReceiptRoots(), ReceiptBundleId);
        return verifier.Verify(blob);
    }

    /// <summary>
    /// The signed region specifically: every flip inside the encapsulated
    /// payload must be rejected, because the CMS signature covers it.
    /// </summary>
    [Fact]
    public void EveryByteFlipInsideTheSignedPayloadIsRejected()
    {
        (int offset, int length) = PayloadRange(Receipt);
        int checkedInputs = 0;
        for (int index = 0; index < length; index += 3)
        {
            byte[] mutated = (byte[])Receipt.Clone();
            mutated[offset + index] ^= 0x01;
            Assert.False(Accepts(mutated), $"a flip at payload offset {index} was accepted");
            checkedInputs++;
        }

        Assert.True(checkedInputs >= 200, $"only {checkedInputs} payload flips were exercised");
    }

    [Fact]
    public void EveryByteFlipInTheGenuineReceiptOnlyEverRaisesAVerificationException()
    {
        int checkedInputs = 0;
        for (int index = 0; index < GenuineReceipt.Length; index += 11)
        {
            byte[] mutated = (byte[])GenuineReceipt.Clone();
            mutated[index] ^= 0x80;
            using ReceiptVerifier verifier = new(
                AppleRootCertificates.ReceiptRoots(), "dev.bonzer.weeka.app");
            OnlyVerificationExceptions(() => verifier.Verify(mutated));
            checkedInputs++;
        }

        Assert.True(checkedInputs >= 450, $"only {checkedInputs} flips were exercised");
    }

    [Fact]
    public void RandomBlobsAreRejectedWithoutEscaping()
    {
        Random random = new(20260904);
        for (int i = 0; i < 400; i++)
        {
            byte[] blob = new byte[random.Next(0, 4096)];
            random.NextBytes(blob);
            Assert.False(Accepts(blob));
        }
    }

    [Fact]
    public void TrailingBytesAfterTheCmsBlobAreRejected()
    {
        foreach (int extra in new[] { 1, 3, 64, 1024 * 1024 })
        {
            byte[] padded = new byte[Receipt.Length + extra];
            Buffer.BlockCopy(Receipt, 0, padded, 0, Receipt.Length);
            Assert.Equal(VerificationReason.InvalidReceiptFormat, ReasonFor(padded));
        }
    }

    // --- named killers -------------------------------------------------------

    /// <summary>
    /// Eleven characters of attacker base64 are what escaped BouncyCastle's
    /// declared contract in the Java port. The C# equivalent is
    /// <c>AsnContentException</c>, which is not a <c>CryptographicException</c>.
    /// </summary>
    [Fact]
    public void TheElevenCharacterBase64ThatBrokeBouncyCastleIsContained()
    {
        using ReceiptVerifier verifier = new(ReceiptRoots(), ReceiptBundleId);
        VerificationException error = Assert.Throws<VerificationException>(() => verifier.Verify("MAsGCSqGSIb3"));
        Assert.Equal(VerificationReason.InvalidReceiptFormat, error.Reason);
    }

    [Theory]
    [InlineData("")]
    [InlineData("!!!!")]
    [InlineData("MA==")]
    [InlineData("AA")]
    public void MalformedBase64ReceiptsAreContained(string input)
    {
        using ReceiptVerifier verifier = new(ReceiptRoots(), ReceiptBundleId);
        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            Assert.Throws<VerificationException>(() => verifier.Verify(input)).Reason);
    }

    [Fact]
    public void NullInputsAreContained()
    {
        using ReceiptVerifier receipts = new(ReceiptRoots(), ReceiptBundleId);
        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            Assert.Throws<VerificationException>(() => receipts.Verify((byte[])null!)).Reason);
        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            Assert.Throws<VerificationException>(() => receipts.Verify((string)null!)).Reason);

        using JwsVerifier jws = new(JwsRoots(), ReceiptBundleId, new[] { AppleEnvironment.Sandbox });
        Assert.Equal(
            VerificationReason.InvalidJwsFormat,
            Assert.Throws<VerificationException>(() => jws.VerifyTransaction(null!)).Reason);
    }

    /// <summary>An attribute type wider than the 32-bit signed range fails the receipt.</summary>
    [Fact]
    public void AnAttributeTypeAboveTheThirtyTwoBitRangeIsRejected()
    {
        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            PayloadReason(TestPki.AttributeSet(new (BigInteger, byte[])[]
            {
                (BigInteger.Pow(2, 64), TestPki.Utf8("x")),
                (2, TestPki.Utf8(ReceiptBundleId)),
            })));
    }

    [Fact]
    public void ANegativeAttributeTypeIsRejected()
    {
        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            PayloadReason(TestPki.AttributeSet(new (BigInteger, byte[])[] { (-1, TestPki.Utf8("x")) })));
    }

    [Fact]
    public void AnAttributeSequenceWithTwoFieldsIsRejected()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSetOf())
        {
            using (writer.PushSequence())
            {
                writer.WriteInteger(2);
                writer.WriteInteger(1);
            }
        }

        Assert.Equal(VerificationReason.InvalidReceiptFormat, PayloadReason(writer.Encode()));
    }

    [Fact]
    public void ASetContainingANonSequenceIsRejected()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSetOf())
        {
            writer.WriteInteger(7);
        }

        Assert.Equal(VerificationReason.InvalidReceiptFormat, PayloadReason(writer.Encode()));
    }

    [Fact]
    public void ADateOutsideTheRepresentableRangeIsRejected()
    {
        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            PayloadReason(TestPki.AttributeSet(new (BigInteger, byte[])[]
            {
                (2, TestPki.Utf8(ReceiptBundleId)),
                (12, TestPki.Ia5("+1000000000-01-01T00:00:00Z")),
            })));
    }

    [Fact]
    public void ADateWithoutATimezoneDesignatorIsRejected()
    {
        // A naive date would be read as the host's local time, and the creation
        // date is the instant the chain's validity is judged at — the same
        // receipt would verify on one host and fail on another.
        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            PayloadReason(TestPki.AttributeSet(new (BigInteger, byte[])[]
            {
                (2, TestPki.Utf8(ReceiptBundleId)),
                (12, TestPki.Ia5("2024-08-06T12:00:00")),
            })));
    }

    [Fact]
    public void AStringAttributeThatIsNotAStringIsRejected()
    {
        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            PayloadReason(TestPki.AttributeSet(new (BigInteger, byte[])[] { (2, TestPki.Integer(7)) })));
    }

    [Fact]
    public void AUtf8StringWholeContentIsAnInvalidByteIsRejected()
    {
        // 0xFF is not a legal UTF-8 byte anywhere.
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.WriteOctetString(new byte[] { 0xFF });
        byte[] octets = writer.Encode();
        octets[0] = 0x0C; // retag OCTET STRING as UTF8String

        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            PayloadReason(TestPki.AttributeSet(new (BigInteger, byte[])[] { (2, octets) })));
    }

    [Fact]
    public void AnAttributeValueWithTrailingDataIsRejected()
    {
        byte[] value = TestPki.Utf8("com.example.app");
        byte[] padded = new byte[value.Length + 2];
        Buffer.BlockCopy(value, 0, padded, 0, value.Length);
        padded[value.Length] = 0x05;
        padded[value.Length + 1] = 0x00;

        Assert.Equal(
            VerificationReason.InvalidReceiptFormat,
            PayloadReason(TestPki.AttributeSet(new (BigInteger, byte[])[] { (2, padded) })));
    }

    /// <summary>
    /// A payload swapped for the attacker's own, under the genuine
    /// certificates and the genuine SignerInfo: the shape a forger reaches
    /// without a private key.
    /// </summary>
    [Fact]
    public void AForgedPayloadUnderGenuineCertificatesIsRejected()
    {
        byte[] forged = ReplacePayload(Receipt, TestPki.StandardPayload("com.attacker.app"));
        using ReceiptVerifier verifier = new(ReceiptRoots(), "com.attacker.app");
        Assert.Equal(
            VerificationReason.InvalidSignature,
            Assert.Throws<VerificationException>(() => verifier.Verify(forged)).Reason);
    }

    // --- JWS sweeps ----------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData("...")]
    [InlineData("a.b")]
    [InlineData("a.b.c.d")]
    [InlineData("a.b.c.d.e")]
    public void JwsSegmentShapesOutsideThreeAreRejected(string jws)
    {
        Assert.Equal(VerificationReason.InvalidJwsFormat, JwsReason(jws));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("RS256")]
    [InlineData("ES384")]
    [InlineData("")]
    public void AlgorithmsOtherThanEs256AreRejected(string algorithm)
    {
        X509Certificate2 root = TestPki.EcRoot();
        X509Certificate2 intermediate = TestPki.EcChild(root, "CN=WWDR", true, TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.EcChild(intermediate, "CN=Signing", false, TestPki.LeafOid);
        string jws = TestPki.SignJws(
            leaf,
            new[] { leaf, intermediate, root },
            "{\"bundleId\":\"com.example.app\",\"environment\":\"Sandbox\"}",
            algorithm);

        using JwsVerifier verifier = new(
            new[] { TestPki.Public(root) }, "com.example.app", new[] { AppleEnvironment.Sandbox });
        Assert.Equal(
            VerificationReason.InvalidJwsFormat,
            Assert.Throws<VerificationException>(() => verifier.VerifyTransaction(jws)).Reason);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    public void AnX5cThatIsNotExactlyThreeCertificatesIsRejected(int count)
    {
        X509Certificate2 root = TestPki.EcRoot();
        X509Certificate2 intermediate = TestPki.EcChild(root, "CN=WWDR", true, TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.EcChild(intermediate, "CN=Signing", false, TestPki.LeafOid);
        X509Certificate2[] all = { leaf, intermediate, root, root };
        X509Certificate2[] x5c = new X509Certificate2[count];
        Array.Copy(all, x5c, count);

        string jws = TestPki.SignJws(
            leaf, x5c, "{\"bundleId\":\"com.example.app\",\"environment\":\"Sandbox\"}");
        using JwsVerifier verifier = new(
            new[] { TestPki.Public(root) }, "com.example.app", new[] { AppleEnvironment.Sandbox });
        Assert.Equal(
            VerificationReason.InvalidJwsFormat,
            Assert.Throws<VerificationException>(() => verifier.VerifyTransaction(jws)).Reason);
    }

    [Fact]
    public void AnX5cEntryThatIsNotACertificateIsRejected()
    {
        string header = "{\"alg\":\"ES256\",\"x5c\":[\"" + Convert.ToBase64String(new byte[] { 1, 2, 3 })
            + "\",\"" + Convert.ToBase64String(new byte[] { 4, 5, 6 }) + "\",\"AAAA\"]}";
        string jws = TestPki.Base64Url(Encoding.UTF8.GetBytes(header))
            + "." + TestPki.Base64Url(Encoding.UTF8.GetBytes("{}"))
            + "." + TestPki.Base64Url(new byte[64]);

        Assert.Equal(VerificationReason.InvalidCertificate, JwsReason(jws));
    }

    /// <summary>
    /// RFC 5280 §4.2: a certificate MUST NOT include more than one instance
    /// of a particular extension. The platform decoder takes such a
    /// certificate, and every reader downstream — the CA flag, the key usage,
    /// the marker-OID lookup — then answers from the copy this library
    /// happened to keep. The verdict is a defect of the certificate, which is
    /// what the shared vector transaction/reject-x5c-duplicate-extension pins.
    /// </summary>
    [Fact]
    public void AnX5cCertificateCarryingOneExtensionTwiceIsRejected()
    {
        X509Certificate2 root = TestPki.EcRoot();
        X509Certificate2 intermediate = TestPki.EcChild(root, "CN=WWDR", true, TestPki.IntermediateOid);
        X509Certificate2 leaf = TestPki.EcChildWithDuplicateExtension(
            intermediate, "CN=Signing", TestPki.LeafOid);

        string jws = TestPki.SignJws(
            leaf,
            new[] { leaf, intermediate, root },
            "{\"bundleId\":\"com.example.app\",\"environment\":\"Sandbox\"}");
        using JwsVerifier verifier = new(
            new[] { TestPki.Public(root) }, "com.example.app", new[] { AppleEnvironment.Sandbox });

        Assert.Equal(
            VerificationReason.InvalidCertificate,
            Assert.Throws<VerificationException>(() => verifier.VerifyTransaction(jws)).Reason);
    }

    [Fact]
    public void AnX5cEntryInPemRatherThanDerIsRejected()
    {
        X509Certificate2 root = TestPki.EcRoot();
        string pem = "-----BEGIN CERTIFICATE-----\n"
            + Convert.ToBase64String(root.RawData) + "\n-----END CERTIFICATE-----";
        string header = "{\"alg\":\"ES256\",\"x5c\":[\"" + pem.Replace("\n", "\\n") + "\",\"AAAA\",\"AAAA\"]}";
        string jws = TestPki.Base64Url(Encoding.UTF8.GetBytes(header))
            + "." + TestPki.Base64Url(Encoding.UTF8.GetBytes("{}"))
            + "." + TestPki.Base64Url(new byte[64]);

        Assert.Equal(VerificationReason.InvalidCertificate, JwsReason(jws));
    }

    [Fact]
    public void EveryTruncationAndCharacterFlipOfTheGenuineJwsIsContained()
    {
        string jws = Jws;
        int checkedInputs = 0;
        for (int length = 0; length < jws.Length; length += 7)
        {
            Assert.False(AcceptsJws(jws.Substring(0, length)));
            checkedInputs++;
        }

        const string Alphabet = "ABXYZ019+/_-.";
        Random random = new(20260904);
        for (int index = 0; index < jws.Length; index += 5)
        {
            char[] chars = jws.ToCharArray();
            char replacement = chars[index];
            while (replacement == chars[index])
            {
                replacement = Alphabet[random.Next(Alphabet.Length)];
            }

            chars[index] = replacement;
            Assert.False(AcceptsJws(new string(chars)), $"a flip at index {index} was accepted");
            checkedInputs++;
        }

        Assert.True(checkedInputs >= 400, $"only {checkedInputs} JWS mutations were exercised");
    }

    /// <summary>
    /// Every boundary is categorical, including the raw-JSON one: neither the
    /// reader nor the writer may escape a method documented as never throwing.
    /// </summary>
    [Fact]
    public void TheRawJsonEndpointContainsEveryFailureAsAStatus()
    {
        using VerifyReceiptEndpoint endpoint = new(ReceiptRoots(), AppleEnvironment.Sandbox);
        Random random = new(20260904);
        for (int i = 0; i < 200; i++)
        {
            char[] chars = new char[random.Next(0, 64)];
            for (int j = 0; j < chars.Length; j++)
            {
                chars[j] = "{}[]\":,\\\"0aA \n\t\u0000\uD800".ToCharArray()[random.Next(16)];
            }

            string answer = endpoint.VerifyReceiptJson(new string(chars));
            Assert.StartsWith("{\"status\":", answer, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void HeaderAndPayloadSwappedIsRejected()
    {
        string[] parts = Jws.Split('.');
        Assert.False(AcceptsJws(parts[1] + "." + parts[0] + "." + parts[2]));
    }

    [Theory]
    [InlineData("~~~~")]
    [InlineData("a")]
    [InlineData("QQ+/")]
    public void NonBase64UrlSegmentsAreRejected(string segment)
    {
        Assert.Equal(VerificationReason.InvalidJwsFormat, JwsReason(segment + ".e30.AAAA"));
    }

    // --- the endpoint never throws ------------------------------------------

    [Fact]
    public void TheEndpointNeverThrowsForTheWholeHostileCorpus()
    {
        using VerifyReceiptEndpoint endpoint = new(ReceiptRoots(), AppleEnvironment.Sandbox);
        Random random = new(20260904);
        int answered = 0;

        foreach (byte[] blob in HostileBlobs(random))
        {
            IReadOnlyDictionary<string, object?> body = Body(Convert.ToBase64String(blob));
            IReadOnlyDictionary<string, object?> response = endpoint.VerifyReceipt(body);
            Assert.True(response.ContainsKey("status"));
            answered++;
        }

        foreach (string raw in new[] { "", "!!!!", "not base64", "e30", new string('A', 10_000) })
        {
            Assert.True(endpoint.VerifyReceipt(Body(raw)).ContainsKey("status"));
            answered++;
        }

        foreach (string json in new[] { "", "null", "[]", "3", "\"x\"", "{", "{\"a\":", "{}" })
        {
            Assert.StartsWith("{\"status\":", endpoint.VerifyReceiptJson(json), StringComparison.Ordinal);
            answered++;
        }

        Assert.True(answered >= 300, $"only {answered} hostile inputs reached the endpoint");
    }

    private static IEnumerable<byte[]> HostileBlobs(Random random)
    {
        for (int length = 0; length < Receipt.Length; length += 17)
        {
            byte[] truncated = new byte[length];
            Buffer.BlockCopy(Receipt, 0, truncated, 0, length);
            yield return truncated;
        }

        for (int index = 0; index < Receipt.Length; index += 23)
        {
            byte[] mutated = (byte[])Receipt.Clone();
            mutated[index] ^= 0x7F;
            yield return mutated;
        }

        for (int i = 0; i < 100; i++)
        {
            byte[] blob = new byte[random.Next(0, 2048)];
            random.NextBytes(blob);
            yield return blob;
        }
    }

    // --- helpers -------------------------------------------------------------

    private static IReadOnlyDictionary<string, object?> Body(string receiptData)
    {
        Dictionary<string, object?> body = new(StringComparer.Ordinal)
        {
            ["receipt-data"] = receiptData,
            ["password"] = "ignored",
            ["exclude-old-transactions"] = true,
        };
        return body;
    }

    private static bool Accepts(byte[] blob)
    {
        using ReceiptVerifier verifier = new(ReceiptRoots(), ReceiptBundleId);
        return OnlyVerificationExceptions(() => verifier.Verify(blob));
    }

    private static bool AcceptsJws(string jws)
    {
        using JwsVerifier verifier = new(
            JwsRoots(), "com.example.app", new[] { AppleEnvironment.Sandbox });
        return OnlyVerificationExceptions(() => verifier.VerifyTransaction(jws));
    }

    /// <summary>
    /// Runs <paramref name="action"/> and asserts that nothing but a
    /// <see cref="VerificationException"/> escapes it.
    /// </summary>
    /// <returns><see langword="true"/> when the call succeeded.</returns>
    private static bool OnlyVerificationExceptions(Action action)
    {
        try
        {
            action();
            return true;
        }
        catch (VerificationException)
        {
            return false;
        }
        catch (Exception e)
        {
            throw new InvalidOperationException(
                $"{e.GetType().FullName} escaped a public entry point: {e.Message}", e);
        }
    }

    private static VerificationReason ReasonFor(byte[] blob)
    {
        using ReceiptVerifier verifier = new(ReceiptRoots(), ReceiptBundleId);
        return Assert.Throws<VerificationException>(() => verifier.Verify(blob)).Reason;
    }

    private static VerificationReason JwsReason(string jws)
    {
        using JwsVerifier verifier = new(
            JwsRoots(), "com.example.app", new[] { AppleEnvironment.Sandbox });
        return Assert.Throws<VerificationException>(() => verifier.VerifyTransaction(jws)).Reason;
    }

    /// <summary>The reason a receipt carrying <paramref name="payload"/> fails with.</summary>
    private static VerificationReason PayloadReason(byte[] payload)
    {
        byte[] receipt = ReplacePayload(Receipt, payload);
        using ReceiptVerifier verifier = new(ReceiptRoots(), ReceiptBundleId);
        return Assert.Throws<VerificationException>(() => verifier.Verify(receipt)).Reason;
    }

    /// <summary>Where the encapsulated content sits inside the CMS blob.</summary>
    private static (int Offset, int Length) PayloadRange(byte[] der)
    {
        int offset = IndexOf(der, ExpectedPayload(der));
        Assert.True(offset > 0, "could not locate the encapsulated payload");
        return (offset, ExpectedPayload(der).Length);
    }

    private static byte[] ExpectedPayload(byte[] der)
    {
        System.Security.Cryptography.Pkcs.SignedCms cms = new();
        cms.Decode(der);
        return cms.ContentInfo.Content;
    }

    /// <summary>Rebuilds the blob with a different encapsulated payload.</summary>
    private static byte[] ReplacePayload(byte[] der, byte[] payload)
    {
        // Re-encode rather than splice when the length changes: the enclosing
        // definite lengths would otherwise be wrong.
        AsnReader reader = new(der, AsnEncodingRules.BER);
        AsnReader contentInfo = reader.ReadSequence();
        string oid = contentInfo.ReadObjectIdentifier();
        Asn1Tag explicitTag = new(TagClass.ContextSpecific, 0, true);
        AsnReader signedData = contentInfo.ReadSequence(explicitTag).ReadSequence();

        byte[] version = signedData.ReadEncodedValue().ToArray();
        byte[] digestAlgorithms = signedData.ReadEncodedValue().ToArray();
        signedData.ReadEncodedValue(); // encapContentInfo, replaced below
        List<byte[]> rest = new();
        while (signedData.HasData)
        {
            rest.Add(signedData.ReadEncodedValue().ToArray());
        }

        // BER, not DER: the fixture uses indefinite lengths, and a DER writer
        // refuses to re-emit those encoded values.
        AsnWriter writer = new(AsnEncodingRules.BER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            using (writer.PushSequence(explicitTag))
            {
                using (writer.PushSequence())
                {
                    writer.WriteEncodedValue(version);
                    writer.WriteEncodedValue(digestAlgorithms);
                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier("1.2.840.113549.1.7.1");
                        using (writer.PushSequence(explicitTag))
                        {
                            writer.WriteOctetString(payload);
                        }
                    }

                    foreach (byte[] element in rest)
                    {
                        writer.WriteEncodedValue(element);
                    }
                }
            }
        }

        return writer.Encode();
    }

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i + needle.Length <= haystack.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                return i;
            }
        }

        return -1;
    }
}
