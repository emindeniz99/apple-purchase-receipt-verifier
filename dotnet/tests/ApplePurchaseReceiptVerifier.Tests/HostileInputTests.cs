using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier.Internal;
using Xunit;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// The mutation sweep. Hostile bytes go into every public entry point and the
/// assertion is categorical: the verify methods never throw, and a failure
/// caused by the input is never INTERNAL_ERROR.
/// </summary>
/// <remarks>
/// Containment has to be categorical because the platform's failure surface is
/// not: <c>AsnContentException</c> derives from <see cref="Exception"/> and not
/// from <c>CryptographicException</c>, and which types the platform decoders
/// raise is undocumented and varies by platform. Enumerating them is exactly
/// how an unexpected type escapes a declared contract.
/// </remarks>
public class HostileInputTests
{
    private static byte[] Receipt => Fixtures070.Bytes("receipt");

    private static byte[] GenuineReceipt => Fixtures070.Bytes("public-receipt-sandbox-g5");

    private static string Jws => Fixtures070.ForSignedData("transaction");

    private static readonly Lazy<IVerifier> ReceiptVerifier = new(() => TestPki.FixtureVerifier("receipt-root"));

    private static readonly Lazy<IVerifier> JwsVerifier = new(() => TestPki.FixtureVerifier("jws-root"));

    // --- receipt sweeps ------------------------------------------------------

    [Fact]
    public void EveryTruncationOfTheReceiptIsRejected()
    {
        int checkedInputs = 0;
        for (int length = 0; length < Receipt.Length; length += 13)
        {
            Assert.False(Accepts(Receipt[..length]), $"a {length}-byte truncation was accepted");
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
    /// because trust comes from the configured roots; the SignerInfo version
    /// field, the SignedData <c>digestAlgorithms</c> set and a certificate's
    /// outer algorithm <em>parameters</em> are likewise read by no check here
    /// or in any other port. What must hold is the property that matters: an
    /// accepted mutation still reports exactly the genuine receipt's content.
    /// </remarks>
    [Fact]
    public void NoByteFlipCanChangeWhatAnAcceptedReceiptSays()
    {
        string genuine = ReceiptVerifier.Value.VerifyReceipt(Convert.ToBase64String(Receipt)).Payload!.ToJson();
        int checkedInputs = 0;
        int rejected = 0;
        for (int index = 0; index < Receipt.Length; index += 7)
        {
            byte[] mutated = (byte[])Receipt.Clone();
            mutated[index] ^= 0xFF;

            VerificationResult<ReceiptPayload> result = Contained(mutated);
            checkedInputs++;
            if (!result.Verified)
            {
                rejected++;
                continue;
            }

            Assert.True(
                genuine == result.Payload.ToJson(),
                $"a flip at offset {index} was accepted with different content");
        }

        Assert.True(checkedInputs >= 450, $"only {checkedInputs} byte flips were exercised");
        Assert.True(rejected > checkedInputs / 2, $"only {rejected} of {checkedInputs} flips were rejected");
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
    public void EveryByteFlipInTheGenuineReceiptIsContained()
    {
        IVerifier verifier = Verifier.Create(Config.Defaults());
        int checkedInputs = 0;
        for (int index = 0; index < GenuineReceipt.Length; index += 11)
        {
            byte[] mutated = (byte[])GenuineReceipt.Clone();
            mutated[index] ^= 0x80;
            Contained(verifier, mutated);
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

    // --- named killers -------------------------------------------------------

    /// <summary>
    /// Eleven characters of attacker base64 are what escaped BouncyCastle's
    /// declared contract in the Java port. The C# equivalent is
    /// <c>AsnContentException</c>, which is not a <c>CryptographicException</c>.
    /// </summary>
    [Theory]
    [InlineData("MAsGCSqGSIb3")]
    [InlineData("MA==")]
    [InlineData("MIA=")]
    [InlineData("MIAwgA==")]
    public void ShortCmsFragmentsAreMalformed(string input)
    {
        Assert.Equal(VerificationReason.Malformed, ReceiptVerifier.Value.VerifyReceipt(input).Failure?.Reason);
    }

    /// <summary>A null input string is input, not a programming error: MALFORMED, never a throw.</summary>
    [Fact]
    public void NullInputsAreMalformed()
    {
        Assert.Equal(VerificationReason.Malformed, ReceiptVerifier.Value.VerifyReceipt(null!).Failure?.Reason);
        Assert.Equal(VerificationReason.Malformed, JwsVerifier.Value.VerifySignedData(null!).Failure?.Reason);
        Assert.Equal(VerificationReason.Malformed, JwsVerifier.Value.VerifySignedData(string.Empty).Failure?.Reason);
    }

    /// <summary>
    /// A negative attribute type is outside the 32-bit signed type space the
    /// grammar has, so the whole Apple-signed payload is unreadable, the same
    /// verdict as a type above <c>int.MaxValue</c>.
    /// </summary>
    [Fact]
    public void ANegativeAttributeTypeMakesThePayloadUnreadable()
    {
        Assert.Equal(
            VerificationReason.UnreadablePayload,
            SignedPayloadReason(TestPki.AttributeSet(new (BigInteger, byte[])[]
            {
                (2, TestPki.Utf8("com.example.app")),
                (-1, TestPki.Utf8("x")),
            })));
    }

    /// <summary>
    /// A string attribute value holds one DER value. Bytes after it are not
    /// part of the string, so the typed field is null and the octets are kept
    /// raw, exactly as for any other value that does not parse.
    /// </summary>
    [Fact]
    public void AnAttributeValueWithTrailingDataDoesNotParse()
    {
        byte[] value = TestPki.Utf8("com.example.app");
        byte[] padded = value.Concat(new byte[] { 0x05, 0x00 }).ToArray();
        byte[] version = TestPki.Utf8("1.2.3").Concat(new byte[] { 0x05, 0x00 }).ToArray();

        ReceiptPayload payload = SignedPayload(TestPki.AttributeSet(new (BigInteger, byte[])[]
        {
            (2, padded),
            (3, version),
            (12, TestPki.Ia5("2024-08-06T12:00:00Z")),
        }));

        Assert.Null(payload.BundleId);
        Assert.Equal(padded, payload.BundleIdBytes);
        Assert.Null(payload.ApplicationVersion);
        Assert.Equal(version, Assert.Single(payload.UnknownAttributes[3]));
    }

    // --- JWS sweeps ----------------------------------------------------------

    [Theory]
    [InlineData(".")]
    [InlineData("...")]
    [InlineData("a.b")]
    [InlineData("a.b.c.d.e")]
    [InlineData("no dots at all")]
    public void JwsSegmentShapesOutsideThreeAreMalformed(string jws)
    {
        Assert.Equal(VerificationReason.Malformed, JwsVerifier.Value.VerifySignedData(jws).Failure?.Reason);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("ES384")]
    [InlineData("es256")]
    [InlineData("")]
    public void AlgorithmsOtherThanEs256AreMalformed(string algorithm)
    {
        TestPki.JwsChain chain = TestPki.SharedJws.Value;
        Assert.Equal(
            VerificationReason.Malformed,
            chain.Verifier().VerifySignedData(chain.Sign(TestPki.Payload, algorithm)).Failure?.Reason);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    public void AnX5cThatIsNotExactlyThreeCertificatesIsMalformed(int count)
    {
        TestPki.JwsChain chain = TestPki.SharedJws.Value;
        X509Certificate2[] all = { chain.Leaf, chain.Intermediate, chain.Root, chain.Root };
        string jws = TestPki.SignJws(chain.Leaf, all.Take(count).ToArray(), TestPki.Payload);

        Assert.Equal(VerificationReason.Malformed, chain.Verifier().VerifySignedData(jws).Failure?.Reason);
    }

    [Fact]
    public void AnX5cEntryInPemRatherThanDerIsAnInvalidCertificate()
    {
        TestPki.JwsChain chain = TestPki.SharedJws.Value;
        string pem = "-----BEGIN CERTIFICATE-----\n"
            + Convert.ToBase64String(chain.Leaf.RawData) + "\n-----END CERTIFICATE-----";
        string header = "{\"alg\":\"ES256\",\"x5c\":[\"" + pem.Replace("\n", "\\n", StringComparison.Ordinal) + "\",\""
            + Convert.ToBase64String(chain.Intermediate.RawData) + "\",\""
            + Convert.ToBase64String(chain.Root.RawData) + "\"]}";
        string jws = TestPki.Base64Url(Encoding.UTF8.GetBytes(header))
            + "." + TestPki.Base64Url(Encoding.UTF8.GetBytes(TestPki.Payload))
            + "." + TestPki.Base64Url(new byte[64]);

        Assert.Equal(VerificationReason.InvalidCertificate, chain.Verifier().VerifySignedData(jws).Failure?.Reason);
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
    [InlineData("QQ==")]
    public void NonBase64UrlSegmentsAreMalformed(string segment)
    {
        Assert.Equal(
            VerificationReason.Malformed,
            JwsVerifier.Value.VerifySignedData(segment + ".e30.AAAA").Failure?.Reason);
    }

    // --- the endpoint never throws ------------------------------------------

    /// <summary>
    /// Every boundary is categorical, including the raw-JSON one: neither the
    /// reader nor the writer may escape a method documented as never throwing.
    /// </summary>
    [Fact]
    public void TheEndpointContainsEveryHostileRequestBodyAsAStatus()
    {
        IVerifier endpoint = ReceiptVerifier.Value;
        Random random = new(20260904);
        char[] alphabet = "{}[]\":,\\\"0aA \n\t\u0000\uD800".ToCharArray();
        for (int i = 0; i < 200; i++)
        {
            char[] chars = new char[random.Next(0, 64)];
            for (int j = 0; j < chars.Length; j++)
            {
                chars[j] = alphabet[random.Next(alphabet.Length)];
            }

            string answer = endpoint.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, new string(chars));
            Assert.StartsWith("{\"status\":", answer, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void TheEndpointNeverThrowsForTheWholeHostileCorpus()
    {
        IVerifier endpoint = ReceiptVerifier.Value;
        Random random = new(20260904);
        int answered = 0;

        foreach (byte[] blob in HostileBlobs(random))
        {
            string body = "{\"receipt-data\":\"" + Convert.ToBase64String(blob)
                + "\",\"password\":\"ignored\",\"exclude-old-transactions\":true}";
            string answer = endpoint.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, body);
            Assert.StartsWith("{\"status\":", answer, StringComparison.Ordinal);
            Assert.NotEqual("{\"status\":21009}", answer);
            answered++;
        }

        foreach (string raw in new[] { "", "!!!!", "not base64", "e30", new string('A', 10_000) })
        {
            Assert.Equal(
                "{\"status\":21002}",
                endpoint.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, "{\"receipt-data\":\"" + raw + "\"}"));
            answered++;
        }

        foreach (string json in new[] { "", "null", "[]", "3", "\"x\"", "{", "{\"a\":", "{}" })
        {
            Assert.Equal("{\"status\":21002}", endpoint.VerifyReceiptEndpoint(AppleEnvironment.Sandbox, json));
            answered++;
        }

        Assert.True(answered >= 300, $"only {answered} hostile inputs reached the endpoint");
    }

    private static IEnumerable<byte[]> HostileBlobs(Random random)
    {
        for (int length = 0; length < Receipt.Length; length += 17)
        {
            yield return Receipt[..length];
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

    // --- the signer is judged from the receipt's own bytes -------------------

    /// <summary>
    /// The two signer mutations are condemned from the receipt's own bytes,
    /// by this library's DER reader, not by the platform certificate decoder.
    /// That is the whole reason the verdict is the same on every operating
    /// system: macOS's certificate parser refuses both of these certificates
    /// outright, and while the decision waited for it the receipt came out as
    /// a format error there and as INVALID_CERTIFICATE everywhere else
    /// (receipt/reject-signer-certificate-version-11,
    /// receipt/reject-signer-with-a-corrupt-extension).
    /// </summary>
    [Theory]
    [InlineData("receipt-signer-version-11")]
    [InlineData("receipt-signer-corrupt-extension")]
    public void TheSignerCertificateIsCondemnedFromTheReceiptsOwnBytes(string fixture)
    {
        byte[] receipt = Fixtures070.Bytes(fixture);
        CmsParsed cms = Cms.Parse(receipt);
        CmsSignerInfo info = Assert.Single(cms.SignerInfos);

        CertificateFields? signer = cms.CertificateEntries
            .Select(CertificateFields.TryParse)
            .SingleOrDefault(f => f is not null
                && f.SerialNumberRaw.AsSpan().SequenceEqual(info.SerialRaw!)
                && f.IssuerRaw.AsSpan().SequenceEqual(info.IssuerRaw!));
        Assert.True(signer is not null, "the library's own reader could not name the certificate the SignerInfo names");
        Assert.True(
            signer!.Version is < 1 or > 3 || signer.HasDuplicateExtension || signer.HasUndecodableExtension,
            "nothing in the signer's own bytes condemns it, so the verdict would be the host's");
    }

    /// <summary>
    /// The ordering, proved without a mac. A bag entry the platform decoder
    /// refuses sits beside a signer this library condemns: on its own that
    /// entry is MALFORMED (receipt/reject-a-stranger-whose-signature-bit-string-is-unaligned),
    /// so INVALID_CERTIFICATE here can only have been reached because a broken
    /// signer outranks a broken stranger.
    /// </summary>
    [Theory]
    [InlineData("receipt-signer-version-11")]
    [InlineData("receipt-signer-corrupt-extension")]
    public void TheSignerIsJudgedBeforeAStrangerTheDecoderRefuses(string fixture)
    {
        byte[] receipt = TestPki.WithExtraCertificates(Fixtures070.Bytes(fixture), JunkCertificate());
        Assert.Equal(
            VerificationReason.InvalidCertificate,
            TestPki.FixtureVerifier("receipt-signer-root").VerifyReceipt(Convert.ToBase64String(receipt)).Failure?.Reason);
    }

    /// <summary>
    /// An extnValue holds one DER value. A reader that decodes the first and
    /// stops never sees bytes left after it, so those bytes are as invisible —
    /// and as much a defect of the certificate — as a value that stops
    /// decoding partway through, which is what
    /// transaction/reject-x5c-corrupt-extension pins.
    /// </summary>
    [Fact]
    public void AnX5cCertificateWithBytesLeftOverInAnExtensionIsAnInvalidCertificate()
    {
        TestPki.JwsChain chain = TestPki.SharedJws.Value;
        X509Certificate2 leaf = TestPki.EcChildWithTrailingBytesInAnExtension(
            chain.Intermediate, "CN=Signing", TestPki.LeafOid);
        string jws = TestPki.SignJws(leaf, new[] { leaf, chain.Intermediate, chain.Root }, TestPki.Payload);

        Assert.Equal(VerificationReason.InvalidCertificate, chain.Verifier().VerifySignedData(jws).Failure?.Reason);
    }

    // --- helpers -------------------------------------------------------------

    /// <summary>A SEQUENCE of two INTEGERs: well-formed ASN.1, no certificate.</summary>
    private static byte[] JunkCertificate()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(42);
            writer.WriteInteger(43);
        }

        return writer.Encode();
    }

    private static bool Accepts(byte[] blob) => Contained(blob).Verified;

    private static VerificationResult<ReceiptPayload> Contained(byte[] blob) => Contained(ReceiptVerifier.Value, blob);

    /// <summary>
    /// Verifies <paramref name="blob"/> and asserts the call was contained: it
    /// returned, and a failure the input caused is not INTERNAL_ERROR.
    /// </summary>
    private static VerificationResult<ReceiptPayload> Contained(IVerifier verifier, byte[] blob)
    {
        VerificationResult<ReceiptPayload> result;
        try
        {
            result = verifier.VerifyReceipt(Convert.ToBase64String(blob));
        }
        catch (Exception e)
        {
            throw new InvalidOperationException($"{e.GetType().FullName} escaped VerifyReceipt: {e.Message}", e);
        }

        Assert.NotEqual(VerificationReason.InternalError, result.Failure?.Reason);
        return result;
    }

    private static bool AcceptsJws(string jws)
    {
        VerificationResult<JsonPayload> result;
        try
        {
            result = JwsVerifier.Value.VerifySignedData(jws);
        }
        catch (Exception e)
        {
            throw new InvalidOperationException($"{e.GetType().FullName} escaped VerifySignedData: {e.Message}", e);
        }

        Assert.NotEqual(VerificationReason.InternalError, result.Failure?.Reason);
        return result.Verified;
    }

    /// <summary>The verdict on <paramref name="payload"/> signed for real under a test PKI the verifier trusts.</summary>
    private static VerificationReason? SignedPayloadReason(byte[] payload)
    {
        TestPki.ReceiptChain chain = TestPki.SharedReceipt.Value;
        return chain.Verifier().VerifyReceipt(chain.SignBase64(payload)).Failure?.Reason;
    }

    private static ReceiptPayload SignedPayload(byte[] payload)
    {
        TestPki.ReceiptChain chain = TestPki.SharedReceipt.Value;
        VerificationResult<ReceiptPayload> result = chain.Verifier().VerifyReceipt(chain.SignBase64(payload));
        Assert.True(result.Verified, result.Failure?.ToString());
        return result.Payload;
    }

    /// <summary>Where the encapsulated content sits inside the CMS blob.</summary>
    private static (int Offset, int Length) PayloadRange(byte[] der)
    {
        byte[] content = Cms.Parse(der).Content;
        int offset = der.AsSpan().IndexOf(content);
        Assert.True(offset > 0, "could not locate the encapsulated payload");
        return (offset, content.Length);
    }
}
