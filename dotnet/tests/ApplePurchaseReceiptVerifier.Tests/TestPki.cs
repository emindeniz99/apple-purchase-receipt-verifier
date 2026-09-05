using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>
/// A fake "Apple" PKI plus JWS and receipt builders, so the negative tests can
/// mint exactly the certificate a real attacker would need. The same technique
/// Apple's own libraries use for their fixtures: no real Apple secret is
/// involved, and pinning is proved by the fact that these chains verify only
/// against the fake root they were minted under.
/// </summary>
internal static class TestPki
{
    internal const string LeafOid = "1.2.840.113635.100.6.11.1";
    internal const string IntermediateOid = "1.2.840.113635.100.6.2.1";

    private static readonly DateTimeOffset DefaultNotBefore = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset DefaultNotAfter = new(2050, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static int _serial;

    /// <summary>A self-signed EC root.</summary>
    internal static X509Certificate2 EcRoot(
        string subject = "CN=Fake Apple Root CA",
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        string? markerOid = null)
    {
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256);
        AddExtensions(request, true, markerOid);
        return request.CreateSelfSigned(notBefore ?? DefaultNotBefore, notAfter ?? DefaultNotAfter);
    }

    /// <summary>
    /// Re-issues a certificate for an existing key, so a test can hand the same
    /// subject and key a different BasicConstraints value than the one the
    /// platform's <c>CertificateRequest.Create</c> is willing to sign under.
    /// </summary>
    internal static X509Certificate2 EcReissue(
        X509Certificate2 issuer,
        X509Certificate2 original,
        bool isCa,
        string? markerOid = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        using ECDsa? key = original.GetECDsaPublicKey();
        CertificateRequest request = new(
            original.Subject,
            key ?? throw new InvalidOperationException("the original has no EC key"),
            HashAlgorithmName.SHA256);
        AddExtensions(request, isCa, markerOid);
        return request.Create(
            issuer, notBefore ?? DefaultNotBefore, notAfter ?? DefaultNotAfter, NextSerial());
    }

    /// <summary>A self-signed RSA root, for the receipt path.</summary>
    internal static X509Certificate2 RsaRoot(
        string subject = "CN=Fake Apple Receipt Root CA",
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        RSA key = RSA.Create(2048);
        CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        return request.CreateSelfSigned(notBefore ?? DefaultNotBefore, notAfter ?? DefaultNotAfter);
    }

    /// <summary>An EC certificate issued by <paramref name="issuer"/>.</summary>
    internal static X509Certificate2 EcChild(
        X509Certificate2 issuer,
        string subject,
        bool isCa,
        string? markerOid = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256);
        AddExtensions(request, isCa, markerOid);
        X509Certificate2 issued = Issue(request, issuer, notBefore, notAfter);
        return issued.CopyWithPrivateKey(key);
    }

    /// <summary>
    /// An EC leaf carrying its first extension twice, re-signed by the issuer
    /// so the only defect is the repetition. RFC 5280 §4.2 forbids a second
    /// instance of any extension; <c>CertificateRequest</c> refuses to build
    /// one, so the TBS is rebuilt and signed by hand, the way
    /// <see cref="EcChildSha1"/> does.
    /// </summary>
    internal static X509Certificate2 EcChildWithDuplicateExtension(
        X509Certificate2 issuer,
        string subject,
        string markerOid)
    {
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256);
        AddExtensions(request, false, markerOid);
        using ECDsa issuerKey = issuer.GetECDsaPrivateKey()
            ?? throw new InvalidOperationException("the issuer has no usable EC key");
        using X509Certificate2 template = request.Create(
            issuer.SubjectName,
            X509SignatureGenerator.CreateForECDsa(issuerKey),
            DefaultNotBefore,
            DefaultNotAfter,
            NextSerial());

        AsnReader outer = new AsnReader(template.RawData, AsnEncodingRules.DER).ReadSequence();
        outer.ReadEncodedValue();                     // tbsCertificate
        byte[] algorithm = outer.ReadEncodedValue().ToArray();
        byte[] tbs = DuplicateFirstExtension(template.RawData);
        byte[] signature = issuerKey.SignData(
            tbs, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return X509CertificateLoader.LoadCertificate(Assemble(tbs, algorithm, signature))
            .CopyWithPrivateKey(key);
    }

    /// <summary>
    /// An EC leaf whose first extension value holds one complete DER value and
    /// then two more bytes, re-signed by the issuer so the only defect is the
    /// leftover. An extnValue is an OCTET STRING wrapping ONE value, and a
    /// reader that stops at the first one never sees what follows it.
    /// </summary>
    internal static X509Certificate2 EcChildWithTrailingBytesInAnExtension(
        X509Certificate2 issuer,
        string subject,
        string markerOid)
    {
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256);
        AddExtensions(request, false, markerOid);
        using ECDsa issuerKey = issuer.GetECDsaPrivateKey()
            ?? throw new InvalidOperationException("the issuer has no usable EC key");
        using X509Certificate2 template = request.Create(
            issuer.SubjectName,
            X509SignatureGenerator.CreateForECDsa(issuerKey),
            DefaultNotBefore,
            DefaultNotAfter,
            NextSerial());

        AsnReader outer = new AsnReader(template.RawData, AsnEncodingRules.DER).ReadSequence();
        outer.ReadEncodedValue();                     // tbsCertificate
        byte[] algorithm = outer.ReadEncodedValue().ToArray();
        byte[] tbs = PadFirstExtensionValue(template.RawData);
        byte[] signature = issuerKey.SignData(
            tbs, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return X509CertificateLoader.LoadCertificate(Assemble(tbs, algorithm, signature))
            .CopyWithPrivateKey(key);
    }

    /// <summary>An RSA certificate issued by <paramref name="issuer"/>.</summary>
    internal static X509Certificate2 RsaChild(
        X509Certificate2 issuer,
        string subject,
        bool isCa,
        string? markerOid = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        RSA key = RSA.Create(2048);
        CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        AddExtensions(request, isCa, markerOid);
        X509Certificate2 issued = Issue(request, issuer, notBefore, notAfter);
        return issued.CopyWithPrivateKey(key);
    }

    /// <summary>
    /// An EC certificate genuinely signed with <c>ecdsa-with-SHA1</c>
    /// (<c>1.2.840.10045.4.1</c>). <c>CertificateRequest</c> refuses SHA-1
    /// outright on .NET 9, so the TBS is re-encoded with the target algorithm
    /// identifier and signed by hand — the signature is real, not retagged.
    /// No Apple chain has ever used this construction; the helper exists so a
    /// test can prove the walk refuses it.
    /// </summary>
    internal static X509Certificate2 EcChildSha1(
        X509Certificate2 issuer,
        string subject,
        bool isCa,
        string? markerOid = null)
    {
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256);
        AddExtensions(request, isCa, markerOid);
        using ECDsa issuerKey = issuer.GetECDsaPrivateKey()
            ?? throw new InvalidOperationException("the issuer has no usable EC key");
        using X509Certificate2 template = request.Create(
            issuer.SubjectName,
            X509SignatureGenerator.CreateForECDsa(issuerKey),
            DefaultNotBefore,
            DefaultNotAfter,
            NextSerial());

        byte[] algorithm = AlgorithmIdentifier("1.2.840.10045.4.1", withNullParameters: false);
        byte[] tbs = RetagTbs(template.RawData, algorithm);
        byte[] signature = issuerKey.SignData(
            tbs, HashAlgorithmName.SHA1, DSASignatureFormat.Rfc3279DerSequence);
        return X509CertificateLoader.LoadCertificate(Assemble(tbs, algorithm, signature))
            .CopyWithPrivateKey(key);
    }

    /// <summary>
    /// An RSA certificate genuinely signed with <c>sha1WithRSAEncryption</c>
    /// (<c>1.2.840.113549.1.1.5</c>) — the shape Apple's own legacy receipt
    /// chain has, and the reason SHA-1 with RSA stays on the allowlist.
    /// </summary>
    internal static X509Certificate2 RsaChildSha1(
        X509Certificate2 issuer,
        string subject,
        bool isCa,
        string? markerOid = null)
    {
        RSA key = RSA.Create(2048);
        CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        AddExtensions(request, isCa, markerOid);
        using RSA issuerKey = issuer.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("the issuer has no usable RSA key");
        using X509Certificate2 template = request.Create(
            issuer.SubjectName,
            X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1),
            DefaultNotBefore,
            DefaultNotAfter,
            NextSerial());

        byte[] algorithm = AlgorithmIdentifier("1.2.840.113549.1.1.5", withNullParameters: true);
        byte[] tbs = RetagTbs(template.RawData, algorithm);
        byte[] signature = issuerKey.SignData(
            tbs, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        return X509CertificateLoader.LoadCertificate(Assemble(tbs, algorithm, signature))
            .CopyWithPrivateKey(key);
    }

    private static byte[] AlgorithmIdentifier(string oid, bool withNullParameters)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            if (withNullParameters)
            {
                writer.WriteNull();
            }
        }

        return writer.Encode();
    }

    /// <summary>Re-encodes a certificate's TBS with a different inner signature algorithm.</summary>
    private static byte[] RetagTbs(byte[] certificate, byte[] algorithm)
    {
        AsnReader tbs = new AsnReader(certificate, AsnEncodingRules.DER).ReadSequence().ReadSequence();
        byte[] version = tbs.ReadEncodedValue().ToArray();
        byte[] serial = tbs.ReadEncodedValue().ToArray();
        tbs.ReadEncodedValue();                       // the algorithm being replaced

        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteEncodedValue(version);
            writer.WriteEncodedValue(serial);
            writer.WriteEncodedValue(algorithm);
            while (tbs.HasData)
            {
                writer.WriteEncodedValue(tbs.ReadEncodedValue().Span);
            }
        }

        return writer.Encode();
    }

    /// <summary>Rebuilds a TBS with a byte-identical second copy of its first extension.</summary>
    private static byte[] DuplicateFirstExtension(byte[] certificate)
    {
        AsnReader tbs = new AsnReader(certificate, AsnEncodingRules.DER).ReadSequence().ReadSequence();
        Asn1Tag extensionsTag = new(TagClass.ContextSpecific, 3, true);

        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            while (tbs.HasData)
            {
                if (tbs.PeekTag() != extensionsTag)
                {
                    writer.WriteEncodedValue(tbs.ReadEncodedValue().Span);
                    continue;
                }

                AsnReader extensions = tbs.ReadSequence(extensionsTag).ReadSequence();
                using (writer.PushSequence(extensionsTag))
                using (writer.PushSequence())
                {
                    bool first = true;
                    while (extensions.HasData)
                    {
                        ReadOnlyMemory<byte> extension = extensions.ReadEncodedValue();
                        writer.WriteEncodedValue(extension.Span);
                        if (first)
                        {
                            writer.WriteEncodedValue(extension.Span);
                            first = false;
                        }
                    }
                }
            }
        }

        return writer.Encode();
    }

    /// <summary>Rebuilds a TBS with a trailing NULL inside its first extension's value.</summary>
    private static byte[] PadFirstExtensionValue(byte[] certificate)
    {
        AsnReader tbs = new AsnReader(certificate, AsnEncodingRules.DER).ReadSequence().ReadSequence();
        Asn1Tag extensionsTag = new(TagClass.ContextSpecific, 3, true);

        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            while (tbs.HasData)
            {
                if (tbs.PeekTag() != extensionsTag)
                {
                    writer.WriteEncodedValue(tbs.ReadEncodedValue().Span);
                    continue;
                }

                AsnReader extensions = tbs.ReadSequence(extensionsTag).ReadSequence();
                using (writer.PushSequence(extensionsTag))
                using (writer.PushSequence())
                {
                    bool first = true;
                    while (extensions.HasData)
                    {
                        AsnReader extension = extensions.ReadSequence();
                        string oid = extension.ReadObjectIdentifier();
                        bool critical = extension.HasData
                            && extension.PeekTag() == Asn1Tag.Boolean
                            && extension.ReadBoolean();
                        byte[] value = extension.ReadOctetString();
                        if (first)
                        {
                            byte[] padded = new byte[value.Length + 2];
                            Buffer.BlockCopy(value, 0, padded, 0, value.Length);
                            padded[value.Length] = 0x05;      // NULL, complete
                            padded[value.Length + 1] = 0x00;  // and unreachable
                            value = padded;
                            first = false;
                        }

                        using (writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier(oid);
                            if (critical)
                            {
                                writer.WriteBoolean(true);
                            }

                            writer.WriteOctetString(value);
                        }
                    }
                }
            }
        }

        return writer.Encode();
    }

    private static byte[] Assemble(byte[] tbs, byte[] algorithm, byte[] signature)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteEncodedValue(tbs);
            writer.WriteEncodedValue(algorithm);
            writer.WriteBitString(signature);
        }

        return writer.Encode();
    }

    /// <summary>The public-only form, as a caller's trust anchor arrives.</summary>
    internal static X509Certificate2 Public(X509Certificate2 certificate) =>
        X509CertificateLoader.LoadCertificate(certificate.RawData);

    /// <summary>Signs a compact JWS with <paramref name="leaf"/> and the given x5c chain.</summary>
    internal static string SignJws(
        X509Certificate2 leaf,
        IReadOnlyList<X509Certificate2> x5c,
        string payloadJson,
        string algorithm = "ES256",
        Func<byte[], byte[]>? mangleSignature = null)
    {
        StringBuilder x5cJson = new();
        foreach (X509Certificate2 certificate in x5c)
        {
            if (x5cJson.Length != 0)
            {
                x5cJson.Append(',');
            }

            x5cJson.Append('"').Append(Convert.ToBase64String(certificate.RawData)).Append('"');
        }

        string header = "{\"alg\":\"" + algorithm + "\",\"x5c\":[" + x5cJson + "]}";
        string signingInput = Base64Url(Encoding.UTF8.GetBytes(header))
            + "." + Base64Url(Encoding.UTF8.GetBytes(payloadJson));

        byte[] signature;
        using (ECDsa? key = leaf.GetECDsaPrivateKey())
        {
            signature = key is not null
                ? key.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256)
                : SignWithRsa(leaf, signingInput);
        }

        if (mangleSignature is not null)
        {
            signature = mangleSignature(signature);
        }

        return signingInput + "." + Base64Url(signature);
    }

    /// <summary>base64url without padding, as RFC 7515 wants it.</summary>
    internal static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Encodes one receipt attribute set from (type, value) pairs.</summary>
    /// <remarks>
    /// BER, not DER: a DER writer sorts SET OF members canonically, which would
    /// silently reorder the attributes a test authored — and repeats of one
    /// attribute type are exactly what the forward-compatibility rule is about.
    /// </remarks>
    internal static byte[] AttributeSet(IEnumerable<(BigInteger Type, byte[] Value)> attributes)
    {
        AsnWriter writer = new(AsnEncodingRules.BER);
        using (writer.PushSetOf())
        {
            foreach ((BigInteger type, byte[] value) in attributes)
            {
                using (writer.PushSequence())
                {
                    writer.WriteInteger(type);
                    writer.WriteInteger(1);
                    writer.WriteOctetString(value);
                }
            }
        }

        return writer.Encode();
    }

    /// <summary>A UTF8String attribute value.</summary>
    internal static byte[] Utf8(string value)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.UTF8String, value);
        return writer.Encode();
    }

    /// <summary>An IA5String attribute value, which is how receipts carry dates.</summary>
    internal static byte[] Ia5(string value)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.IA5String, value);
        return writer.Encode();
    }

    /// <summary>An INTEGER attribute value.</summary>
    internal static byte[] Integer(BigInteger value)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.WriteInteger(value);
        return writer.Encode();
    }

    /// <summary>Wraps a payload in a CMS SignedData signed by <paramref name="signer"/>.</summary>
    internal static byte[] SignReceipt(
        byte[] payload,
        X509Certificate2 signer,
        IEnumerable<X509Certificate2> extraCertificates,
        string digestOid = "2.16.840.1.101.3.4.2.1")
    {
        SignedCms cms = new(new ContentInfo(new Oid("1.2.840.113549.1.7.1"), payload), detached: false);
        CmsSigner cmsSigner = new(SubjectIdentifierType.IssuerAndSerialNumber, signer)
        {
            IncludeOption = X509IncludeOption.EndCertOnly,
            DigestAlgorithm = new Oid(digestOid),
        };
        foreach (X509Certificate2 certificate in extraCertificates)
        {
            cmsSigner.Certificates.Add(certificate);
        }

        cms.ComputeSignature(cmsSigner);
        return cms.Encode();
    }

    /// <summary>The app-level attribute set every valid test receipt carries.</summary>
    internal static byte[] StandardPayload(
        string bundleId = "com.example.app",
        string creationDate = "2024-08-06T12:00:00Z",
        string receiptType = "ProductionSandbox")
    {
        return AttributeSet(new (BigInteger, byte[])[]
        {
            (0, Utf8(receiptType)),
            (2, Utf8(bundleId)),
            (3, Utf8("1.2.3")),
            (4, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }),
            (12, Ia5(creationDate)),
            (19, Utf8("1.0")),
        });
    }

    /// <summary>
    /// Issues from <paramref name="issuer"/> whatever key algorithm each side
    /// uses: the convenience overload refuses to mix an EC issuer with an RSA
    /// subject, and one of the negative tests needs exactly that mix.
    /// </summary>
    private static X509Certificate2 Issue(
        CertificateRequest request,
        X509Certificate2 issuer,
        DateTimeOffset? notBefore,
        DateTimeOffset? notAfter)
    {
        DateTimeOffset from = notBefore ?? DefaultNotBefore;
        DateTimeOffset to = notAfter ?? DefaultNotAfter;
        using ECDsa? issuerEc = issuer.GetECDsaPrivateKey();
        if (issuerEc is not null)
        {
            return request.Create(
                issuer.SubjectName,
                X509SignatureGenerator.CreateForECDsa(issuerEc),
                from,
                to,
                NextSerial());
        }

        using RSA issuerRsa = issuer.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("the issuer has no usable private key");
        return request.Create(
            issuer.SubjectName,
            X509SignatureGenerator.CreateForRSA(issuerRsa, RSASignaturePadding.Pkcs1),
            from,
            to,
            NextSerial());
    }

    private static void AddExtensions(CertificateRequest request, bool isCa, string? markerOid)
    {
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCa, false, 0, true));
        if (markerOid is not null)
        {
            request.CertificateExtensions.Add(
                new X509Extension(new Oid(markerOid), new byte[] { 0x05, 0x00 }, false));
        }
    }

    private static byte[] SignWithRsa(X509Certificate2 leaf, string signingInput)
    {
        using RSA? key = leaf.GetRSAPrivateKey();
        return key is null
            ? throw new InvalidOperationException("the leaf has no usable private key")
            : key.SignData(
                Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static byte[] NextSerial()
    {
        int value = System.Threading.Interlocked.Increment(ref _serial);
        return Encoding.ASCII.GetBytes(value.ToString("D8", CultureInfo.InvariantCulture));
    }
}
