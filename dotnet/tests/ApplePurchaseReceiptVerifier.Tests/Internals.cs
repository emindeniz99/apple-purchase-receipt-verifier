using System;
using System.Security.Cryptography.X509Certificates;
using ApplePurchaseReceiptVerifier.Internal;

namespace ApplePurchaseReceiptVerifier.Tests;

/// <summary>Thin access to the internals a few tests need to exercise directly.</summary>
internal static class Internals
{
    internal static bool IssuedBy(X509Certificate2 subject, X509Certificate2 issuer) =>
        CertificateChain.IssuedBy(subject, issuer);

    internal static byte[]? DerToP1363(byte[] der, int fieldSizeBytes) =>
        EcdsaSignatureFormat.DerToP1363(der, fieldSizeBytes);

    internal static int PreScan(byte[] der, int limit) => CmsPreScan.Scan(der, limit);

    internal static byte[]? FindSignerCertificate(byte[] der, int limit) =>
        CmsPreScan.FindSignerCertificate(der, limit);

    /// <summary>
    /// What the library's own DER reader makes of a certificate: the X.509
    /// version, whether an extension OID repeats, and whether an extension
    /// value fails to decode. Null when the bytes will not parse at all.
    /// </summary>
    internal static (int Version, bool Duplicate, bool Undecodable)? CertificateShape(byte[] raw)
    {
        CertificateFields? fields = CertificateFields.TryParse(raw);
        return fields is null
            ? null
            : (fields.Version, fields.HasDuplicateExtension, fields.HasUndecodableExtension);
    }
}
