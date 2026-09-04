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
}
