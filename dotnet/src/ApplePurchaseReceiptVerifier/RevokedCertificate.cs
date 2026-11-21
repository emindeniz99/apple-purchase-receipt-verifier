using System;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// One certificate to refuse, named by its revocation key: the issuer id
    /// of the certificate that issued it, and its serial number
    /// (docs/design/revocation.md §2). Passed in <see cref="Config"/>'s
    /// <c>distrust</c>.
    /// </summary>
    /// <remarks>
    /// It holds both strings exactly as given. The verification module checks
    /// and normalises them when <see cref="Verifier.Create"/> builds the
    /// verifier, and refuses a malformed one there.
    /// </remarks>
    public sealed class RevokedCertificate
    {
        /// <summary>Names the certificate with serial <paramref name="serial"/> issued by <paramref name="issuer"/>.</summary>
        /// <param name="issuer">The issuer id: see <see cref="Issuer"/>.</param>
        /// <param name="serial">The serial number in hex: see <see cref="Serial"/>.</param>
        /// <exception cref="ArgumentNullException"><paramref name="issuer"/> or <paramref name="serial"/> is null.</exception>
        public RevokedCertificate(string issuer, string serial)
        {
            Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
            Serial = serial ?? throw new ArgumentNullException(nameof(serial));
        }

        /// <summary>
        /// The issuer id: the SHA-256, in hex, of the issuing certificate's
        /// subject Name followed by its subjectPublicKeyInfo, both as encoded
        /// in that certificate. 64 hex digits.
        /// </summary>
        public string Issuer { get; }

        /// <summary>
        /// The revoked certificate's serial number in hex, either letter case,
        /// with or without leading zeros.
        /// </summary>
        public string Serial { get; }

        /// <summary><c>issuer:serial</c>.</summary>
        public override string ToString() => Issuer + ":" + Serial;
    }
}
