<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier;

/**
 * One `distrust` entry of a {@see Config}: a certificate the verifier
 * refuses, named by the issuer id of the certificate that signed it and
 * its serial (docs/design/revocation.md §2, §4).
 *
 * The issuer id is 64 hex digits, the SHA-256 of the issuing CA's subject
 * Name and SubjectPublicKeyInfo as they appear in its certificate. The
 * serial is hex, in either letter case, with or without leading zeros.
 * The strings are kept exactly as given: {@see Verifier::create()} passes
 * them to `aprv`, whose module judges and normalises them and refuses a
 * malformed one, naming its index.
 */
final readonly class RevokedCertificate
{
    public function __construct(
        public string $issuer,
        public string $serial,
    ) {
    }
}
