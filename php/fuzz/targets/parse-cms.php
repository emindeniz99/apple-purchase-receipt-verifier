<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Fuzz;

use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Certificate;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Cms;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\ParseException;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\VerificationException;

/**
 * The CMS `SignedData` walk, plus the readers a parsed structure feeds: the
 * two signed-attribute readers, the embedded certificates, and the signer
 * lookup that compares issuer and serial across every SignerInfo (0.7
 * accepts multiple, docs/design/0.7-api.md §1, "Several SignerInfos"). This
 * is the walk the probe that preceded the port found an out-of-bounds panic
 * in by mutating a genuine receipt, so it gets its own target rather than
 * only being reached through `verify-receipt`.
 *
 * `Cms::parse` converts every decoding failure to `VerificationException`;
 * the attribute readers below are internal and are documented to raise
 * `ParseException`, which the public entry points convert. Both are allowed
 * here, and nothing else is.
 */

/** @var \PhpFuzzer\Config $config */
require __DIR__ . '/../bootstrap.php';

$config->setMaxLen(16384);
$config->setAllowedExceptions([VerificationException::class, ParseException::class]);

$config->setTarget(static function (string $input): void {
    $cms = Cms::parse($input);

    $embedded = [];
    foreach ($cms->certificates as $der) {
        try {
            $embedded[] = Certificate::parse($der);
        } catch (ParseException) {
            // An unreadable embedded certificate is skipped by the verifier
            // too: a receipt may carry one alongside the one it needs.
        }
    }
    foreach ($cms->signerInfos as $signer) {
        Cms::findSignerIndices($signer, $embedded);
        if ($signer->signedAttrs !== null) {
            $cms->messageDigestAttribute($signer);
            Cms::signedAttrsSignedBytes($signer);
        }
    }
});
