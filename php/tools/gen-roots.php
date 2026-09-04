<?php

declare(strict_types=1);

/**
 * Regenerates php/src/Internal/RootsData.php from php/certs/*.cer.
 *
 * Run it after php/certs/ is refreshed from the repository-root certs/ (which
 * the scheduled apple-root-watch workflow guards). CI diffs php/certs/ against
 * certs/ and re-runs this script to prove the compiled-in bytes match, so a
 * roots change that forgets either step fails loudly instead of shipping stale
 * trust anchors.
 *
 *     php php/tools/gen-roots.php
 */

$certsDir = __DIR__ . '/../certs';
$target = __DIR__ . '/../src/Internal/RootsData.php';

$files = ['AppleIncRootCertificate.cer', 'AppleRootCA-G2.cer', 'AppleRootCA-G3.cer'];

$out = <<<HEADER
<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Internal;

/**
 * GENERATED from php/certs/*.cer by php/tools/gen-roots.php — do not edit by hand.
 *
 * The roots are compiled in rather than read from disk at call time so the
 * package works from a phar, from an opcache-preloaded image and from any
 * deployment whose vendor directory is not on a readable filesystem at
 * request time. The repository-root certs/ stays the reviewable source of
 * truth; php/certs/ is a checked copy, CI diffs the two, and a native test
 * proves these constants are byte-identical to the copy.
 *
 * @internal
 */
final class RootsData
{
    /** @var list<string> DER, base64, in the order certs/ lists them. */
    public const APPLE_ROOT_DER_BASE64 = [

HEADER;

foreach ($files as $file) {
    $der = file_get_contents($certsDir . '/' . $file);
    if ($der === false || $der === '') {
        fwrite(STDERR, "missing or empty: {$file}\n");
        exit(1);
    }
    $chunks = str_split(base64_encode($der), 76);
    $out .= "        // {$file}\n";
    $out .= "        '" . implode("'\n        . '", $chunks) . "',\n";
}
$out .= "    ];\n}\n";

file_put_contents($target, $out);
echo "wrote {$target}\n";
