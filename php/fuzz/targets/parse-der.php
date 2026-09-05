<?php

declare(strict_types=1);

namespace EminDeniz99\ApplePurchaseReceiptVerifier\Fuzz;

use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Asn1Node;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\Der;
use EminDeniz99\ApplePurchaseReceiptVerifier\Internal\ParseException;

/**
 * The bounded ASN.1 reader, on its own. Every other target reaches it through
 * a structure walk; this one hands it arbitrary bytes directly so a length or
 * depth bug shows up without a CMS or certificate shape around it.
 *
 * A parsed tree is then walked and every accessor is called on every node,
 * because the accessors slice `contents` again — an offset a mutated length
 * left wrong shows up there rather than in `parse()`.
 *
 * The invariant is the module's own: one well-formed value or a
 * `ParseException`, never a `TypeError`, an `Error`, a warning or a fatal.
 */

/** @var \PhpFuzzer\Config $config */
require __DIR__ . '/../bootstrap.php';

$config->setMaxLen(4096);
$config->setAllowedExceptions([ParseException::class]);

$walk = static function (Asn1Node $node) use (&$walk): void {
    if (Der::isOctetString($node)) {
        Der::octets($node);
    }
    if ($node->tag === Der::TAG_OID) {
        try {
            Der::decodeOid($node->contents);
        } catch (ParseException) {
            // A malformed OID inside an otherwise well-formed tree is a
            // verdict the callers make, not a crash.
        }
    }
    $node->childCount();
    $node->child(0);
    foreach ($node->children() as $child) {
        /** @var callable(Asn1Node): void $walk */
        $walk($child);
    }
};

$config->setTarget(static function (string $input) use ($walk): void {
    $walk(Der::parse($input));
});
